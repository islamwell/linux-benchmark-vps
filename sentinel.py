#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔════════════════════════════════════════════════════════════════════════════╗
║  LINUX HEALTH SENTINEL  ·  top-10 server health checks + fixes + alerts    ║
║  Zero dependencies · Python 3.7+ · stdlib only                             ║
╚════════════════════════════════════════════════════════════════════════════╝

  sudo python3 sentinel.py                  # dashboard on http://127.0.0.1:8686
  sudo python3 sentinel.py --once           # pretty CLI report (exit 0/1/2)
  sudo python3 sentinel.py --once --json    # machine readable
  sudo python3 sentinel.py --test-alerts    # verify email/slack/telegram setup
"""

import argparse
import json
import os
import re
import shutil
import smtplib
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import formatdate
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VERSION = "1.4.2"
UPDATED = "2026-08-27 15:50"

try:
    PAGE = os.sysconf("SC_PAGE_SIZE")
except Exception:
    PAGE = 4096

try:
    CLK = os.sysconf("SC_CLK_TCK")
except Exception:
    CLK = 100

CORES = os.cpu_count() or 1

# ─────────────────────────────────────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────────────────────────────────────

DEFAULTS = {
    "hostname": None,                    # None -> auto
    "scan_interval": 30,                 # seconds between background scans
    "history_points": 720,
    "state_file": "/var/lib/health-sentinel/state.json",
    "web": {"enabled": True, "bind": "127.0.0.1", "port": 8686, "token": ""},
    "thresholds": {
        "cpu_warn": 85, "cpu_crit": 95,
        "steal_warn": 5, "steal_crit": 12,
        "load_warn": 1.0, "load_crit": 2.0,          # per core
        "mem_warn": 85, "mem_crit": 94,
        "swap_warn": 35, "swap_crit": 75,
        "disk_warn": 80, "disk_crit": 92,
        "inode_warn": 80, "inode_crit": 92,
        "io_util_warn": 80, "io_util_crit": 95,
        "await_warn": 25, "await_crit": 120,          # ms
        "iowait_warn": 12, "iowait_crit": 30,
        "neterr_warn": 1, "neterr_crit": 25,          # errors+drops per second
        "retrans_warn": 1.5, "retrans_crit": 6,       # % of out segments
        "conntrack_warn": 75, "conntrack_crit": 90,
        "fd_warn": 70, "fd_crit": 88,
        "pid_warn": 70, "pid_crit": 88,
        "zombie_warn": 15, "zombie_crit": 60,
        "logerr_warn": 25, "logerr_crit": 150,        # journal errors / hour
        "authfail_warn": 30, "authfail_crit": 250,    # failed logins / hour
    },
    "alerts": {
        "enabled": True,
        "min_severity": "warn",          # warn | crit
        "consecutive": 2,                # scans in a row before alerting (anti-flap)
        "cooldown_minutes": 60,          # re-notify same problem after N minutes
        "notify_recovery": True,
        "email": {
            "enabled": False, "host": "smtp.gmail.com", "port": 587,
            "tls": True, "ssl": False, "user": "", "password": "",
            "from": "sentinel@example.com", "to": ["ops@example.com"]
        },
        "slack":    {"enabled": False, "webhook_url": ""},
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "ntfy":     {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": ""},
        "webhook":  {"enabled": False, "url": "", "headers": {}},
        "desktop":  {"enabled": False},
    },
}


def deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    if path and os.path.exists(path):
        with open(path) as fh:
            cfg = deep_merge(cfg, json.load(fh))
    cfg["hostname"] = cfg["hostname"] or socket.gethostname()
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
#  LOW LEVEL HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def read(path, default=""):
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read()
    except Exception:
        return default


def read_int(path, default=0):
    try:
        val = read(path).strip()
        return int(val.split()[0]) if val else default
    except Exception:
        return default


_cache = {}
_cache_lock = threading.Lock()


def sh(cmd, timeout=4, ttl=0):
    """Run a shell-less command list; optional TTL cache for slow tools."""
    key = tuple(cmd)
    now = time.time()
    if ttl:
        with _cache_lock:
            hit = _cache.get(key)
            if hit and now - hit[0] < ttl:
                return hit[1]
    if not shutil.which(cmd[0]):
        res = (127, "")
    else:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            res = (p.returncode, (p.stdout or "") + (p.stderr or ""))
        except Exception:
            res = (1, "")
    if ttl:
        with _cache_lock:
            _cache[key] = (now, res)
    return res


def fmt_bytes(n, digits=1):
    n = float(n or 0)
    for u in ("B", "K", "M", "G", "T", "P"):
        if abs(n) < 1024 or u == "P":
            return f"{n:.{0 if u == 'B' else digits}f}{u}"
        n /= 1024.0


def fmt_dur(sec):
    sec = int(sec or 0)
    d, r = divmod(sec, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h {m}m"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


def clamp(v, lo=0.0, hi=100.0):
    return max(lo, min(hi, v))


def score_from(v, warn, crit):
    """Higher value = worse. Maps to 0..100 score + status."""
    v = max(0.0, float(v))
    if v >= crit:
        over = (v - crit) / max(crit, 1e-9)
        return clamp(18 - 18 * min(over, 1.0)), "crit"
    if v >= warn:
        return clamp(20 + 45 * (crit - v) / max(crit - warn, 1e-9)), "warn"
    return clamp(65 + 35 * (warn - v) / max(warn, 1e-9)), "ok"


def psi(kind):
    out = {}
    content = read(f"/proc/pressure/{kind}")
    if not content:
        return out
    for line in content.splitlines():
        parts = line.split()
        if not parts:
            continue
        for kv in parts[1:]:
            k, _, val = kv.partition("=")
            try:
                out[f"{parts[0]}_{k}"] = float(val)
            except ValueError:
                pass
    return out


# ─────────────────────────────────────────────────────────────────────────────
#  RAW SAMPLERS  (delta based)
# ─────────────────────────────────────────────────────────────────────────────

def sample_cpu():
    for line in read("/proc/stat").splitlines():
        if line.startswith("cpu "):
            f = [float(x) for x in line.split()[1:]]
            f += [0.0] * (10 - len(f))
            keys = ["user", "nice", "system", "idle", "iowait", "irq",
                    "softirq", "steal", "guest", "guest_nice"]
            d = dict(zip(keys, f))
            d["total"] = sum(f[:8])
            return d
    return {}


def sample_diskstats():
    out = {}
    blocks = set(os.listdir("/sys/block")) if os.path.isdir("/sys/block") else set()
    for line in read("/proc/diskstats").splitlines():
        p = line.split()
        if len(p) < 14:
            continue
        name = p[2]
        if name not in blocks or re.match(r"^(loop|ram|zram|sr|fd|dm-)", name):
            continue
        out[name] = {
            "reads": int(p[3]), "rsect": int(p[5]), "rticks": int(p[6]),
            "writes": int(p[7]), "wsect": int(p[9]), "wticks": int(p[10]),
            "inflight": int(p[11]), "ioticks": int(p[12]),
            "rot": read_int(f"/sys/block/{name}/queue/rotational", 0),
        }
    return out


def sample_netdev():
    out = {}
    for line in read("/proc/net/dev").splitlines()[2:]:
        name, _, rest = line.partition(":")
        name = name.strip()
        f = rest.split()
        if name == "lo" or len(f) < 16 or re.match(r"^(veth|docker|br-|virbr|cni|flannel|tail)", name):
            continue
        out[name] = {"rx": int(f[0]), "rxerr": int(f[2]), "rxdrop": int(f[3]), "rxfifo": int(f[4]),
                     "tx": int(f[8]), "txerr": int(f[10]), "txdrop": int(f[11])}
    return out


def sample_snmp():
    out = {}
    lines = read("/proc/net/snmp").splitlines() + read("/proc/net/netstat").splitlines()
    for i in range(0, len(lines) - 1, 2):
        head, vals = lines[i].split(), lines[i + 1].split()
        if not head or head[0] != vals[0]:
            continue
        for k, v in zip(head[1:], vals[1:]):
            try:
                out[f"{head[0].rstrip(':')}.{k}"] = int(v)
            except ValueError:
                pass
    return out


def sample_vmstat():
    d = {}
    for line in read("/proc/vmstat").splitlines():
        p = line.split()
        if len(p) == 2:
            try:
                d[p[0]] = int(p[1])
            except ValueError:
                pass
    return d


def sample_procs():
    procs, states = {}, {}
    try:
        pids = [p for p in os.listdir("/proc") if p.isdigit()]
    except Exception:
        return procs, states
    for pid in pids:
        st = read(f"/proc/{pid}/stat")
        r = st.rfind(")")
        if r < 0:
            continue
        comm = st[st.find("(") + 1: r]
        f = st[r + 2:].split()
        if len(f) < 22:
            continue
        try:
            state = f[0]
            procs[pid] = {"comm": comm, "state": state,
                          "ticks": int(f[11]) + int(f[12]),
                          "rss": int(f[21]) * PAGE,
                          "threads": int(f[17])}
            states[state] = states.get(state, 0) + 1
        except ValueError:
            continue
    return procs, states


class Sampler:
    """Holds previous raw counters so checks can compute true rates."""

    def __init__(self):
        self.prev = None

    def take(self):
        return {"t": time.monotonic(), "cpu": sample_cpu(), "disk": sample_diskstats(),
                "net": sample_netdev(), "snmp": sample_snmp(), "vm": sample_vmstat(),
                "procs": sample_procs()}

    def collect(self, prime_wait=0.85):
        if self.prev is None:
            self.prev = self.take()
            time.sleep(prime_wait)
        cur = self.take()
        prev, self.prev = self.prev, cur
        dt = max(cur["t"] - prev["t"], 0.05)
        return cur, prev, dt


# ─────────────────────────────────────────────────────────────────────────────
#  RESULT MODEL
# ─────────────────────────────────────────────────────────────────────────────

RANK = {"ok": 0, "info": 0, "warn": 1, "crit": 2}
LEVELS = ["ok", "warn", "crit"]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str = ""
    why: str = ""
    diagnose: list = field(default_factory=list)
    fix: list = field(default_factory=list)


@dataclass
class Check:
    id: str
    name: str
    icon: str
    weight: float = 1.0
    status: str = "ok"
    score: float = 100.0
    value: str = "—"
    unit: str = ""
    pct: float = 0.0
    summary: str = ""
    metrics: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)

    def set_primary(self, v, warn, crit, pct=None):
        self.score, self.status = score_from(v, warn, crit)
        self.pct = clamp(pct if pct is not None else (v / max(crit, 1e-9)) * 100.0)

    def add(self, sev, title, detail="", why="", diagnose=(), fix=()):
        self.findings.append(Finding(sev, title, detail, why, list(diagnose), list(fix)))

    def finalize(self):
        worst = max([RANK[f.severity] for f in self.findings] + [RANK[self.status]])
        self.status = LEVELS[worst]
        if self.status == "crit":
            self.score = min(self.score, 32)
        elif self.status == "warn":
            self.score = min(self.score, 68)
        self.score = round(self.score, 1)
        self.findings.sort(key=lambda f: -RANK[f.severity])
        return self


# ─────────────────────────────────────────────────────────────────────────────
#  THE 10 CHECKS
# ─────────────────────────────────────────────────────────────────────────────

def top_cpu(cur, prev, dt, n=5):
    out = []
    pc, pp = cur["procs"][0], prev["procs"][0]
    for pid, p in pc.items():
        old = pp.get(pid)
        if not old:
            continue
        used = (p["ticks"] - old["ticks"]) / CLK / dt * 100.0
        if used > 0.8:
            out.append((round(used, 1), pid, p["comm"]))
    out.sort(reverse=True)
    return out[:n]


def top_mem(cur, n=5):
    ps = [(p["rss"], pid, p["comm"]) for pid, p in cur["procs"][0].items()]
    ps.sort(reverse=True)
    return [(fmt_bytes(r), pid, c) for r, pid, c in ps[:n]]


# 1 ── CPU ────────────────────────────────────────────────────────────────────
def check_cpu(cur, prev, dt, T):
    c = Check("cpu", "CPU Utilisation", "cpu", 1.3)
    a, b = cur["cpu"], prev["cpu"]
    if not a or not b:
        return c.finalize()
    tot = max(a.get("total", 0) - b.get("total", 0), 1e-9)
    d = {k: (a.get(k, 0) - b.get(k, 0)) / tot * 100 for k in
         ("user", "nice", "system", "iowait", "steal", "irq", "softirq", "idle")}
    busy = clamp(100 - d["idle"])
    p = psi("cpu")
    cpu_model_match = re.search(r"model name\s*:\s*(.+)", read("/proc/cpuinfo"))
    cpu_model = cpu_model_match.group(1).strip() if cpu_model_match else "Generic CPU"
    c.metrics = {"busy": round(busy, 1), "user": round(d["user"] + d["nice"], 1),
                 "system": round(d["system"], 1), "iowait": round(d["iowait"], 1),
                 "steal": round(d["steal"], 1), "irq": round(d["irq"] + d["softirq"], 1),
                 "cores": CORES, "psi10": p.get("some_avg10", 0.0),
                 "model": cpu_model}
    c.value, c.unit = f"{busy:.0f}", "%"
    c.set_primary(busy, T["cpu_warn"], T["cpu_crit"], pct=busy)
    tops = top_cpu(cur, prev, dt)
    c.summary = (f"{CORES} cores · usr {c.metrics['user']}% · sys {c.metrics['system']}% · "
                 f"io {c.metrics['iowait']}% · steal {c.metrics['steal']}%")

    if busy >= T["cpu_warn"]:
        sev = "crit" if busy >= T["cpu_crit"] else "warn"
        c.add(sev, f"CPU saturated at {busy:.0f}%",
              "Top consumers: " + (", ".join(f"{n}({pid}) {u}%" for u, pid, n in tops) or "n/a"),
              "Sustained >85% CPU means runnable threads wait for cores: request latency grows "
              "non-linearly and queues (nginx/php-fpm/DB) start backing up.",
              ["top -bn1 -o %CPU | head -20",
               "pidstat -u 2 5            # per-process trend",
               "ps -eo pid,ppid,%cpu,comm --sort=-%cpu | head",
               "perf top -F 99 --stdio   # kernel/user hotspots (5s, Ctrl-C)"],
              [f"renice +10 -p {tops[0][1]}   # deprioritise the hog" if tops else "renice +10 -p <PID>",
               "systemctl set-property <unit> CPUQuota=200%   # cgroup cap, persists",
               "Scale out: add workers/replicas or move the noisy job off this box",
               "If it is a cron/batch job: run it with `nice -n 19 ionice -c3 …` off-peak"])
    if d["system"] > 30:
        c.add("warn", f"Kernel (system) time high: {d['system']:.0f}%",
              "More than 30% of CPU is spent in kernel space.",
              "Usually excessive syscalls, context switches, softirq/network interrupts, "
              "or a chatty container runtime.",
              ["vmstat 1 5                # cs/in columns",
               "pidstat -w 2 5            # context switch offenders",
               "cat /proc/interrupts | sort -k2 -nr | head"],
              ["Batch I/O (larger buffers), enable connection pooling / keep-alive",
               "Spread NIC interrupts: `sudo systemctl enable --now irqbalance`",
               "Check for a syscall storm: `strace -c -f -p <PID>` (30s)"])
    if d["steal"] >= T["steal_warn"]:
        c.add("crit" if d["steal"] >= T["steal_crit"] else "warn",
              f"Hypervisor steal time {d['steal']:.1f}%",
              "The host is not giving this VM the CPU it asks for.",
              "Steal time = noisy neighbours or a CPU-credit/burst limit exhausted "
              "(AWS T-series, GCP shared-core, oversold VPS).",
              ["mpstat -P ALL 2 5", "grep -c ^processor /proc/cpuinfo",
               "curl -s http://169.254.169.254/latest/meta-data/instance-type  # AWS"],
              ["Switch to a dedicated/unlimited instance type (t3→m6i, or enable T3 Unlimited)",
               "Migrate the VM to another host (stop/start on cloud = new host)",
               "Open a ticket with the provider quoting steal% and timestamps"])
    if p.get("some_avg10", 0) > 40:
        c.add("warn", f"CPU pressure (PSI) {p['some_avg10']:.0f}%",
              "Tasks are stalling waiting for CPU time even if utilisation looks ok.",
              "PSI counts real stall time — the most accurate saturation signal.",
              ["cat /proc/pressure/cpu",
               "for f in /sys/fs/cgroup/*/cpu.pressure; do echo $f; cat $f; done"],
              ["Find the cgroup with the highest cpu.pressure and raise CPUQuota or move it",
               "Reduce worker concurrency so it matches core count"])
    return c.finalize()


# 2 ── LOAD ───────────────────────────────────────────────────────────────────
def check_load(cur, prev, dt, T):
    c = Check("load", "Load Average", "activity", 1.0)
    try:
        parts = read("/proc/loadavg").split()
        if len(parts) >= 3:
            l1, l5, l15 = [float(x) for x in parts[:3]]
        else:
            l1, l5, l15 = os.getloadavg()
    except Exception:
        return c.finalize()
    n1, n15 = l1 / CORES, l15 / CORES
    blocked = cur["procs"][1].get("D", 0)
    running = cur["procs"][1].get("R", 0)
    c.metrics = {"load1": round(l1, 2), "load5": round(l5, 2), "load15": round(l15, 2),
                 "per_core": round(n1, 2), "cores": CORES, "running": running, "blocked_io": blocked}
    c.value, c.unit = f"{l1:.2f}", f"/ {CORES} cores"
    c.set_primary(n1, T["load_warn"], T["load_crit"], pct=n1 / T["load_crit"] * 100)
    trend = "rising ↑" if l1 > l5 * 1.25 else ("falling ↓" if l1 < l5 * 0.75 else "stable →")
    c.summary = f"1m {l1:.2f} · 5m {l5:.2f} · 15m {l15:.2f} · {trend} · {n1:.2f} per core"

    if n1 >= T["load_warn"]:
        sev = "crit" if n1 >= T["load_crit"] else "warn"
        cause = ("I/O wait — most of the queue is in uninterruptible D state"
                 if blocked >= max(2, running) else "CPU contention — runnable tasks exceed cores")
        c.add(sev, f"Run queue {n1:.2f}× cores ({l1:.2f} on {CORES} cores)",
              f"Likely cause: {cause}. R={running}, D={blocked}.",
              "Load counts runnable AND uninterruptible tasks. >1×cores sustained = "
              "everything queues; >2× and latency SLOs break.",
              ["uptime; vmstat 1 5",
               "ps -eo state,pid,comm | awk '$1~/^[RD]/' | sort | uniq -c | sort -rn | head",
               "ps -eo pid,stat,wchan:25,comm | awk '$2~/D/'   # what are they blocked on?"],
              ["If D-state dominated → fix storage/NFS first (see Disk I/O check)",
               "If R dominated → cap concurrency, add cores, scale horizontally",
               "Kill/pause the batch job: `systemctl stop <unit>` then re-run with nice/ionice"])
    if l1 > l15 * 2 and n1 > 0.7:
        c.add("info", "Load is spiking fast",
              f"1m load is {l1 / max(l15, .01):.1f}× the 15m average.",
              "A sudden burst — deploy, cron storm, traffic spike or a stuck retry loop.",
              ["journalctl --since '-10 min' -p warning --no-pager | tail -40",
               "ss -s ; systemctl list-jobs"],
              ["Correlate with cron: `grep CRON /var/log/syslog | tail`",
               "Add jitter/backoff to retries; stagger cron with RandomizedDelaySec="])
    return c.finalize()


# 3 ── MEMORY ─────────────────────────────────────────────────────────────────
def check_memory(cur, prev, dt, T):
    c = Check("memory", "Memory & Swap", "memory", 1.3)
    mi = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        try:
            mi[k] = int(v.split()[0]) * 1024
        except Exception:
            pass
    total = mi.get("MemTotal", 1)
    avail = mi.get("MemAvailable", mi.get("MemFree", 0))
    used_pct = clamp((1 - avail / total) * 100) if total else 0.0
    sw_t, sw_f = mi.get("SwapTotal", 0), mi.get("SwapFree", 0)
    sw_pct = ((sw_t - sw_f) / sw_t * 100) if sw_t else 0.0
    si = (cur["vm"].get("pswpin", 0) - prev["vm"].get("pswpin", 0)) / dt
    so = (cur["vm"].get("pswpout", 0) - prev["vm"].get("pswpout", 0)) / dt
    p = psi("memory")
    c.metrics = {"total": total, "available": avail, "used_pct": round(used_pct, 1),
                 "cached": mi.get("Cached", 0), "buffers": mi.get("Buffers", 0),
                 "swap_total": sw_t, "swap_used_pct": round(sw_pct, 1),
                 "swap_in_s": round(si, 1), "swap_out_s": round(so, 1),
                 "psi10": p.get("some_avg10", 0.0),
                 "commit": mi.get("Committed_AS", 0), "slab": mi.get("Slab", 0),
                 "hugepages": mi.get("AnonHugePages", 0)}
    c.value, c.unit = f"{used_pct:.0f}", "%"
    c.set_primary(used_pct, T["mem_warn"], T["mem_crit"], pct=used_pct)
    c.summary = (f"{fmt_bytes(total - avail)} of {fmt_bytes(total)} in use · "
                 f"{fmt_bytes(avail)} available · cache {fmt_bytes(c.metrics['cached'])} · "
                 f"swap {sw_pct:.0f}%")

    if used_pct >= T["mem_warn"]:
        c.add("crit" if used_pct >= T["mem_crit"] else "warn",
              f"Only {fmt_bytes(avail)} available ({used_pct:.0f}% used)",
              "Top RSS: " + ", ".join(f"{n}({pid}) {r}" for r, pid, n in top_mem(cur)),
              "Below ~10% available the kernel reclaims page cache aggressively → disk reads "
              "explode; then the OOM killer picks a victim (often your DB).",
              ["free -h ; ps -eo pid,rss,comm --sort=-rss | head -15",
               "smem -tk -c 'pid user command rss uss pss' 2>/dev/null | tail -15",
               "sudo slabtop -o | head -15     # kernel/slab leaks",
               "cat /proc/meminfo | egrep 'MemAvail|Committed|Slab|Shmem'"],
              ["Cap the offender: `systemctl set-property <unit> MemoryMax=2G MemoryHigh=1.6G`",
               "Tune app heaps: JVM -Xmx, PHP memory_limit, PG shared_buffers ≈25% RAM, "
               "MySQL innodb_buffer_pool_size ≈50–60% RAM (do not overcommit!)",
               "Reduce worker count: gunicorn/php-fpm workers × RSS must fit in RAM",
               "Protect critical services: `systemctl set-property db.service OOMScoreAdjust=-800`",
               "Long-term: add RAM or move the memory-heavy tier to its own node"])
    if sw_t and sw_pct >= T["swap_warn"]:
        c.add("crit" if sw_pct >= T["swap_crit"] else "warn",
              f"Swap {sw_pct:.0f}% used ({fmt_bytes(sw_t - sw_f)})",
              f"Swap-in {si:.0f} pg/s · swap-out {so:.0f} pg/s",
              "Anonymous memory on disk is ~1000× slower than RAM. Heavy swap traffic "
              "(thrashing) looks like a total outage while CPU appears idle.",
              ["vmstat 1 5   # watch si/so",
               "for f in /proc/*/status; do awk '/^Name|VmSwap/{printf \"%s \",$2}END{print \"\"}' $f; "
               "done | sort -k2 -h | tail -10"],
              ["Free RAM first (see above) — swap is a symptom, not the disease",
               "Lower swappiness for latency-sensitive boxes: "
               "`sudo sysctl -w vm.swappiness=10` (persist in /etc/sysctl.d/99-tune.conf)",
               "Then reset swap once RAM is free: `sudo swapoff -a && sudo swapon -a`",
               "Consider zram instead of disk swap on small VMs"])
    if si + so > 200:
        c.add("crit", "Swap thrashing detected", f"{si + so:.0f} pages/s moving in+out of swap.",
              "The working set no longer fits in RAM; the box is effectively down.",
              ["vmstat 1", "dstat -tmsg 1"],
              ["Immediately stop the largest non-critical consumer",
               "Then add RAM / reduce workers — do not just add more swap"])
    if p.get("some_avg10", 0) > 20:
        c.add("warn", f"Memory pressure (PSI) {p['some_avg10']:.0f}%",
              "Tasks stalled on memory reclaim in the last 10s.",
              "Best early-warning signal for OOM — fires before free memory hits zero.",
              ["cat /proc/pressure/memory",
               "grep -r '' /sys/fs/cgroup/*/memory.pressure 2>/dev/null | sort -t= -k2 -nr | head"],
              ["Set MemoryHigh= on the guilty cgroup to throttle it instead of OOM-killing it",
               "Trim page-cache-hostile jobs (big rsync/backup) with `nocache` or ionice"])
    oom = _recent_oom()
    if oom:
        c.add("crit", f"OOM killer fired {len(oom)}× recently", " | ".join(oom[:3]),
              "The kernel had to kill processes to survive. Data loss / partial writes possible.",
              ["journalctl -k --since '-24h' | grep -iE 'out of memory|oom-kill' ",
               "dmesg -T | grep -i 'killed process'",
               "systemctl status <killed-unit>"],
              ["Add RAM or MemoryMax limits so the *right* process is throttled",
               "Set OOMScoreAdjust=-500 on critical units, +500 on batch units",
               "Verify the killed service restarted: `Restart=always` + `RestartSec=5`"])
    return c.finalize()


def _recent_oom():
    rc, out = sh(["journalctl", "-k", "--since", "-24h", "--no-pager", "-q"], timeout=6, ttl=120)
    if rc != 0 or not out:
        rc, out = sh(["dmesg", "-T"], timeout=6, ttl=120)
    return [l.strip()[:160] for l in out.splitlines()
            if re.search(r"(out of memory: killed|oom-kill|killed process)", l, re.I)][-5:]


# 4 ── DISK SPACE ─────────────────────────────────────────────────────────────

SKIP_FS = {"proc", "sysfs", "devtmpfs", "devpts", "cgroup", "cgroup2", "pstore", "tracefs",
           "debugfs", "mqueue", "hugetlbfs", "fusectl", "configfs", "securityfs", "bpf",
           "binfmt_misc", "nsfs", "autofs", "rpc_pipefs", "squashfs", "overlay", "ramfs",
           "efivarfs", "selinuxfs", "fuse.snapfuse", "fuse.gvfsd-fuse", "nfsd"}


def _mounts():
    seen, out = set(), []
    mounts_content = read("/proc/mounts")
    if not mounts_content:
        # Fallback to root mount
        try:
            s = os.statvfs("/")
            total = s.f_blocks * s.f_frsize
            if total > 0:
                out.append(("/", "/", "rootfs", "rw", s, total))
        except Exception:
            pass
        return out

    for line in mounts_content.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        dev, mp, fs, opts = p[0], p[1].replace("\\040", " "), p[2], p[3]
        if fs in SKIP_FS or mp.startswith(("/snap", "/var/lib/docker/", "/proc", "/sys")):
            continue
        try:
            s = os.statvfs(mp)
        except OSError:
            continue
        total = s.f_blocks * s.f_frsize
        if total < 64 * 1024 * 1024:
            continue
        key = (dev, s.f_blocks, s.f_files)
        if key in seen:
            continue
        seen.add(key)
        out.append((dev, mp, fs, opts, s, total))
    return out


def check_disk_space(cur, prev, dt, T):
    c = Check("disk", "Disk Space", "drive", 1.4)
    worst, rows = 0.0, []
    for dev, mp, fs, opts, s, total in _mounts():
        free = s.f_bavail * s.f_frsize
        used = total - (s.f_bfree * s.f_frsize)
        pct = clamp(used / total * 100 if total else 0)
        rows.append({"mount": mp, "dev": dev, "fs": fs, "pct": round(pct, 1),
                     "free": free, "total": total, "ro": "ro" in opts.split(",")})
        worst = max(worst, pct)
    rows.sort(key=lambda r: -r["pct"])
    c.metrics = {"mounts": rows, "worst_pct": round(worst, 1)}
    c.value, c.unit = f"{worst:.0f}", "% max"
    c.set_primary(worst, T["disk_warn"], T["disk_crit"], pct=worst)
    top = rows[0] if rows else None
    c.summary = (f"{len(rows)} filesystems · worst {top['mount']} {top['pct']:.0f}% "
                 f"({fmt_bytes(top['free'])} free)" if top else "no filesystems")

    for r in rows:
        if r["pct"] < T["disk_warn"]:
            continue
        sev = "crit" if r["pct"] >= T["disk_crit"] else "warn"
        mp = r["mount"]
        c.add(sev, f"{mp} is {r['pct']:.0f}% full ({fmt_bytes(r['free'])} free)",
              f"{r['dev']} · {r['fs']} · total {fmt_bytes(r['total'])}",
              "A full filesystem breaks everything writing to it: DBs go read-only and "
              "corrupt, logs stop, sessions/uploads fail, package upgrades break. "
              "ext4 also reserves 5% for root — non-root writes fail before 100%.",
              [f"du -xh --max-depth=1 {mp} 2>/dev/null | sort -h | tail -15",
               f"find {mp} -xdev -type f -size +500M -printf '%s\\t%p\\n' 2>/dev/null | sort -rn | head",
               "journalctl --disk-usage",
               "sudo lsof +L1 | head       # deleted files still held open by a process",
               f"df -h {mp}; df -i {mp}"],
              ["Logs: `sudo journalctl --vacuum-size=300M` and set "
               "SystemMaxUse=300M in /etc/systemd/journald.conf",
               "Rotate now: `sudo logrotate -f /etc/logrotate.conf`",
               "Packages: `sudo apt clean && sudo apt autoremove --purge` "
               "(RHEL: `sudo dnf clean all`)",
               "Containers: `docker system prune -af --volumes` (⚠ removes unused volumes)",
               "Deleted-but-open files: restart the holder shown by `lsof +L1` "
               "(truncating with `: > /proc/<pid>/fd/<n>` is a last resort)",
               "Old kernels: `sudo apt autoremove --purge` / `sudo dnf remove --oldinstallonly`",
               f"Still tight → grow it: `sudo lvextend -l +100%FREE {r['dev']} && "
               f"sudo resize2fs {r['dev']}` (xfs: `xfs_growfs {mp}`)"])
        if r["ro"]:
            c.add("crit", f"{mp} is mounted READ-ONLY",
                  "The kernel remounted it ro — almost always after an I/O or fs error.",
                  "Writes are silently failing across every service using this mount.",
                  ["dmesg -T | grep -iE 'ext4|xfs|i/o error|remount' | tail -20",
                   f"sudo smartctl -a {re.sub(r'[0-9]+$', '', r['dev'])}"],
                  [f"Check & repair (unmounted!): `sudo fsck -y {r['dev']}` / `xfs_repair {r['dev']}`",
                   "Replace the disk if SMART shows reallocated/pending sectors",
                   f"Temporary: `sudo mount -o remount,rw {mp}` — only after fsck"])
    return c.finalize()


# 5 ── DISK I/O BOTTLENECK ────────────────────────────────────────────────────
def check_disk_io(cur, prev, dt, T):
    c = Check("io", "Disk I/O Bottleneck", "gauge", 1.2)
    devs, worst_util, worst_await, worst_dev = [], 0.0, 0.0, "—"
    for name, a in cur["disk"].items():
        b = prev["disk"].get(name)
        if not b:
            continue
        ios = (a["reads"] - b["reads"]) + (a["writes"] - b["writes"])
        util = clamp((a["ioticks"] - b["ioticks"]) / (dt * 1000.0) * 100)
        awt = ((a["rticks"] - b["rticks"]) + (a["wticks"] - b["wticks"])) / ios if ios else 0.0
        rmb = (a["rsect"] - b["rsect"]) * 512 / dt
        wmb = (a["wsect"] - b["wsect"]) * 512 / dt
        devs.append({"dev": name, "util": round(util, 1), "await_ms": round(awt, 1),
                     "iops": round(ios / dt, 1), "read_s": rmb, "write_s": wmb,
                     "inflight": a["inflight"], "rotational": bool(a["rot"])})
        if util > worst_util:
            worst_util, worst_dev = util, name
        worst_await = max(worst_await, awt)
    devs.sort(key=lambda d: -d["util"])
    ca, cb = cur["cpu"], prev["cpu"]
    tot = max(ca.get("total", 1) - cb.get("total", 0), 1e-9)
    iowait = (ca.get("iowait", 0) - cb.get("iowait", 0)) / tot * 100
    p = psi("io")
    c.metrics = {"devices": devs, "worst_util": round(worst_util, 1),
                 "worst_await": round(worst_await, 1), "iowait": round(iowait, 1),
                 "psi10": p.get("some_avg10", 0.0),
                 "blocked": cur["procs"][1].get("D", 0)}
    c.value, c.unit = f"{worst_util:.0f}", f"% util ({worst_dev})"
    s1, st1 = score_from(worst_util, T["io_util_warn"], T["io_util_crit"])
    s2, st2 = score_from(worst_await, T["await_warn"], T["await_crit"])
    s3, st3 = score_from(iowait, T["iowait_warn"], T["iowait_crit"])
    c.score, c.status = min(s1, s2, s3), LEVELS[max(RANK[st1], RANK[st2], RANK[st3])]
    c.pct = clamp(worst_util)
    c.summary = (f"iowait {iowait:.1f}% · worst await {worst_await:.1f}ms · "
                 f"{devs[0]['iops'] if devs else 0:.0f} IOPS · D-state {c.metrics['blocked']}")

    if worst_util >= T["io_util_warn"] or worst_await >= T["await_warn"] or iowait >= T["iowait_warn"]:
        d0 = devs[0] if devs else {"dev": "?", "rotational": False}
        sev = "crit" if (worst_util >= T["io_util_crit"] or worst_await >= T["await_crit"]
                         or iowait >= T["iowait_crit"]) else "warn"
        c.add(sev, f"Storage is the bottleneck on {d0['dev']}",
              f"util {worst_util:.0f}% · await {worst_await:.1f}ms · iowait {iowait:.1f}% · "
              f"{'HDD' if d0.get('rotational') else 'SSD/NVMe'}",
              "When a device is ~100% busy or await climbs, every read/write queues. "
              "Rule of thumb: >20ms await on SSD or >100ms on HDD = user-visible slowness; "
              "processes pile up in D state and load average explodes.",
              ["iostat -xz 2 5                 # %util, await, aqu-sz per device",
               "sudo iotop -oPa                # which process does the I/O",
               "pidstat -d 2 5",
               "sudo biolatency 10 1           # bcc-tools: latency histogram",
               "cat /proc/pressure/io",
               f"sudo smartctl -a /dev/{d0['dev']} | egrep -i 'reallocat|pending|error|Wear'"],
              ["Find & throttle the writer: `sudo ionice -c2 -n7 -p <PID>` "
               "(or `systemctl set-property <unit> IOWeight=20 IOReadBandwidthMax=…`)",
               "Move backups/rsync/log shipping off peak; add `--bwlimit`",
               "Databases: add indexes for the slow queries, raise buffer pool so reads hit RAM, "
               "check checkpoint/fsync storms (PG: `log_checkpoints=on`)",
               "Scheduler: NVMe/SSD → `echo none > /sys/block/<dev>/queue/scheduler`; "
               "HDD → `mq-deadline`",
               "Filesystem: mount with `noatime` (fstab) to kill metadata writes",
               "If cloud: you are probably at the volume IOPS/throughput cap → "
               "upgrade gp2→gp3/io2, raise provisioned IOPS, or stripe volumes (RAID0/LVM)"])
    if p.get("full_avg10", 0) > 10:
        c.add("warn", f"I/O pressure stall (PSI full) {p['full_avg10']:.0f}%",
              "All tasks were blocked on I/O for a measurable share of time.",
              "PSI 'full' means the machine did nothing but wait for storage.",
              ["cat /proc/pressure/io", "grep -r '' /sys/fs/cgroup/*/io.pressure 2>/dev/null | head"],
              ["Apply io.max / IOWeight limits to the guilty cgroup", "Move the workload to faster storage"])
    errs = [l.strip()[:160] for l in _kernel_errors()
            if re.search(r"(i/o error|ata\d+.*failed|medium error|ext4-fs error|xfs.*corrupt|"
                         r"nvme.*(timeout|reset)|blk_update_request)", l, re.I)]
    if errs:
        c.add("crit", f"Kernel storage errors detected ({len(errs)})", " | ".join(errs[:2]),
              "Hardware or transport level failures — data loss risk is immediate.",
              ["dmesg -T --level=err,crit | tail -30",
               "sudo smartctl --scan | awk '{print $1}' | xargs -I{} sudo smartctl -H {}",
               "cat /proc/mdstat ; sudo nvme error-log /dev/nvme0"],
              ["Back up NOW, then replace the failing device",
               "Degraded RAID: `sudo mdadm --detail /dev/md0` and re-add/replace the member",
               "Cloud: detach/reattach or restore the volume from snapshot"])
    return c.finalize()


def _kernel_errors():
    rc, out = sh(["journalctl", "-k", "-p", "err", "--since", "-6h", "--no-pager", "-q"], timeout=6, ttl=120)
    if rc != 0 or not out.strip():
        rc, out = sh(["dmesg", "-T", "--level=err,crit,alert,emerg"], timeout=6, ttl=120)
    return out.splitlines()[-400:]


# 6 ── INODES ─────────────────────────────────────────────────────────────────
def check_inodes(cur, prev, dt, T):
    c = Check("inodes", "Inodes & File Handles", "layers", 0.8)
    rows, worst = [], 0.0
    for dev, mp, fs, opts, s, total in _mounts():
        if not s.f_files:
            continue
        pct = clamp((s.f_files - s.f_ffree) / s.f_files * 100)
        rows.append({"mount": mp, "pct": round(pct, 1), "free": s.f_ffree, "total": s.f_files})
        worst = max(worst, pct)
    rows.sort(key=lambda r: -r["pct"])
    fn = read("/proc/sys/fs/file-nr").split()
    fd_used, fd_max = (int(fn[0]), int(fn[2])) if len(fn) == 3 else (0, 1)
    fd_pct = fd_used / max(fd_max, 1) * 100
    c.metrics = {"mounts": rows, "worst_pct": round(worst, 1), "fd_used": fd_used,
                 "fd_max": fd_max, "fd_pct": round(fd_pct, 1)}
    c.value, c.unit = f"{worst:.0f}", "% inodes"
    s1, st1 = score_from(worst, T["inode_warn"], T["inode_crit"])
    s2, st2 = score_from(fd_pct, T["fd_warn"], T["fd_crit"])
    c.score, c.status = min(s1, s2), LEVELS[max(RANK[st1], RANK[st2])]
    c.pct = clamp(max(worst, fd_pct))
    c.summary = (f"worst {rows[0]['mount'] if rows else '—'} {worst:.0f}% · "
                 f"open files {fd_used:,}/{fd_max:,} ({fd_pct:.0f}%)")

    for r in rows:
        if r["pct"] >= T["inode_warn"]:
            c.add("crit" if r["pct"] >= T["inode_crit"] else "warn",
                  f"{r['mount']} inodes {r['pct']:.0f}% used ({r['free']:,} free)",
                  "Millions of tiny files exhaust inodes long before bytes run out.",
                  "With no free inodes you get 'No space left on device' while `df -h` shows "
                  "free space — classic cause: session files, mail queue, cache dirs, "
                  "unrotated per-request logs.",
                  [f"df -i {r['mount']}",
                   f"sudo find {r['mount']} -xdev -type d -printf '%p\\n' 2>/dev/null | "
                   f"while read d; do echo \"$(ls -U \"$d\" 2>/dev/null|wc -l) $d\"; done | sort -rn | head",
                   "sudo find /var/lib/php/sessions /tmp /var/spool -xdev -type f | wc -l"],
                  ["Purge old small files: `sudo find /tmp -xdev -type f -mtime +7 -delete`",
                   "PHP sessions: `sudo find /var/lib/php/sessions -type f -mmin +180 -delete` "
                   "and enable session.gc",
                   "Mail queue: `sudo postsuper -d ALL deferred` (check first!)",
                   "Delete faster in huge dirs: `find <dir> -type f -print0 | xargs -0 -P4 rm -f`",
                   "Permanent: ext4 inode count is fixed at mkfs → recreate with "
                   "`mkfs.ext4 -i 8192`, or migrate that path to XFS (dynamic inodes)"])
    if fd_pct >= T["fd_warn"]:
        c.add("crit" if fd_pct >= T["fd_crit"] else "warn",
              f"System-wide open files at {fd_pct:.0f}% ({fd_used:,}/{fd_max:,})",
              "Hitting fs.file-max causes 'Too many open files' across all services.",
              "Usually a descriptor leak (unclosed sockets/files) in an app.",
              ["sudo lsof | awk '{print $2}' | sort | uniq -c | sort -rn | head",
               "for p in /proc/[0-9]*; do echo \"$(ls $p/fd 2>/dev/null|wc -l) $(cat $p/comm)\"; done "
               "| sort -rn | head",
               "cat /proc/sys/fs/file-nr ; ulimit -n"],
              ["Raise limits: `sudo sysctl -w fs.file-max=2097152` (persist in /etc/sysctl.d/)",
               "Per-service: `systemctl set-property <unit> LimitNOFILE=65535`",
               "Fix the leak — restart the top offender and watch its fd count trend"])
    return c.finalize()


# 7 ── NETWORK ────────────────────────────────────────────────────────────────
def check_network(cur, prev, dt, T):
    c = Check("network", "Network Health", "network", 1.0)
    ifaces, worst_err = [], 0.0
    for name, a in cur["net"].items():
        b = prev["net"].get(name)
        if not b:
            continue
        errs = ((a["rxerr"] - b["rxerr"]) + (a["txerr"] - b["txerr"]) +
                (a["rxdrop"] - b["rxdrop"]) + (a["txdrop"] - b["txdrop"])) / dt
        ifaces.append({"iface": name, "rx_s": (a["rx"] - b["rx"]) / dt,
                       "tx_s": (a["tx"] - b["tx"]) / dt, "err_s": round(errs, 2),
                       "speed": read_int(f"/sys/class/net/{name}/speed", 0),
                       "state": read(f"/sys/class/net/{name}/operstate", "?").strip()})
        worst_err = max(worst_err, errs)
    ifaces.sort(key=lambda i: -(i["rx_s"] + i["tx_s"]))
    sa, sb = cur["snmp"], prev["snmp"]
    outseg = max(sa.get("Tcp.OutSegs", 0) - sb.get("Tcp.OutSegs", 0), 1)
    retrans = (sa.get("Tcp.RetransSegs", 0) - sb.get("Tcp.RetransSegs", 0)) / outseg * 100
    listen_drops = (sa.get("TcpExt.ListenDrops", 0) - sb.get("TcpExt.ListenDrops", 0)) / dt
    overflow = (sa.get("TcpExt.ListenOverflows", 0) - sb.get("TcpExt.ListenOverflows", 0)) / dt
    ct_max = read_int("/proc/sys/net/netfilter/nf_conntrack_max", 0)
    ct_cnt = read_int("/proc/sys/net/netfilter/nf_conntrack_count", 0)
    ct_pct = ct_cnt / ct_max * 100 if ct_max else 0.0
    est = tw = 0
    for line in read("/proc/net/sockstat").splitlines():
        if line.startswith("TCP:"):
            m = dict(zip(line.split()[1::2], line.split()[2::2]))
            est, tw = int(m.get("inuse", 0)), int(m.get("tw", 0))
    c.metrics = {"ifaces": ifaces, "retrans_pct": round(retrans, 2),
                 "listen_drops_s": round(listen_drops, 2), "overflow_s": round(overflow, 2),
                 "conntrack_pct": round(ct_pct, 1), "conntrack": f"{ct_cnt:,}/{ct_max:,}",
                 "tcp_inuse": est, "tcp_tw": tw, "worst_err_s": round(worst_err, 2)}
    c.value, c.unit = f"{retrans:.1f}", "% retrans"
    scores = [score_from(worst_err, T["neterr_warn"], T["neterr_crit"]),
              score_from(retrans, T["retrans_warn"], T["retrans_crit"]),
              score_from(ct_pct, T["conntrack_warn"], T["conntrack_crit"])]
    c.score = min(s for s, _ in scores)
    c.status = LEVELS[max(RANK[st] for _, st in scores)]
    c.pct = clamp(max(retrans / T["retrans_crit"] * 100, ct_pct))
    top = ifaces[0] if ifaces else None
    c.summary = (f"{top['iface']} ↓{fmt_bytes(top['rx_s'])}/s ↑{fmt_bytes(top['tx_s'])}/s · "
                 f"retrans {retrans:.2f}% · conntrack {ct_pct:.0f}% · TCP {est:,} open"
                 if top else "no physical interfaces")

    for i in ifaces:
        if i["err_s"] >= T["neterr_warn"]:
            c.add("crit" if i["err_s"] >= T["neterr_crit"] else "warn",
                  f"{i['iface']}: {i['err_s']:.1f} errors+drops/s",
                  f"link {i['state']} · {i['speed'] or '?'} Mb/s",
                  "Drops mean the NIC ring buffer or the socket queue overflowed, or the "
                  "cable/switch port is flaky. TCP hides it as latency; UDP just loses data.",
                  [f"ip -s link show {i['iface']}",
                   f"ethtool -S {i['iface']} | egrep -i 'drop|err|miss|fifo|nobuf'",
                   f"ethtool {i['iface']} | egrep -i 'speed|duplex|link'",
                   "netstat -su | grep -i 'packet receive errors'"],
                  [f"Grow ring buffers: `sudo ethtool -G {i['iface']} rx 4096 tx 4096`",
                   "Grow socket buffers: `sudo sysctl -w net.core.rmem_max=16777216 "
                   "net.core.netdev_max_backlog=5000`",
                   "Check the physical layer: replace cable/SFP, verify switch port counters",
                   "Fix duplex/speed mismatch (never leave one side hard-coded)"])
    if retrans >= T["retrans_warn"]:
        c.add("crit" if retrans >= T["retrans_crit"] else "warn",
              f"TCP retransmits {retrans:.2f}% of segments",
              f"{sa.get('Tcp.RetransSegs',0) - sb.get('Tcp.RetransSegs',0)} retransmitted in {dt:.0f}s",
              "Above ~1% retransmission users feel stalls and timeouts. Cause is packet loss "
              "on the path, an overloaded peer, or a saturated uplink.",
              ["ss -ti | grep -E 'retrans|rto' | head",
               "nstat -az | egrep 'TcpRetrans|TcpExtTCPLostRetransmit|TcpExtTCPTimeouts'",
               "mtr -rwzc 100 <peer-ip>", "ping -c 100 -i .2 <peer-ip> | tail -3"],
              ["Enable BBR + fq: `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr "
               "net.core.default_qdisc=fq`",
               "Check if you saturate the uplink (`iftop`, cloud NIC bandwidth caps)",
               "Escalate the loss segment found by mtr to the network/hosting provider"])
    if overflow > 0 or listen_drops > 5:
        c.add("crit" if overflow > 0 else "warn",
              f"Listen queue overflow ({overflow:.1f}/s, drops {listen_drops:.1f}/s)",
              "New connections are being dropped before your app ever sees them.",
              "The accept backlog is full: the app accepts too slowly or somaxconn is too small.",
              ["ss -ltn      # Recv-Q vs Send-Q on listeners",
               "nstat -az | grep -i listen", "sysctl net.core.somaxconn net.ipv4.tcp_max_syn_backlog"],
              ["`sudo sysctl -w net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=8192`",
               "Raise the app's backlog too (nginx `listen … backlog=4096`, gunicorn `--backlog`)",
               "Add worker processes — overflow usually means the app is too slow to accept"])
    if ct_pct >= T["conntrack_warn"]:
        c.add("crit" if ct_pct >= T["conntrack_crit"] else "warn",
              f"conntrack table {ct_pct:.0f}% full ({ct_cnt:,}/{ct_max:,})",
              "When it fills, the firewall drops new connections: 'nf_conntrack: table full'.",
              "Common on NAT gateways, busy proxies, or under SYN floods.",
              ["conntrack -S ; dmesg -T | grep -i conntrack | tail",
               "conntrack -L 2>/dev/null | awk '{print $4}' | sort | uniq -c | sort -rn | head"],
              ["`sudo sysctl -w net.netfilter.nf_conntrack_max=524288`",
               "Shorten timeouts: `net.netfilter.nf_conntrack_tcp_timeout_time_wait=30`",
               "NOTRACK high-volume flows in iptables/nftables if state is not needed"])
    return c.finalize()


# 8 ── PROCESSES & LIMITS ─────────────────────────────────────────────────────
def check_processes(cur, prev, dt, T):
    c = Check("processes", "Processes & Limits", "list", 0.9)
    procs, states = cur["procs"]
    total = len(procs)
    zombies = states.get("Z", 0)
    dstate = states.get("D", 0)
    threads = sum(p["threads"] for p in procs.values())
    pid_max = read_int("/proc/sys/kernel/pid_max", 32768)
    thr_max = read_int("/proc/sys/kernel/threads-max", 100000)
    pid_pct = total / max(pid_max, 1) * 100
    thr_pct = threads / max(thr_max, 1) * 100
    zpids = [(pid, p["comm"]) for pid, p in procs.items() if p["state"] == "Z"][:6]
    dpids = [(pid, p["comm"]) for pid, p in procs.items() if p["state"] == "D"][:6]
    c.metrics = {"total": total, "threads": threads, "zombies": zombies, "dstate": dstate,
                 "pid_max": pid_max, "pid_pct": round(pid_pct, 1),
                 "threads_max": thr_max, "thread_pct": round(thr_pct, 1),
                 "top_cpu": [{"cpu": u, "pid": p, "comm": n} for u, p, n in top_cpu(cur, prev, dt)],
                 "top_mem": [{"rss": r, "pid": p, "comm": n} for r, p, n in top_mem(cur)],
                 "zombie_pids": zpids, "dstate_pids": dpids}
    c.value, c.unit = f"{total:,}", "processes"
    scores = [score_from(pid_pct, T["pid_warn"], T["pid_crit"]),
              score_from(zombies, T["zombie_warn"], T["zombie_crit"]),
              score_from(thr_pct, T["pid_warn"], T["pid_crit"])]
    c.score = min(s for s, _ in scores)
    c.status = LEVELS[max(RANK[st] for _, st in scores)]
    c.pct = clamp(max(pid_pct, thr_pct))
    c.summary = (f"{total:,} procs ({pid_pct:.0f}% of pid_max) · {threads:,} threads · "
                 f"{zombies} zombie · {dstate} in D-state")

    if zombies >= T["zombie_warn"]:
        c.add("crit" if zombies >= T["zombie_crit"] else "warn",
              f"{zombies} zombie processes",
              "e.g. " + ", ".join(f"{n}({p})" for p, n in zpids),
              "Zombies keep PID slots and signal that a parent never calls wait(). "
              "Thousands of them exhaust the PID space.",
              ["ps -eo pid,ppid,state,comm | awk '$3==\"Z\"'",
               "ps -o pid,cmd -p $(ps -eo ppid,state | awk '$2==\"Z\"{print $1}' | sort -u | tr '\\n' ',' | sed 's/,$//')"],
              ["Fix/restart the PARENT (zombies cannot be killed): `sudo systemctl restart <parent-unit>`",
               "In containers run an init that reaps: `docker run --init …` / Kubernetes shareProcessNamespace",
               "In code: handle SIGCHLD or waitpid() after fork"])
    if pid_pct >= T["pid_warn"] or thr_pct >= T["pid_warn"]:
        c.add("crit" if max(pid_pct, thr_pct) >= T["pid_crit"] else "warn",
              f"Process/thread table {max(pid_pct, thr_pct):.0f}% used",
              f"{total:,}/{pid_max:,} pids · {threads:,}/{thr_max:,} threads",
              "Exhausting pids/threads gives 'fork: Resource temporarily unavailable' — "
              "you cannot even log in to fix it.",
              ["ps -eLf | wc -l",
               "ps -eo comm --no-headers | sort | uniq -c | sort -rn | head",
               "systemd-cgtop -m ; cat /sys/fs/cgroup/pids.max"],
              ["Find the fork bomb / thread leak in the list above and restart it",
               "Cap it: `systemctl set-property <unit> TasksMax=4096`",
               "Raise the ceiling if legitimate: `sudo sysctl -w kernel.pid_max=131072`",
               "Guard the system: /etc/security/limits.d/99-nproc.conf → `* soft nproc 8192`"])
    if dstate >= max(4, CORES):
        c.add("warn", f"{dstate} processes stuck in uninterruptible sleep",
              "e.g. " + ", ".join(f"{n}({p})" for p, n in dpids),
              "D-state = blocked in the kernel, nearly always storage or NFS. They inflate "
              "load average and cannot be killed with SIGKILL.",
              ["ps -eo pid,stat,wchan:30,comm | awk '$2~/D/'",
               "for p in $(ps -eo pid,stat | awk '$2~/D/{print $1}'); do "
               "echo \"== $p\"; sudo cat /proc/$p/stack 2>/dev/null | head -5; done",
               "mount | grep nfs ; dmesg -T | tail -30"],
              ["If NFS: `sudo umount -f -l <mnt>` then remount with `soft,timeo=30,retrans=3`",
               "If local disk: see the Disk I/O check — the device is saturated or failing",
               "Only a reboot clears truly wedged D-state tasks"])
    return c.finalize()


# 9 ── SERVICES / SYSTEM STATE ────────────────────────────────────────────────
def check_services(cur, prev, dt, T):
    c = Check("services", "Services & System State", "server", 1.2)
    uptime_raw = read("/proc/uptime", "0 0").split()
    uptime = float(uptime_raw[0]) if uptime_raw else 0.0
    rc, state = sh(["systemctl", "is-system-running"], ttl=25)
    state = (state or "").strip() or "unknown"
    rc2, failed_raw = sh(["systemctl", "list-units", "--state=failed", "--no-legend",
                          "--plain", "--no-pager"], ttl=25)
    failed = [l.split()[0] for l in failed_raw.splitlines() if l.strip()] if rc2 == 0 else []
    rc3, ntp = sh(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], ttl=120)
    synced = ntp.strip() == "yes" if rc3 == 0 else None
    reboot_required = os.path.exists("/var/run/reboot-required") or os.path.exists("/run/reboot-required")
    rc4, nr = sh(["needs-restarting", "-r"], ttl=300)
    if rc4 == 1:
        reboot_required = True
    pkgs = ""
    if os.path.exists("/var/run/reboot-required.pkgs"):
        pkgs = ", ".join(sorted(set(read("/var/run/reboot-required.pkgs").split()))[:6])
    c.metrics = {"system_state": state, "failed_units": failed, "uptime": uptime,
                 "uptime_h": fmt_dur(uptime), "ntp_synced": synced,
                 "reboot_required": reboot_required, "reboot_pkgs": pkgs,
                 "kernel": read("/proc/sys/kernel/osrelease", os.uname().release).strip()}
    c.value, c.unit = (str(len(failed)), "failed units")
    c.score, c.status = (100.0, "ok")
    if failed:
        c.score, c.status = (max(15.0, 70 - 12 * len(failed)), "crit" if len(failed) > 1 else "warn")
    c.pct = clamp(len(failed) * 25)
    c.summary = (f"{state} · up {fmt_dur(uptime)} · kernel {c.metrics['kernel']} · "
                 f"time {'synced' if synced else 'NOT synced' if synced is False else 'n/a'}")

    if failed:
        c.add("crit" if len(failed) > 1 else "warn",
              f"{len(failed)} failed systemd unit(s)", ", ".join(failed[:8]),
              "A failed unit means a service is not doing its job — and if Restart= is set "
              "it may be crash-looping, burning CPU and filling logs.",
              ["systemctl --failed",
               f"systemctl status {failed[0]} -l --no-pager",
               f"journalctl -u {failed[0]} -n 80 --no-pager",
               f"systemd-analyze verify {failed[0]} 2>&1 | head"],
              [f"Read the log above, fix config, then: `sudo systemctl reset-failed {failed[0]} && "
               f"sudo systemctl restart {failed[0]}`",
               "Config typo? validate first (`nginx -t`, `apachectl configtest`, `sshd -t`)",
               "Crash loop? add `Restart=on-failure`, `RestartSec=5s`, `StartLimitIntervalSec=0`",
               "Port conflict? `sudo ss -ltnp | grep <port>`"])
    if state not in ("running", "unknown", "starting"):
        c.add("warn", f"systemd reports '{state}'",
              "The system is degraded or in maintenance mode.",
              "Something failed at boot or a unit is masked/not started.",
              ["systemctl status --no-pager | head -20", "systemctl list-units --state=failed,not-found"],
              ["Resolve failed units then `sudo systemctl reset-failed`",
               "Check boot: `systemd-analyze blame | head` and `journalctl -b -p err`"])
    if uptime < 900 and uptime > 0:
        c.add("info", f"Server rebooted {fmt_dur(uptime)} ago",
              "Recent boot — confirm it was planned and that everything came back up.",
              "Unplanned reboots point to kernel panic, OOM, watchdog or host maintenance.",
              ["last reboot | head -5", "journalctl --list-boots | tail -3",
               "journalctl -b -1 -p err --no-pager | tail -30   # logs of the PREVIOUS boot"],
              ["Verify all services are enabled: `systemctl list-unit-files --state=enabled`",
               "Check for panic/watchdog evidence in the previous boot log",
               "Cloud: check the provider's maintenance events feed"])
    if synced is False:
        c.add("warn", "Clock is not synchronised with NTP",
              "Time drift breaks TLS handshakes, JWT/OAuth tokens, DB replication, "
              "cron schedules and makes logs impossible to correlate.",
              "chrony/systemd-timesyncd is stopped, blocked by firewall (UDP 123), or unconfigured.",
              ["timedatectl status", "chronyc tracking 2>/dev/null || ntpq -p",
               "systemctl status systemd-timesyncd chrony chronyd 2>/dev/null | head -20"],
              ["`sudo timedatectl set-ntp true` (or `sudo systemctl enable --now chronyd`)",
               "Force a step: `sudo chronyc makestep`",
               "Allow UDP/123 egress in the firewall/security group"])
    if reboot_required:
        c.add("warn", "Reboot required to apply updates", pkgs or "kernel/libc updated",
              "Patched libraries/kernel are on disk but the running processes still use the "
              "vulnerable versions in memory.",
              ["cat /var/run/reboot-required.pkgs 2>/dev/null",
               "sudo needs-restarting -r ; sudo needs-restarting -s",
               "ls -l /boot/vmlinuz* ; uname -r"],
              ["Schedule a maintenance window, drain traffic, then `sudo systemctl reboot`",
               "Zero-downtime alternative for libs: `sudo needs-restarting -s | xargs -r "
               "sudo systemctl restart`",
               "Consider kexec/livepatch (Ubuntu Pro `canonical-livepatch`) for kernel CVEs"])
    return c.finalize()


def _scan_php_slowlogs():
    """Scan Plesk & Linux PHP-FPM slow logs and pool configurations."""
    results = {
        "slow_entries": [],
        "slow_count_1h": 0,
        "slow_count_24h": 0,
        "top_slow_scripts": [],
        "unlogged_pools": [],
        "active_php_pools": 0,
        "is_plesk": os.path.exists("/usr/local/psa") or os.path.exists("/opt/plesk/php"),
    }
    
    log_candidates = []
    # Plesk PHP log paths
    for ver in ("70", "71", "72", "73", "74", "80", "81", "82", "83", "84", "85"):
        d = f"/var/log/plesk-php{ver}-fpm"
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if "slow" in f.lower() and f.endswith(".log"):
                        log_candidates.append(os.path.join(d, f))
            except Exception:
                pass
    
    # Generic & distro PHP-FPM log paths
    for pattern_dir in ("/var/log/php-fpm", "/var/log/php", "/var/log"):
        if os.path.isdir(pattern_dir):
            try:
                for f in os.listdir(pattern_dir):
                    if "slow" in f.lower() and (f.endswith(".log") or "fpm" in f.lower()):
                        log_candidates.append(os.path.join(pattern_dir, f))
            except Exception:
                pass

    # Plesk per-domain system logs
    if os.path.isdir("/var/www/vhosts/system"):
        try:
            for domain in os.listdir("/var/www/vhosts/system"):
                logs_dir = os.path.join("/var/www/vhosts/system", domain, "logs")
                if os.path.isdir(logs_dir):
                    for f in os.listdir(logs_dir):
                        if "slow" in f.lower() and f.endswith(".log"):
                            log_candidates.append(os.path.join(logs_dir, f))
        except Exception:
            pass

    seen_blocks = []
    for log_path in set(log_candidates):
        try:
            content = read(log_path)
            if not content:
                continue
            if len(content) > 300000:
                content = content[-300000:]
            
            blocks = re.split(r'\n(?=\[\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\])', content)
            for block in blocks:
                block = block.strip()
                if not block or "script_filename" not in block:
                    continue
                header_m = re.search(r'\[(\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})\].*?\[pool\s+([^\]]+)\]', block)
                script_m = re.search(r'script_filename\s*=\s*(.+)', block)
                
                ts_str = header_m.group(1) if header_m else ""
                pool_name = header_m.group(2) if header_m else "default"
                script_path = script_m.group(1).strip() if script_m else "unknown"
                
                trace_lines = [l.strip() for l in block.splitlines() if re.search(r'\[0x[0-9a-fA-F]+\]|\.php:\d+', l)]
                top_trace = trace_lines[0] if trace_lines else ""
                top_trace = re.sub(r'^\[0x[0-9a-fA-F]+\]\s*', '', top_trace)[:120]
                
                entry_age_hours = 0
                try:
                    dt_entry = datetime.strptime(ts_str, "%d-%b-%Y %H:%M:%S")
                    entry_age_hours = (datetime.now() - dt_entry).total_seconds() / 3600.0
                except Exception:
                    pass
                
                if entry_age_hours <= 1.0:
                    results["slow_count_1h"] += 1
                if entry_age_hours <= 24.0:
                    results["slow_count_24h"] += 1
                    
                seen_blocks.append({
                    "pool": pool_name,
                    "script": script_path,
                    "time": ts_str,
                    "trace": top_trace,
                    "age_h": round(entry_age_hours, 1)
                })
        except Exception:
            continue

    seen_blocks.sort(key=lambda x: x["age_h"])
    results["slow_entries"] = seen_blocks[:20]
    
    script_counts = {}
    for b in seen_blocks[:50]:
        key = (b["pool"], b["script"], b["trace"])
        script_counts[key] = script_counts.get(key, 0) + 1
    
    top_scripts = []
    for (pool, script, trace), count in sorted(script_counts.items(), key=lambda kv: -kv[1])[:6]:
        display_script = script.replace("/var/www/vhosts/", ".../")
        top_scripts.append({
            "pool": pool,
            "script": display_script,
            "duration": f"{count}× slow",
            "trace": trace
        })
    results["top_slow_scripts"] = top_scripts

    pool_conf_dirs = [
        "/opt/plesk/php/8.4/etc/php-fpm.d",
        "/opt/plesk/php/8.3/etc/php-fpm.d",
        "/opt/plesk/php/8.2/etc/php-fpm.d",
        "/opt/plesk/php/8.1/etc/php-fpm.d",
        "/opt/plesk/php/8.0/etc/php-fpm.d",
        "/opt/plesk/php/7.4/etc/php-fpm.d",
        "/etc/php/8.3/fpm/pool.d",
        "/etc/php/8.2/fpm/pool.d",
        "/etc/php/8.1/fpm/pool.d",
        "/etc/php/7.4/fpm/pool.d",
        "/etc/php-fpm.d",
    ]
    for pdir in pool_conf_dirs:
        if os.path.isdir(pdir):
            try:
                for f in os.listdir(pdir):
                    if f.endswith(".conf"):
                        results["active_php_pools"] += 1
                        conf_path = os.path.join(pdir, f)
                        conf_txt = read(conf_path)
                        if not re.search(r'^\s*request_slowlog_timeout\s*=\s*[1-9]', conf_txt, re.M):
                            results["unlogged_pools"].append(f.replace(".conf", ""))
            except Exception:
                pass

    return results


# 10 ── LOGS & SECURITY ───────────────────────────────────────────────────────
def check_logs(cur, prev, dt, T):
    c = Check("logs", "Logs & Security Signals", "shield", 1.0)
    rc, errs = sh(["journalctl", "--since", "-1h", "-p", "err", "--no-pager", "-q"], timeout=8, ttl=120)
    lines = [l for l in errs.splitlines() if l.strip()] if rc == 0 else []
    nerr = len(lines)
    top_err = {}
    for l in lines:
        key = re.sub(r"\d+", "#", l.split(": ", 1)[-1])[:110]
        top_err[key] = top_err.get(key, 0) + 1
    top = sorted(top_err.items(), key=lambda kv: -kv[1])[:5]

    rc2, auth = sh(["journalctl", "--since", "-1h", "--no-pager", "-q", "-t", "sshd"], timeout=8, ttl=120)
    if rc2 != 0 or not auth.strip():
        auth = "".join(read(p) for p in ("/var/log/auth.log", "/var/log/secure"))[-400000:]
    fails = re.findall(r"Failed (?:password|publickey).* from ([\d.a-f:]+)", auth)
    ips = {}
    for ip in fails:
        ips[ip] = ips.get(ip, 0) + 1
    top_ips = sorted(ips.items(), key=lambda kv: -kv[1])[:5]
    segv = [l for l in _kernel_errors() if re.search(r"segfault|general protection|traps:", l, re.I)]
    rc3, jstat = sh(["journalctl", "--disk-usage"], ttl=300)
    permit_root = bool(re.search(r"^\s*PermitRootLogin\s+yes", read("/etc/ssh/sshd_config"), re.M | re.I))

    php_data = _scan_php_slowlogs()

    c.metrics = {"errors_1h": nerr, "top_errors": [{"count": n, "text": t} for t, n in top],
                 "auth_fails_1h": len(fails), "top_ips": top_ips, "segfaults": len(segv),
                 "journal_usage": (jstat or "").strip().split("take up ")[-1].strip(". \n"),
                 "permit_root_login": permit_root,
                 "php_slow_1h": php_data["slow_count_1h"],
                 "php_slow_24h": php_data["slow_count_24h"],
                 "top_slow_scripts": php_data["top_slow_scripts"],
                 "unlogged_php_pools": len(php_data["unlogged_pools"]),
                 "is_plesk": php_data["is_plesk"]}
    c.value, c.unit = f"{nerr}", "errors/h"
    scores = [score_from(nerr, T["logerr_warn"], T["logerr_crit"]),
              score_from(len(fails), T["authfail_warn"], T["authfail_crit"])]
    if php_data["slow_count_1h"] > 0:
        s_php, st_php = score_from(php_data["slow_count_1h"], 5, 25)
        scores.append((s_php, st_php))
    c.score = min(s for s, _ in scores)
    c.status = LEVELS[max(RANK[st] for _, st in scores)]
    c.pct = clamp(nerr / max(T["logerr_crit"], 1) * 100)
    
    extra_summary = ""
    if php_data["slow_count_1h"] > 0:
        extra_summary = f" · {php_data['slow_count_1h']} PHP slow/h"
    c.summary = (f"{nerr} journal errors/h · {len(fails)} failed logins/h · "
                 f"{len(segv)} segfaults{extra_summary} · journal {c.metrics['journal_usage'] or 'n/a'}")

    if nerr >= T["logerr_warn"]:
        c.add("crit" if nerr >= T["logerr_crit"] else "warn",
              f"{nerr} error-level log entries in the last hour",
              " ⟶ ".join(f"[{n}×] {t}" for t, n in top[:2]),
              "A rising error rate is the earliest sign of a failing dependency, a bad deploy "
              "or a crash loop — long before users complain.",
              ["journalctl -p err --since '-1h' --no-pager | tail -50",
               "journalctl -p err --since '-1h' -o cat | sed 's/[0-9]\\+/#/g' | sort | uniq -c | sort -rn | head",
               "journalctl -u <unit> -f"],
              ["Fix the top repeating message first — it is usually 80% of the volume",
               "Crash loop? `systemctl status <unit>` + add backoff (RestartSec/StartLimitBurst)",
               "Cap log growth: SystemMaxUse=500M in /etc/systemd/journald.conf, then "
               "`sudo systemctl restart systemd-journald`"])
    if len(fails) >= T["authfail_warn"]:
        c.add("crit" if len(fails) >= T["authfail_crit"] else "warn",
              f"{len(fails)} failed SSH logins in the last hour",
              "Top sources: " + ", ".join(f"{ip} ({n}×)" for ip, n in top_ips),
              "An active brute-force / credential-stuffing attempt. Even if it fails it burns "
              "CPU and may eventually succeed against a weak password.",
              ["journalctl -t sshd --since '-1h' | grep -i 'failed' | tail -30",
               "lastb | head -20 ; who ; last -20",
               "sudo fail2ban-client status sshd 2>/dev/null"],
              [f"Block the worst offender now: `sudo iptables -I INPUT -s {top_ips[0][0]} -j DROP`"
               if top_ips else "Block offending IPs at the firewall",
               "Install fail2ban: `sudo apt install fail2ban && sudo systemctl enable --now fail2ban`",
               "Disable password auth: sshd_config → `PasswordAuthentication no`, `PermitRootLogin no`, "
               "`KbdInteractiveAuthentication no` → `sudo sshd -t && sudo systemctl reload sshd`",
               "Restrict SSH to a VPN/bastion CIDR in the security group, or move to WireGuard"])
    if php_data["slow_count_1h"] > 0:
        c.add("crit" if php_data["slow_count_1h"] >= 20 else "warn",
              f"{php_data['slow_count_1h']} PHP slow script execution(s) in the last hour",
              "Top: " + (" | ".join(f"{s['script']} ({s['pool']}, {s['duration']})" for s in php_data["top_slow_scripts"][:3]) or "see details"),
              "Slow PHP scripts lock up worker processes in the FPM pool until pm.max_children "
              "is exhausted, triggering 502 Bad Gateway and 504 Gateway Timeout errors.",
              ["tail -f /var/log/plesk-php*-fpm/slow.log 2>/dev/null || tail -f /var/log/php*-fpm.slow.log",
               "grep -rn 'script_filename' /var/log/plesk-php*-fpm/ /var/log/php*-fpm/ 2>/dev/null | tail -20",
               "plesk bin php_handler --list 2>/dev/null || php -v"],
              ["Inspect the backtrace function/plugin above to optimize slow DB queries or unbuffered external cURL calls",
               "Enable Redis / Memcached object cache (e.g. `redis-server` + WP Redis plugin)",
               "Tune PHP OPcache in php.ini: `opcache.enable=1 opcache.memory_consumption=256 opcache.max_accelerated_files=20000`",
               "Raise FPM pool capacity: adjust `pm.max_children` in /opt/plesk/php/*/etc/php-fpm.d/<domain>.conf"])
    if php_data["active_php_pools"] > 0 and len(php_data["unlogged_pools"]) > 0:
        c.add("info" if php_data["slow_count_1h"] == 0 else "warn",
              f"PHP-FPM slow logging disabled on {len(php_data['unlogged_pools'])} pool(s)",
              "e.g. " + ", ".join(php_data["unlogged_pools"][:6]),
              "When PHP requests freeze or exceed 5–10s, PHP slow logging records the exact script "
              "filename, line number, and function backtrace (e.g. plugin xyz) for instant resolution.",
              ["grep -rnE 'request_slowlog_timeout|slowlog' /opt/plesk/php/*/etc/php-fpm.d/ /etc/php/*/fpm/pool.d/ 2>/dev/null",
               "ls -la /opt/plesk/php/*/etc/php-fpm.d/ 2>/dev/null"],
              ["Run `sudo bash deploy/enable-plesk-php-slowlog.sh` to auto-configure all Plesk PHP pools",
               "Plesk CLI per domain: `plesk bin site -u <domain> -php_handler_type fpm -additional-settings $'slowlog = /var/log/plesk-php82-fpm/slow.log\\nrequest_slowlog_timeout = 5s\\nrequest_slowlog_trace_depth = 20'`",
               "Standard PHP-FPM: Add `request_slowlog_timeout = 5s` & `slowlog = /var/log/php-fpm/www-slow.log` to pool config, then reload"])
    if permit_root:
        c.add("warn", "SSH allows direct root login",
              "PermitRootLogin yes in /etc/ssh/sshd_config",
              "Root login removes accountability and is the #1 brute-force target.",
              ["sudo sshd -T | egrep 'permitrootlogin|passwordauthentication'"],
              ["Set `PermitRootLogin prohibit-password` (or `no`), keep a sudo user with a key",
               "`sudo sshd -t && sudo systemctl reload sshd`"])
    if segv:
        c.add("warn", f"{len(segv)} segfault(s) in kernel log", segv[-1][:160],
              "A process crashed hard: memory corruption, bad RAM, or a buggy/mismatched library.",
              ["journalctl -k --since '-24h' | grep -i segfault | tail",
               "coredumpctl list | tail ; coredumpctl info <PID>",
               "sudo memtester 1G 1   # or boot memtest86+ for real RAM validation"],
              ["Update/downgrade the crashing package; rebuild against the current libc",
               "Run a RAM test if crashes are random across different binaries",
               "Enable core dumps and get a backtrace: `ulimit -c unlimited` + `coredumpctl gdb`"])
    return c.finalize()


CHECKS = [check_cpu, check_load, check_memory, check_disk_space, check_disk_io,
          check_inodes, check_network, check_processes, check_services, check_logs]


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN / SCORING
# ─────────────────────────────────────────────────────────────────────────────

def grade(score):
    for lim, g, label in ((93, "A+", "Excellent"), (85, "A", "Healthy"), (75, "B", "Good"),
                          (65, "C", "Needs attention"), (50, "D", "Degraded"), (0, "F", "Critical")):
        if score >= lim:
            return g, label
    return "F", "Critical"


class Engine:
    def __init__(self, cfg):
        self.cfg = cfg
        self.sampler = Sampler()
        self.history = deque(maxlen=cfg["history_points"])
        self.report = None
        self.lock = threading.Lock()
        self._load_state()

    def _load_state(self):
        try:
            with open(self.cfg["state_file"]) as fh:
                for pt in json.load(fh).get("history", []):
                    self.history.append(pt)
        except Exception:
            pass

    def _save_state(self):
        path = self.cfg["state_file"]
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({"history": list(self.history)[-self.cfg["history_points"]:]}, fh)
            os.replace(tmp, path)
        except Exception:
            pass

    def scan(self):
        t0 = time.time()
        cur, prev, dt = self.sampler.collect()
        T = self.cfg["thresholds"]
        checks = []
        for fn in CHECKS:
            try:
                checks.append(fn(cur, prev, dt, T))
            except Exception as e:  # never let one probe kill the scan
                bad = Check(fn.__name__.replace("check_", ""), fn.__name__, "alert", 0.4)
                bad.status, bad.score, bad.value = "warn", 60.0, "n/a"
                bad.summary = f"probe error: {e}"
                checks.append(bad.finalize())

        wsum = sum(c.weight for c in checks) or 1
        overall = sum(c.score * c.weight for c in checks) / wsum
        crits = [c for c in checks if c.status == "crit"]
        warns = [c for c in checks if c.status == "warn"]
        if crits:
            overall = min(overall, 54)
        elif warns:
            overall = min(overall, 79)
        g, label = grade(overall)
        report = {
            "version": VERSION,
            "host": self.cfg["hostname"],
            "fqdn": socket.getfqdn(),
            "os": _os_pretty(),
            "kernel": read("/proc/sys/kernel/osrelease", os.uname().release).strip(),
            "arch": os.uname().machine,
            "cores": CORES,
            "uptime": fmt_dur(float(read("/proc/uptime", "0 0").split()[0])),
            "ts": time.time(),
            "time": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "duration_ms": int((time.time() - t0) * 1000),
            "score": round(overall, 1), "grade": g, "grade_label": label,
            "status": "crit" if crits else ("warn" if warns else "ok"),
            "counts": {"ok": len(checks) - len(crits) - len(warns),
                       "warn": len(warns), "crit": len(crits), "total": len(checks)},
            "checks": [asdict(c) for c in checks],
        }
        cm = {c["id"]: c for c in report["checks"]}
        self.history.append({
            "t": int(report["ts"]), "score": report["score"],
            "cpu": cm["cpu"]["metrics"].get("busy", 0),
            "mem": cm["memory"]["metrics"].get("used_pct", 0),
            "load": cm["load"]["metrics"].get("per_core", 0),
            "disk": cm["disk"]["metrics"].get("worst_pct", 0),
            "io": cm["io"]["metrics"].get("worst_util", 0),
            "net": cm["network"]["metrics"].get("retrans_pct", 0),
        })
        with self.lock:
            self.report = report
        self._save_state()
        return report


def _os_pretty():
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', read("/etc/os-release"))
    return m.group(1) if m else f"{os.uname().sysname} {os.uname().release}"


# ─────────────────────────────────────────────────────────────────────────────
#  ALERTING
# ─────────────────────────────────────────────────────────────────────────────

EMOJI = {"crit": "🔴", "warn": "🟠", "ok": "🟢", "info": "🔵"}


class AlertManager:
    def __init__(self, cfg):
        self.cfg = cfg["alerts"]
        self.host = cfg["hostname"]
        self.state = {}

    def process(self, report):
        if not self.cfg.get("enabled"):
            return []
        min_rank = RANK[self.cfg.get("min_severity", "warn")]
        need = int(self.cfg.get("consecutive", 2))
        cooldown = float(self.cfg.get("cooldown_minutes", 60)) * 60
        now = time.time()
        events = []
        for c in report["checks"]:
            st = self.state.setdefault(c["id"], {"status": "ok", "streak": 0,
                                                 "notified": None, "last": 0.0})
            st["streak"] = st["streak"] + 1 if c["status"] == st["status"] else 1
            st["status"] = c["status"]
            r = RANK[c["status"]]
            if r >= min_rank and st["streak"] >= need:
                escalated = st["notified"] is None or RANK[c["status"]] > RANK[st["notified"]]
                if escalated or now - st["last"] > cooldown:
                    events.append({"type": "problem", "check": c})
                    st["notified"], st["last"] = c["status"], now
            elif c["status"] == "ok" and st["notified"] and st["streak"] >= need:
                if self.cfg.get("notify_recovery", True):
                    events.append({"type": "recovery", "check": c})
                st["notified"], st["last"] = None, now
        if events:
            self.dispatch(events, report)
        return events

    # ── rendering ──────────────────────────────────────────────────────────
    def subject(self, events, report):
        probs = [e["check"] for e in events if e["type"] == "problem"]
        if probs:
            worst = "CRITICAL" if any(c["status"] == "crit" for c in probs) else "WARNING"
        else:
            worst = "RECOVERED"
        names = ", ".join(c["name"] for c in (probs or [e["check"] for e in events]))[:90]
        icon = EMOJI["crit"] if worst == "CRITICAL" else (EMOJI["warn"] if worst == "WARNING" else EMOJI["ok"])
        return f"{icon} {worst} · {self.host} · {names} · health {report['score']:.0f}/100"

    def text(self, events, report):
        L = [f"{EMOJI[report['status']]}  {self.host}  —  health {report['score']:.0f}/100 "
             f"({report['grade']} · {report['grade_label']})",
             f"{report['os']} · kernel {report['kernel']} · up {report['uptime']} · {report['time']}", ""]
        for e in events:
            c = e["check"]
            if e["type"] == "recovery":
                L.append(f"{EMOJI['ok']} RECOVERED · {c['name']} — {c['summary']}")
                continue
            L.append(f"{EMOJI[c['status']]} {c['status'].upper()} · {c['name']}: "
                     f"{c['value']}{(' ' + c['unit']) if c['unit'] else ''}  (score {c['score']:.0f}/100)")
            L.append(f"   {c['summary']}")
            for f in c["findings"][:2]:
                L.append(f"   ▸ {f['title']}")
                if f["detail"]:
                    L.append(f"     {f['detail']}")
                for fx in f["fix"][:3]:
                    L.append(f"     ✔ fix: {fx}")
                for dg in f["diagnose"][:2]:
                    L.append(f"     ⌘ check: {dg}")
            L.append("")
        L.append("— Linux Health Sentinel v" + VERSION)
        return "\n".join(L)

    def html(self, events, report):
        col = {"crit": "#e5484d", "warn": "#f5a524", "ok": "#17c964", "info": "#4a7dff"}
        top = col.get(report["status"], "#17c964")
        rows = []
        for e in events:
            c, sev = e["check"], ("ok" if e["type"] == "recovery" else e["check"]["status"])
            fl = ""
            for f in c["findings"][:2]:
                fixes = "".join(
                    f'<li style="margin:4px 0">{_esc(x)}</li>' for x in f["fix"][:3])
                diags = "".join(
                    f'<div style="font-family:ui-monospace,Menlo,monospace;font-size:12px;'
                    f'background:#0e1220;color:#c9d4ff;padding:7px 10px;border-radius:6px;'
                    f'margin:4px 0;white-space:pre-wrap">{_esc(x)}</div>' for x in f["diagnose"][:3])
                fl += (f'<div style="margin-top:12px;padding:12px;border-radius:10px;'
                       f'background:#f7f8fb;border:1px solid #e6e9f0">'
                       f'<b style="color:{col.get(f["severity"], top)}">{_esc(f["title"])}</b>'
                       f'<div style="color:#5b6478;font-size:13px;margin:4px 0">{_esc(f["detail"])}</div>'
                       f'<div style="color:#39415a;font-size:13px;margin:6px 0">{_esc(f["why"])}</div>'
                       f'<div style="font-size:12px;color:#8a90a2;margin-top:8px">DIAGNOSE</div>{diags}'
                       f'<div style="font-size:12px;color:#8a90a2;margin-top:8px">FIX</div>'
                       f'<ul style="margin:6px 0 0 18px;padding:0;font-size:13px;color:#2b3245">{fixes}</ul>'
                       f'</div>')
            rows.append(
                f'<tr><td style="padding:16px;border-top:1px solid #eceef4">'
                f'<div style="display:flex;justify-content:space-between;align-items:center">'
                f'<div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;'
                f'background:{col.get(sev, "#17c964")};margin-right:8px"></span>'
                f'<b style="font-size:15px">{_esc(c["name"])}</b>'
                f'<span style="color:#8a90a2;font-size:13px"> · {_esc(c["summary"])}</span></div>'
                f'<span style="background:{col.get(sev, "#17c964")}1a;color:{col.get(sev, "#17c964")};font-size:11px;font-weight:700;'
                f'padding:4px 10px;border-radius:999px;letter-spacing:.5px">'
                f'{"RECOVERED" if e["type"] == "recovery" else sev.upper()}</span></div>'
                f'<div style="font-size:26px;font-weight:700;margin:8px 0 0">{_esc(c["value"])}'
                f'<span style="font-size:13px;color:#8a90a2;font-weight:500"> {_esc(c["unit"])}</span></div>'
                f'{fl}</td></tr>')
        return f"""<!doctype html><html><body style="margin:0;background:#eef1f7;
 font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#1a1f2e">
<div style="max-width:720px;margin:0 auto;padding:24px 14px">
 <div style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(20,30,60,.10)">
  <div style="background:linear-gradient(135deg,{top},{top}bb);padding:22px 24px;color:#fff">
   <div style="font-size:12px;letter-spacing:2px;opacity:.85">LINUX HEALTH SENTINEL</div>
   <div style="font-size:22px;font-weight:800;margin-top:4px">{_esc(report['host'])} · {report['status'].upper()}</div>
   <div style="opacity:.9;font-size:13px;margin-top:6px">Health {report['score']:.0f}/100
     ({report['grade']} — {report['grade_label']}) · {report['counts']['crit']} critical ·
     {report['counts']['warn']} warning · {report['counts']['ok']} ok</div>
  </div>
  <div style="padding:14px 24px;background:#fafbfe;font-size:12px;color:#6b7387;border-bottom:1px solid #eceef4">
   {_esc(report['os'])} · kernel {_esc(report['kernel'])} · {report['cores']} cores ·
   up {_esc(report['uptime'])} · {_esc(report['time'])}
  </div>
  <table style="width:100%;border-collapse:collapse">{''.join(rows)}</table>
  <div style="padding:16px 24px;background:#fafbfe;color:#8a90a2;font-size:11px;border-top:1px solid #eceef4">
   Sentinel v{VERSION} — automated report. Reply-to-fix commands above are safe to copy-paste;
   review anything destructive before running.
  </div>
 </div></div></body></html>"""

    # ── channels ───────────────────────────────────────────────────────────
    def dispatch(self, events, report):
        subject, text, htmlbody = self.subject(events, report), self.text(events, report), self.html(events, report)
        for fn in (self._email, self._slack, self._telegram, self._ntfy, self._webhook, self._desktop):
            threading.Thread(target=self._safe, args=(fn, subject, text, htmlbody, report, events),
                             daemon=True).start()

    @staticmethod
    def _safe(fn, *a):
        try:
            fn(*a)
        except Exception as e:
            print(f"[sentinel] notifier {fn.__name__} failed: {e}", file=sys.stderr)

    def _email(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["email"]
        if not cfg.get("enabled"):
            return
        msg = EmailMessage()
        msg["Subject"], msg["From"] = subject, cfg["from"]
        msg["To"] = ", ".join(cfg["to"])
        msg["Date"] = formatdate(localtime=True)
        msg["X-Sentinel-Host"] = report["host"]
        msg.set_content(text)
        msg.add_alternative(htmlbody, subtype="html")
        ctx = ssl.create_default_context()
        if cfg.get("ssl"):
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=20) as s:
                if cfg.get("user"):
                    s.login(cfg["user"], cfg["password"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=20) as s:
                s.ehlo()
                if cfg.get("tls"):
                    s.starttls(context=ctx)
                    s.ehlo()
                if cfg.get("user"):
                    s.login(cfg["user"], cfg["password"])
                s.send_message(msg)

    def _post(self, url, payload, headers=None, form=False):
        data = urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
        h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json",
             "User-Agent": f"health-sentinel/{VERSION}"}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h)
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status

    def _slack(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["slack"]
        if not cfg.get("enabled") or not cfg.get("webhook_url"):
            return
        colour = {"crit": "#e5484d", "warn": "#f5a524", "ok": "#17c964"}.get(report["status"], "#17c964")
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": subject[:150]}}]
        for e in events[:6]:
            c = e["check"]
            fix = ("\n".join(f"• {x}" for x in (c["findings"][0]["fix"][:3] if c["findings"] else []))) or "—"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                          "text": f"*{EMOJI.get(c['status'] if e['type'] == 'problem' else 'ok', '🟢')} "
                                  f"{c['name']}* — `{c['value']} {c['unit']}`\n{c['summary']}\n"
                                  f"*Fix:*\n{fix}"}})
        self._post(cfg["webhook_url"], {"text": subject,
                                        "attachments": [{"color": colour, "blocks": blocks}]})

    def _telegram(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["telegram"]
        if not cfg.get("enabled") or not cfg.get("bot_token"):
            return
        self._post(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                   {"chat_id": cfg["chat_id"], "text": f"<pre>{_esc(text[:3800])}</pre>",
                    "parse_mode": "HTML", "disable_web_page_preview": "true"}, form=True)

    def _ntfy(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["ntfy"]
        if not cfg.get("enabled") or not cfg.get("topic"):
            return
        priority = {"crit": "urgent", "warn": "high", "ok": "default"}.get(report["status"], "default")
        tag = {"crit": "rotating_light", "warn": "warning", "ok": "white_check_mark"}.get(report["status"], "white_check_mark")
        h = {"Title": subject[:200], "Content-Type": "text/plain",
             "Priority": priority,
             "Tags": tag}
        if cfg.get("token"):
            h["Authorization"] = "Bearer " + cfg["token"]
        req = urllib.request.Request(f"{cfg['server'].rstrip('/')}/{cfg['topic']}",
                                     data=text[:3800].encode(), headers=h)
        urllib.request.urlopen(req, timeout=15)

    def _webhook(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["webhook"]
        if not cfg.get("enabled") or not cfg.get("url"):
            return
        self._post(cfg["url"], {"subject": subject, "text": text, "report": report,
                                "events": events}, cfg.get("headers"))

    def _desktop(self, subject, text, htmlbody, report, events):
        if not self.cfg["desktop"].get("enabled"):
            return
        sh(["notify-send", "-u", "critical" if report["status"] == "crit" else "normal",
            subject, text[:400]])


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


# ─────────────────────────────────────────────────────────────────────────────
#  WEB UI  (single page, no external assets)
# ─────────────────────────────────────────────────────────────────────────────

HTML_PAGE = r"""<!doctype html>
<html lang="en" data-theme="dark"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Health Sentinel</title>
<link rel="icon" href="/favicon.svg">
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#070a13; --bg2:#0b1020; --card:rgba(255,255,255,.045); --card2:rgba(255,255,255,.07);
  --stroke:rgba(255,255,255,.085); --stroke2:rgba(255,255,255,.16);
  --txt:#e9edf8; --mut:#8d97b0; --dim:#5f6880;
  --ok:#25e39a; --warn:#ffb340; --crit:#ff5566; --acc:#7d9dff; --acc2:#b98cff;
  --shadow:0 20px 50px -20px rgba(0,0,0,.75); --r:18px;
}
[data-theme=light]{
  --bg:#f2f5fb; --bg2:#e8edf8; --card:rgba(255,255,255,.85); --card2:#fff;
  --stroke:rgba(16,24,48,.09); --stroke2:rgba(16,24,48,.18);
  --txt:#111a2e; --mut:#5b6580; --dim:#8b95ab;
  --ok:#0aa06a; --warn:#c97d09; --crit:#d92c3c; --acc:#3b62e8; --acc2:#8b5cf6;
  --shadow:0 18px 40px -22px rgba(20,35,80,.35);
}
html,body{min-height:100%}
body{background:var(--bg);color:var(--txt);
 font:15px/1.55 'Inter',system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;
 -webkit-font-smoothing:antialiased;overflow-x:hidden}
body:before{content:"";position:fixed;inset:-30%;z-index:-2;
 background:
  radial-gradient(38% 32% at 18% 8%, rgba(125,157,255,.20), transparent 60%),
  radial-gradient(34% 30% at 84% 12%, rgba(185,140,255,.17), transparent 62%),
  radial-gradient(46% 40% at 60% 96%, rgba(37,227,154,.11), transparent 65%),
  var(--bg);
 filter:saturate(1.1);animation:drift 26s ease-in-out infinite alternate}
@keyframes drift{to{transform:translate3d(2%, -2%, 0) scale(1.06)}}
body:after{content:"";position:fixed;inset:0;z-index:-1;pointer-events:none;opacity:.35;
 background-image:radial-gradient(rgba(255,255,255,.045) 1px, transparent 1px);background-size:3px 3px}
code,pre,.mono{font-family:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
.wrap{max-width:1360px;margin:0 auto;padding:26px 22px 70px}
.glass{background:var(--card);border:1px solid var(--stroke);border-radius:var(--r);
 backdrop-filter:blur(18px) saturate(140%);-webkit-backdrop-filter:blur(18px);box-shadow:var(--shadow)}

/* ── header ─────────────────────────────────────────── */
header{display:flex;align-items:center;gap:16px;flex-wrap:wrap;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:13px}
.logo{width:44px;height:44px;border-radius:13px;display:grid;place-items:center;position:relative;
 background:linear-gradient(145deg,var(--acc),var(--acc2));box-shadow:0 8px 24px -8px var(--acc)}
.logo svg{width:23px;height:23px;stroke:#fff;fill:none;stroke-width:2.1}
.logo:after{content:"";position:absolute;inset:-4px;border-radius:17px;border:1px solid var(--acc);
 opacity:.35;animation:pulse 2.6s ease-out infinite}
@keyframes pulse{0%{transform:scale(.92);opacity:.5}100%{transform:scale(1.25);opacity:0}}
h1{font-size:19px;font-weight:750;letter-spacing:-.3px}
.sub{font-size:12.5px;color:var(--mut)}
.spacer{flex:1}
.btn{display:inline-flex;align-items:center;gap:7px;height:38px;padding:0 15px;border-radius:11px;
 border:1px solid var(--stroke2);background:var(--card);color:var(--txt);font-size:13.5px;font-weight:550;
 cursor:pointer;transition:.18s;white-space:nowrap}
.btn:hover{background:var(--card2);transform:translateY(-1px);border-color:var(--acc)}
.btn.primary{background:linear-gradient(135deg,var(--acc),var(--acc2));border:0;color:#fff;
 box-shadow:0 10px 26px -12px var(--acc)}
.btn svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2}
.btn.on{border-color:var(--ok);color:var(--ok)}
.spin{animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}

/* ── hero ───────────────────────────────────────────── */
.hero{display:grid;grid-template-columns:300px 1fr;gap:18px;margin-bottom:18px}
@media(max-width:900px){.hero{grid-template-columns:1fr}}
.gauge{padding:24px;display:flex;flex-direction:column;align-items:center;gap:6px;position:relative;overflow:hidden}
.gauge:before{content:"";position:absolute;top:-60%;left:-20%;width:140%;height:130%;
 background:radial-gradient(closest-side,var(--gc,var(--acc)),transparent 70%);opacity:.14}
.ring{position:relative;width:206px;height:206px}
.ring svg{transform:rotate(-90deg)}
.ring .track{stroke:var(--stroke);stroke-width:13;fill:none}
.ring .bar{stroke-width:13;fill:none;stroke-linecap:round;
 transition:stroke-dashoffset 1.1s cubic-bezier(.16,1,.3,1),stroke .5s;filter:drop-shadow(0 0 10px var(--gc))}
.ring .mid{position:absolute;inset:0;display:grid;place-content:center;text-align:center}
.score{font-size:53px;font-weight:800;letter-spacing:-2.5px;line-height:1}
.score small{font-size:16px;color:var(--mut);font-weight:600;letter-spacing:0}
.gl{font-size:12px;font-weight:700;letter-spacing:2.4px;color:var(--gc,var(--acc));margin-top:5px}
.gsub{font-size:13px;color:var(--mut)}
.pills{display:flex;gap:7px;margin-top:10px;flex-wrap:wrap;justify-content:center}
.pill{font-size:11.5px;font-weight:650;padding:4px 11px;border-radius:999px;border:1px solid transparent}
.pill.c{background:color-mix(in srgb,var(--crit) 16%,transparent);color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,transparent)}
.pill.w{background:color-mix(in srgb,var(--warn) 16%,transparent);color:var(--warn);border-color:color-mix(in srgb,var(--warn) 35%,transparent)}
.pill.o{background:color-mix(in srgb,var(--ok) 14%,transparent);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 32%,transparent)}

.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:14px}
.kpi{padding:16px 17px;position:relative;overflow:hidden;transition:.2s}
.kpi:hover{transform:translateY(-2px)}
.kpi .kh{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--mut);
 letter-spacing:.6px;text-transform:uppercase;font-weight:650}
.kpi .kv{font-size:31px;font-weight:780;letter-spacing:-1.2px;margin:6px 0 2px}
.kpi .kv i{font-size:13px;font-style:normal;color:var(--mut);font-weight:600;letter-spacing:0}
.kpi .kd{font-size:12px;color:var(--dim)}
.kpi svg.spark{position:absolute;right:0;bottom:0;width:100%;height:44px;opacity:.9}
.dot{width:8px;height:8px;border-radius:50%;box-shadow:0 0 9px currentColor}

/* ── toolbar ────────────────────────────────────────── */
.tools{display:flex;gap:9px;align-items:center;margin:20px 0 14px;flex-wrap:wrap}
.chip{height:33px;padding:0 14px;border-radius:999px;border:1px solid var(--stroke2);background:var(--card);
 color:var(--mut);font-size:13px;font-weight:600;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:.16s}
.chip:hover{color:var(--txt);border-color:var(--acc)}
.chip.active{background:var(--txt);color:var(--bg);border-color:transparent}
.chip b{font-size:11px;opacity:.8}
.search{flex:1;min-width:180px;max-width:320px;height:36px;border-radius:11px;border:1px solid var(--stroke2);
 background:var(--card);color:var(--txt);padding:0 13px;font-size:13.5px;outline:0}
.search:focus{border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 18%,transparent)}

/* ── check cards ────────────────────────────────────── */
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(390px,1fr));gap:16px}
.card{padding:0;overflow:hidden;transition:.22s;position:relative}
.card:hover{transform:translateY(-2px);border-color:var(--stroke2)}
.card:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--sc);opacity:.9}
.ch{display:flex;gap:13px;align-items:flex-start;padding:17px 18px 0}
.ico{width:40px;height:40px;flex:0 0 40px;border-radius:12px;display:grid;place-items:center;
 background:color-mix(in srgb,var(--sc) 14%,transparent);border:1px solid color-mix(in srgb,var(--sc) 28%,transparent)}
.ico svg{width:20px;height:20px;stroke:var(--sc);fill:none;stroke-width:1.9;stroke-linecap:round;stroke-linejoin:round}
.cn{font-size:15.5px;font-weight:700;letter-spacing:-.2px}
.badge{font-size:10.5px;font-weight:750;letter-spacing:1.1px;padding:3.5px 9px;border-radius:7px;
 background:color-mix(in srgb,var(--sc) 16%,transparent);color:var(--sc);
 border:1px solid color-mix(in srgb,var(--sc) 30%,transparent)}
.cv{display:flex;align-items:baseline;gap:7px;padding:11px 18px 0}
.cv b{font-size:33px;font-weight:790;letter-spacing:-1.6px}
.cv span{font-size:13px;color:var(--mut);font-weight:600}
.cv .sq{margin-left:auto;font-size:11.5px;color:var(--dim)}
.bar{height:6px;border-radius:99px;background:var(--stroke);margin:12px 18px 0;overflow:hidden;position:relative}
.bar i{display:block;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--sc),color-mix(in srgb,var(--sc) 55%,#fff));
 transition:width .9s cubic-bezier(.16,1,.3,1);box-shadow:0 0 12px var(--sc)}
.cs{font-size:12.5px;color:var(--mut);padding:11px 18px 0;min-height:38px}
.cf{padding:2px 18px 0;display:flex;flex-direction:column;gap:6px}
.fnd{display:flex;gap:9px;align-items:flex-start;font-size:12.5px;padding:8px 10px;border-radius:10px;
 background:color-mix(in srgb,var(--fc) 9%,transparent);border:1px solid color-mix(in srgb,var(--fc) 20%,transparent)}
.fnd .fdot{margin-top:5px;flex:0 0 7px;width:7px;height:7px;border-radius:50%;background:var(--fc);box-shadow:0 0 8px var(--fc)}
.fnd b{color:var(--txt);font-weight:650}
.fnd em{display:block;color:var(--dim);font-style:normal;font-size:11.5px;margin-top:2px}
.expand{width:100%;margin-top:14px;padding:11px;border:0;border-top:1px solid var(--stroke);
 background:transparent;color:var(--acc);font-size:12.5px;font-weight:650;cursor:pointer;
 display:flex;align-items:center;justify-content:center;gap:7px;transition:.15s;font-family:inherit}
.expand:hover{background:color-mix(in srgb,var(--acc) 9%,transparent)}
.expand svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2.2;transition:.25s}
.card.open .expand svg{transform:rotate(180deg)}
.det{max-height:0;overflow:hidden;transition:max-height .45s cubic-bezier(.2,.9,.2,1)}
.card.open .det{max-height:2600px}
.dbody{padding:4px 18px 18px;border-top:1px solid var(--stroke)}
.sec{margin-top:15px}
.sec h4{font-size:10.5px;letter-spacing:1.5px;color:var(--dim);text-transform:uppercase;font-weight:700;margin-bottom:8px;
 display:flex;align-items:center;gap:7px}
.sec h4:after{content:"";flex:1;height:1px;background:var(--stroke)}
.why{font-size:12.8px;color:var(--mut);background:color-mix(in srgb,var(--acc) 7%,transparent);
 border-left:2px solid var(--acc);padding:10px 12px;border-radius:0 10px 10px 0}
.cmd{position:relative;margin:6px 0}
.cmd pre{background:rgba(0,0,0,.42);border:1px solid var(--stroke);border-radius:10px;padding:10px 40px 10px 12px;
 font-size:12.2px;color:#cfe0ff;overflow-x:auto;white-space:pre;line-height:1.5}
[data-theme=light] .cmd pre{background:#0d1426;color:#d6e4ff}
.cmd .cp{position:absolute;top:6px;right:6px;width:26px;height:26px;border-radius:7px;border:1px solid var(--stroke2);
 background:var(--card2);color:var(--mut);cursor:pointer;display:grid;place-items:center;opacity:0;transition:.15s}
.cmd:hover .cp{opacity:1}.cmd .cp:hover{color:var(--ok);border-color:var(--ok)}
.cmd .cp svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}
ol.fix{list-style:none;counter-reset:f}
ol.fix li{counter-increment:f;position:relative;padding:8px 10px 8px 34px;font-size:12.8px;color:var(--txt);
 background:color-mix(in srgb,var(--ok) 7%,transparent);border-radius:10px;margin:5px 0;
 border:1px solid color-mix(in srgb,var(--ok) 16%,transparent)}
ol.fix li:before{content:counter(f);position:absolute;left:9px;top:8px;width:18px;height:18px;border-radius:6px;
 background:var(--ok);color:#04120c;font-size:11px;font-weight:800;display:grid;place-items:center}
.mtable{width:100%;border-collapse:collapse;font-size:12.2px}
.mtable td{padding:5px 8px;border-bottom:1px solid var(--stroke);color:var(--mut)}
.mtable td:first-child{color:var(--dim)}
.mtable td:last-child{text-align:right;color:var(--txt);font-weight:600}
.mtable tr:last-child td{border:0}

/* ── misc ───────────────────────────────────────────── */
.toasts{position:fixed;right:18px;bottom:18px;display:flex;flex-direction:column;gap:9px;z-index:99}
.toast{min-width:250px;max-width:380px;padding:13px 15px;border-radius:13px;font-size:13.5px;
 border-left:3px solid var(--tc,var(--acc));animation:in .35s cubic-bezier(.16,1,.3,1)}
@keyframes in{from{transform:translateX(40px) scale(.96);opacity:0}}
.toast b{display:block;margin-bottom:2px}
footer{margin-top:30px;display:flex;gap:14px;flex-wrap:wrap;align-items:center;
 color:var(--dim);font-size:12px;padding-top:18px;border-top:1px solid var(--stroke)}
.ch2{padding:3px 10px;border-radius:999px;border:1px solid var(--stroke2);font-size:11.5px}
.ch2.on{color:var(--ok);border-color:color-mix(in srgb,var(--ok) 40%,transparent)}
.ver-badge{display:inline-flex;align-items:center;gap:6px;padding:3px 10px;border-radius:999px;background:var(--card);border:1px solid var(--stroke2);color:var(--mut);font-size:11.5px}
.skel{height:190px;border-radius:var(--r);background:linear-gradient(100deg,var(--card) 30%,var(--card2) 50%,var(--card) 70%);
 background-size:220% 100%;animation:sh 1.3s linear infinite}
@keyframes sh{to{background-position:-120% 0}}
kbd{font-size:10.5px;padding:1px 5px;border-radius:5px;border:1px solid var(--stroke2);background:var(--card)}
</style></head><body>
<div class="wrap">
 <header>
  <div class="brand">
   <div class="logo"><svg viewBox="0 0 24 24"><path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6l8-4z"/><path d="M8.5 12.5l2.2 2.2 4.8-5"/></svg></div>
   <div><h1>Health Sentinel <span style="font-size:11px;color:var(--dim);font-weight:600">v__VER__</span></h1>
    <div class="sub" id="hostline">loading…</div></div>
  </div>
  <div class="spacer"></div>
  <input class="search" id="q" placeholder="Filter checks…  ( / )">
  <button class="btn" id="autoBtn" onclick="toggleAuto()"><svg viewBox="0 0 24 24"><path d="M12 6v6l4 2"/><circle cx="12" cy="12" r="9"/></svg><span id="autoTxt">Auto</span></button>
  <button class="btn" onclick="toggleTheme()"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="4.5"/><path d="M12 2v2M12 20v2M2 12h2M20 12h2M5 5l1.5 1.5M17.5 17.5L19 19M19 5l-1.5 1.5M6.5 17.5L5 19"/></svg></button>
  <button class="btn" onclick="testAlert(this)"><svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 10-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 01-3.4 0"/></svg>Test alert</button>
  <button class="btn" onclick="dl()"><svg viewBox="0 0 24 24"><path d="M12 3v12M7 11l5 5 5-5M4 20h16"/></svg>JSON</button>
  <button class="btn primary" id="scanBtn" onclick="scan()"><svg viewBox="0 0 24 24" id="scanIco"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></svg>Scan now</button>
 </header>

 <div class="hero">
  <div class="glass gauge" id="gauge">
   <div class="ring">
    <svg width="206" height="206" viewBox="0 0 206 206">
     <circle class="track" cx="103" cy="103" r="90"/>
     <circle class="bar" id="gbar" cx="103" cy="103" r="90" stroke="var(--gc)"
       stroke-dasharray="565.5" stroke-dashoffset="565.5"/>
    </svg>
    <div class="mid"><div class="score" id="gscore">–<small>/100</small></div>
     <div class="gl" id="ggrade">SCANNING</div></div>
   </div>
   <div class="gsub" id="gsub">collecting samples…</div>
   <div class="pills" id="gpills"></div>
  </div>
  <div class="kpis" id="kpis">
   <div class="glass skel"></div><div class="glass skel"></div>
   <div class="glass skel"></div><div class="glass skel"></div>
  </div>
 </div>

 <div class="tools">
  <button class="chip active" data-f="all" onclick="setF('all',this)">All <b id="c-all">0</b></button>
  <button class="chip" data-f="crit" onclick="setF('crit',this)"><span class="dot" style="color:var(--crit);background:var(--crit)"></span>Critical <b id="c-crit">0</b></button>
  <button class="chip" data-f="warn" onclick="setF('warn',this)"><span class="dot" style="color:var(--warn);background:var(--warn)"></span>Warning <b id="c-warn">0</b></button>
  <button class="chip" data-f="ok" onclick="setF('ok',this)"><span class="dot" style="color:var(--ok);background:var(--ok)"></span>Healthy <b id="c-ok">0</b></button>
  <div class="spacer"></div>
  <button class="chip" onclick="allOpen(true)">Expand all</button>
  <button class="chip" onclick="allOpen(false)">Collapse</button>
  <button class="chip" onclick="copyReport(this)">Copy report</button>
 </div>

 <div class="grid" id="grid">
  <div class="glass skel"></div><div class="glass skel"></div><div class="glass skel"></div>
  <div class="glass skel"></div><div class="glass skel"></div><div class="glass skel"></div>
 </div>

 <footer>
  <span id="chans"></span>
  <span class="ver-badge">v__VER__ (updated __UPDATED__)</span>
  <div class="spacer"></div>
  <span>Shortcuts: <kbd>r</kbd> rescan · <kbd>/</kbd> search · <kbd>e</kbd> expand · <kbd>t</kbd> theme</span>
 </footer>
</div>
<div class="toasts" id="toasts"></div>

<script>
const BOOT = __BOOTSTRAP__;
const ICONS = {
 cpu:'<rect x="4.5" y="4.5" width="15" height="15" rx="2.5"/><rect x="9" y="9" width="6" height="6" rx="1"/><path d="M9 2v2.5M15 2v2.5M9 19.5V22M15 19.5V22M2 9h2.5M2 15h2.5M19.5 9H22M19.5 15H22"/>',
 activity:'<path d="M3 12h3.5l2.5-7 3.5 14 3-7H21"/>',
 memory:'<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 7V4M12 7V4M17 7V4M7 17v3M12 17v3M17 17v3"/>',
 drive:'<rect x="2.5" y="13" width="19" height="7" rx="2"/><path d="M5 13l2.6-7.4A2 2 0 019.5 4h5a2 2 0 011.9 1.6L19 13"/><circle cx="17.5" cy="16.5" r="1"/>',
 gauge:'<path d="M4 18a9 9 0 1116 0"/><path d="M12 18l4.5-6"/><circle cx="12" cy="18" r="1.4"/>',
 layers:'<path d="M12 3l9 5-9 5-9-5 9-5z"/><path d="M3 13l9 5 9-5"/>',
 network:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3.4 3 14.6 0 18M12 3c-3 3.4-3 14.6 0 18"/>',
 list:'<path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/>',
 server:'<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01M11 7.5h4M11 16.5h4"/>',
 shield:'<path d="M12 3l8 3.5v5.5c0 4.8-3.3 8.2-8 9.5-4.7-1.3-8-4.7-8-9.5V6.5L12 3z"/><path d="M9 12l2 2 4-4.5"/>',
 alert:'<path d="M12 3l9.5 17H2.5L12 3z"/><path d="M12 9v5M12 17h.01"/>'
};
const CLR={ok:'var(--ok)',warn:'var(--warn)',crit:'var(--crit)',info:'var(--acc)'};
let REPORT=null, HIST=[], FILTER='all', AUTO=true, TIMER=null, OPEN=new Set();

const $=s=>document.querySelector(s), esc=s=>String(s==null?'':s)
 .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const api=(p,o={})=>fetch(p,{headers:{'X-Auth-Token':BOOT.token||''},...o}).then(r=>r.json());
const bytes=n=>{n=+n||0;const u=['B','K','M','G','T','P'];let i=0;while(n>=1024&&i<5){n/=1024;i++}
 return (i?n.toFixed(1):n)+u[i]};

/* ── toasts ── */
function toast(title,msg,kind='info',ms=4200){
 const d=document.createElement('div');d.className='glass toast';d.style.setProperty('--tc',CLR[kind]||CLR.info);
 d.innerHTML=`<b style="color:${CLR[kind]||CLR.info}">${esc(title)}</b><span style="color:var(--mut)">${esc(msg)}</span>`;
 $('#toasts').appendChild(d);setTimeout(()=>{d.style.opacity=0;d.style.transform='translateX(30px)';
  setTimeout(()=>d.remove(),300)},ms);
}

/* ── sparkline ── */
function spark(vals,color,max){
 if(!vals||vals.length<2) return '';
 const W=240,H=44,mx=max||Math.max(...vals,1)*1.15||1;
 const pts=vals.map((v,i)=>[i/(vals.length-1)*W, H-Math.max(0,Math.min(v/mx,1))*(H-6)-3]);
 const line=pts.map((p,i)=>(i?'L':'M')+p[0].toFixed(1)+' '+p[1].toFixed(1)).join(' ');
 const id='g'+Math.random().toString(36).slice(2,8);
 return `<svg class="spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
  <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
   <stop offset="0" stop-color="${color}" stop-opacity=".38"/><stop offset="1" stop-color="${color}" stop-opacity="0"/>
  </linearGradient></defs>
  <path d="${line} L ${W} ${H} L 0 ${H} Z" fill="url(#${id})"/>
  <path d="${line}" fill="none" stroke="${color}" stroke-width="1.8" stroke-linejoin="round"/></svg>`;
}

/* ── render ── */
function render(r){
 REPORT=r;
 const col=CLR[r.status] || CLR.ok;
 $('#hostline').textContent=`${r.host} · ${r.os} · kernel ${r.kernel} · ${r.cores} cores · up ${r.uptime}`;
 document.title=`${r.score.toFixed(0)}/100 · ${r.host} · Sentinel`;

 // gauge
 const g=$('#gauge');g.style.setProperty('--gc',col);
 const C=2*Math.PI*90;
 $('#gbar').setAttribute('stroke-dashoffset', C-(C*Math.max(r.score,2)/100));
 $('#gscore').innerHTML=`${r.score.toFixed(0)}<small>/100</small>`;
 $('#ggrade').textContent=`${r.grade} · ${r.grade_label.toUpperCase()}`;
 $('#gsub').textContent=`${r.counts.total} checks in ${r.duration_ms}ms · ${new Date(r.ts*1000).toLocaleTimeString()}`;
 $('#gpills').innerHTML=
  (r.counts.crit?`<span class="pill c">${r.counts.crit} critical</span>`:'')+
  (r.counts.warn?`<span class="pill w">${r.counts.warn} warning</span>`:'')+
  `<span class="pill o">${r.counts.ok} healthy</span>`;
 ['all','crit','warn','ok'].forEach(k=>$('#c-'+k).textContent=k==='all'?r.counts.total:r.counts[k]);

 // KPI tiles
 const m=id=>r.checks.find(c=>c.id===id)||{metrics:{},status:'ok'};
 const cpu=m('cpu'),mem=m('memory'),ld=m('load'),dk=m('disk'),io=m('io');
 const H=k=>HIST.map(p=>p[k]);
 const tiles=[
  {t:'CPU',v:cpu.metrics.busy?.toFixed(0)??'–',u:'%',d:`usr ${cpu.metrics.user||0}% · sys ${cpu.metrics.system||0}% · steal ${cpu.metrics.steal||0}%`,s:cpu.status,k:'cpu',max:100},
  {t:'Memory',v:mem.metrics.used_pct?.toFixed(0)??'–',u:'%',d:`${bytes(mem.metrics.available)} available · swap ${(mem.metrics.swap_used_pct||0).toFixed(0)}%`,s:mem.status,k:'mem',max:100},
  {t:'Load / core',v:(ld.metrics.per_core??0).toFixed(2),u:`× ${r.cores}c`,d:`1m ${ld.metrics.load1||0} · 5m ${ld.metrics.load5||0} · 15m ${ld.metrics.load15||0}`,s:ld.status,k:'load',max:2.5},
  {t:'Disk / IO',v:dk.metrics.worst_pct?.toFixed(0)??'–',u:'% full',d:`busiest dev ${io.metrics.worst_util||0}% util · await ${io.metrics.worst_await||0}ms`,s:dk.status==='ok'?io.status:dk.status,k:'disk',max:100}
 ];
 $('#kpis').innerHTML=tiles.map(t=>`<div class="glass kpi">
   <div class="kh"><span>${t.t}</span><span class="dot" style="color:${CLR[t.s]||CLR.ok};background:${CLR[t.s]||CLR.ok}"></span></div>
   <div class="kv">${t.v}<i> ${t.u}</i></div><div class="kd">${esc(t.d)}</div>
   ${spark(H(t.k),CLR[t.s]||CLR.ok,t.max)}</div>`).join('');

 // check cards
 $('#grid').innerHTML=r.checks.map(c=>card(c)).join('');
 applyFilter();
}

function card(c){
 const col=CLR[c.status] || CLR.ok;
 const findings=c.findings.map(f=>`<div class="fnd" style="--fc:${CLR[f.severity]||CLR.info}">
   <span class="fdot"></span><div><b>${esc(f.title)}</b>${f.detail?`<em>${esc(f.detail)}</em>`:''}</div></div>`).join('');
 const detail=c.findings.map(f=>`
  <div class="sec"><h4 style="color:${CLR[f.severity]||CLR.info}">${esc(f.title)}</h4>
   ${f.why?`<div class="why">${esc(f.why)}</div>`:''}
   ${f.diagnose.length?`<div class="sec"><h4>① Diagnose</h4>${f.diagnose.map(cmd).join('')}</div>`:''}
   ${f.fix.length?`<div class="sec"><h4>② Fix</h4><ol class="fix">${f.fix.map(x=>`<li>${esc(x)}</li>`).join('')}</ol></div>`:''}
  </div>`).join('');
 const metrics=`<div class="sec"><h4>Metrics</h4><table class="mtable">${
  Object.entries(c.metrics).filter(([k,v])=>['number','string','boolean'].includes(typeof v))
  .map(([k,v])=>`<tr><td>${esc(k)}</td><td>${esc(typeof v==='number'?(Math.round(v*100)/100):v)}</td></tr>`).join('')
 }</table>${tables(c)}</div>`;
 return `<div class="glass card${OPEN.has(c.id)?' open':''}" data-id="${c.id}" data-s="${c.status}"
   data-q="${esc((c.name+' '+c.summary+' '+c.findings.map(f=>f.title).join(' ')).toLowerCase())}"
   style="--sc:${col}">
  <div class="ch"><div class="ico"><svg viewBox="0 0 24 24">${ICONS[c.icon]||ICONS.alert}</svg></div>
   <div style="flex:1"><div class="cn">${esc(c.name)}</div>
    <div style="font-size:11.5px;color:var(--dim)">score ${c.score.toFixed(0)}/100 · weight ${c.weight}</div></div>
   <span class="badge">${c.status==='ok'?'HEALTHY':c.status.toUpperCase()}</span></div>
  <div class="cv"><b>${esc(c.value)}</b><span>${esc(c.unit)}</span>
   <span class="sq">${c.findings.length?c.findings.length+' finding'+(c.findings.length>1?'s':''):'no issues'}</span></div>
  <div class="bar"><i style="width:${Math.max(2,Math.min(100,c.pct)).toFixed(1)}%"></i></div>
  <div class="cs">${esc(c.summary)}</div>
  ${findings?`<div class="cf">${findings}</div>`:''}
  <button class="expand" onclick="tog(this)">${c.findings.length?'Diagnose &amp; fix':'Details'}
   <svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></button>
  <div class="det"><div class="dbody">${detail||'<div class="sec"><h4>All good</h4><div class="why">No issues detected for this subsystem.</div></div>'}${metrics}</div></div>
 </div>`;
}
function tables(c){
 const t=[];
 const list=(arr,cols,title)=>{if(!Array.isArray(arr)||!arr.length)return'';
  return `<h4 style="margin-top:12px">${title}</h4><table class="mtable">`+arr.slice(0,8).map(o=>
   `<tr>${cols.map((k,i)=>`<td>${esc(typeof o[k]==='number'?Math.round(o[k]*100)/100:(k.match(/free|total|rss|rx_s|tx_s|read_s|write_s/)?bytes(o[k]):o[k]))}</td>`).join('')}</tr>`).join('')+'</table>'};
 if(c.metrics.mounts) t.push(list(c.metrics.mounts,['mount','pct','free'],'Filesystems (%, free)'));
 if(c.metrics.devices) t.push(list(c.metrics.devices,['dev','util','await_ms','iops'],'Devices (util%, await ms, IOPS)'));
 if(c.metrics.ifaces) t.push(list(c.metrics.ifaces,['iface','rx_s','tx_s','err_s'],'Interfaces (rx/s, tx/s, err/s)'));
 if(c.metrics.top_cpu) t.push(list(c.metrics.top_cpu,['comm','pid','cpu'],'Top CPU (%)'));
 if(c.metrics.top_mem) t.push(list(c.metrics.top_mem,['comm','pid','rss'],'Top memory (RSS)'));
 if(c.metrics.top_errors) t.push(list(c.metrics.top_errors,['count','text'],'Most frequent log errors'));
 if(c.metrics.top_slow_scripts) t.push(list(c.metrics.top_slow_scripts,['pool','script','duration','trace'],'PHP-FPM Slow Script Executions'));
 if(c.metrics.failed_units&&c.metrics.failed_units.length)
   t.push(`<h4 style="margin-top:12px">Failed units</h4><table class="mtable">`+
    c.metrics.failed_units.map(u=>`<tr><td colspan="2" style="color:var(--crit)">${esc(u)}</td></tr>`).join('')+'</table>');
 return t.join('');
}
const cmd=x=>`<div class="cmd"><pre>${esc(x)}</pre><button class="cp" title="Copy"
 onclick="cp(this,${JSON.stringify(x).replace(/"/g,'&quot;')})"><svg viewBox="0 0 24 24">
 <rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 012-2h8"/></svg></button></div>`;

/* ── interactions ── */
function tog(b){const c=b.closest('.card');c.classList.toggle('open');
 c.classList.contains('open')?OPEN.add(c.dataset.id):OPEN.delete(c.dataset.id)}
function allOpen(v){document.querySelectorAll('.card').forEach(c=>{c.classList.toggle('open',v);
 v?OPEN.add(c.dataset.id):OPEN.delete(c.dataset.id)})}
function setF(f,el){FILTER=f;document.querySelectorAll('.chip[data-f]').forEach(c=>c.classList.remove('active'));
 el.classList.add('active');applyFilter()}
function applyFilter(){const q=$('#q').value.trim().toLowerCase();
 document.querySelectorAll('.card').forEach(c=>{
  const okF=FILTER==='all'||c.dataset.s===FILTER, okQ=!q||c.dataset.q.includes(q);
  c.style.display=(okF&&okQ)?'':'none'})}
$('#q').addEventListener('input',applyFilter);
function cp(btn,txt){navigator.clipboard.writeText(txt).then(()=>{
 btn.style.color='var(--ok)';toast('Copied','Command copied to clipboard','ok',1800);
 setTimeout(()=>btn.style.color='',900)})}
function copyReport(b){if(!REPORT)return;
 const L=[`Health Sentinel · ${REPORT.host} · ${REPORT.score}/100 (${REPORT.grade})`,REPORT.time,''];
 REPORT.checks.forEach(c=>{L.push(`[${c.status.toUpperCase()}] ${c.name}: ${c.value} ${c.unit} — ${c.summary}`);
  c.findings.forEach(f=>{L.push(`  ▸ ${f.title}`);f.fix.slice(0,3).forEach(x=>L.push(`     fix: ${x}`))})});
 navigator.clipboard.writeText(L.join('\n'));toast('Report copied','Plain-text summary in clipboard','ok')}
function dl(){const a=document.createElement('a');
 a.href='data:application/json,'+encodeURIComponent(JSON.stringify(REPORT,null,2));
 a.download=`health-${REPORT.host}-${new Date().toISOString().slice(0,19)}.json`;a.click()}
function toggleTheme(){const t=document.documentElement.dataset.theme==='dark'?'light':'dark';
 document.documentElement.dataset.theme=t;localStorage.sentinelTheme=t;if(REPORT)render(REPORT)}
function toggleAuto(){AUTO=!AUTO;$('#autoBtn').classList.toggle('on',AUTO);
 $('#autoTxt').textContent=AUTO?`Auto ${BOOT.interval}s`:'Auto off';
 clearInterval(TIMER);if(AUTO)TIMER=setInterval(load,BOOT.interval*1000)}
async function scan(){const b=$('#scanBtn');b.disabled=true;$('#scanIco').classList.add('spin');
 try{const r=await api('/api/scan',{method:'POST'});HIST=r.history||HIST;render(r.report);
  const bad=r.report.counts.crit+r.report.counts.warn;
  toast('Scan complete',bad?`${bad} issue(s) need attention`:'All ten checks healthy',bad?(r.report.counts.crit?'crit':'warn'):'ok')}
 catch(e){toast('Scan failed',e.message,'crit')}
 finally{b.disabled=false;$('#scanIco').classList.remove('spin')}}
async function load(){try{const r=await api('/api/health');HIST=r.history||[];render(r.report)}catch(e){}}
async function testAlert(b){b.disabled=true;
 try{const r=await api('/api/test-alert',{method:'POST'});
  toast(r.ok?'Test alert sent':'No channel enabled',r.detail,r.ok?'ok':'warn',6000)}
 finally{b.disabled=false}}
document.addEventListener('keydown',e=>{
 if(e.target.tagName==='INPUT')return;
 if(e.key==='r')scan(); if(e.key==='e')allOpen(!document.querySelector('.card.open'));
 if(e.key==='t')toggleTheme(); if(e.key==='/'){e.preventDefault();$('#q').focus()}});

/* ── boot ── */
document.documentElement.dataset.theme=localStorage.sentinelTheme||'dark';
$('#chans').innerHTML=BOOT.channels.length
 ? 'Alert channels: '+BOOT.channels.map(c=>`<span class="ch2 on">${esc(c)}</span>`).join(' ')
 : '<span class="ch2">No alert channel configured — edit config.json</span>';
$('#autoBtn').classList.add('on');$('#autoTxt').textContent=`Auto ${BOOT.interval}s`;
load();TIMER=setInterval(load,BOOT.interval*1000);
</script></body></html>"""

FAVICON = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24">
<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#7d9dff"/><stop offset="1" stop-color="#b98cff"/></linearGradient></defs>
<rect width="24" height="24" rx="6" fill="url(#g)"/>
<path d="M12 4l6 3v5c0 4-2.6 6.4-6 7.5C8.6 18.4 6 16 6 12V7l6-3z" fill="none" stroke="#fff" stroke-width="1.6"/>
<path d="M9.4 12.2l1.8 1.8 3.6-4" fill="none" stroke="#fff" stroke-width="1.6" stroke-linecap="round"/></svg>"""


class Handler(BaseHTTPRequestHandler):
    server_version = f"HealthSentinel/{VERSION}"
    engine: Engine = None
    alerts: AlertManager = None
    cfg: dict = None

    def log_message(self, *a):
        pass

    # ── helpers ──
    def _authed(self):
        tok = (self.cfg["web"].get("token") or "").strip()
        if not tok:
            return True
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return (self.headers.get("X-Auth-Token") == tok or q.get("token", [""])[0] == tok
                or self.headers.get("Authorization", "") == f"Bearer {tok}")

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, default=str)
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def _payload(self):
        with self.engine.lock:
            rep = self.engine.report
        return {"report": rep or self.engine.scan(), "history": list(self.engine.history)[-240:]}

    # ── routes ──
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/favicon.svg":
            return self._send(200, FAVICON, "image/svg+xml")
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        if path in ("/", "/index.html"):
            channels = [n for n, c in self.cfg["alerts"].items()
                        if isinstance(c, dict) and c.get("enabled")]
            boot = {"interval": self.cfg["scan_interval"],
                    "token": self.cfg["web"].get("token", ""),
                    "channels": channels}
            page = HTML_PAGE.replace("__BOOTSTRAP__", json.dumps(boot)).replace("__VER__", VERSION).replace("__UPDATED__", UPDATED)
            return self._send(200, page, "text/html; charset=utf-8")
        if path == "/api/health":
            return self._send(200, self._payload())
        if path == "/api/history":
            return self._send(200, {"history": list(self.engine.history)})
        if path == "/metrics":                       # Prometheus exposition
            return self._send(200, prometheus(self.engine), "text/plain; version=0.0.4")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        path = urllib.parse.urlparse(self.path).path
        try:
            n = int(self.headers.get("Content-Length") or 0)
            self.rfile.read(n)
        except Exception:
            pass
        if path == "/api/scan":
            rep = self.engine.scan()
            if self.alerts:
                self.alerts.process(rep)
            return self._send(200, self._payload())
        if path == "/api/test-alert":
            rep = self.engine.report or self.engine.scan()
            chans = [n for n, c in self.cfg["alerts"].items()
                     if isinstance(c, dict) and c.get("enabled")]
            if not chans:
                return self._send(200, {"ok": False, "detail": "Enable a channel in config.json first"})
            worst = max(rep["checks"], key=lambda c: (RANK[c["status"]], -c["score"]))
            self.alerts.dispatch([{"type": "problem", "check": worst}], rep)
            return self._send(200, {"ok": True, "detail": "Sent via " + ", ".join(chans)})
        return self._send(404, {"error": "not found"})


def prometheus(engine):
    r = engine.report or engine.scan()
    L = ["# HELP sentinel_health_score Overall health score 0-100",
         "# TYPE sentinel_health_score gauge",
         f'sentinel_health_score{{host="{r["host"]}"}} {r["score"]}']
    L += ["# HELP sentinel_check_score Per-check score", "# TYPE sentinel_check_score gauge"]
    for c in r["checks"]:
        L.append(f'sentinel_check_score{{host="{r["host"]}",check="{c["id"]}",'
                 f'status="{c["status"]}"}} {c["score"]}')
        for k, v in c["metrics"].items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                L.append(f'sentinel_metric{{host="{r["host"]}",check="{c["id"]}",metric="{k}"}} {v}')
    return "\n".join(L) + "\n"


# ─────────────────────────────────────────────────────────────────────────────
#  CLI RENDERER
# ─────────────────────────────────────────────────────────────────────────────

class A:
    R = "\033[0m"; B = "\033[1m"; D = "\033[2m"; I = "\033[3m"
    OK = "\033[38;5;42m"; WARN = "\033[38;5;214m"; CRIT = "\033[38;5;203m"
    ACC = "\033[38;5;111m"; MUT = "\033[38;5;245m"; DIM = "\033[38;5;240m"; W = "\033[97m"


def _c(status):
    return {"ok": A.OK, "warn": A.WARN, "crit": A.CRIT, "info": A.ACC}.get(status, A.OK)


def bar(pct, width=26, colour=A.ACC):
    fill = int(clamp(pct) / 100 * width)
    return colour + "█" * fill + A.DIM + "░" * (width - fill) + A.R


def cli_report(r, verbose=True, colour=True):
    if not colour or not sys.stdout.isatty():
        for k in dir(A):
            if not k.startswith("_"):
                setattr(A, k, "")
    W = 92
    sc = _c(r["status"])
    print()
    print(f"{A.ACC}╭{'─' * (W - 2)}╮{A.R}")
    title = f" 🛡  LINUX HEALTH SENTINEL v{VERSION}"
    print(f"{A.ACC}│{A.R}{A.B}{title}{A.R}{' ' * (W - 2 - len(title))}{A.ACC}│{A.R}")
    line = f" {r['host']} · {r['os']} · {r['kernel']} · {r['cores']} cores · up {r['uptime']}"
    print(f"{A.ACC}│{A.R}{A.MUT}{line[:W-3]}{A.R}{' ' * max(0, W - 2 - len(line[:W-3]))}{A.ACC}│{A.R}")
    print(f"{A.ACC}╰{'─' * (W - 2)}╯{A.R}")
    print(f"\n  {sc}{A.B}{r['score']:.0f}{A.R}{A.MUT}/100{A.R}  "
          f"{sc}{A.B}{r['grade']}{A.R} {A.MUT}·{A.R} {sc}{r['grade_label']}{A.R}   "
          f"{bar(r['score'], 30, sc)}")
    print(f"  {A.CRIT}●{A.R} {r['counts']['crit']} critical   "
          f"{A.WARN}●{A.R} {r['counts']['warn']} warning   "
          f"{A.OK}●{A.R} {r['counts']['ok']} healthy      "
          f"{A.DIM}{r['time']} ({r['duration_ms']}ms){A.R}\n")

    order = sorted(r["checks"], key=lambda c: (-RANK[c["status"]], c["score"]))
    for c in order:
        cc = _c(c["status"])
        tag = {"ok": " OK ", "warn": "WARN", "crit": "CRIT"}.get(c["status"], " OK ")
        print(f"  {cc}▌{A.R} {cc}{A.B}[{tag}]{A.R} {A.B}{c['name']:<26}{A.R}"
              f"{A.W}{c['value']:>9}{A.R} {A.MUT}{c['unit']:<14}{A.R}"
              f"{bar(c['pct'], 18, cc)} {A.DIM}{c['score']:.0f}/100{A.R}")
        print(f"      {A.MUT}{c['summary'][:W - 8]}{A.R}")
        if verbose:
            for f in c["findings"]:
                fc = _c(f["severity"])
                print(f"      {fc}▸ {A.B}{f['title']}{A.R}")
                if f["detail"]:
                    print(f"        {A.DIM}{f['detail'][:W - 10]}{A.R}")
                if f["why"]:
                    print(f"        {A.I}{A.MUT}why: {f['why'][:W - 15]}{A.R}")
                for d in f["diagnose"][:3]:
                    print(f"        {A.ACC}⌘{A.R} {A.DIM}{d}{A.R}")
                for x in f["fix"][:4]:
                    print(f"        {A.OK}✔{A.R} {x}")
        print()
    print(f"  {A.DIM}Dashboard: python3 {os.path.basename(sys.argv[0])}   "
          f"Prometheus: /metrics   Alerts: config.json{A.R}\n")


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────

def background_loop(engine, alerts, interval, stop):
    while not stop.is_set():
        try:
            rep = engine.scan()
            if alerts:
                for e in alerts.process(rep):
                    c = e["check"]
                    print(f"[sentinel] {e['type']} · {c['name']} · {c['status']}", flush=True)
        except Exception as e:
            print(f"[sentinel] scan error: {e}", file=sys.stderr, flush=True)
        stop.wait(interval)


def main():
    ap = argparse.ArgumentParser(description="Linux Health Sentinel — 10 checks, fixes, alerts")
    ap.add_argument("-c", "--config", default=os.environ.get("SENTINEL_CONFIG", "/etc/health-sentinel/config.json"))
    ap.add_argument("--once", action="store_true", help="single scan, print report, exit 0/1/2")
    ap.add_argument("--json", action="store_true", help="with --once: JSON output")
    ap.add_argument("--quiet", action="store_true", help="with --once: no per-finding detail")
    ap.add_argument("--no-alerts", action="store_true")
    ap.add_argument("--test-alerts", action="store_true", help="send a sample alert and exit")
    ap.add_argument("--bind"), ap.add_argument("--port", type=int)
    ap.add_argument("--interval", type=int)
    args = ap.parse_args()

    cfg = load_config(args.config)
    if args.bind:
        cfg["web"]["bind"] = args.bind
    if args.port:
        cfg["web"]["port"] = args.port
    if args.interval:
        cfg["scan_interval"] = args.interval
    if args.no_alerts:
        cfg["alerts"]["enabled"] = False

    engine = Engine(cfg)
    alerts = AlertManager(cfg) if cfg["alerts"]["enabled"] else None

    if args.test_alerts:
        rep = engine.scan()
        worst = max(rep["checks"], key=lambda c: (RANK[c["status"]], -c["score"]))
        AlertManager(cfg).dispatch([{"type": "problem", "check": worst}], rep)
        print("Test alert dispatched (check your channels).")
        time.sleep(4)
        return 0

    if args.once:
        rep = engine.scan()
        if alerts:
            alerts.process(rep)
        print(json.dumps(rep, indent=2, default=str)) if args.json else cli_report(rep, not args.quiet)
        return {"ok": 0, "warn": 1, "crit": 2}[rep["status"]]

    # daemon: background scanner + web dashboard
    stop = threading.Event()
    threading.Thread(target=background_loop,
                     args=(engine, alerts, cfg["scan_interval"], stop), daemon=True).start()

    if not cfg["web"]["enabled"]:
        print("[sentinel] web UI disabled — running alert-only loop. Ctrl-C to stop.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            return 0

    Handler.engine, Handler.alerts, Handler.cfg = engine, alerts, cfg
    srv = ThreadingHTTPServer((cfg["web"]["bind"], cfg["web"]["port"]), Handler)
    url = f"http://{cfg['web']['bind']}:{cfg['web']['port']}"
    if cfg["web"].get("token"):
        url += "?token=" + cfg["web"]["token"]
    print(f"\n  🛡  Linux Health Sentinel v{VERSION}\n  ▸ dashboard  {url}\n"
          f"  ▸ metrics    {url.split('?')[0]}/metrics\n"
          f"  ▸ scanning every {cfg['scan_interval']}s · alerts: "
          f"{', '.join(n for n, c in cfg['alerts'].items() if isinstance(c, dict) and c.get('enabled')) or 'none'}\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
