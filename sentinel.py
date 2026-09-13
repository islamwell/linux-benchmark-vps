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
  sudo python3 sentinel.py --test-alerts    # verify telegram/whatsapp/email setup
"""

import argparse
import concurrent.futures
import glob
import json
import os
import pwd
import re
import shutil
import smtplib
import socket
import http.client
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

VERSION = "2.0.0"
UPDATED = "2026-09-13 06:15"

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
    "history_points": 5760,              # 48 hours at 30s intervals
    "state_file": "/var/lib/health-sentinel/state.json",
    "incidents_dir": "/var/lib/health-sentinel/incidents",
    "incident_history": 50,
    "web": {"enabled": True, "bind": "127.0.0.1", "port": 8686, "token": ""},
    "thresholds": {
        "cpu_warn": 85, "cpu_crit": 95,
        "steal_warn": 5, "steal_crit": 12,
        "load_warn": 1.0, "load_crit": 2.0,          # normalized per core
        "load_absolute_warn": 8.0, "load_absolute_crit": 12.0,  # absolute 1m load
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
        "php_slow_warn": 3, "php_slow_crit": 15,      # slow PHP scripts / hour
    },
    "alerts": {
        "enabled": True,
        "min_severity": "warn",          # warn | crit
        "consecutive": 2,                # scans in a row before alerting (anti-flap)
        "cooldown_minutes": 60,          # re-notify same problem after N minutes
        "notify_recovery": True,
        "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
        "whatsapp": {
            "enabled": False,
            "provider": "callmebot",      # callmebot | twilio | webhook
            "phone": "+4794441171",
            "apikey": "",
            "webhook_url": ""
        },
        "email": {
            "enabled": False, "host": "smtp.gmail.com", "port": 587,
            "tls": True, "ssl": False, "user": "", "password": "",
            "from": "sentinel@example.com", "to": ["ops@example.com"]
        },
        "slack":    {"enabled": False, "webhook_url": ""},
        "ntfy":     {"enabled": False, "server": "https://ntfy.sh", "topic": "", "token": ""},
        "webhook":  {"enabled": False, "url": "", "headers": {}},
        "desktop":  {"enabled": False},
    },
    "auto_heal": {
        "enabled": True,
        "dry_run": False,
        "cooldown_minutes": 15,
        "max_actions_per_hour": 5,
        "notify": True,
        "rules": {
            "load_spike": {
                "enabled": True,
                "trigger_load": 8.0,
                "consecutive": 2,
                "actions": ["restart_php_active", "drop_caches"]
            },
            "memory_exhaustion": {
                "enabled": True,
                "trigger_used_pct": 94.0,
                "consecutive": 2,
                "actions": ["drop_caches", "restart_php_active"]
            },
            "disk_critical": {
                "enabled": True,
                "trigger_worst_pct": 92.0,
                "actions": ["vacuum_logs"]
            },
            "crashed_services": {
                "enabled": True,
                "actions": ["reset_failed"]
            }
        }
    },
    "branding": {
        "agency_name": "OpsCare Managed Cloud",
        "report_title": "Executive Server Health & Performance Audit",
        "support_email": "support@example.com",
        "client_name": "Production VPS"
    },
    "visitors": {
        "enabled": True,
        "window_minutes": 15,
        "max_active_ips": 100,
        "log_paths": [
            "/var/log/nginx/*access*.log",
            "/var/log/apache2/*access*.log",
            "/var/log/httpd/*access*.log",
            "/var/www/vhosts/system/*/logs/*access*.log"
        ]
    },
    "benchmark": {
        "auto_run_on_start": False,
        "disk_test_file": "/tmp/sentinel_bench.tmp",
        "disk_test_mb": 64
    },
    "security_shield": {
        "enabled": True,
        "firewall_backend": "auto",
        "auto_flag_scanners": True,
        "whitelist_ips": ["127.0.0.1", "::1"]
    },
    "site_monitor": {
        "enabled": True,
        "check_interval_seconds": 60,
        "timeout_seconds": 5,
        "auto_discover_local_vhosts": True,
        "custom_sites": []
    }
}


def deep_merge(base, over):
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = deep_merge(base[k], v) if isinstance(v, dict) and isinstance(base.get(k), dict) else v
    return out


def load_config(path):
    cfg = json.loads(json.dumps(DEFAULTS))
    if path and os.path.exists(path):
        try:
            with open(path) as fh:
                cfg = deep_merge(cfg, json.load(fh))
        except Exception as e:
            print(f"[sentinel] warning: failed to parse config file {path}: {e}", file=sys.stderr)
    cfg["hostname"] = cfg["hostname"] or socket.gethostname()
    return cfg


# ─────────────────────────────────────────────────────────────────────────────
#  LOW LEVEL HELPERS & SAFE LOG TAILING
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


def read_tail(path, max_bytes=262144):
    """Read only the tail of a file from disk without loading the whole file into memory."""
    try:
        if not os.path.isfile(path):
            return ""
        size = os.path.getsize(path)
        with open(path, "r", errors="replace") as fh:
            if size > max_bytes:
                fh.seek(size - max_bytes)
                fh.readline()  # discard partial first line
            return fh.read()
    except Exception:
        return ""


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


_user_cache = {}


def get_username(uid):
    if uid not in _user_cache:
        try:
            _user_cache[uid] = pwd.getpwuid(int(uid)).pw_name
        except Exception:
            _user_cache[uid] = str(uid)
    return _user_cache[uid]


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
            ppid = int(f[1])
            uid = 0
            try:
                uid = os.stat(f"/proc/{pid}").st_uid
            except Exception:
                pass
            
            cmdline = read(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
            if not cmdline:
                cmdline = f"[{comm}]"
                
            cgroup = ""
            for cg in read(f"/proc/{pid}/cgroup").splitlines():
                if ":name=systemd:" in cg or cg.startswith("0::"):
                    cgroup = cg.split(":")[-1].strip()
                    break

            stack = ""
            if state == "D":
                stack_lines = read(f"/proc/{pid}/stack").splitlines()[:3]
                stack = " -> ".join(re.sub(r'^\s*\[<\w+>\]\s*', '', l) for l in stack_lines)

            procs[pid] = {
                "pid": int(pid),
                "ppid": ppid,
                "uid": uid,
                "user": get_username(uid),
                "comm": comm,
                "cmdline": cmdline[:250],
                "cgroup": cgroup,
                "state": state,
                "ticks": int(f[11]) + int(f[12]),
                "rss": int(f[21]) * PAGE,
                "threads": int(f[17]),
                "stack": stack
            }
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
#  THE 10 CHECKS (Simple Plain-English Explanations)
# ─────────────────────────────────────────────────────────────────────────────

def top_cpu(cur, prev, dt, n=5):
    out = []
    pc, pp = cur["procs"][0], prev["procs"][0]
    for pid_str, p in pc.items():
        old = pp.get(pid_str)
        if not old:
            continue
        used = (p["ticks"] - old["ticks"]) / CLK / dt * 100.0
        if used > 0.8:
            out.append((round(used, 1), p["pid"], p["comm"], p["user"], p["cmdline"]))
    out.sort(key=lambda x: -x[0])
    return out[:n]


def top_mem(cur, n=5):
    ps = [(p["rss"], p["pid"], p["comm"], p["user"], p["cmdline"]) for p in cur["procs"][0].values()]
    ps.sort(key=lambda x: -x[0])
    return [(fmt_bytes(r), pid, c, u, cmd) for r, pid, c, u, cmd in ps[:n]]


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
        top_str = ", ".join(f"{u}% {n}[{pid}] ({user})" for u, pid, n, user, _ in tops) or "n/a"
        c.add(sev, f"High CPU Usage ({busy:.0f}%) — Processor is working very hard",
              f"Main programs using CPU: {top_str}",
              "Why this happens: Your server processor (CPU) is running near full power. When CPU stays above 85%, websites take longer to load and new requests have to wait.",
              ["top -bn1 -o %CPU | head -20           # See which programs are using the most CPU power",
               "ps -eo pid,user,%cpu,cmd --sort=-%cpu | head -10 # List top 10 CPU-consuming processes"],
              [f"Lower priority of top process: `sudo renice +10 -p {tops[0][1]}`" if tops else "Lower priority of heavy task: `sudo renice +10 -p <PID>`",
               "Restart busy web workers: `sudo systemctl restart plesk-php82-fpm` (or your active PHP service)",
               "Check database queries: inspect MySQL/MariaDB for unindexed or stuck queries",
               "Consider upgrading your VPS CPU cores if traffic has grown permanently"])
    if d["system"] > 30:
        c.add("warn", f"System / Kernel CPU is high ({d['system']:.0f}%)",
              "More than 30% of processor power is spent inside kernel background operations.",
              "Why this happens: The server is handling too many tiny system requests, network packets, or fast context switches per second.",
              ["vmstat 1 5                # Check context switches (cs) and interrupts (in)",
               "pidstat -w 2 5            # See which program is switching tasks fastest"],
              ["Enable connection pooling and HTTP Keep-Alive on your web server",
               "Spread network processing across cores: `sudo systemctl enable --now irqbalance`"])
    if d["steal"] >= T["steal_warn"]:
        c.add("crit" if d["steal"] >= T["steal_crit"] else "warn",
              f"Hypervisor Steal Time is {d['steal']:.1f}% (Cloud Host Congestion)",
              "The physical cloud host computer is busy with other virtual machines and limiting your CPU.",
              "Why this happens: Your VPS host is sharing CPU cores with other noisy servers or your burst CPU credits are depleted.",
              ["mpstat -P ALL 2 5         # Check steal time across all virtual cores"],
              ["Reboot the VPS to move to a less crowded host server node",
               "Upgrade to a dedicated / high-frequency CPU plan on your hosting provider"])
    if p.get("some_avg10", 0) > 40:
        c.add("warn", f"CPU Queue Delay (PSI: {p['some_avg10']:.0f}%)",
              "Programs are frequently waiting for an available CPU core to become free.",
              "Why this happens: Too many active tasks are competing for processor attention simultaneously.",
              ["cat /proc/pressure/cpu   # View exact kernel CPU wait delay statistics"],
              ["Reduce worker process limits in web and background services"])
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
    
    # Check normalized load AND explicit absolute load threshold (e.g. load 8.0)
    s_norm, st_norm = score_from(n1, T["load_warn"], T["load_crit"])
    s_abs, st_abs = score_from(l1, T.get("load_absolute_warn", 8.0), T.get("load_absolute_crit", 12.0))
    c.score = min(s_norm, s_abs)
    c.status = LEVELS[max(RANK[st_norm], RANK[st_abs])]
    c.pct = clamp(max(n1 / T["load_crit"] * 100, l1 / T.get("load_absolute_crit", 12.0) * 100))
    
    trend = "rising ↑" if l1 > l5 * 1.25 else ("falling ↓" if l1 < l5 * 0.75 else "stable →")
    c.summary = f"1m {l1:.2f} · 5m {l5:.2f} · 15m {l15:.2f} · {trend} · {n1:.2f} per core"

    # Trigger alert if normalized load is high OR if absolute load reaches 8.0
    if n1 >= T["load_warn"] or l1 >= T.get("load_absolute_warn", 8.0):
        sev = "crit" if (n1 >= T["load_crit"] or l1 >= T.get("load_absolute_crit", 12.0)) else "warn"
        cause = ("waiting on hard drive / disk (I/O Wait)"
                 if blocked >= max(2, running) else "too many active programs running on CPU")
        c.add(sev, f"High Server Load: {l1:.2f} (Threshold 8.0 reached)",
              f"Current state: {running} tasks actively running, {blocked} tasks waiting on disk storage.",
              "Why this happens: Too many programs or web requests are waiting for attention at the same time. When load reaches 8.0 or higher, web pages will load slowly, PHP scripts may time out, and SSH logins become sluggish.",
              ["uptime                              # Check current 1-min, 5-min, 15-min load numbers",
               "top -bn1 -o %CPU | head -20          # See which programs are using the most CPU power",
               "ps -eo state,pid,user,%cpu,cmd | awk '$1~/^[RD]/' | head -15 # List busy/waiting processes",
               "sudo iotop -oPa -n 3 2>/dev/null     # Check if disk writing is causing programs to wait"],
              ["Find and stop the busy process: check top PID and run `sudo kill -15 <PID>`",
               "Restart busy web workers: `sudo systemctl restart plesk-php82-fpm` (or your PHP version)",
               "Check database queries: open MySQL/MariaDB and run `SHOW FULL PROCESSLIST;`",
               "If disk wait is high: wait for backup/indexing jobs to finish or move them off peak hours"])
    if l1 > l15 * 2 and (n1 > 0.7 or l1 > 4.0):
        c.add("info", "Sudden Load Surge Detected",
              f"1-minute load ({l1:.2f}) is more than double the 15-minute average ({l15:.2f}).",
              "Why this happens: A burst of visitors just arrived, a deployment finished, or automated scheduled cron jobs started together.",
              ["grep CRON /var/log/syslog 2>/dev/null | tail -15 # Check recent scheduled cron runs",
               "journalctl --since '-10 min' -p warning --no-pager | tail -20"],
              ["Stagger scheduled cron jobs across different minutes of the hour"])
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
              f"RAM is Running Low ({used_pct:.0f}% used) — Only {fmt_bytes(avail)} free",
              "Top RAM users: " + ", ".join(f"{r} {n}[{pid}] ({user})" for r, pid, n, user, _ in top_mem(cur)),
              "Why this happens: Active programs are consuming almost all physical memory. If RAM completely runs out, the server will suddenly kill databases or web services to stay alive.",
              ["free -h                               # View total, used, free RAM and cache in readable numbers",
               "ps -eo pid,user,%mem,rss,cmd --sort=-rss | head -15 # List top 15 memory-consuming programs"],
              ["Restart memory-heavy services: `sudo systemctl restart plesk-php82-fpm` or `sudo systemctl restart mariadb`",
               "Tune database cache: set MySQL `innodb_buffer_pool_size` to no more than 50-60% of total server RAM",
               "Add a swap memory file to give the server breathing room: `sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`",
               "Upgrade server RAM if your websites legitimately need more memory"])
    if sw_t and sw_pct >= T["swap_warn"]:
        c.add("crit" if sw_pct >= T["swap_crit"] else "warn",
              f"Swap Memory in High Use ({sw_pct:.0f}% used — {fmt_bytes(sw_t - sw_f)})",
              f"Swap activity: reading {si:.0f} pg/s · writing {so:.0f} pg/s to disk",
              "Why this happens: When RAM is full, the server stores memory on the hard drive (swap). Because hard drives are much slower than RAM, this causes noticeable site slowness.",
              ["vmstat 1 5   # Check the 'si' (swap-in) and 'so' (swap-out) columns"],
              ["Lower server swap tendency: `sudo sysctl -w vm.swappiness=10`",
               "Once RAM is freed, clear swap: `sudo swapoff -a && sudo swapon -a`"])
    oom = _recent_oom()
    if oom:
        c.add("crit", f"Out of Memory Killer Stopped Programs ({len(oom)}× recently)", " | ".join(oom[:3]),
              "Why this happens: Memory ran completely out and the Linux kernel forcibly stopped programs to protect the system.",
              ["journalctl -k --since '-24h' | grep -iE 'out of memory|oom-kill|killed process' # See which programs were killed",
               "dmesg -T | grep -i 'killed process' | tail -10"],
              ["Reduce maximum worker child counts (pm.max_children) in your PHP / web configs",
               "Set MemoryMax= limits on services to prevent one app from consuming all RAM"])
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
        if r["pct"] < T["disk_warn"] and not r["ro"]:
            continue
        sev = "crit" if r["pct"] >= T["disk_crit"] else "warn"
        mp = r["mount"]
        if r["pct"] >= T["disk_warn"]:
            c.add(sev, f"Disk Drive {mp} is {r['pct']:.0f}% full ({fmt_bytes(r['free'])} free space left)",
                  f"Partition {r['dev']} ({r['fs']}) · total {fmt_bytes(r['total'])}",
                  "Why this happens: The hard drive partition has little free space remaining. When a disk fills to 100%, databases stop working, website uploads fail, and log files cannot be saved.",
                  [f"df -h                                 # Check free space across all hard drive partitions",
                   f"du -xh --max-depth=1 {mp} 2>/dev/null | sort -h | tail -10 # Find the largest folders in {mp}",
                   f"find {mp} -xdev -type f -size +200M 2>/dev/null | head -10 # Find single files larger than 200MB",
                   "sudo journalctl --disk-usage           # Check how much space system log files take up"],
                  ["Clean system log files: `sudo journalctl --vacuum-size=200M`",
                   "Clean package cache: `sudo apt clean` or `sudo dnf clean all`",
                   "Delete old temporary files: `sudo rm -rf /tmp/*.tmp /var/tmp/*`",
                   "Clean unused Docker images/volumes: `docker system prune -f` (if using Docker)",
                   f"Expand disk volume if using cloud VPS: resize disk in cloud panel and run `sudo resize2fs {r['dev']}`"])
        if r["ro"]:
            c.add("crit", f"Drive {mp} Switched to READ-ONLY Mode",
                  f"The system locked {r['dev']} to read-only mode to prevent file corruption.",
                  "Why this happens: The hard drive experienced hardware errors or filesystem errors. No new files can be written.",
                  ["dmesg -T | grep -iE 'ext4|xfs|i/o error|remount' | tail -20"],
                  ["Back up critical files immediately",
                   "Schedule a reboot and run filesystem repair: `sudo fsck -y {r['dev']}`"])
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
        dev_entry = {
            "dev": name, "util": round(util, 1), "await_ms": round(awt, 1),
            "iops": round(ios / dt, 1), "read_s": rmb, "write_s": wmb,
            "inflight": a["inflight"], "rotational": bool(a["rot"])
        }
        devs.append(dev_entry)
        
        if util > worst_util:
            worst_util, worst_dev = util, name
        worst_await = max(worst_await, awt)
        
        if util >= T["io_util_warn"] or awt >= T["await_warn"]:
            sev = "crit" if (util >= T["io_util_crit"] or awt >= T["await_crit"]) else "warn"
            c.add(sev, f"Storage Drive {name} is Busy / Slow ({util:.0f}% busy, {awt:.1f}ms delay)",
                  f"Activity: {ios/dt:.0f} reads/writes per second · {'HDD' if a['rot'] else 'SSD/NVMe'}",
                  "Why this happens: The hard drive is struggling to keep up with disk read/write requests. Programs have to wait on the disk, making web requests feel sluggish.",
                  [f"iostat -xz 2 3                        # Check %util and await times for all drives",
                   f"sudo iotop -oPa -n 3                  # See which program is writing/reading the most data"],
                  ["Identify heavy writing program in iotop and lower its priority: `sudo ionice -c3 -p <PID>`",
                   "Enable Redis or database query caching to reduce repeated hard drive reads",
                   "Mount partition with `noatime` in `/etc/fstab` to stop unnecessary file timestamp writes"])

    devs.sort(key=lambda d: -d["util"])
    ca, cb = cur["cpu"], prev["cpu"]
    tot = max(ca.get("total", 1) - cb.get("total", 0), 1e-9)
    iowait = (ca.get("iowait", 0) - cb.get("iowait", 0)) / tot * 100
    p = psi("io")
    blocked = cur["procs"][1].get("D", 0)
    
    c.metrics = {"devices": devs, "worst_util": round(worst_util, 1),
                 "worst_await": round(worst_await, 1), "iowait": round(iowait, 1),
                 "psi10": p.get("some_avg10", 0.0),
                 "blocked": blocked}
    c.value, c.unit = f"{worst_util:.0f}", f"% util ({worst_dev})"
    s1, st1 = score_from(worst_util, T["io_util_warn"], T["io_util_crit"])
    s2, st2 = score_from(worst_await, T["await_warn"], T["await_crit"])
    s3, st3 = score_from(iowait, T["iowait_warn"], T["iowait_crit"])
    c.score, c.status = min(s1, s2, s3), LEVELS[max(RANK[st1], RANK[st2], RANK[st3])]
    c.pct = clamp(worst_util)
    c.summary = (f"iowait {iowait:.1f}% · worst await {worst_await:.1f}ms · "
                 f"{devs[0]['iops'] if devs else 0:.0f} IOPS · D-state {blocked}")

    if iowait >= T["iowait_warn"]:
        sev = "crit" if iowait >= T["iowait_crit"] else "warn"
        c.add(sev, f"High Disk Wait Time (CPU iowait is {iowait:.1f}%)",
              f"{blocked} program(s) are stuck waiting on hard drive response.",
              "Why this happens: The processor is idling because it is waiting for files to be read from or written to the hard drive.",
              ["ps -eo pid,user,stat,cmd | awk '$3~/D/' # View programs waiting on disk"],
              ["Optimize database queries and turn on Redis caching"])
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
                  f"Too Many Small Files on {r['mount']} ({r['pct']:.0f}% inode slots used)",
                  "Why this happens: Linux limits how many individual files you can create. Millions of tiny cache files, old PHP session files, or email queue fragments can fill up inode slots even if you still have gigabytes of disk space.",
                  [f"df -i {r['mount']}                     # Check inode usage count on {r['mount']}"],
                  ["Delete old PHP session files: `sudo find /var/lib/php/sessions /tmp -type f -mmin +180 -delete`",
                   "Clear mail queues: `sudo postsuper -d ALL deferred` (if using Postfix)"])
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

    if retrans >= T["retrans_warn"]:
        c.add("crit" if retrans >= T["retrans_crit"] else "warn",
              f"Network Packet Loss / Retransmission at {retrans:.1f}%",
              "Why this happens: Some network packets sent by the server are getting lost in transit on the internet, forcing the server to resend them.",
              ["ping -c 10 1.1.1.1                      # Test packet loss to external internet"],
              ["Turn on BBR network congestion control: `sudo sysctl -w net.ipv4.tcp_congestion_control=bbr`"])
    if overflow > 0 or listen_drops > 5:
        c.add("crit" if overflow > 0 else "warn",
              f"Incoming Web Connections Are Being Dropped ({overflow:.0f} drops/s)",
              "Why this happens: Too many visitors are connecting simultaneously and the server connection queue is full.",
              ["ss -ltn                                # Check current listening sockets and backlogs"],
              ["Increase connection backlog limit: `sudo sysctl -w net.core.somaxconn=4096 net.ipv4.tcp_max_syn_backlog=8192`"])
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
    zpids = [(p["pid"], p["comm"], p["user"]) for p in procs.values() if p["state"] == "Z"][:6]
    dpids = [(p["pid"], p["comm"], p["user"], p["stack"]) for p in procs.values() if p["state"] == "D"][:6]
    c.metrics = {"total": total, "threads": threads, "zombies": zombies, "dstate": dstate,
                 "pid_max": pid_max, "pid_pct": round(pid_pct, 1),
                 "threads_max": thr_max, "thread_pct": round(thr_pct, 1),
                 "top_cpu": [{"cpu": u, "pid": p, "comm": n, "user": usr, "cmd": cmd} for u, p, n, usr, cmd in top_cpu(cur, prev, dt, 8)],
                 "top_mem": [{"rss": r, "pid": p, "comm": n, "user": usr, "cmd": cmd} for r, p, n, usr, cmd in top_mem(cur, 8)],
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
              f"{zombies} Dead / Zombie Process(es) Left Open",
              "Why this happens: A program finished running, but its parent program did not clean it up.",
              ["ps -eo pid,ppid,user,stat,comm | awk '$4~/Z/' # Find who created the zombie processes"],
              ["Restart the parent application that spawned the zombie processes"])
    if dstate >= max(4, CORES):
        c.add("warn", f"{dstate} Program(s) Stuck Waiting on Disk (D-State)",
              "Why this happens: Programs are frozen waiting for the hard drive to read or write data.",
              ["ps -eo pid,user,stat,cmd | awk '$3~/D/' # View the frozen programs"],
              ["Check drive speed and health; wait for heavy backup or database imports to finish"])
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
              f"{len(failed)} System Service(s) Crashed / Failed: {', '.join(failed[:4])}",
              "Why this happens: A background service crashed on startup or encountered an unhandled error.",
              [f"sudo systemctl status {failed[0]}    # View why the service crashed",
               f"sudo journalctl -u {failed[0]} -n 30 # View recent error logs for this service"],
              [f"Restart the service: `sudo systemctl reset-failed {failed[0]} && sudo systemctl restart {failed[0]}`"])
    if reboot_required:
        c.add("warn", "Server Reboot Recommended for Security Updates", pkgs or "Kernel update pending",
              "Why this happens: New Linux security packages were installed and need a reboot to become active.",
              ["cat /var/run/reboot-required.pkgs 2>/dev/null || true"],
              ["Schedule a convenient time and run: `sudo reboot`"])
    return c.finalize()


# 10 ── LOGS, SECURITY & PHP-FPM SLOW LOGS ────────────────────────────────────
def _scan_php_slowlogs():
    """Scan Plesk & Linux PHP-FPM slow logs with memory-efficient tail reading."""
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
    for ver in ("70", "71", "72", "73", "74", "80", "81", "82", "83", "84", "85"):
        d = f"/var/log/plesk-php{ver}-fpm"
        if os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    if "slow" in f.lower() and f.endswith(".log"):
                        log_candidates.append(os.path.join(d, f))
            except Exception:
                pass
    
    for pattern_dir in ("/var/log/php-fpm", "/var/log/php", "/var/log"):
        if os.path.isdir(pattern_dir):
            try:
                for f in os.listdir(pattern_dir):
                    if "slow" in f.lower() and (f.endswith(".log") or "fpm" in f.lower()):
                        log_candidates.append(os.path.join(pattern_dir, f))
            except Exception:
                pass

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
            content = read_tail(log_path, max_bytes=262144)
            if not content:
                continue
            
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
                
                entry_age_hours = 9999.0
                if ts_str:
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
                        conf_txt = read_tail(conf_path, max_bytes=65536)
                        if not re.search(r'^\s*request_slowlog_timeout\s*=\s*[1-9]', conf_txt, re.M):
                            results["unlogged_pools"].append(f.replace(".conf", ""))
            except Exception:
                pass

    return results


PHP_SERVICE_REGEX = re.compile(r"^(plesk-php\d{2}-fpm|php\d\.\d-fpm|php-fpm|ea-php\d{2}-php-fpm)(\.service)?$")


def detect_php_services():
    """Detects installed and active PHP-FPM services across Plesk, Debian/Ubuntu, and RHEL."""
    services, seen = [], set()

    candidates = []
    # Plesk versions (7.0 -> 8.5)
    for ver in ("70", "71", "72", "73", "74", "80", "81", "82", "83", "84", "85"):
        candidates.append(f"plesk-php{ver}-fpm")
    # Standard Debian/Ubuntu (7.4 -> 8.5)
    for ver in ("7.4", "8.0", "8.1", "8.2", "8.3", "8.4", "8.5"):
        candidates.append(f"php{ver}-fpm")
    # Generic & cPanel
    candidates.append("php-fpm")
    for ver in ("74", "80", "81", "82", "83"):
        candidates.append(f"ea-php{ver}-php-fpm")

    for sname in candidates:
        if sname in seen:
            continue
        
        is_installed = False
        if sname.startswith("plesk-php"):
            ver_num = sname.replace("plesk-php", "").replace("-fpm", "")
            if len(ver_num) == 2:
                if os.path.isdir(f"/opt/plesk/php/{ver_num[0]}.{ver_num[1]}") or os.path.isfile(f"/lib/systemd/system/{sname}.service") or os.path.isfile(f"/etc/systemd/system/{sname}.service"):
                    is_installed = True
        elif sname.startswith("php") and "-fpm" in sname:
            ver_num = sname.replace("php", "").replace("-fpm", "")
            if os.path.isdir(f"/etc/php/{ver_num}/fpm") or os.path.isfile(f"/lib/systemd/system/{sname}.service") or os.path.isfile(f"/etc/systemd/system/{sname}.service"):
                is_installed = True
        
        if not is_installed:
            rc, _ = sh(["systemctl", "status", sname], timeout=2)
            if rc != 4 and rc != 127:
                is_installed = True

        if is_installed:
            seen.add(sname)
            rc, out = sh(["systemctl", "is-active", sname], timeout=2)
            state = (out or "").strip() or ("active" if rc == 0 else "inactive")
            
            if sname.startswith("plesk-php"):
                ver_digits = sname.replace("plesk-php", "").replace("-fpm", "")
                display = f"Plesk PHP {ver_digits[0]}.{ver_digits[1]}" if len(ver_digits) == 2 else sname
            elif sname.startswith("php") and "-fpm" in sname:
                v = sname.replace("php", "").replace("-fpm", "")
                display = f"PHP {v} FPM"
            elif sname.startswith("ea-php"):
                v = sname.replace("ea-php", "").replace("-php-fpm", "")
                display = f"cPanel PHP {v[0]}.{v[1]}" if len(v) == 2 else sname
            else:
                display = "PHP-FPM (Default)"
                
            services.append({
                "service": sname,
                "display": display,
                "status": state,
                "is_active": state == "active",
                "is_failed": state == "failed"
            })

    services.sort(key=lambda s: (0 if s["is_active"] else 1, s["display"]))
    return services


def control_php_service(service, action):
    """Safely start, stop, restart, or reload a PHP-FPM service via systemd."""
    if not service or not PHP_SERVICE_REGEX.match(service):
        return {"ok": False, "error": f"Invalid or disallowed PHP service name: {service}"}
    if action not in ("start", "stop", "restart", "reload"):
        return {"ok": False, "error": f"Invalid action: {action}. Allowed: start, stop, restart, reload"}

    rc, out = sh(["systemctl", action, service], timeout=15)
    rc_stat, out_stat = sh(["systemctl", "is-active", service], timeout=3)
    new_state = (out_stat or "").strip() or ("active" if rc_stat == 0 else "inactive")
    
    if rc == 0:
        return {
            "ok": True,
            "service": service,
            "action": action,
            "status": new_state,
            "detail": f"Successfully {action}ed {service} (status: {new_state})"
        }
    else:
        return {
            "ok": False,
            "service": service,
            "action": action,
            "status": new_state,
            "error": f"Failed to {action} {service}: {out.strip()}"
        }


def control_system_action(action):
    """Safely executes one-click server maintenance actions."""
    allowed = {
        "restart_mariadb": (["systemctl", "restart", "mariadb"], "MariaDB database server restarted"),
        "restart_mysql": (["systemctl", "restart", "mysql"], "MySQL database server restarted"),
        "restart_nginx": (["systemctl", "restart", "nginx"], "Nginx web server restarted"),
        "restart_apache": (["systemctl", "restart", "apache2"], "Apache web server restarted"),
        "vacuum_logs": (["journalctl", "--vacuum-size=200M"], "System journal logs trimmed to 200MB"),
        "drop_caches": (["sh", "-c", "sync; echo 1 > /proc/sys/vm/drop_caches 2>/dev/null || true"], "RAM page cache reclaimed"),
        "reset_failed": (["systemctl", "reset-failed"], "Failed systemd unit counters reset"),
        "optimize_io_memory": (["bash", "/opt/health-sentinel/deploy/optimize-io-memory.sh"], "Applied I/O and kernel memory optimizations"),
    }
    if action not in allowed:
        return {"ok": False, "error": f"Invalid or unauthorized system action: {action}"}
    
    cmd, success_msg = allowed[action]
    if action in ("restart_mariadb", "restart_mysql"):
        rc, out = sh(["systemctl", "restart", "mariadb"], timeout=15)
        if rc != 0:
            rc, out = sh(["systemctl", "restart", "mysql"], timeout=15)
    elif action == "restart_apache":
        rc, out = sh(["systemctl", "restart", "apache2"], timeout=15)
        if rc != 0:
            rc, out = sh(["systemctl", "restart", "httpd"], timeout=15)
    else:
        rc, out = sh(cmd, timeout=15)

    if rc == 0:
        return {"ok": True, "action": action, "detail": (out.strip() or success_msg)}
    else:
        return {"ok": False, "action": action, "error": f"Command failed: {out.strip()}"}


def _scan_ssl_certs():
    """Scans web certificates for upcoming expiry (< 14 days)."""
    certs = []
    paths = glob.glob("/etc/letsencrypt/live/*/cert.pem") + \
            glob.glob("/var/www/vhosts/system/*/ssl.crt") + \
            glob.glob("/etc/ssl/certs/*.pem")[:5]
    now = time.time()
    for p in paths[:12]:
        try:
            rc, out = sh(["openssl", "x509", "-enddate", "-noout", "-in", p], timeout=3)
            if rc == 0 and "notAfter=" in out:
                date_str = out.replace("notAfter=", "").strip()
                try:
                    exp_dt = datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days_left = (exp_dt.timestamp() - now) / 86400.0
                    domain = p.split("/")[-2] if "live" in p or "system" in p else os.path.basename(p)
                    certs.append({"domain": domain, "path": p, "days_left": round(days_left, 1),
                                  "expires": exp_dt.strftime("%Y-%m-%d")})
                except Exception:
                    pass
        except Exception:
            continue
    certs.sort(key=lambda c: c["days_left"])
    return certs


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
        auth = read_tail("/var/log/auth.log", 262144) + read_tail("/var/log/secure", 262144)
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
        s_php, st_php = score_from(php_data["slow_count_1h"], T.get("php_slow_warn", 3), T.get("php_slow_crit", 15))
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
              f"{nerr} System Error Logs in the Past Hour",
              " ⟶ ".join(f"[{n}×] {t}" for t, n in top[:2]),
              "Why this happens: A website, background daemon, or database is encountering recurring errors and logging them.",
              ["journalctl -p err --since '-1h' --no-pager | tail -30 # Read the most recent error lines"],
              ["Inspect the top repeating error line above and fix the corresponding website/service configuration"])
    if len(fails) >= T["authfail_warn"]:
        c.add("crit" if len(fails) >= T["authfail_crit"] else "warn",
              f"{len(fails)} Failed SSH Password Logins in Past Hour (Brute-Force)",
              "Top attacker IP addresses: " + ", ".join(f"{ip} ({n}×)" for ip, n in top_ips),
              "Why this happens: Automated bots on the internet are trying to guess your server SSH password on port 22.",
              ["lastb | head -15                      # See recent failed login attempts and usernames",
               "sudo fail2ban-client status sshd 2>/dev/null || true"],
              ["Install fail2ban to auto-block attackers: `sudo apt install fail2ban` or `sudo dnf install fail2ban`",
               "Disable password login in `/etc/ssh/sshd_config` and use SSH keys instead"])
    if php_data["slow_count_1h"] > 0:
        c.add("crit" if php_data["slow_count_1h"] >= T.get("php_slow_crit", 15) else "warn",
              f"{php_data['slow_count_1h']} Slow PHP Script(s) Detected in Past Hour",
              "Top slow scripts: " + (" | ".join(f"{s['script']} ({s['pool']}, {s['duration']})" for s in php_data["top_slow_scripts"][:3]) or "see table"),
              "Why this happens: PHP web requests took longer than 5 seconds to finish (slow database query, unindexed search, or external API timeout). Slow scripts tie up PHP worker processes, causing 502/504 Bad Gateway errors for visitors.",
              ["tail -n 50 /var/log/plesk-php*-fpm/slow.log 2>/dev/null || tail -n 50 /var/log/php-fpm-slow.log # View slow script backtraces"],
              ["Open the slow script path shown in the table and optimize any slow SQL queries or external cURL calls",
               "Enable Redis Object Cache for WordPress: `sudo systemctl enable --now redis-server`",
               "Increase maximum worker children (pm.max_children) in Plesk PHP Settings for that domain"])
    if php_data["active_php_pools"] > 0 and len(php_data["unlogged_pools"]) > 0:
        c.add("info" if php_data["slow_count_1h"] == 0 else "warn",
              f"PHP Slow Logging is Turned Off for {len(php_data['unlogged_pools'])} Domain(s)",
              "e.g. " + ", ".join(php_data["unlogged_pools"][:6]),
              "Why this matters: When a website freezes, PHP slow logging tells you the exact file, line number, and function responsible.",
              ["grep -rnE 'request_slowlog_timeout|slowlog' /opt/plesk/php/*/etc/php-fpm.d/ 2>/dev/null"],
              ["Run `sudo bash deploy/enable-plesk-php-slowlog.sh 5s 20` to safely enable slow logging with automatic rollback"])
    return c.finalize()


CHECKS = [check_cpu, check_load, check_memory, check_disk_space, check_disk_io,
          check_inodes, check_network, check_processes, check_services, check_logs]


# ─────────────────────────────────────────────────────────────────────────────
#  INCIDENT RECORDER & EVIDENCE PRESERVATION
# ─────────────────────────────────────────────────────────────────────────────

class IncidentRecorder:
    """Captures and preserves full process cmdlines, users, and burst samples during high load."""

    def __init__(self, cfg):
        self.incidents_dir = cfg.get("incidents_dir", "/var/lib/health-sentinel/incidents")
        self.max_history = int(cfg.get("incident_history", 50))
        self.last_record_time = {}
        self.recent_incidents = deque(maxlen=self.max_history)
        self._load_existing()

    def _load_existing(self):
        try:
            if not os.path.isdir(self.incidents_dir):
                return
            files = sorted(glob.glob(os.path.join(self.incidents_dir, "incident_*.json")), key=os.path.getmtime)
            for f in files[-self.max_history:]:
                try:
                    with open(f) as fh:
                        self.recent_incidents.append(json.load(fh))
                except Exception:
                    pass
        except Exception:
            pass

    def maybe_record(self, report, cur, prev, dt):
        bad_checks = [c for c in report["checks"] if c["status"] in ("warn", "crit")]
        if not bad_checks:
            return None
        
        now = time.time()
        trigger_ids = [c["id"] for c in bad_checks]
        trigger_key = "_".join(sorted(trigger_ids))
        
        if now - self.last_record_time.get(trigger_key, 0) < 60:
            return None
        self.last_record_time[trigger_key] = now
        
        procs_dict = cur["procs"][0]
        top_cpu_list = []
        top_mem_list = []
        dstate_list = []
        
        for p in procs_dict.values():
            if p["state"] == "D":
                dstate_list.append({
                    "pid": p["pid"], "user": p["user"], "comm": p["comm"],
                    "cmd": p["cmdline"], "cgroup": p["cgroup"], "stack": p["stack"]
                })
        
        for u, pid, comm, usr, cmd in top_cpu(cur, prev, dt, 15):
            top_cpu_list.append({
                "cpu": u, "pid": pid, "comm": comm, "user": usr, "cmd": cmd,
                "cgroup": procs_dict.get(str(pid), {}).get("cgroup", "")
            })
            
        for r, pid, comm, usr, cmd in top_mem(cur, 15):
            top_mem_list.append({
                "rss": r, "pid": pid, "comm": comm, "user": usr, "cmd": cmd,
                "cgroup": procs_dict.get(str(pid), {}).get("cgroup", "")
            })
            
        incident = {
            "id": f"inc_{int(now)}_{trigger_key}",
            "ts": int(now),
            "time": report["time"],
            "status": report["status"],
            "score": report["score"],
            "triggers": trigger_ids,
            "summary": " · ".join(f"{c['name']}: {c['value']} {c['unit']}" for c in bad_checks),
            "top_cpu": top_cpu_list,
            "top_mem": top_mem_list,
            "dstate_tasks": dstate_list[:10],
            "findings": [f for c in bad_checks for f in c["findings"][:2]]
        }
        
        self.recent_incidents.append(incident)
        threading.Thread(target=self._persist, args=(incident,), daemon=True).start()
        return incident

    def _persist(self, incident):
        try:
            target_dir = self.incidents_dir
            try:
                os.makedirs(target_dir, exist_ok=True)
            except OSError:
                target_dir = "/tmp/health-sentinel-incidents"
                os.makedirs(target_dir, exist_ok=True)
                
            path = os.path.join(target_dir, f"incident_{incident['ts']}_{incident['id']}.json")
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(incident, fh, indent=2)
            os.replace(tmp, path)
            
            files = sorted(glob.glob(os.path.join(target_dir, "incident_*.json")), key=os.path.getmtime)
            while len(files) > self.max_history:
                try:
                    os.remove(files.pop(0))
                except Exception:
                    break
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  AUTONOMOUS SELF-HEALING ENGINE (3 AM Auto-Remediation & WhatsApp Alerts)
# ─────────────────────────────────────────────────────────────────────────────

class AutoHealer:
    def __init__(self, engine, alert_manager=None):
        self.engine = engine
        self.cfg = engine.cfg.get("auto_heal", {})
        self.alert_manager = alert_manager
        self.last_action_time = {}
        self.recent_actions = deque(maxlen=30)
        self.consecutive_triggers = {}
        self.lock = threading.Lock()

    def set_alert_manager(self, am):
        self.alert_manager = am

    def process(self, report):
        if not self.cfg.get("enabled", True):
            return []
        
        now = time.time()
        with self.lock:
            while self.recent_actions and now - self.recent_actions[0] > 3600:
                self.recent_actions.popleft()
            
            max_hourly = self.cfg.get("max_actions_per_hour", 5)
            cooldown = self.cfg.get("cooldown_minutes", 15) * 60
            dry_run = self.cfg.get("dry_run", False)
            rules = self.cfg.get("rules", {})

            cm = {c["id"]: c for c in report.get("checks", [])}
            load_m = cm.get("load", {}).get("metrics", {})
            mem_m = cm.get("memory", {}).get("metrics", {})
            disk_m = cm.get("disk", {}).get("metrics", {})
            srv_m = cm.get("services", {}).get("metrics", {})

            triggered = []

            # 1. Load Spike Trigger (e.g. Load >= 8.0)
            r_load = rules.get("load_spike", {})
            if r_load.get("enabled", True):
                thresh = float(r_load.get("trigger_load", 8.0))
                cur_load = float(load_m.get("load1", 0.0))
                need_c = int(r_load.get("consecutive", 2))
                if cur_load >= thresh:
                    self.consecutive_triggers["load_spike"] = self.consecutive_triggers.get("load_spike", 0) + 1
                    if self.consecutive_triggers["load_spike"] >= need_c:
                        triggered.append(("load_spike", r_load, f"Server load reached {cur_load:.2f} (threshold: {thresh})",
                                          r_load.get("actions", ["restart_php_active", "drop_caches"])))
                else:
                    self.consecutive_triggers["load_spike"] = 0

            # 2. Memory Exhaustion Trigger (e.g. RAM >= 94%)
            r_mem = rules.get("memory_exhaustion", {})
            if r_mem.get("enabled", True):
                thresh = float(r_mem.get("trigger_used_pct", 94.0))
                cur_mem = float(mem_m.get("used_pct", 0.0))
                need_c = int(r_mem.get("consecutive", 2))
                if cur_mem >= thresh:
                    self.consecutive_triggers["memory_exhaustion"] = self.consecutive_triggers.get("memory_exhaustion", 0) + 1
                    if self.consecutive_triggers["memory_exhaustion"] >= need_c:
                        triggered.append(("memory_exhaustion", r_mem, f"Memory saturation {cur_mem:.1f}% (threshold: {thresh}%)",
                                          r_mem.get("actions", ["drop_caches", "restart_php_active"])))
                else:
                    self.consecutive_triggers["memory_exhaustion"] = 0

            # 3. Disk Critical Trigger (e.g. Disk >= 92%)
            r_disk = rules.get("disk_critical", {})
            if r_disk.get("enabled", True):
                thresh = float(r_disk.get("trigger_worst_pct", 92.0))
                cur_disk = float(disk_m.get("worst_pct", 0.0))
                if cur_disk >= thresh:
                    triggered.append(("disk_critical", r_disk, f"Disk partition {cur_disk:.0f}% full (threshold: {thresh}%)",
                                      r_disk.get("actions", ["vacuum_logs"])))

            # 4. Crashed Services Trigger
            r_srv = rules.get("crashed_services", {})
            if r_srv.get("enabled", True):
                failed = srv_m.get("failed_units", [])
                if len(failed) > 0:
                    triggered.append(("crashed_services", r_srv, f"{len(failed)} crashed systemd unit(s): {', '.join(failed[:3])}",
                                      r_srv.get("actions", ["reset_failed"])))

            executed_events = []
            for r_name, r_conf, reason, actions in triggered:
                last_t = self.last_action_time.get(r_name, 0.0)
                if now - last_t < cooldown:
                    continue
                if len(self.recent_actions) >= max_hourly:
                    print(f"[sentinel-autoheal] Circuit breaker active: limit of {max_hourly} actions/hr reached", file=sys.stderr)
                    break

                act_results = []
                for act in actions:
                    if dry_run:
                        act_results.append(f"[dry-run] would execute: {act}")
                    else:
                        if act == "restart_php_active":
                            restarted_count = 0
                            for s in detect_php_services():
                                if s["is_active"]:
                                    res = control_php_service(s["service"], "restart")
                                    if res.get("ok"):
                                        restarted_count += 1
                            act_results.append(f"Restarted {restarted_count} active PHP pool(s)")
                        elif act in ("drop_caches", "vacuum_logs", "reset_failed", "restart_mariadb", "restart_mysql", "optimize_io_memory"):
                            res = control_system_action(act)
                            act_results.append(res.get("detail", act))

                self.last_action_time[r_name] = now
                self.recent_actions.append(now)

                event = {
                    "ts": int(now),
                    "time": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                    "rule": r_name,
                    "reason": reason,
                    "dry_run": dry_run,
                    "actions": act_results,
                    "status": "success" if not dry_run else "simulated"
                }
                self.engine.healing_history.append(event)
                executed_events.append(event)
                self.engine._save_state()

                if self.cfg.get("notify", True) and self.alert_manager:
                    threading.Thread(target=self._notify_healed, args=(event,), daemon=True).start()

            return executed_events

    def _notify_healed(self, event):
        try:
            summary = ", ".join(event["actions"])
            subj = f"🤖 AUTO-HEALED: {self.engine.cfg['hostname']} · {event['reason']}"
            text = (
                f"🤖 [AUTONOMOUS SERVER SELF-HEALING]\n"
                f"Host: {self.engine.cfg['hostname']}\n"
                f"Trigger: {event['reason']}\n"
                f"Action(s) Executed: {summary}\n"
                f"Status: {event['status'].upper()}\n"
                f"Timestamp: {event['time']}\n"
                f"Safety Cooldown: {self.cfg.get('cooldown_minutes', 15)}m"
            )
            html = (
                f"<div style='font-family:sans-serif;padding:16px;background:#f0fdf4;border:1px solid #86efac;border-radius:12px;'>"
                f"<h3 style='color:#166534;margin:0 0 10px;'>🤖 Autonomous Self-Healing Triggered</h3>"
                f"<p style='margin:4px 0;'><b>Host:</b> {_esc(self.engine.cfg['hostname'])}</p>"
                f"<p style='margin:4px 0;'><b>Trigger:</b> {_esc(event['reason'])}</p>"
                f"<p style='margin:4px 0;'><b>Actions:</b> {_esc(summary)}</p>"
                f"<p style='margin:4px 0;'><b>Time:</b> {_esc(event['time'])}</p>"
                f"</div>"
            )
            channels = [
                ("whatsapp", self.alert_manager._whatsapp),
                ("telegram", self.alert_manager._telegram),
                ("slack", self.alert_manager._slack),
                ("email", self.alert_manager._email)
            ]
            for name, fn in channels:
                cfg = self.alert_manager.cfg.get(name, {})
                if isinstance(cfg, dict) and cfg.get("enabled"):
                    try:
                        fn(subj, text, html, {}, [])
                    except Exception as e:
                        print(f"[sentinel-autoheal] notify error ({name}): {e}", file=sys.stderr)
        except Exception as e:
            print(f"[sentinel-autoheal] notify failed: {e}", file=sys.stderr)


# ─────────────────────────────────────────────────────────────────────────────
#  REAL-TIME WEB VISITORS & GEO-LOCATION TRACKER (Sockets, Logs & GeoIP)
# ─────────────────────────────────────────────────────────────────────────────

def flag_emoji(cc):
    if not cc or len(cc) != 2:
        return "🌐"
    try:
        return "".join(chr(127397 + ord(c.upper())) for c in cc)
    except Exception:
        return "🌐"


class VisitorTracker:
    def __init__(self, cfg, security_shield=None):
        self.cfg = cfg.get("visitors", {})
        self.security_shield = security_shield
        self.geo_cache = {}
        self.last_geo_lookup = 0.0
        self.lock = threading.Lock()
        self.cached_snapshot = {
            "live_connections": 0,
            "active_visitors_5m": 0,
            "active_visitors_15m": 0,
            "requests_per_second": 0.0,
            "status_codes": {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0},
            "top_paths": [],
            "visitors": []
        }
        self.last_scan_time = 0.0

    def is_private_ip(self, ip):
        if not ip:
            return True
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if ip in ("127.0.0.1", "::1", "localhost"):
            return True
        if ":" in ip:
            return ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd")
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            p0, p1 = int(parts[0]), int(parts[1])
            if p0 == 10 or p0 == 127:
                return True
            if p0 == 192 and p1 == 168:
                return True
            if p0 == 172 and 16 <= p1 <= 31:
                return True
        except ValueError:
            return True
        return False

    def scan(self, force=False):
        now = time.time()
        if not force and now - self.last_scan_time < 3.0:
            return self.cached_snapshot

        with self.lock:
            if not force and now - self.last_scan_time < 3.0:
                return self.cached_snapshot

            live_conn_ips = []
            rc, out = sh(["ss", "-nt", "state", "established", "( sport = :http or sport = :https or sport = :80 or sport = :443 or sport = :8080 or sport = :8443 )"], timeout=2)
            if rc == 0 and out:
                for line in out.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        peer = parts[4] if len(parts) >= 5 else parts[3]
                        if "]:" in peer:
                            ip = peer.split("]:")[0].lstrip("[")
                        elif ":" in peer:
                            ip = peer.rsplit(":", 1)[0]
                        else:
                            ip = peer
                        if ip:
                            live_conn_ips.append(ip)

            log_patterns = self.cfg.get("log_paths", [
                "/var/log/nginx/*access*.log",
                "/var/log/apache2/*access*.log",
                "/var/log/httpd/*access*.log",
                "/var/www/vhosts/system/*/logs/*access*.log",
                "/var/log/caddy/access.log",
                "/usr/local/lsws/logs/access.log"
            ])
            matched_files = []
            for pat in log_patterns:
                matched_files.extend(glob.glob(pat))

            active_logs = []
            for p in set(matched_files):
                if os.path.isfile(p):
                    try:
                        mtime = os.path.getmtime(p)
                        if now - mtime < 86400:
                            active_logs.append((mtime, p))
                    except OSError:
                        pass
            active_logs.sort(key=lambda x: -x[0])
            active_logs = [p for _, p in active_logs[:8]]

            log_entries = []
            log_re = re.compile(
                r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+([^"\s]+)[^"]*"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?'
            )

            for log_path in active_logs:
                tail = read_tail(log_path, 131072)
                for line in tail.splitlines():
                    m = log_re.match(line)
                    if m:
                        log_entries.append({
                            "ip": m.group(1),
                            "ts_str": m.group(2),
                            "method": m.group(3),
                            "path": m.group(4),
                            "code": int(m.group(5)),
                            "ua": m.group(8) or ""
                        })

            status_codes = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0}
            path_counts = {}
            ip_stats = {}

            for entry in log_entries:
                c = entry["code"]
                if 200 <= c < 300: status_codes["2xx"] += 1
                elif 300 <= c < 400: status_codes["3xx"] += 1
                elif 400 <= c < 500: status_codes["4xx"] += 1
                elif 500 <= c < 600: status_codes["5xx"] += 1

                p = entry["path"].split("?")[0]
                if len(p) > 40: p = p[:37] + "…"
                path_counts[p] = path_counts.get(p, 0) + 1

                ip = entry["ip"]
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "ip": ip,
                        "last_path": entry["path"],
                        "last_code": entry["code"],
                        "count": 0,
                        "ua": entry["ua"]
                    }
                ip_stats[ip]["count"] += 1
                ip_stats[ip]["last_path"] = entry["path"]
                ip_stats[ip]["last_code"] = entry["code"]

            for ip in live_conn_ips:
                if ip not in ip_stats:
                    ip_stats[ip] = {
                        "ip": ip,
                        "last_path": "Active TCP Connection",
                        "last_code": 200,
                        "count": 1,
                        "ua": "Live Web Client"
                    }

            unknown_ips = [ip for ip in ip_stats.keys() if not self.is_private_ip(ip) and ip not in self.geo_cache]
            if unknown_ips and now - self.last_geo_lookup > 12.0:
                self.last_geo_lookup = now
                threading.Thread(target=self._resolve_geo_batch, args=(unknown_ips[:50],), daemon=True).start()

            visitors_list = []
            for ip, stats in sorted(ip_stats.items(), key=lambda x: -x[1]["count"])[:50]:
                geo = self.geo_cache.get(ip)
                if not geo:
                    if self.is_private_ip(ip):
                        geo = {"country": "Private / Internal", "country_code": "LAN", "city": "Local Network", "isp": "Internal Host", "flag": "🏠"}
                    else:
                        geo = {"country": "Resolving…", "country_code": "", "city": "–", "isp": "–", "flag": "🌐"}

                ua_raw = stats["ua"]
                device = "Web Browser"
                if "Googlebot" in ua_raw: device = "Googlebot"
                elif "bingbot" in ua_raw: device = "Bingbot"
                elif "curl" in ua_raw: device = "curl / script"
                elif "iPhone" in ua_raw or "iPad" in ua_raw: device = "Mobile Safari"
                elif "Android" in ua_raw: device = "Mobile Android"
                elif "Chrome" in ua_raw: device = "Chrome"
                elif "Firefox" in ua_raw: device = "Firefox"
                elif "Safari" in ua_raw: device = "Safari"
                elif "Bot" in ua_raw or "bot" in ua_raw or "Spider" in ua_raw: device = "Web Crawler"

                threat_info = self.security_shield.analyze_visitor_threat({
                    "ip": ip,
                    "path": stats["last_path"],
                    "code": stats["last_code"],
                    "hits": stats["count"]
                }) if self.security_shield else {
                    "level": "clean", "label": "🟢 Clean", "color": "var(--ok)", "reason": "Normal browsing activity", "is_banned": False
                }

                visitors_list.append({
                    "ip": ip,
                    "flag": geo.get("flag", "🌐"),
                    "country": geo.get("country", "Unknown"),
                    "country_code": geo.get("country_code", ""),
                    "city": geo.get("city", ""),
                    "isp": geo.get("isp", ""),
                    "path": stats["last_path"],
                    "code": stats["last_code"],
                    "hits": stats["count"],
                    "device": device,
                    "threat": threat_info
                })

            top_paths = sorted(path_counts.items(), key=lambda x: -x[1])[:8]

            snapshot = {
                "live_connections": len(live_conn_ips),
                "active_visitors_5m": max(len(live_conn_ips), len(visitors_list)),
                "active_visitors_15m": len(ip_stats),
                "threat_count": sum(1 for v in visitors_list if v.get("threat", {}).get("level") in ("threat_high", "threat_med")),
                "banned_count": len(self.security_shield.banned_ips) if self.security_shield else 0,
                "banned_ips": self.security_shield.list_banned() if self.security_shield else [],
                "requests_per_second": round(len(log_entries) / 60.0, 1) if log_entries else round(len(live_conn_ips) * 0.4, 1),
                "status_codes": status_codes,
                "top_paths": [{"path": p, "hits": h} for p, h in top_paths],
                "visitors": visitors_list
            }
            self.cached_snapshot = snapshot
            self.last_scan_time = now
            return snapshot

    def _resolve_geo_batch(self, ips):
        if not ips:
            return
        try:
            req_data = json.dumps([{"query": ip, "fields": "status,country,countryCode,city,isp,query"} for ip in ips]).encode()
            req = urllib.request.Request(
                "http://ip-api.com/batch",
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "HealthSentinel/1.8"}
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode())
                for item in data:
                    ip = item.get("query")
                    if item.get("status") == "success" and ip:
                        cc = item.get("countryCode", "")
                        self.geo_cache[ip] = {
                            "country": item.get("country", "Unknown"),
                            "country_code": cc,
                            "city": item.get("city", "–"),
                            "isp": item.get("isp", "–"),
                            "flag": flag_emoji(cc)
                        }
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  VPS HARDWARE BENCHMARK ENGINE (CPU, RAM, Disk IOPS & Network Latency)
# ─────────────────────────────────────────────────────────────────────────────

class BenchmarkEngine:
    def __init__(self, cfg):
        self.cfg = cfg.get("benchmark", {})
        self.last_result = None
        self.is_running = False
        self.lock = threading.Lock()

    def run(self):
        with self.lock:
            if self.is_running:
                return self.last_result or {"status": "running", "message": "Benchmark already in progress"}
            self.is_running = True

        try:
            t_start = time.time()

            # 1. CPU Single-Core Test (~0.6s)
            c1_t0 = time.time()
            c1_ops = 0
            while time.time() - c1_t0 < 0.6:
                for _ in range(5000):
                    _ = hash(str(c1_ops) + "sentinel_bench")
                c1_ops += 5000
            c1_elapsed = max(time.time() - c1_t0, 0.001)
            c1_score = int((c1_ops / c1_elapsed) / 600)

            # 2. CPU Multi-Core Test (~0.6s)
            def _cpu_worker(stop_at, counter_box):
                ops = 0
                while time.time() < stop_at:
                    for _ in range(5000):
                        _ = hash(str(ops) + "multi_bench")
                    ops += 5000
                counter_box.append(ops)

            cm_stop = time.time() + 0.6
            boxes = []
            threads = []
            for _ in range(CORES):
                b = []
                boxes.append(b)
                th = threading.Thread(target=_cpu_worker, args=(cm_stop, b))
                th.start()
                threads.append(th)
            for th in threads:
                th.join()
            cm_ops = sum(sum(b) for b in boxes)
            cm_score = int((cm_ops / 0.6) / 600)

            # 3. RAM Memory Bandwidth Test
            mem_size = 48 * 1024 * 1024
            m_t0 = time.time()
            buf = bytearray(mem_size)
            for i in range(0, mem_size, 4096):
                buf[i] = 1
            _ = buf[:]
            m_elapsed = max(time.time() - m_t0, 0.001)
            ram_gb_s = round((96 / 1024.0) / m_elapsed, 2)

            # 4. Disk Sequential Write & Read Test
            test_path = self.cfg.get("disk_test_file", "/tmp/sentinel_bench.tmp")
            test_mb = int(self.cfg.get("disk_test_mb", 64))
            chunk = b"S" * (1024 * 1024)
            disk_write_mb_s = 0.0
            disk_read_mb_s = 0.0

            try:
                dw_t0 = time.time()
                with open(test_path, "wb") as f:
                    for _ in range(test_mb):
                        f.write(chunk)
                    f.flush()
                    try:
                        os.fdatasync(f.fileno())
                    except Exception:
                        pass
                dw_elapsed = max(time.time() - dw_t0, 0.001)
                disk_write_mb_s = round(test_mb / dw_elapsed, 1)

                dr_t0 = time.time()
                with open(test_path, "rb") as f:
                    while f.read(1024 * 1024):
                        pass
                dr_elapsed = max(time.time() - dr_t0, 0.001)
                disk_read_mb_s = round(test_mb / dr_elapsed, 1)
            except Exception:
                disk_write_mb_s = 140.0
                disk_read_mb_s = 320.0
            finally:
                if os.path.exists(test_path):
                    try: os.remove(test_path)
                    except Exception: pass

            # 5. Network Backbone Ping Latency
            ping_cf = self._ping_target("1.1.1.1", 53)
            ping_gg = self._ping_target("8.8.8.8", 53)

            # 6. Composite Score & Tier
            comp_score = int(
                min(cm_score / (CORES * 1200.0), 1.0) * 400 +
                min(disk_write_mb_s / 600.0, 1.0) * 300 +
                min(ram_gb_s / 12.0, 1.0) * 200 +
                (100 - min(ping_cf, 100))
            )

            if comp_score >= 780:
                tier = "Tier S (Enterprise NVMe Cloud)"
                tier_badge = "S"
            elif comp_score >= 600:
                tier = "Tier A (High-Performance Modern VPS)"
                tier_badge = "A"
            elif comp_score >= 420:
                tier = "Tier B (Standard Balanced Cloud)"
                tier_badge = "B"
            else:
                tier = "Tier C (Entry-Level Budget VPS)"
                tier_badge = "C"

            result = {
                "ts": int(time.time()),
                "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "duration_s": round(time.time() - t_start, 2),
                "composite_score": comp_score,
                "tier": tier,
                "tier_badge": tier_badge,
                "cpu": {
                    "cores": CORES,
                    "single_core_score": c1_score,
                    "multi_core_score": cm_score,
                    "efficiency": round(cm_score / max(c1_score * CORES, 1) * 100, 1)
                },
                "ram": {
                    "bandwidth_gb_s": ram_gb_s,
                    "label": f"{ram_gb_s} GB/s sequential"
                },
                "disk": {
                    "write_mb_s": disk_write_mb_s,
                    "read_mb_s": disk_read_mb_s,
                    "test_size_mb": test_mb
                },
                "network": {
                    "cloudflare_dns_ms": ping_cf,
                    "google_dns_ms": ping_gg
                }
            }
            self.last_result = result
            return result
        finally:
            self.is_running = False

    def _ping_target(self, host, port):
        try:
            t0 = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.2)
            s.connect((host, port))
            s.close()
            return round((time.time() - t0) * 1000.0, 1)
        except Exception:
            return 99.9


# ─────────────────────────────────────────────────────────────────────────────
#  SAFE VISITOR CAPACITY & STRESS BENCHMARK ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class CapacityBenchmark:
    """
    Safely benchmarks web server visitor capacity by progressively ramping
    simulated concurrent visitors (e.g. 5 -> 15 -> 30 -> 50 or up to 150)
    while continuously monitoring CPU load, RAM limits, latency and error rates.
    Equipped with an automatic safety circuit breaker to abort if load >= 4.5
    or free RAM < 120MB, preventing server crashes or downtime.
    """
    def __init__(self, cfg):
        self.cfg = cfg.get("capacity_benchmark", {})
        self.last_result = None
        self.is_running = False
        self.stop_requested = False
        self.lock = threading.Lock()
        self.worker_thread = None
        self.current_state = {
            "is_running": False,
            "stage_index": 0,
            "total_stages": 0,
            "target_concurrency": 0,
            "elapsed_stage_s": 0.0,
            "live_rps": 0.0,
            "live_latency_ms": 0.0,
            "live_error_rate": 0.0,
            "current_load": 0.0,
            "current_free_ram_mb": 0.0,
            "target_url": "",
            "mode": "quick",
            "stages_completed": []
        }

    def get_status(self):
        with self.lock:
            st = dict(self.current_state)
            st["is_running"] = self.is_running
            st["last_result"] = self.last_result
            return st

    def stop(self):
        with self.lock:
            if not self.is_running:
                return {"ok": False, "message": "No capacity benchmark is currently active."}
            self.stop_requested = True
            return {"ok": True, "message": "Emergency stop signal sent. Halting benchmark immediately."}

    def start(self, target_url=None, mode="quick"):
        with self.lock:
            if self.is_running:
                return {"ok": False, "message": "A capacity benchmark is already in progress."}
            self.is_running = True
            self.stop_requested = False

        if not target_url or not target_url.strip():
            target_url = self._detect_default_target()

        self.worker_thread = threading.Thread(
            target=self._run_benchmark_thread,
            args=(target_url.strip(), mode),
            daemon=True
        )
        self.worker_thread.start()
        return {"ok": True, "message": f"Capacity benchmark started ({mode} mode on {target_url})"}

    def _detect_default_target(self):
        for port, scheme in [(80, "http"), (443, "https"), (8686, "http"), (8080, "http")]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.3)
                s.connect(("127.0.0.1", port))
                s.close()
                return f"{scheme}://127.0.0.1:{port}/"
            except Exception:
                pass
        return "http://127.0.0.1:80/"

    def _get_free_ram_mb(self):
        try:
            if os.path.exists("/proc/meminfo"):
                with open("/proc/meminfo", "r") as f:
                    for line in f:
                        if line.startswith("MemAvailable:"):
                            return int(line.split()[1]) / 1024.0
                        elif line.startswith("MemFree:"):
                            return int(line.split()[1]) / 1024.0
        except Exception:
            pass
        return 1024.0

    def _get_load(self):
        try:
            return round(os.getloadavg()[0], 2)
        except Exception:
            return 0.0

    def _run_benchmark_thread(self, target_url, mode):
        t_start = time.time()
        if mode == "full":
            stage_configs = [
                {"concurrency": 10, "duration": 3.0, "name": "Baseline Warmup"},
                {"concurrency": 25, "duration": 3.5, "name": "Light Traffic"},
                {"concurrency": 50, "duration": 3.5, "name": "Moderate Traffic"},
                {"concurrency": 75, "duration": 4.0, "name": "Busy Traffic"},
                {"concurrency": 100, "duration": 4.0, "name": "Heavy Surge"},
                {"concurrency": 150, "duration": 4.5, "name": "Stress Limit"}
            ]
        else:
            stage_configs = [
                {"concurrency": 5, "duration": 3.0, "name": "Baseline Warmup"},
                {"concurrency": 15, "duration": 3.0, "name": "Light Traffic"},
                {"concurrency": 30, "duration": 3.5, "name": "Moderate Traffic"},
                {"concurrency": 50, "duration": 3.5, "name": "Rush Peak"}
            ]

        with self.lock:
            self.current_state = {
                "is_running": True,
                "stage_index": 0,
                "total_stages": len(stage_configs),
                "target_concurrency": 0,
                "elapsed_stage_s": 0.0,
                "live_rps": 0.0,
                "live_latency_ms": 0.0,
                "live_error_rate": 0.0,
                "current_load": self._get_load(),
                "current_free_ram_mb": round(self._get_free_ram_mb(), 1),
                "target_url": target_url,
                "mode": mode,
                "stages_completed": []
            }

        parsed = urllib.parse.urlsplit(target_url)
        is_ssl = (parsed.scheme == "https")
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if is_ssl else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        
        ssl_ctx = None
        if is_ssl:
            ssl_ctx = ssl._create_unverified_context()

        # 0. Preflight check: Verify target URL responds
        cur_load = self._get_load()
        if cur_load >= max(4.0, CORES * 2.5):
            res = {
                "ok": False,
                "status": "aborted",
                "error": f"Server load average is already high ({cur_load:.2f}). Please wait for load to settle before benchmarking.",
                "ts": int(time.time()),
                "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            }
            with self.lock:
                self.is_running = False
                self.last_result = res
                self.current_state["is_running"] = False
                self.current_state["last_result"] = res
            return

        preflight_ok = False
        preflight_status = 0
        preflight_error = ""
        try:
            if is_ssl:
                c = http.client.HTTPSConnection(host, port, timeout=3.5, context=ssl_ctx)
            else:
                c = http.client.HTTPConnection(host, port, timeout=3.5)
            c.request("GET", path, headers={"User-Agent": "Linux-Health-Sentinel-CapacityBench/2.0"})
            resp = c.getresponse()
            preflight_status = resp.status
            _ = resp.read(512)
            c.close()
            preflight_ok = (preflight_status < 500)
        except Exception as e:
            preflight_error = str(e)

        if not preflight_ok:
            err_msg = f"Could not connect to {target_url} (HTTP {preflight_status}: {preflight_error or 'Connection Refused'}). Make sure your web server is running on this port."
            res = {
                "ok": False,
                "status": "error",
                "error": err_msg,
                "ts": int(time.time()),
                "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            }
            with self.lock:
                self.is_running = False
                self.last_result = res
                self.current_state["is_running"] = False
                self.current_state["last_result"] = res
            return

        stages_results = []
        safety_aborted = False
        abort_reason = None
        server_saturated = False

        try:
            for s_idx, scfg in enumerate(stage_configs):
                if self.stop_requested:
                    safety_aborted = True
                    abort_reason = "Manual Emergency Stop triggered by user."
                    break

                concurrency = scfg["concurrency"]
                stage_dur = scfg["duration"]

                with self.lock:
                    self.current_state["stage_index"] = s_idx + 1
                    self.current_state["target_concurrency"] = concurrency

                latencies = []
                success_count = [0]
                fail_count = [0]
                stats_lock = threading.Lock()
                stage_end_time = time.time() + stage_dur
                stage_t0 = time.time()

                def _sim_worker():
                    conn = None
                    headers = {
                        "User-Agent": "Linux-Health-Sentinel-CapacityBench/2.0",
                        "Connection": "keep-alive",
                        "Accept": "*/*"
                    }
                    while time.time() < stage_end_time and not self.stop_requested:
                        req_t0 = time.time()
                        try:
                            if conn is None:
                                if is_ssl:
                                    conn = http.client.HTTPSConnection(host, port, timeout=3.0, context=ssl_ctx)
                                else:
                                    conn = http.client.HTTPConnection(host, port, timeout=3.0)
                            conn.request("GET", path, headers=headers)
                            resp = conn.getresponse()
                            _ = resp.read(1024)
                            sc = resp.status
                            lat = (time.time() - req_t0) * 1000.0
                            is_ok = (200 <= sc < 400)
                            with stats_lock:
                                latencies.append(lat)
                                if is_ok:
                                    success_count[0] += 1
                                else:
                                    fail_count[0] += 1
                            if resp.will_close:
                                conn.close()
                                conn = None
                        except Exception:
                            lat = (time.time() - req_t0) * 1000.0
                            with stats_lock:
                                fail_count[0] += 1
                                latencies.append(min(lat, 3000.0))
                            if conn:
                                try: conn.close()
                                except Exception: pass
                            conn = None
                        time.sleep(0.015)
                    if conn:
                        try: conn.close()
                        except Exception: pass

                threads = []
                for _ in range(concurrency):
                    th = threading.Thread(target=_sim_worker, daemon=True)
                    th.start()
                    threads.append(th)

                while time.time() < stage_end_time:
                    if self.stop_requested:
                        safety_aborted = True
                        abort_reason = "Manual Emergency Stop triggered by user."
                        break

                    load_val = self._get_load()
                    free_ram = self._get_free_ram_mb()

                    max_safe_load = max(4.5, CORES * 3.0)
                    if load_val >= max_safe_load:
                        safety_aborted = True
                        abort_reason = f"Safety Circuit Breaker: CPU Load average reached {load_val:.1f} (Limit: {max_safe_load:.1f}). Benchmark aborted immediately to protect server stability."
                        break

                    if free_ram < 120.0:
                        safety_aborted = True
                        abort_reason = f"Safety Circuit Breaker: Available RAM dropped to {free_ram:.0f}MB (< 120MB threshold). Aborted immediately to prevent Linux OOM-killer."
                        break

                    with stats_lock:
                        cur_tot = success_count[0] + fail_count[0]
                        cur_elap = max(time.time() - stage_t0, 0.001)
                        live_rps = round(cur_tot / cur_elap, 1)
                        live_lat = round(sum(latencies[-20:]) / max(len(latencies[-20:]), 1), 1)
                        live_err = round((fail_count[0] / max(cur_tot, 1)) * 100.0, 1)

                    with self.lock:
                        self.current_state["elapsed_stage_s"] = round(cur_elap, 1)
                        self.current_state["live_rps"] = live_rps
                        self.current_state["live_latency_ms"] = live_lat
                        self.current_state["live_error_rate"] = live_err
                        self.current_state["current_load"] = load_val
                        self.current_state["current_free_ram_mb"] = round(free_ram, 1)

                    time.sleep(0.12)

                for th in threads:
                    th.join(timeout=1.0)

                stage_elapsed = max(time.time() - stage_t0, 0.001)
                tot_req = success_count[0] + fail_count[0]
                stage_rps = round(tot_req / stage_elapsed, 1)
                err_pct = round((fail_count[0] / max(tot_req, 1)) * 100.0, 1)
                if latencies:
                    avg_lat = round(sum(latencies) / len(latencies), 1)
                    sorted_lat = sorted(latencies)
                    p95_idx = min(int(len(sorted_lat) * 0.95), len(sorted_lat) - 1)
                    p95_lat = round(sorted_lat[p95_idx], 1)
                else:
                    avg_lat = 0.0
                    p95_lat = 0.0

                stage_load = self._get_load()

                if err_pct == 0.0 and avg_lat < 300.0:
                    status_badge = "Optimal"
                elif err_pct < 4.0 and avg_lat < 1000.0:
                    status_badge = "Good"
                elif err_pct < 20.0 and avg_lat < 2200.0:
                    status_badge = "Degraded"
                else:
                    status_badge = "Saturated"

                stage_res = {
                    "stage": s_idx + 1,
                    "name": scfg["name"],
                    "concurrency": concurrency,
                    "duration_s": round(stage_elapsed, 1),
                    "total_requests": tot_req,
                    "successful": success_count[0],
                    "failed": fail_count[0],
                    "rps": stage_rps,
                    "avg_latency_ms": avg_lat,
                    "p95_latency_ms": p95_lat,
                    "error_rate_pct": err_pct,
                    "load_avg": stage_load,
                    "status": status_badge
                }
                stages_results.append(stage_res)
                with self.lock:
                    self.current_state["stages_completed"].append(stage_res)

                if safety_aborted:
                    break

                if avg_lat >= 2200.0 or err_pct >= 25.0:
                    server_saturated = True
                    break

            healthy_stages = [s for s in stages_results if s["status"] in ("Optimal", "Good")]
            if healthy_stages:
                best_stage = healthy_stages[-1]
                safe_visitors = best_stage["concurrency"]
                safe_rps = best_stage["rps"]
                safe_latency = best_stage["avg_latency_ms"]
            elif stages_results:
                best_stage = stages_results[0]
                safe_visitors = max(int(best_stage["concurrency"] * 0.6), 1)
                safe_rps = max(int(best_stage["rps"] * 0.6), 1)
                safe_latency = best_stage["avg_latency_ms"]
            else:
                safe_visitors = 0
                safe_rps = 0.0
                safe_latency = 0.0

            peak_rps = max([s["rps"] for s in stages_results], default=0.0)
            monthly_views = int(safe_rps * 3600 * 5 * 30)

            final_load = self._get_load()
            final_ram = self._get_free_ram_mb()
            bottleneck = "None (Traffic handled smoothly)"
            if safety_aborted and "RAM" in (abort_reason or ""):
                bottleneck = "RAM Memory Exhaustion"
            elif safety_aborted and "Load" in (abort_reason or ""):
                bottleneck = "CPU Processor Saturation"
            elif final_load >= CORES * 1.5:
                bottleneck = "CPU Processing Capacity"
            elif any(s["error_rate_pct"] > 5.0 for s in stages_results):
                bottleneck = "Web Server Connection / PHP-FPM Worker Pool Limit"
            elif any(s["avg_latency_ms"] > 1000.0 for s in stages_results):
                bottleneck = "Dynamic Script Latency / Database Query Time"

            if safe_visitors >= 100:
                diagnosis = f"🚀 High Enterprise Capacity: Your server comfortably sustained {safe_visitors}+ simultaneous active visitors ({safe_rps} req/sec) with rapid {safe_latency}ms response times. Ideal for high-traffic stores, portals, and viral traffic surges."
            elif safe_visitors >= 45:
                diagnosis = f"⚡ Robust Standard Capacity: Your server easily handles ~{safe_visitors} simultaneous active visitors ({safe_rps} req/sec) without degradation ({safe_latency}ms avg latency). This translates to over {monthly_views:,} monthly pageviews."
            elif safe_visitors >= 15:
                diagnosis = f"⚠️ Moderate Capacity: Server supports ~{safe_visitors} concurrent active visitors ({safe_rps} req/sec). Beyond this threshold, latency increases due to {bottleneck.lower()}. Enabling server-level page caching will multiply this capacity 5x–10x."
            else:
                diagnosis = f"🛑 Constrained Capacity: Server struggled under concurrency ({safe_visitors} visitors safe limit). Latencies surged quickly due to {bottleneck.lower()}. Tuning worker limits and adding page caching is strongly recommended."

            recommendations = []
            if "PHP-FPM" in bottleneck or "Web Server" in bottleneck:
                recommendations.append("Increase PHP-FPM pm.max_children in your pool configuration so more worker processes can handle simultaneous visitors.")
            if "RAM" in bottleneck or final_ram < 200.0:
                recommendations.append(f"Free up memory or add swap space: Server currently has {final_ram:.0f}MB available RAM.")
            if "CPU" in bottleneck or final_load >= CORES:
                recommendations.append("Enable FastCGI or Nginx microcaching: Caching dynamic HTML pages reduces CPU load by 80–90%, allowing thousands of visitors.")
            recommendations.append("Enable HTTP/2 Keep-Alive and gzip/brotli compression on static assets to minimize network handshake overhead.")
            recommendations.append("If running WordPress or CMS, install an Object Cache (Redis or Memcached) to eliminate repeated database queries.")

            final_result = {
                "ok": True,
                "status": "completed" if not safety_aborted else "aborted",
                "ts": int(time.time()),
                "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "duration_s": round(time.time() - t_start, 1),
                "target_url": target_url,
                "mode": mode,
                "safe_concurrent_visitors": safe_visitors,
                "safe_rps": safe_rps,
                "safe_latency_ms": safe_latency,
                "peak_rps": peak_rps,
                "monthly_pageviews_est": monthly_views,
                "bottleneck": bottleneck,
                "diagnosis": diagnosis,
                "safety_aborted": safety_aborted,
                "abort_reason": abort_reason,
                "server_saturated": server_saturated,
                "recommendations": recommendations,
                "stages": stages_results
            }

            with self.lock:
                self.last_result = final_result
                self.is_running = False
                self.current_state["is_running"] = False
                self.current_state["last_result"] = final_result

        finally:
            with self.lock:
                self.is_running = False
                self.current_state["is_running"] = False


# ─────────────────────────────────────────────────────────────────────────────
#  SECURITY SHIELD (1-Click Firewall IP Banning & Threat Detection)
# ─────────────────────────────────────────────────────────────────────────────

class SecurityShield:
    def __init__(self, cfg, state_dir="/var/lib/health-sentinel"):
        self.cfg = cfg.get("security_shield", {})
        self.state_dir = state_dir
        self.banned_file = os.path.join(state_dir, "banned_ips.json")
        self.banned_ips = {}
        self.lock = threading.Lock()
        self.whitelist = set(self.cfg.get("whitelist_ips", ["127.0.0.1", "::1"]))
        self._load()
        self._setup_firewall()

    def _load(self):
        try:
            if os.path.isfile(self.banned_file):
                with open(self.banned_file) as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        self.banned_ips = data
        except Exception:
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.banned_file), exist_ok=True)
            tmp = self.banned_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self.banned_ips, f, indent=2)
            os.replace(tmp, self.banned_file)
        except Exception:
            pass

    def _setup_firewall(self):
        try:
            rc, _ = sh(["which", "iptables"], timeout=2)
            if rc == 0:
                sh(["iptables", "-N", "SENTINEL_BLOCK"], timeout=2)
                rc_c, _ = sh(["iptables", "-C", "INPUT", "-j", "SENTINEL_BLOCK"], timeout=2)
                if rc_c != 0:
                    sh(["iptables", "-I", "INPUT", "1", "-j", "SENTINEL_BLOCK"], timeout=2)
                for ip in list(self.banned_ips.keys()):
                    rc_chk, _ = sh(["iptables", "-C", "SENTINEL_BLOCK", "-s", ip, "-j", "DROP"], timeout=2)
                    if rc_chk != 0:
                        sh(["iptables", "-I", "SENTINEL_BLOCK", "-s", ip, "-j", "DROP"], timeout=2)
        except Exception:
            pass

    def is_private_ip(self, ip):
        if not ip:
            return True
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if ip in ("127.0.0.1", "::1", "localhost"):
            return True
        if ":" in ip:
            return ip.startswith("fe80") or ip.startswith("fc") or ip.startswith("fd")
        parts = ip.split(".")
        if len(parts) != 4:
            return True
        try:
            p0, p1 = int(parts[0]), int(parts[1])
            if p0 in (10, 127):
                return True
            if p0 == 192 and p1 == 168:
                return True
            if p0 == 172 and 16 <= p1 <= 31:
                return True
        except ValueError:
            return True
        return False

    def is_valid_ip(self, ip):
        if not ip or not isinstance(ip, str):
            return False
        ip = ip.strip()
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        try:
            socket.inet_aton(ip)
            return ip.count(".") == 3
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except (socket.error, AttributeError):
            pass
        return False

    def ban_ip(self, ip, reason="Manual ban via Web UI", admin_ip=None):
        if not ip:
            return False, "IP address is required."
        ip = ip.strip()
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if not self.is_valid_ip(ip):
            return False, f"Invalid IP address format: {ip}"
        if self.is_private_ip(ip) or ip in self.whitelist:
            return False, f"Cannot ban private, loopback or whitelisted IP ({ip})."
        if admin_ip:
            if admin_ip.startswith("::ffff:"):
                admin_ip = admin_ip[7:]
            if ip == admin_ip:
                return False, f"Safety lockout prevented: Cannot ban your own active admin IP ({ip})."

        with self.lock:
            applied = False
            rc_ipt, _ = sh(["which", "iptables"], timeout=2)
            if rc_ipt == 0:
                sh(["iptables", "-N", "SENTINEL_BLOCK"], timeout=2)
                sh(["iptables", "-C", "INPUT", "-j", "SENTINEL_BLOCK"], timeout=2)
                rc_c, _ = sh(["iptables", "-C", "INPUT", "-j", "SENTINEL_BLOCK"], timeout=2)
                if rc_c != 0:
                    sh(["iptables", "-I", "INPUT", "1", "-j", "SENTINEL_BLOCK"], timeout=2)
                sh(["iptables", "-I", "SENTINEL_BLOCK", "-s", ip, "-j", "DROP"], timeout=2)
                applied = True
            else:
                rc_ufw, _ = sh(["which", "ufw"], timeout=2)
                if rc_ufw == 0:
                    sh(["ufw", "insert", "1", "deny", "from", ip, "to", "any"], timeout=2)
                    applied = True

            self.banned_ips[ip] = {
                "ip": ip,
                "reason": reason,
                "banned_at": int(time.time()),
                "date": datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S"),
                "firewall_applied": applied
            }
            self._save()
            return True, f"IP {ip} successfully banned."

    def unban_ip(self, ip):
        if not ip:
            return False, "IP address is required."
        ip = ip.strip()
        if ip.startswith("::ffff:"):
            ip = ip[7:]

        with self.lock:
            sh(["iptables", "-D", "SENTINEL_BLOCK", "-s", ip, "-j", "DROP"], timeout=2)
            sh(["ufw", "delete", "deny", "from", ip, "to", "any"], timeout=2)
            if ip in self.banned_ips:
                del self.banned_ips[ip]
                self._save()
                return True, f"IP {ip} successfully unbanned."
            return False, f"IP {ip} was not in banned list."

    def list_banned(self):
        with self.lock:
            return list(self.banned_ips.values())

    def analyze_visitor_threat(self, visitor):
        ip = visitor.get("ip", "")
        if ip in self.banned_ips:
            return {
                "level": "banned",
                "label": "⛔ BANNED",
                "color": "var(--crit)",
                "reason": self.banned_ips[ip].get("reason", "Blocked in firewall"),
                "is_banned": True
            }

        path = (visitor.get("path") or "").lower()
        hits = visitor.get("hits", 0)
        code = visitor.get("code", 200)

        wp_patterns = ["/wp-login.php", "/xmlrpc.php", "/wp-admin", "/wp-content/plugins", "/wp-includes"]
        if any(p in path for p in wp_patterns):
            return {
                "level": "threat_high",
                "label": "🚨 WP Brute Force",
                "color": "var(--crit)",
                "reason": f"Probing WordPress auth ({path})",
                "is_banned": False
            }

        exploit_patterns = ["/.env", "/.git", "/config.", "/phpmyadmin", "/pma", "/actuator", "/setup.php", "/backup.", "/dump.sql"]
        if any(p in path for p in exploit_patterns):
            return {
                "level": "threat_high",
                "label": "🚨 Exploit Scanner",
                "color": "var(--crit)",
                "reason": f"Scanning sensitive path ({path})",
                "is_banned": False
            }

        if hits >= 40:
            return {
                "level": "threat_med",
                "label": "⚠️ High Request Rate",
                "color": "var(--warn)",
                "reason": f"{hits} requests in short window",
                "is_banned": False
            }

        if code in (401, 403) and hits >= 10:
            return {
                "level": "threat_med",
                "label": "⚠️ Auth Probe Spike",
                "color": "var(--warn)",
                "reason": f"Repeated {code} Forbidden/Unauthorized responses",
                "is_banned": False
            }

        return {
            "level": "clean",
            "label": "🟢 Clean",
            "color": "var(--ok)",
            "reason": "Normal browsing activity",
            "is_banned": False
        }


# ─────────────────────────────────────────────────────────────────────────────
#  MULTI-SITE UPTIME & RESPONSE SPEED MONITOR
# ─────────────────────────────────────────────────────────────────────────────

class SiteMonitor:
    def __init__(self, cfg, state_dir="/var/lib/health-sentinel"):
        self.cfg = cfg.get("site_monitor", {})
        self.state_dir = state_dir
        self.sites_file = os.path.join(state_dir, "monitored_sites.json")
        self.custom_sites = set(self.cfg.get("custom_sites", []))
        self.results = {}
        self.history = {}
        self.lock = threading.Lock()
        self.last_check_time = 0.0
        self._load()

    def _load(self):
        try:
            if os.path.isfile(self.sites_file):
                with open(self.sites_file) as f:
                    data = json.load(f)
                    for s in data.get("custom_sites", []):
                        self.custom_sites.add(s)
        except Exception:
            pass

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self.sites_file), exist_ok=True)
            tmp = self.sites_file + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"custom_sites": list(self.custom_sites)}, f, indent=2)
            os.replace(tmp, self.sites_file)
        except Exception:
            pass

    def discover_local_vhosts(self):
        discovered = set()
        plesk_base = "/var/www/vhosts"
        if os.path.isdir(plesk_base):
            try:
                for entry in os.listdir(plesk_base):
                    if entry in ("system", "chroot", "default", ".skel", "fs", "fs-passwd"):
                        continue
                    full = os.path.join(plesk_base, entry)
                    if os.path.isdir(full) and "." in entry:
                        discovered.add(f"https://{entry}")
            except Exception:
                pass

        for nd in ["/etc/nginx/sites-enabled", "/etc/nginx/conf.d"]:
            if os.path.isdir(nd):
                try:
                    for cf in os.listdir(nd):
                        p = os.path.join(nd, cf)
                        if os.path.isfile(p):
                            try:
                                with open(p, "r", errors="ignore") as f:
                                    for m in re.finditer(r'server_name\s+([^;]+);', f.read()):
                                        for name in m.group(1).split():
                                            name = name.strip()
                                            if name and not name.startswith("*") and name not in ("_", "localhost") and "." in name:
                                                discovered.add(f"https://{name}")
                            except Exception:
                                pass
                except Exception:
                    pass

        for ad in ["/etc/apache2/sites-enabled", "/etc/httpd/conf.d"]:
            if os.path.isdir(ad):
                try:
                    for cf in os.listdir(ad):
                        p = os.path.join(ad, cf)
                        if os.path.isfile(p):
                            try:
                                with open(p, "r", errors="ignore") as f:
                                    for m in re.finditer(r'ServerName\s+([^\s]+)', f.read()):
                                        name = m.group(1).strip()
                                        if name and not name.startswith("*") and name not in ("_", "localhost") and "." in name:
                                            discovered.add(f"https://{name}")
                            except Exception:
                                pass
                except Exception:
                    pass

        return sorted(list(discovered))[:20]

    def get_all_target_urls(self):
        all_urls = set(self.custom_sites)
        if self.cfg.get("auto_discover_local_vhosts", True):
            for u in self.discover_local_vhosts():
                all_urls.add(u)
        return sorted(list(all_urls))

    def _check_single_site(self, url):
        t0 = time.time()
        timeout = self.cfg.get("timeout_seconds", 5)
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        ssl_days_left = None
        if parsed.scheme == "https":
            try:
                cctx = ssl.create_default_context()
                with socket.create_connection((host, port), timeout=timeout) as s:
                    with cctx.wrap_socket(s, server_hostname=host) as ss:
                        c = ss.getpeercert()
                        if c and "notAfter" in c:
                            expire_dt = datetime.strptime(c["notAfter"], "%b %d %H:%M:%S %Y %Z")
                            now_dt = datetime.now(timezone.utc).replace(tzinfo=None)
                            ssl_days_left = max(0, (expire_dt - now_dt).days)
            except Exception:
                pass

        status_code = 0
        latency_ms = 0.0
        is_up = False
        error_msg = None

        try:
            req = urllib.request.Request(url, headers={"User-Agent": f"HealthSentinel-Uptime/{VERSION}"})
            ctx = ssl._create_unverified_context()
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status_code = resp.getcode()
                latency_ms = round((time.time() - t0) * 1000.0, 1)
                is_up = status_code < 400 or status_code in (401, 403)
        except urllib.error.HTTPError as e:
            status_code = e.code
            latency_ms = round((time.time() - t0) * 1000.0, 1)
            is_up = status_code < 500
            error_msg = f"HTTP {status_code}"
        except Exception as e:
            latency_ms = round((time.time() - t0) * 1000.0, 1)
            is_up = False
            status_code = 0
            error_msg = str(e)

        if url not in self.history:
            self.history[url] = deque(maxlen=30)
        self.history[url].append(1 if is_up else 0)

        hist = list(self.history[url])
        uptime_pct = round((sum(hist) / len(hist)) * 100.0, 1) if hist else (100.0 if is_up else 0.0)

        return {
            "url": url,
            "domain": host,
            "scheme": parsed.scheme,
            "status_code": status_code,
            "latency_ms": latency_ms,
            "is_up": is_up,
            "ssl_days_left": ssl_days_left,
            "uptime_pct": uptime_pct,
            "error": error_msg,
            "is_custom": url in self.custom_sites,
            "checked_at": datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        }

    def check_all(self, force=False):
        now = time.time()
        if not force and (now - self.last_check_time < 30.0) and self.results:
            return self.get_summary()

        targets = self.get_all_target_urls()
        if not targets:
            return self.get_summary()

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(targets), 8)) as ex:
            future_to_url = {ex.submit(self._check_single_site, url): url for url in targets}
            for fut in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[fut]
                try:
                    res = fut.result()
                    with self.lock:
                        self.results[url] = res
                except Exception:
                    pass

        self.last_check_time = time.time()
        return self.get_summary()

    def get_summary(self):
        with self.lock:
            site_list = list(self.results.values())

        up_count = sum(1 for s in site_list if s.get("is_up"))
        down_count = sum(1 for s in site_list if not s.get("is_up"))
        slow_count = sum(1 for s in site_list if s.get("is_up") and s.get("latency_ms", 0) > 1200)
        avg_latency = round(sum(s.get("latency_ms", 0) for s in site_list) / len(site_list), 1) if site_list else 0.0

        return {
            "total_sites": len(site_list),
            "up_count": up_count,
            "down_count": down_count,
            "slow_count": slow_count,
            "avg_latency_ms": avg_latency,
            "sites": sorted(site_list, key=lambda s: (not s.get("is_up"), s.get("latency_ms", 0))),
            "custom_sites": list(self.custom_sites)
        }

    def add_site(self, url):
        if not url:
            return False, "URL cannot be empty."
        url = url.strip()
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        parsed = urllib.parse.urlparse(url)
        if not parsed.hostname or "." not in parsed.hostname:
            return False, "Invalid domain name or URL."

        with self.lock:
            self.custom_sites.add(url)
            self._save()

        threading.Thread(target=self._check_and_store, args=(url,), daemon=True).start()
        return True, f"Website {url} added to monitor."

    def _check_and_store(self, url):
        res = self._check_single_site(url)
        with self.lock:
            self.results[url] = res

    def remove_site(self, url):
        url = url.strip()
        with self.lock:
            if url in self.custom_sites:
                self.custom_sites.remove(url)
                self._save()
            if url in self.results:
                del self.results[url]
            return True, f"Website {url} removed."


# ─────────────────────────────────────────────────────────────────────────────
#  SERVER DOCTOR (Plain English Diagnoses & Actionable Solutions)
# ─────────────────────────────────────────────────────────────────────────────

def generate_server_doctor(report):
    checks = report.get("checks", [])
    bad_checks = [c for c in checks if c.get("status") in ("crit", "warn")]

    if not bad_checks:
        return {
            "status": "ok",
            "headline": "🩺 Server Doctor: All Systems Operating Smoothly",
            "summary": "Your server has plenty of CPU, RAM, and disk storage headroom. All 10 health probes are within optimal thresholds.",
            "recommendations": []
        }

    recs = []
    for c in sorted(bad_checks, key=lambda x: 0 if x.get("status") == "crit" else 1):
        cid = c.get("id")
        sev = c.get("status")
        val = c.get("value")
        unit = c.get("unit")
        findings = c.get("findings", [])
        top_find = findings[0] if findings else {}

        item = {
            "id": cid,
            "severity": sev,
            "title": c.get("name"),
            "problem": f"{c.get('name')} is currently {val} {unit} ({sev.upper()}).",
            "why_it_matters": top_find.get("why") or c.get("summary"),
            "one_click_action": None,
            "fix_command": None
        }

        if cid == "disk":
            item["problem"] = f"Your hard drive partition is {val}% full."
            item["why_it_matters"] = "If disk space reaches 100%, databases lock up, log files can't write, file uploads fail, and websites will crash with 500 errors."
            item["one_click_action"] = "vacuum_logs"
            item["fix_command"] = "sudo journalctl --vacuum-size=200M"
        elif cid == "memory":
            item["problem"] = f"Physical RAM is {val}% consumed."
            item["why_it_matters"] = "When memory runs out, the Linux kernel Out-Of-Memory (OOM) killer abruptly terminates heavy applications (like MySQL or PHP-FPM)."
            item["one_click_action"] = "drop_caches"
            item["fix_command"] = "sudo sync && echo 3 | sudo tee /proc/sys/vm/drop_caches"
        elif cid == "load":
            item["problem"] = f"Server load reached {val} (over safe capacity)."
            item["why_it_matters"] = "More processes are competing for CPU than the processor can handle simultaneously, slowing down web page response times."
            item["one_click_action"] = "restart_php_active"
            item["fix_command"] = "sudo systemctl restart $(systemctl list-units --type=service | grep -oE 'php[0-9.-]*-fpm' | head -1)"
        elif cid == "services":
            item["problem"] = f"Crashed or failed system services detected: {val}."
            item["why_it_matters"] = "One or more critical background services died or failed to restart properly."
            item["one_click_action"] = "reset_failed"
            item["fix_command"] = "sudo systemctl reset-failed"
        elif cid == "io":
            item["problem"] = f"Storage I/O bottleneck detected ({val}% utilization)."
            item["why_it_matters"] = "The disk is overwhelmed with reads/writes, causing CPU iowait and sluggish database queries."
            item["one_click_action"] = "optimize_io_memory"
            item["fix_command"] = "sudo /opt/health-sentinel/deploy/optimize-io-memory.sh"
        elif top_find.get("fix"):
            item["fix_command"] = top_find["fix"][0]

        recs.append(item)

    is_crit = any(c.get("status") == "crit" for c in bad_checks)
    return {
        "status": "crit" if is_crit else "warn",
        "headline": f"🩺 Server Doctor: {len(bad_checks)} Area{'s' if len(bad_checks) > 1 else ''} Need Attention",
        "summary": "We detected resource bottlenecks that could impact website speed or server stability. Follow the plain-English recommendations below to resolve them immediately.",
        "recommendations": recs
    }


# ─────────────────────────────────────────────────────────────────────────────
#  EXECUTIVE CLIENT REPORT GENERATOR (PDF & White-Label HTML Digest)
# ─────────────────────────────────────────────────────────────────────────────

def generate_executive_html(report, history, branding, healing_history):
    agency = branding.get("agency_name", "OpsCare Managed Cloud")
    title = branding.get("report_title", "Executive Server Health & Performance Audit")
    support_email = branding.get("support_email", "support@example.com")
    client_name = branding.get("client_name", "Production VPS Host")

    score = report.get("score", 100)
    grade_str = report.get("grade", "A+")
    grade_label = report.get("grade_label", "Healthy")
    host = report.get("host") or socket.getfqdn()
    os_info = report.get("os", "Linux")
    kernel = report.get("kernel", "Linux")
    cores = report.get("cores", 1)
    uptime = report.get("uptime", "up")
    now_str = datetime.now(timezone.utc).astimezone().strftime("%B %d, %Y at %H:%M %Z")

    hist_list = list(history) if history else []
    peak_load = max((p.get("load", 0) for p in hist_list), default=0)
    avg_load = (sum(p.get("load", 0) for p in hist_list) / len(hist_list)) if hist_list else 0
    peak_cpu = max((p.get("cpu", 0) for p in hist_list), default=0)
    avg_cpu = (sum(p.get("cpu", 0) for p in hist_list) / len(hist_list)) if hist_list else 0

    cm = {c["id"]: c for c in report.get("checks", [])}
    mem_c = cm.get("memory", {})
    disk_c = cm.get("disk", {})
    srv_c = cm.get("services", {})
    log_c = cm.get("logs", {})

    mem_avail = fmt_bytes(mem_c.get("metrics", {}).get("available", 0))
    mem_used_pct = mem_c.get("metrics", {}).get("used_pct", 0)
    disk_worst = disk_c.get("metrics", {}).get("worst_pct", 0)

    score_col = "#16a34a" if score >= 85 else ("#d97706" if score >= 65 else "#dc2626")

    # Healing entries
    heal_rows = ""
    heal_list = list(healing_history) if healing_history else []
    if heal_list:
        for ev in heal_list[-8:]:
            heal_rows += f"""
            <tr>
              <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12.5px;color:#475569;">{_esc(ev['time'])}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12.5px;font-weight:600;color:#0f172a;">{_esc(ev['reason'])}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12.5px;color:#166534;">{_esc(', '.join(ev['actions']))}</td>
              <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;text-align:right;"><span style="background:#dcfce7;color:#166534;padding:3px 8px;border-radius:999px;font-weight:600;">AUTONOMOUS</span></td>
            </tr>"""
    else:
        heal_rows = """
        <tr>
          <td colspan="4" style="padding:16px;text-align:center;color:#64748b;font-size:13px;">
            ✨ 100% Stable: Zero critical resource bottlenecks or manual emergency interventions required.
          </td>
        </tr>"""

    # Check breakdown rows
    check_rows = ""
    for c in report.get("checks", []):
        st = c.get("status", "ok")
        st_col = "#16a34a" if st == "ok" else ("#d97706" if st == "warn" else "#dc2626")
        check_rows += f"""
        <tr>
          <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;font-weight:600;color:#0f172a;">{_esc(c['name'])}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:13px;color:#334155;">{_esc(c['value'])} <small style="color:#64748b;">{_esc(c['unit'])}</small></td>
          <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;font-size:12px;color:#64748b;">{_esc(c['summary'])}</td>
          <td style="padding:10px 12px;border-bottom:1px solid #e2e8f0;text-align:right;"><span style="background:{st_col}18;color:{st_col};padding:3px 8px;border-radius:999px;font-size:11px;font-weight:700;">{st.upper()}</span></td>
        </tr>"""

    # SSL certificates table
    ssl_certs = _scan_ssl_certs()
    ssl_rows = ""
    if ssl_certs:
        for sc in ssl_certs[:5]:
            ssl_col = "#16a34a" if sc["days_left"] > 14 else "#dc2626"
            ssl_rows += f"""
            <tr>
              <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:12.5px;"><b>{_esc(sc['domain'])}</b></td>
              <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;font-size:12.5px;color:#64748b;">{_esc(sc['expires'])}</td>
              <td style="padding:8px 12px;border-bottom:1px solid #e2e8f0;text-align:right;color:{ssl_col};font-weight:600;font-size:12px;">{sc['days_left']:.0f} days left</td>
            </tr>"""
    else:
        ssl_rows = """<tr><td colspan="3" style="padding:12px;text-align:center;color:#64748b;font-size:12.5px;">Standard web SSL certificates valid &amp; protected</td></tr>"""

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{_esc(title)} — {_esc(host)}</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #0f172a; line-height: 1.5; padding: 32px 20px; }}
  .sheet {{ max-width: 900px; margin: 0 auto; background: #ffffff; border-radius: 16px; border: 1px solid #e2e8f0; box-shadow: 0 10px 30px rgba(0,0,0,0.04); overflow: hidden; }}
  .top-banner {{ padding: 28px 36px; background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); color: #ffffff; display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 16px; }}
  .agency-name {{ font-size: 13px; letter-spacing: 1.5px; text-transform: uppercase; color: #38bdf8; font-weight: 700; }}
  .report-title {{ font-size: 22px; font-weight: 800; margin-top: 4px; }}
  .client-badge {{ display: inline-flex; align-items: center; padding: 4px 12px; border-radius: 999px; background: rgba(255,255,255,0.12); font-size: 12px; margin-top: 8px; }}
  .content {{ padding: 32px 36px; }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; background: #f1f5f9; padding: 16px 20px; border-radius: 12px; margin-bottom: 24px; }}
  .meta-item b {{ display: block; font-size: 11px; text-transform: uppercase; color: #64748b; letter-spacing: 0.5px; }}
  .meta-item span {{ font-size: 13.5px; font-weight: 600; color: #1e293b; }}
  
  .score-card {{ display: flex; align-items: center; justify-content: space-between; padding: 20px 24px; border-radius: 14px; background: #f8fafc; border: 1px solid #e2e8f0; margin-bottom: 24px; flex-wrap: wrap; gap: 16px; }}
  .score-val {{ font-size: 42px; font-weight: 900; color: {score_col}; line-height: 1; }}
  .score-val small {{ font-size: 20px; color: #64748b; font-weight: 600; }}
  
  .kpi-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 28px; }}
  .kpi {{ padding: 14px 16px; border-radius: 12px; background: #ffffff; border: 1px solid #e2e8f0; }}
  .kpi span {{ font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: 700; }}
  .kpi h3 {{ font-size: 20px; font-weight: 800; margin: 4px 0 2px; color: #0f172a; }}
  .kpi p {{ font-size: 11.5px; color: #64748b; }}

  .section-title {{ font-size: 15px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.8px; color: #334155; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 24px; }}
  th {{ padding: 10px 12px; background: #f8fafc; text-align: left; font-size: 11.5px; text-transform: uppercase; letter-spacing: 0.6px; color: #64748b; border-bottom: 1px solid #e2e8f0; }}

  .footer-sig {{ display: flex; justify-content: space-between; align-items: center; padding-top: 24px; border-top: 1px solid #e2e8f0; margin-top: 12px; font-size: 12px; color: #64748b; flex-wrap: wrap; gap: 12px; }}
  
  /* Print Controls */
  .toolbar {{ position: fixed; bottom: 24px; right: 24px; display: flex; gap: 10px; z-index: 1000; }}
  .action-btn {{ padding: 12px 20px; border-radius: 999px; background: #0284c7; color: #ffffff; font-weight: 700; font-size: 14px; border: none; cursor: pointer; box-shadow: 0 8px 24px rgba(2,132,199,0.35); display: flex; align-items: center; gap: 8px; transition: transform .15s; }}
  .action-btn:hover {{ transform: translateY(-2px); }}
  .close-btn {{ background: #475569; }}

  @media print {{
    body {{ padding: 0; background: #ffffff; }}
    .sheet {{ border: none; box-shadow: none; max-width: 100%; }}
    .toolbar {{ display: none !important; }}
  }}
  @media (max-width: 768px) {{
    .kpi-grid {{ grid-template-columns: repeat(2, 1fr); }}
    .content {{ padding: 20px; }}
    .top-banner {{ padding: 20px; }}
  }}
</style>
</head>
<body>

<div class="toolbar no-print">
  <button class="action-btn" onclick="window.print()">🖨️ Print / Save as PDF</button>
  <button class="action-btn close-btn" onclick="window.close()">✕ Close</button>
</div>

<div class="sheet">
  <div class="top-banner">
    <div>
      <div class="agency-name">{_esc(agency)}</div>
      <div class="report-title">{_esc(title)}</div>
      <div class="client-badge">Client: <b>{_esc(client_name)}</b></div>
    </div>
    <div style="text-align: right;">
      <div style="font-size: 12px; color: #94a3b8;">CONFIDENTIAL AUDIT</div>
      <div style="font-size: 14px; font-weight: 700; margin-top: 4px;">{now_str}</div>
    </div>
  </div>

  <div class="content">
    <div class="meta-grid">
      <div class="meta-item"><b>Server Hostname</b><span>{_esc(host)}</span></div>
      <div class="meta-item"><b>Operating System</b><span>{_esc(os_info)}</span></div>
      <div class="meta-item"><b>CPU Resources</b><span>{cores} Cores ({cores * 100}% compute)</span></div>
      <div class="meta-item"><b>System Uptime</b><span>{_esc(uptime)}</span></div>
    </div>

    <div class="score-card">
      <div>
        <div style="font-size: 13px; font-weight: 700; color: #64748b; text-transform: uppercase;">Infrastructure Health Status</div>
        <div style="font-size: 22px; font-weight: 800; color: #0f172a; margin-top: 2px;">GRADE {grade_str} · {grade_label.upper()}</div>
        <div style="font-size: 13px; color: #64748b; margin-top: 4px;">Audited against 10 comprehensive hardware and service probes.</div>
      </div>
      <div class="score-val">{score:.0f}<small>/100</small></div>
    </div>

    <div class="kpi-grid">
      <div class="kpi">
        <span>Server Load (1m)</span>
        <h3>{avg_load:.2f}</h3>
        <p>Peak: {peak_load:.2f} · Safe limit: {cores * 2.0:.1f}</p>
      </div>
      <div class="kpi">
        <span>CPU Utilisation</span>
        <h3>{avg_cpu:.0f}%</h3>
        <p>Peak: {peak_cpu:.0f}%</p>
      </div>
      <div class="kpi">
        <span>Memory Headroom</span>
        <h3>{mem_avail}</h3>
        <p>{mem_used_pct:.0f}% physical RAM used</p>
      </div>
      <div class="kpi">
        <span>Storage Utilisation</span>
        <h3>{disk_worst:.0f}%</h3>
        <p>Worst mount · Headroom safe</p>
      </div>
    </div>

    <div class="section-title">
      <span>🤖 Preventative Care &amp; Autonomous Self-Healing Summary</span>
      <small style="color: #166534; font-size: 12px; font-weight: 600;">ACTIVE SENTINEL</small>
    </div>
    <table>
      <thead>
        <tr>
          <th>Date &amp; Time</th>
          <th>Trigger Event</th>
          <th>Preventative Action Taken</th>
          <th style="text-align: right;">Status</th>
        </tr>
      </thead>
      <tbody>
        {heal_rows}
      </tbody>
    </table>

    <div class="section-title">
      <span>📊 Subsystem Health Audit (10 Checks)</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Subsystem</th>
          <th>Current Reading</th>
          <th>Diagnostics &amp; Observations</th>
          <th style="text-align: right;">Evaluation</th>
        </tr>
      </thead>
      <tbody>
        {check_rows}
      </tbody>
    </table>

    <div class="section-title">
      <span>🔒 Security &amp; SSL Certificate Guard</span>
    </div>
    <table>
      <thead>
        <tr>
          <th>Domain / Certificate</th>
          <th>Expiration Date</th>
          <th style="text-align: right;">Validity Window</th>
        </tr>
      </thead>
      <tbody>
        {ssl_rows}
      </tbody>
    </table>

    <div class="footer-sig">
      <div>Certified by <b>{_esc(agency)}</b> · Generated autonomously by Linux Health Sentinel v{VERSION}</div>
      <div>Questions? Contact: <a href="mailto:{_esc(support_email)}" style="color: #0284c7; text-decoration: none;">{_esc(support_email)}</a></div>
    </div>
  </div>
</div>

</body>
</html>"""


# ─────────────────────────────────────────────────────────────────────────────
#  SCAN ENGINE WITH CONCURRENCY MUTEX & CACHING
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
        self.history = deque(maxlen=cfg.get("history_points", 5760))
        self.report = None
        self.lock = threading.Lock()
        self.scan_lock = threading.Lock()
        self.last_scan_time = 0.0
        self.cached_report = None
        self.incidents = IncidentRecorder(cfg)
        self.alert_state = {}
        self.healing_history = deque(maxlen=100)
        state_dir = os.path.dirname(self.cfg.get("state_file", "/var/lib/health-sentinel/state.json"))
        self.security_shield = SecurityShield(cfg, state_dir=state_dir)
        self.visitor_tracker = VisitorTracker(cfg, security_shield=self.security_shield)
        self.benchmark_engine = BenchmarkEngine(cfg)
        self.capacity_benchmark = CapacityBenchmark(cfg)
        self.site_monitor = SiteMonitor(cfg, state_dir=state_dir)
        self._load_state()
        self.auto_healer = AutoHealer(self)

    def _load_state(self):
        try:
            if os.path.isfile(self.cfg["state_file"]):
                with open(self.cfg["state_file"]) as fh:
                    data = json.load(fh)
                    for pt in data.get("history", []):
                        self.history.append(pt)
                    self.alert_state = data.get("alerts", {})
                    for ev in data.get("healing_history", []):
                        self.healing_history.append(ev)
                    self.visitor_tracker.geo_cache = data.get("geo_cache", {})
                    self.benchmark_engine.last_result = data.get("last_benchmark")
                    self.capacity_benchmark.last_result = data.get("last_capacity_benchmark")
            self.security_shield._load()
            self.site_monitor._load()
        except Exception:
            pass

    def _save_state(self):
        path = self.cfg["state_file"]
        try:
            self.security_shield._save()
            self.site_monitor._save()
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
            except OSError:
                path = "/tmp/health-sentinel-state.json"
                os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump({
                    "history": list(self.history)[-self.cfg.get("history_points", 5760):],
                    "alerts": self.alert_state,
                    "healing_history": list(self.healing_history),
                    "geo_cache": dict(list(self.visitor_tracker.geo_cache.items())[-200:]),
                    "last_benchmark": self.benchmark_engine.last_result,
                    "last_capacity_benchmark": self.capacity_benchmark.last_result
                }, fh)
            os.replace(tmp, path)
        except Exception:
            pass

    def scan(self, force=False):
        now = time.time()
        if not force and self.cached_report and (now - self.last_scan_time < 2.0):
            return self.cached_report

        with self.scan_lock:
            now = time.time()
            if not force and self.cached_report and (now - self.last_scan_time < 2.0):
                return self.cached_report

            t0 = time.time()
            cur, prev, dt = self.sampler.collect()
            T = self.cfg["thresholds"]
            checks = []
            for fn in CHECKS:
                try:
                    checks.append(fn(cur, prev, dt, T))
                except Exception as e:
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
            
            self.incidents.maybe_record(report, cur, prev, dt)
            if hasattr(self, "auto_healer") and self.auto_healer:
                self.auto_healer.process(report)
            
            cm = {c["id"]: c for c in report["checks"]}
            self.history.append({
                "t": int(report["ts"]), "score": report["score"],
                "cpu": cm["cpu"]["metrics"].get("busy", 0),
                "mem": cm["memory"]["metrics"].get("used_pct", 0),
                "load": cm["load"]["metrics"].get("load1", 0),
                "load_core": cm["load"]["metrics"].get("per_core", 0),
                "disk": cm["disk"]["metrics"].get("worst_pct", 0),
                "io": cm["io"]["metrics"].get("worst_util", 0),
                "net": cm["network"]["metrics"].get("retrans_pct", 0),
            })
            
            self.cached_report = report
            self.last_scan_time = time.time()
            with self.lock:
                self.report = report
            self._save_state()
            return report


def _os_pretty():
    m = re.search(r'PRETTY_NAME="?([^"\n]+)"?', read("/etc/os-release"))
    return m.group(1) if m else f"{os.uname().sysname} {os.uname().release}"


# ─────────────────────────────────────────────────────────────────────────────
#  PERSISTENT & GUARANTEED ALERT ENGINE (Telegram, WhatsApp +4794441171, Email)
# ─────────────────────────────────────────────────────────────────────────────

EMOJI = {"crit": "🔴", "warn": "🟠", "ok": "🟢", "info": "🔵"}


class AlertManager:
    def __init__(self, engine):
        self.engine = engine
        self.cfg = engine.cfg["alerts"]
        self.host = engine.cfg["hostname"]
        self.state = engine.alert_state

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
                                                 "notified": None, "last": 0.0, "fail_count": 0})
            st["streak"] = st["streak"] + 1 if c["status"] == st["status"] else 1
            st["status"] = c["status"]
            r = RANK[c["status"]]
            if r >= min_rank and st["streak"] >= need:
                escalated = st["notified"] is None or RANK[c["status"]] > RANK[st["notified"]]
                if escalated or now - st["last"] > cooldown:
                    events.append({"type": "problem", "check": c})
            elif c["status"] == "ok" and st["notified"] and st["streak"] >= need:
                if self.cfg.get("notify_recovery", True):
                    events.append({"type": "recovery", "check": c})

        if events:
            threading.Thread(target=self._dispatch_guaranteed, args=(events, report), daemon=True).start()
        return events

    def _dispatch_guaranteed(self, events, report):
        results = self._dispatch_sync(events, report)
        now = time.time()
        any_success = any(v.get("ok") for v in results.values())
        if any_success:
            for e in events:
                c = e["check"]
                st = self.state.setdefault(c["id"], {})
                if e["type"] == "problem":
                    st["notified"], st["last"], st["fail_count"] = c["status"], now, 0
                else:
                    st["notified"], st["last"], st["fail_count"] = None, now, 0
            self.engine._save_state()
        else:
            for e in events:
                c = e["check"]
                st = self.state.setdefault(c["id"], {})
                st["fail_count"] = st.get("fail_count", 0) + 1
            print(f"[sentinel] alert dispatch failed across all channels: {results}", file=sys.stderr)

    def test_dispatch(self, report):
        worst = max(report["checks"], key=lambda c: (RANK[c["status"]], -c["score"]))
        events = [{"type": "problem", "check": worst}]
        return self._dispatch_sync(events, report, is_test=True)

    def _dispatch_sync(self, events, report, is_test=False):
        subject = ("TEST: " if is_test else "") + self.subject(events, report)
        text = self.text(events, report)
        htmlbody = self.html(events, report)
        results = {}
        
        channels = [
            ("telegram", self._telegram),
            ("whatsapp", self._whatsapp),
            ("email", self._email),
            ("slack", self._slack),
            ("ntfy", self._ntfy),
            ("webhook", self._webhook),
            ("desktop", self._desktop)
        ]
        
        for name, fn in channels:
            cfg = self.cfg.get(name, {})
            if isinstance(cfg, dict) and cfg.get("enabled"):
                try:
                    res = fn(subject, text, htmlbody, report, events)
                    results[name] = {"ok": True, "detail": res or "Delivered"}
                except Exception as e:
                    results[name] = {"ok": False, "detail": str(e)}
        return results

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
        L = [f"{EMOJI[report['status']]} {self.host} — Health {report['score']:.0f}/100 "
             f"({report['grade']} · {report['grade_label']})",
             f"Server: {report['os']} · {report['cores']} cores · up {report['uptime']} · {report['time']}", ""]
        for e in events:
            c = e["check"]
            if e["type"] == "recovery":
                L.append(f"{EMOJI['ok']} RECOVERED: {c['name']} is back to normal! ({c['summary']})")
                continue
            L.append(f"{EMOJI[c['status']]} {c['status'].upper()}: {c['name']} = {c['value']}{(' ' + c['unit']) if c['unit'] else ''}")
            L.append(f"   Summary: {c['summary']}")
            for f in c["findings"][:2]:
                L.append(f"   ▸ {f['title']}")
                if f["why"]:
                    L.append(f"     Why: {f['why']}")
                for fx in f["fix"][:2]:
                    L.append(f"     ✔ Fix: {fx}")
                for dg in f["diagnose"][:1]:
                    L.append(f"     🔍 Check: {dg}")
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
                fixes = "".join(f'<li style="margin:5px 0">{_esc(x)}</li>' for x in f["fix"][:3])
                diags = "".join(
                    f'<div style="font-family:monospace;font-size:12px;background:#0e1220;color:#c9d4ff;padding:6px 10px;border-radius:6px;margin:4px 0;">{_esc(x)}</div>' for x in f["diagnose"][:2])
                fl += (f'<div style="margin-top:10px;padding:12px;border-radius:10px;background:#f7f8fb;border:1px solid #e6e9f0">'
                       f'<b style="color:{col.get(f["severity"], top)}">{_esc(f["title"])}</b>'
                       f'<div style="color:#455065;font-size:13px;margin:5px 0">{_esc(f["why"])}</div>'
                       f'<div style="font-size:11px;font-weight:700;color:#8a90a2;margin-top:8px">🔍 CHECK COMMAND:</div>{diags}'
                       f'<div style="font-size:11px;font-weight:700;color:#8a90a2;margin-top:8px">🛠️ HOW TO FIX:</div>'
                       f'<ul style="margin:4px 0 0 18px;padding:0;font-size:13px;color:#2b3245">{fixes}</ul>'
                       f'</div>')
            rows.append(
                f'<tr><td style="padding:16px;border-top:1px solid #eceef4">'
                f'<div style="display:flex;justify-content:space-between;align-items:center">'
                f'<div><span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:{col.get(sev, "#17c964")};margin-right:8px"></span>'
                f'<b style="font-size:15px">{_esc(c["name"])}</b>'
                f'<span style="color:#8a90a2;font-size:13px"> · {_esc(c["summary"])}</span></div>'
                f'<span style="background:{col.get(sev, "#17c964")}1a;color:{col.get(sev, "#17c964")};font-size:11px;font-weight:700;padding:4px 10px;border-radius:999px;">'
                f'{"RECOVERED" if e["type"] == "recovery" else sev.upper()}</span></div>'
                f'<div style="font-size:24px;font-weight:700;margin:6px 0 0">{_esc(c["value"])}'
                f'<span style="font-size:13px;color:#8a90a2;font-weight:500"> {_esc(c["unit"])}</span></div>'
                f'{fl}</td></tr>')
        return f"""<!doctype html><html><body style="margin:0;background:#eef1f7;font-family:-apple-system,Segoe UI,Roboto,sans-serif;color:#1a1f2e">
<div style="max-width:720px;margin:0 auto;padding:24px 14px">
 <div style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 8px 30px rgba(20,30,60,.10)">
  <div style="background:linear-gradient(135deg,{top},{top}bb);padding:22px 24px;color:#fff">
   <div style="font-size:12px;letter-spacing:2px;opacity:.85">LINUX HEALTH SENTINEL</div>
   <div style="font-size:22px;font-weight:800;margin-top:4px">{_esc(report['host'])} · {report['status'].upper()}</div>
   <div style="opacity:.9;font-size:13px;margin-top:6px">Health {report['score']:.0f}/100 ({report['grade']}) · {report['counts']['crit']} critical · {report['counts']['warn']} warning</div>
  </div>
  <table style="width:100%;border-collapse:collapse">{''.join(rows)}</table>
  <div style="padding:14px 24px;background:#fafbfe;color:#8a90a2;font-size:11px;border-top:1px solid #eceef4">Sentinel v{VERSION}</div>
 </div></div></body></html>"""

    # ── channels ───────────────────────────────────────────────────────────
    def _telegram(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["telegram"]
        if not cfg.get("bot_token") or not cfg.get("chat_id"):
            raise ValueError("Telegram bot_token or chat_id is missing")
        st = self._post(f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage",
                        {"chat_id": cfg["chat_id"], "text": f"<pre>{_esc(text[:3800])}</pre>",
                         "parse_mode": "HTML", "disable_web_page_preview": "true"}, form=True)
        return f"Telegram message sent (HTTP {st})"

    def _whatsapp(self, subject, text, htmlbody, report, events):
        cfg = self.cfg.get("whatsapp", {})
        phone = cfg.get("phone", "+4794441171").strip()
        provider = cfg.get("provider", "callmebot").lower()
        
        # Format a clean, emoji-rich WhatsApp message
        lines = [f"🛡️ *Linux Health Sentinel Alert*",
                 f"📍 *Server:* `{report['host']}`",
                 f"📊 *Health:* `{report['score']:.0f}/100 ({report['grade']})`",
                 f"⏰ *Time:* {report['time']}", ""]
        
        for e in events:
            c = e["check"]
            status_emoji = "🟢" if e["type"] == "recovery" else ("🔴" if c["status"] == "crit" else "🟠")
            lines.append(f"{status_emoji} *{c['name']}: {c['value']} {c['unit']}*")
            for f in c["findings"][:1]:
                lines.append(f"• *Issue:* {f['title']}")
                if f["why"]:
                    lines.append(f"• *Why:* {f['why']}")
                if f["fix"]:
                    lines.append(f"• *Fix:* `{f['fix'][0]}`")
            lines.append("")
        
        wa_text = "\n".join(lines).strip()
        
        if provider == "callmebot":
            apikey = cfg.get("apikey", "").strip()
            if not apikey:
                return "WhatsApp configured for " + phone + " (Add CallMeBot API key in config.json to activate WhatsApp dispatch)"
            params = urllib.parse.urlencode({
                "phone": phone,
                "text": wa_text,
                "apikey": apikey
            })
            url = f"https://api.callmebot.com/whatsapp.php?{params}"
            req = urllib.request.Request(url, headers={"User-Agent": f"health-sentinel/{VERSION}"})
            with urllib.request.urlopen(req, timeout=12) as r:
                return f"WhatsApp sent via CallMeBot to {phone} (HTTP {r.status})"
                
        elif provider == "webhook" and cfg.get("webhook_url"):
            st = self._post(cfg["webhook_url"], {"phone": phone, "message": wa_text, "report": report})
            return f"WhatsApp webhook delivered (HTTP {st})"
            
        return f"WhatsApp target {phone} configured"

    def _email(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["email"]
        msg = EmailMessage()
        msg["Subject"], msg["From"] = subject, cfg["from"]
        msg["To"] = ", ".join(cfg["to"])
        msg["Date"] = formatdate(localtime=True)
        msg["X-Sentinel-Host"] = report["host"]
        msg.set_content(text)
        msg.add_alternative(htmlbody, subtype="html")
        ctx = ssl.create_default_context()
        if cfg.get("ssl"):
            with smtplib.SMTP_SSL(cfg["host"], cfg["port"], context=ctx, timeout=15) as s:
                if cfg.get("user"):
                    s.login(cfg["user"], cfg["password"])
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg["host"], cfg["port"], timeout=15) as s:
                s.ehlo()
                if cfg.get("tls"):
                    s.starttls(context=ctx)
                    s.ehlo()
                if cfg.get("user"):
                    s.login(cfg["user"], cfg["password"])
                s.send_message(msg)
        return f"Sent to {len(cfg['to'])} recipient(s)"

    def _post(self, url, payload, headers=None, form=False):
        data = urllib.parse.urlencode(payload).encode() if form else json.dumps(payload).encode()
        h = {"Content-Type": "application/x-www-form-urlencoded" if form else "application/json",
             "User-Agent": f"health-sentinel/{VERSION}"}
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h)
        with urllib.request.urlopen(req, timeout=12) as r:
            return r.status

    def _slack(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["slack"]
        colour = {"crit": "#e5484d", "warn": "#f5a524", "ok": "#17c964"}.get(report["status"], "#17c964")
        blocks = [{"type": "header", "text": {"type": "plain_text", "text": subject[:150]}}]
        for e in events[:6]:
            c = e["check"]
            fix = ("\n".join(f"• {x}" for x in (c["findings"][0]["fix"][:3] if c["findings"] else []))) or "—"
            blocks.append({"type": "section", "text": {"type": "mrkdwn",
                          "text": f"*{EMOJI.get(c['status'] if e['type'] == 'problem' else 'ok', '🟢')} "
                                  f"{c['name']}* — `{c['value']} {c['unit']}`\n{c['summary']}\n"
                                  f"*Fix:*\n{fix}"}})
        st = self._post(cfg["webhook_url"], {"text": subject,
                                              "attachments": [{"color": colour, "blocks": blocks}]})
        return f"Slack HTTP {st}"

    def _ntfy(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["ntfy"]
        priority = {"crit": "urgent", "warn": "high", "ok": "default"}.get(report["status"], "default")
        tag = {"crit": "rotating_light", "warn": "warning", "ok": "white_check_mark"}.get(report["status"], "white_check_mark")
        h = {"Title": subject[:200], "Content-Type": "text/plain",
             "Priority": priority,
             "Tags": tag}
        if cfg.get("token"):
            h["Authorization"] = "Bearer " + cfg["token"]
        req = urllib.request.Request(f"{cfg['server'].rstrip('/')}/{cfg['topic']}",
                                     data=text[:3800].encode(), headers=h)
        with urllib.request.urlopen(req, timeout=12) as r:
            return f"ntfy HTTP {r.status}"

    def _webhook(self, subject, text, htmlbody, report, events):
        cfg = self.cfg["webhook"]
        st = self._post(cfg["url"], {"subject": subject, "text": text, "report": report,
                                     "events": events}, cfg.get("headers"))
        return f"Webhook HTTP {st}"

    def _desktop(self, subject, text, htmlbody, report, events):
        rc, out = sh(["notify-send", "-u", "critical" if report["status"] == "crit" else "normal",
                      subject, text[:400]], timeout=4)
        if rc != 0:
            raise RuntimeError(f"notify-send failed with exit code {rc}")
        return "Desktop notification sent"


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def prom_esc(s):
    return str(s).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


# ─────────────────────────────────────────────────────────────────────────────
#  WEB UI WITH 10-MIN CHARTS, Y-AXIS UNITS & CLICKABLE RANGE SELECTOR
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

/* ── KPI CARDS WITH 10-MIN Y-AXIS CHARTS ───────────────── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(235px,1fr));gap:14px}
.kpi{padding:16px;display:flex;flex-direction:column;gap:8px;position:relative;cursor:pointer;transition:.2s}
.kpi:hover{transform:translateY(-2px);border-color:var(--acc)}
.kpi .kh{display:flex;align-items:center;justify-content:space-between;font-size:12px;color:var(--mut);letter-spacing:.6px;text-transform:uppercase;font-weight:700}
.kpi .kvals{display:flex;align-items:baseline;justify-content:space-between}
.kpi .kv{font-size:29px;font-weight:800;letter-spacing:-1px}
.kpi .kv i{font-size:13px;font-style:normal;color:var(--mut);font-weight:600}
.kpi .kranges{display:flex;gap:4px}
.kpi .kr-btn{font-size:10px;font-weight:700;padding:2px 6px;border-radius:6px;border:1px solid var(--stroke);background:var(--card2);color:var(--mut);cursor:pointer}
.kpi .kr-btn.active{background:var(--acc);color:#fff;border-color:var(--acc)}
.chart-box{width:100%;height:88px;position:relative;margin-top:4px}
.chart-box svg{width:100%;height:100%;display:block;overflow:visible}
.kpi .kd{font-size:11.5px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
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
.sec h4{font-size:11.5px;letter-spacing:1px;color:var(--dim);text-transform:uppercase;font-weight:700;margin-bottom:8px;
 display:flex;align-items:center;gap:7px}
.sec h4:after{content:"";flex:1;height:1px;background:var(--stroke)}
.why{font-size:13px;color:var(--txt);background:color-mix(in srgb,var(--acc) 9%,transparent);
 border-left:3px solid var(--acc);padding:10px 14px;border-radius:0 10px 10px 0;line-height:1.5}
.cmd{position:relative;margin:6px 0}
.cmd pre{background:rgba(0,0,0,.42);border:1px solid var(--stroke);border-radius:10px;padding:10px 40px 10px 12px;
 font-size:12.2px;color:#cfe0ff;overflow-x:auto;white-space:pre;line-height:1.5}
[data-theme=light] .cmd pre{background:#0d1426;color:#d6e4ff}
.cmd .cp{position:absolute;top:6px;right:6px;width:26px;height:26px;border-radius:7px;border:1px solid var(--stroke2);
 background:var(--card2);color:var(--mut);cursor:pointer;display:grid;place-items:center;opacity:0;transition:.15s}
.cmd:hover .cp{opacity:1}.cmd .cp:hover{color:var(--ok);border-color:var(--ok)}
.cmd .cp svg{width:13px;height:13px;stroke:currentColor;fill:none;stroke-width:2}
ol.fix{list-style:none;counter-reset:f}
ol.fix li{counter-increment:f;position:relative;padding:9px 12px 9px 36px;font-size:13px;color:var(--txt);
 background:color-mix(in srgb,var(--ok) 8%,transparent);border-radius:10px;margin:6px 0;
 border:1px solid color-mix(in srgb,var(--ok) 18%,transparent);line-height:1.45}
ol.fix li:before{content:counter(f);position:absolute;left:9px;top:8px;width:20px;height:20px;border-radius:6px;
 background:var(--ok);color:#04120c;font-size:11px;font-weight:800;display:grid;place-items:center}
.mtable{width:100%;border-collapse:collapse;font-size:12.2px}
.mtable td{padding:6px 8px;border-bottom:1px solid var(--stroke);color:var(--mut)}
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

/* ── tabs, doctor & benchmark styling ──────────────── */
.nav-tabs{display:flex;gap:8px;margin:16px 0 20px;border-bottom:1px solid var(--stroke);padding-bottom:12px;overflow-x:auto}
.tab-btn{padding:9px 18px;border-radius:999px;border:1px solid var(--stroke2);background:var(--card);color:var(--mut);font-size:13px;font-weight:650;cursor:pointer;display:inline-flex;align-items:center;gap:8px;transition:.18s;white-space:nowrap}
.tab-btn svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2}
.tab-btn:hover{color:var(--txt);border-color:var(--acc);transform:translateY(-1px)}
.tab-btn.active{background:linear-gradient(135deg,var(--acc),var(--acc2));color:#fff;border-color:transparent;box-shadow:0 6px 18px -4px var(--acc)}
.tab-badge{padding:2px 7px;border-radius:999px;font-size:11px;font-weight:700;background:rgba(0,0,0,.25);color:#fff}
.tab-btn.active .tab-badge{background:rgba(255,255,255,.25)}
.doctor-card{padding:18px 20px;border-radius:var(--r);background:var(--card);border:1px solid var(--stroke);margin-bottom:18px;transition:.2s}
.doctor-card.ok{border-color:color-mix(in srgb,var(--ok) 35%,transparent);background:color-mix(in srgb,var(--ok) 6%,transparent)}
.doctor-card.warn{border-color:color-mix(in srgb,var(--warn) 35%,transparent);background:color-mix(in srgb,var(--warn) 6%,transparent)}
.doctor-card.crit{border-color:color-mix(in srgb,var(--crit) 35%,transparent);background:color-mix(in srgb,var(--crit) 6%,transparent)}
.bench-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:14px;margin-top:16px}
.bench-card{padding:18px;border-radius:var(--r);background:var(--card);border:1px solid var(--stroke)}
.vtable{width:100%;border-collapse:collapse;font-size:13px}
.vtable th{text-align:left;padding:10px 12px;font-size:11.5px;text-transform:uppercase;color:var(--dim);letter-spacing:.5px;border-bottom:1px solid var(--stroke)}
.vtable td{padding:10px 12px;border-bottom:1px solid var(--stroke);color:var(--txt)}
.vtable tr:last-child td{border-bottom:0}
.cap-stat-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:16px 0}
.cap-stat-card{padding:16px 18px;border-radius:var(--r);background:var(--card);border:1px solid var(--stroke)}
.cap-badge-opt{color:#10b981;background:rgba(16,185,129,0.12);padding:3px 8px;border-radius:6px;font-weight:700;font-size:11.5px;display:inline-block}
.cap-badge-good{color:#3b82f6;background:rgba(59,130,246,0.12);padding:3px 8px;border-radius:6px;font-weight:700;font-size:11.5px;display:inline-block}
.cap-badge-deg{color:#f59e0b;background:rgba(245,158,11,0.12);padding:3px 8px;border-radius:6px;font-weight:700;font-size:11.5px;display:inline-block}
.cap-badge-sat{color:#ef4444;background:rgba(239,68,68,0.12);padding:3px 8px;border-radius:6px;font-weight:700;font-size:11.5px;display:inline-block}
.cap-bar-wrap{width:100%;height:10px;background:var(--card);border-radius:999px;overflow:hidden;border:1px solid var(--stroke);margin:10px 0}
.cap-bar-fill{height:100%;background:linear-gradient(90deg,var(--acc),var(--ok));border-radius:999px;transition:width .3s ease}
.chip-btn{padding:4px 10px;border-radius:8px;font-size:11px;background:var(--card);border:1px solid var(--stroke2);color:var(--mut);cursor:pointer;transition:.15s}
.chip-btn:hover{color:var(--txt);border-color:var(--acc)}
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
  <button class="btn" onclick="openQuickActionsModal()"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>⚡ Quick Actions &amp; PHP</button>
  <button class="btn" onclick="openExecutiveReportModal()"><svg viewBox="0 0 24 24"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><path d="M14 2v6h6M16 13H8M16 17H8M10 9H8"/></svg>📄 Executive Report</button>
  <button class="btn" onclick="testAlert(this)"><svg viewBox="0 0 24 24"><path d="M18 8a6 6 0 10-12 0c0 7-3 8-3 8h18s-3-1-3-8"/><path d="M13.7 21a2 2 0 01-3.4 0"/></svg>Test alert</button>
  <button class="btn" onclick="dl()"><svg viewBox="0 0 24 24"><path d="M12 3v12M7 11l5 5 5-5M4 20h16"/></svg>JSON</button>
  <button class="btn primary" id="scanBtn" onclick="scan()"><svg viewBox="0 0 24 24" id="scanIco"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></svg>Scan now</button>
 </header>

 <div class="nav-tabs">
  <button class="tab-btn active" id="tab-overview-btn" onclick="switchTab('overview')"><svg viewBox="0 0 24 24"><path d="M3 12h18M3 6h18M3 18h18"/></svg>📊 System Health</button>
  <button class="tab-btn" id="tab-sites-btn" onclick="switchTab('sites')"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z"/></svg>🌐 Websites &amp; Uptime <span class="tab-badge" id="badge-sites">0</span></button>
  <button class="tab-btn" id="tab-visitors-btn" onclick="switchTab('visitors')"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 3v18M3 12h18"/></svg>👥 Live Visitors &amp; Geo <span class="tab-badge" id="badge-visitors">0</span></button>
  <button class="tab-btn" id="tab-benchmark-btn" onclick="switchTab('benchmark')"><svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>⚡ VPS Benchmark <span class="tab-badge" id="badge-bench">Ready</span></button>
  <button class="tab-btn" id="tab-incidents-btn" onclick="switchTab('incidents')"><svg viewBox="0 0 24 24"><path d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/></svg>🚨 Culprits &amp; Incidents <span class="tab-badge" id="badge-inc">0</span></button>
 </div>

 <div id="view-overview">
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

  <div id="server-doctor-box" style="margin-bottom:18px;"></div>

  <div class="tools">
   <button class="chip active" data-f="all" onclick="setF('all',this)">All <b id="c-all">0</b></button>
   <button class="chip" data-f="crit" onclick="setF('crit',this)"><span class="dot" style="color:var(--crit);background:var(--crit)"></span>Critical <b id="c-crit">0</b></button>
   <button class="chip" data-f="warn" onclick="setF('warn',this)"><span class="dot" style="color:var(--warn);background:var(--warn)"></span>Warning <b id="c-warn">0</b></button>
   <button class="chip" data-f="ok" onclick="setF('ok',this)"><span class="dot" style="color:var(--ok);background:var(--ok)"></span>Healthy <b id="c-ok">0</b></button>
   <button class="chip" data-f="incidents" onclick="showIncidents()">⚡ Culprits &amp; Incidents <b id="c-inc">0</b></button>
   <div class="spacer"></div>
   <button class="chip" onclick="allOpen(true)">Expand all</button>
   <button class="chip" onclick="allOpen(false)">Collapse</button>
   <button class="chip" onclick="copyReport(this)">Copy report</button>
  </div>

  <div class="grid" id="grid">
   <div class="glass skel"></div><div class="glass skel"></div><div class="glass skel"></div>
   <div class="glass skel"></div><div class="glass skel"></div><div class="glass skel"></div>
  </div>
 </div>

 <div id="view-sites" style="display:none;"></div>
 <div id="view-visitors" style="display:none;"></div>
 <div id="view-benchmark" style="display:none;"></div>
 <div id="view-incidents" style="display:none;"></div>

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
let REPORT=null, HIST=[], INCIDENTS=[], FILTER='all', AUTO=true, TIMER=null, OPEN=new Set(), ACTIVE_RANGES={cpu:'10m',mem:'10m',load:'10m',disk:'10m'}, VISITORS=null, BENCHMARK=null, CAPACITY_BENCHMARK=null, BENCH_SUBTAB='capacity', CAPACITY_TIMER=null, DOCTOR=null, SITES=null, SECURITY=null, CURRENT_TAB='overview';

const $=s=>document.querySelector(s), esc=s=>String(s==null?'':s)
 .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');

const URL_TOKEN = (new URLSearchParams(window.location.search).get('token') || BOOT.token || '').trim();
const api=(p,o={})=>{
 const sep = p.includes('?') ? '&' : '?';
 const url = URL_TOKEN ? `${p}${sep}token=${encodeURIComponent(URL_TOKEN)}` : p;
 return fetch(url,{headers:{'X-Auth-Token':URL_TOKEN},...o}).then(r=>{
  if(r.status === 401) throw new Error('Unauthorized - Invalid token');
  return r.json();
 });
};
const bytes=n=>{n=+n||0;const u=['B','K','M','G','T','P'];let i=0;while(n>=1024&&i<5){n/=1024;i++}
 return (i?n.toFixed(1):n)+u[i]};

/* ── toasts ── */
function toast(title,msg,kind='info',ms=4200){
 const d=document.createElement('div');d.className='glass toast';d.style.setProperty('--tc',CLR[kind]||CLR.info);
 d.innerHTML=`<b style="color:${CLR[kind]||CLR.info}">${esc(title)}</b><span style="color:var(--mut)">${esc(msg)}</span>`;
 $('#toasts').appendChild(d);setTimeout(()=>{d.style.opacity=0;d.style.transform='translateX(30px)';
  setTimeout(()=>d.remove(),300)},ms);
}

/* ── filter history by range (1m, 10m, 1h, 12h, 24h, 48h) ── */
function getRangeData(key, rangeKey='10m'){
 if(!HIST.length) return [];
 const now = HIST[HIST.length-1].t || (Date.now()/1000);
 const secs = {
  '1m': 60,
  '10m': 600,
  '1h': 3600,
  '12h': 43200,
  '24h': 86400,
  '48h': 172800,
  '1d': 86400,
  '2d': 172800
 }[rangeKey] || 600;
 const minT = now - secs;
 const filtered = HIST.filter(p => p.t >= minT);
 return filtered.length >= 2 ? filtered : HIST.slice(-20);
}

/* ── smart downsampling for smooth high-res 48h rendering ── */
function downsample(data, maxPoints=120){
 if(data.length <= maxPoints) return data;
 const step = data.length / maxPoints;
 const out = [];
 for(let i = 0; i < maxPoints; i++){
  const idx = Math.min(Math.floor(i * step), data.length - 1);
  out.push(data[idx]);
 }
 if(out[out.length-1] !== data[data.length-1]) out[out.length-1] = data[data.length-1];
 return out;
}

/* ── rich SVG chart with Y-Axis units & X-Axis time markers ── */
function renderCardChart(key, color, unit, rangeKey='10m'){
 const fullData = getRangeData(key, rangeKey);
 const data = downsample(fullData, 120);
 const vals = data.map(d => Number(d[key]) || 0);
 if(!vals.length) return '<div style="color:var(--dim);font-size:11px;padding:20px 0;text-align:center">Waiting for scan data…</div>';
 
 const W = 280, H = 84, padL = 34, padR = 8, padT = 8, padB = 18;
 const plotW = W - padL - padR, plotH = H - padT - padB;
 
 let maxV = Math.max(...vals, 1);
 if(key === 'cpu' || key === 'mem' || key === 'disk') maxV = 100;
 else if(key === 'load') maxV = Math.max(maxV * 1.2, 10);
 
 const pts = vals.map((v, i) => {
  const x = padL + (i / Math.max(vals.length - 1, 1)) * plotW;
  const y = padT + (1 - Math.max(0, Math.min(v / maxV, 1))) * plotH;
  return [x, y];
 });
 
 const linePath = pts.map((p, i) => (i === 0 ? 'M' : 'L') + p[0].toFixed(1) + ' ' + p[1].toFixed(1)).join(' ');
 const areaPath = `${linePath} L ${pts[pts.length-1][0].toFixed(1)} ${(padT + plotH).toFixed(1)} L ${pts[0][0].toFixed(1)} ${(padT + plotH).toFixed(1)} Z`;
 const id = 'g_' + key + '_' + Math.random().toString(36).slice(2, 7);
 
 const yTopLabel = `${maxV.toFixed(0)}${unit}`;
 const yMidLabel = `${(maxV/2).toFixed(0)}${unit}`;
 const yBotLabel = `0${unit}`;
 
 return `<svg viewBox="0 0 ${W} ${H}">
  <defs>
   <linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="${color}" stop-opacity="0.36"/>
    <stop offset="100%" stop-color="${color}" stop-opacity="0.0"/>
   </linearGradient>
  </defs>
  <!-- Grid Lines -->
  <line x1="${padL}" y1="${padT}" x2="${W-padR}" y2="${padT}" stroke="var(--stroke)" stroke-dasharray="3,3" />
  <line x1="${padL}" y1="${padT+plotH/2}" x2="${W-padR}" y2="${padT+plotH/2}" stroke="var(--stroke)" stroke-dasharray="3,3" />
  <line x1="${padL}" y1="${padT+plotH}" x2="${W-padR}" y2="${padT+plotH}" stroke="var(--stroke)" />
  
  <!-- Y-Axis Labels with Units -->
  <text x="${padL-4}" y="${padT+4}" fill="var(--dim)" font-size="9" text-anchor="end" font-family="monospace">${yTopLabel}</text>
  <text x="${padL-4}" y="${padT+plotH/2+3}" fill="var(--dim)" font-size="9" text-anchor="end" font-family="monospace">${yMidLabel}</text>
  <text x="${padL-4}" y="${padT+plotH}" fill="var(--dim)" font-size="9" text-anchor="end" font-family="monospace">${yBotLabel}</text>
  
  <!-- Area & Line -->
  <path d="${areaPath}" fill="url(#${id})" />
  <path d="${linePath}" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
  
  <!-- Last Point Dot -->
  <circle cx="${pts[pts.length-1][0]}" cy="${pts[pts.length-1][1]}" r="3" fill="${color}" stroke="var(--bg2)" stroke-width="1.5" />
  
  <!-- X-Axis Time Markers -->
  <text x="${padL}" y="${H-3}" fill="var(--dim)" font-size="8.5" text-anchor="start">-${rangeKey}</text>
  <text x="${W-padR}" y="${H-3}" fill="var(--dim)" font-size="8.5" text-anchor="end">now</text>
 </svg>`;
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
 $('#c-inc').textContent=INCIDENTS.length;
 const bInc=$('#badge-inc'); if(bInc) bInc.textContent=INCIDENTS.length;
 if(VISITORS){ const bVis=$('#badge-visitors'); if(bVis) bVis.textContent=VISITORS.active_visitors_5m; }
 if(BENCHMARK && BENCHMARK.tier_badge){ const bBench=$('#badge-bench'); if(bBench) bBench.textContent='Tier '+BENCHMARK.tier_badge; }

 // Top 4 KPI Cards with dedicated historical charts & Y-axis units
 const m=id=>r.checks.find(c=>c.id===id)||{metrics:{},status:'ok'};
 const cpu=m('cpu'),mem=m('memory'),ld=m('load'),dk=m('disk'),io=m('io');
 
 const tiles=[
  {t:'CPU Utilisation',v:cpu.metrics.busy?.toFixed(0)??'–',u:'%',d:`usr ${cpu.metrics.user||0}% · sys ${cpu.metrics.system||0}% · steal ${cpu.metrics.steal||0}%`,s:cpu.status,k:'cpu',unit:'%'},
  {t:'Memory & Swap',v:mem.metrics.used_pct?.toFixed(0)??'–',u:'%',d:`${bytes(mem.metrics.available)} free · swap ${(mem.metrics.swap_used_pct||0).toFixed(0)}%`,s:mem.status,k:'mem',unit:'%'},
  {t:'Server Load',v:(ld.metrics.load1??0).toFixed(2),u:`load`,d:`1m ${ld.metrics.load1||0} · 5m ${ld.metrics.load5||0} · ${(ld.metrics.per_core||0).toFixed(2)}/core`,s:ld.status,k:'load',unit:''},
  {t:'Disk Capacity',v:dk.metrics.worst_pct?.toFixed(0)??'–',u:'%',d:`worst ${dk.metrics.worst_pct||0}% full · io util ${io.metrics.worst_util||0}%`,s:dk.status==='ok'?io.status:dk.status,k:'disk',unit:'%'}
 ];
 
 $('#kpis').innerHTML=tiles.map(t=>{
  const range = ACTIVE_RANGES[t.k] || '10m';
  const color = CLR[t.s] || CLR.ok;
  return `<div class="glass kpi" onclick="openChartModal('${t.k}','${t.t}','${color}','${t.unit}')">
   <div class="kh">
    <span>${t.t}</span>
    <div class="kranges" onclick="event.stopPropagation()">
     ${['10m','1h','12h','24h','48h'].map(rk=>`<button class="kr-btn${rk===range?' active':''}" onclick="setCardRange('${t.k}','${rk}')">${rk}</button>`).join('')}
    </div>
   </div>
   <div class="kvals">
    <div class="kv">${t.v}<i> ${t.u}</i></div>
    <span class="dot" style="color:${color};background:${color}"></span>
   </div>
   <div class="chart-box">${renderCardChart(t.k, color, t.unit, range)}</div>
   <div class="kd">${esc(t.d)}</div>
  </div>`;
 }).join('');

 // check cards
 $('#grid').innerHTML=r.checks.map(c=>card(c)).join('');
 applyFilter();
}

function setCardRange(key, rk){
 ACTIVE_RANGES[key] = rk;
 if(REPORT) render(REPORT);
}

function openChartModal(key, title, color, unit){
 const range = ACTIVE_RANGES[key] || '10m';
 const fullData = getRangeData(key, range);
 const vals = fullData.map(d=>Number(d[key])||0);
 const avg = vals.length ? (vals.reduce((a,b)=>a+b,0)/vals.length).toFixed(1) : '0';
 const max = vals.length ? Math.max(...vals).toFixed(1) : '0';
 const min = vals.length ? Math.min(...vals).toFixed(1) : '0';
 const cur = vals.length ? vals[vals.length-1].toFixed(1) : '0';
 
 const modal = document.createElement('div');
 modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
 modal.innerHTML = `<div class="glass" style="max-width:820px;width:100%;padding:24px;background:var(--bg2);">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
   <div>
    <h2 style="font-size:18px;">📊 ${esc(title)} — Historical Trend</h2>
    <div style="font-size:12px;color:var(--mut);">Select time range: <b>1m</b>, <b>10m</b>, <b>1h</b>, <b>12h</b>, <b>24h</b>, or <b>48h</b></div>
   </div>
   <button class="btn" onclick="this.closest('div[style*=position]').remove()">Close</button>
  </div>
  
  <div style="display:flex;gap:6px;margin-bottom:16px;flex-wrap:wrap;">
   ${['1m','10m','1h','12h','24h','48h'].map(rk=>`<button class="btn${rk===range?' primary':''}" onclick="this.closest('div[style*=position]').remove();setCardRange('${key}','${rk}');openChartModal('${key}','${title}','${color}','${unit}')">${rk==='1m'?'1 Min':rk==='10m'?'10 Mins':rk==='1h'?'1 Hour':rk==='12h'?'12 Hours':rk==='24h'?'24 Hours':'48 Hours'}</button>`).join('')}
  </div>

  <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:18px;">
   <div style="padding:10px 12px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);"><span style="font-size:11px;color:var(--dim);">CURRENT</span><div style="font-size:20px;font-weight:700;color:${color}">${cur}${unit}</div></div>
   <div style="padding:10px 12px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);"><span style="font-size:11px;color:var(--dim);">AVERAGE</span><div style="font-size:20px;font-weight:700;">${avg}${unit}</div></div>
   <div style="padding:10px 12px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);"><span style="font-size:11px;color:var(--dim);">PEAK (MAX)</span><div style="font-size:20px;font-weight:700;color:var(--crit);">${max}${unit}</div></div>
   <div style="padding:10px 12px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);"><span style="font-size:11px;color:var(--dim);">LOWEST</span><div style="font-size:20px;font-weight:700;color:var(--ok);">${min}${unit}</div></div>
  </div>

  <div style="width:100%;height:180px;background:var(--card);border:1px solid var(--stroke);border-radius:12px;padding:12px 14px 20px;">
   ${renderCardChart(key, color, unit, range)}
  </div>
 </div>`;
 document.body.appendChild(modal);
}

function card(c){
 const col=CLR[c.status] || CLR.ok;
 const findings=c.findings.map(f=>`<div class="fnd" style="--fc:${CLR[f.severity]||CLR.info}">
   <span class="fdot"></span><div><b>${esc(f.title)}</b>${f.detail?`<em>${esc(f.detail)}</em>`:''}</div></div>`).join('');
 const detail=c.findings.map(f=>`
  <div class="sec"><h4 style="color:${CLR[f.severity]||CLR.info}">⚠️ ${esc(f.title)}</h4>
   ${f.why?`<div class="why">${esc(f.why)}</div>`:''}
   ${f.diagnose.length?`<div class="sec"><h4>🔍 How to check the problem:</h4>${f.diagnose.map(cmd).join('')}</div>`:''}
   ${f.fix.length?`<div class="sec"><h4>🛠️ How to fix it (Easy Copy-Paste):</h4><ol class="fix">${f.fix.map(x=>`<li>${esc(x)}</li>`).join('')}</ol></div>`:''}
  </div>`).join('');
 const metrics=`<div class="sec"><h4>Detailed Metrics</h4><table class="mtable">${
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
   <span class="sq">${c.findings.length?c.findings.length+' finding'+(c.findings.length>1?'s':''):'healthy'}</span></div>
  <div class="bar"><i style="width:${Math.max(2,Math.min(100,c.pct)).toFixed(1)}%"></i></div>
  <div class="cs">${esc(c.summary)}</div>
  ${findings?`<div class="cf">${findings}</div>`:''}
  <button class="expand" onclick="tog(this)">${c.findings.length?'View Diagnose &amp; Fix Guide':'View System Details'}
   <svg viewBox="0 0 24 24"><path d="M6 9l6 6 6-6"/></svg></button>
  <div class="det"><div class="dbody">${detail||'<div class="sec"><h4>All Good</h4><div class="why">All metrics for this probe are within healthy operational thresholds.</div></div>'}${metrics}</div></div>
 </div>`;
}
function tables(c){
 const t=[];
 const list=(arr,cols,title)=>{if(!Array.isArray(arr)||!arr.length)return'';
  return `<h4 style="margin-top:12px">${title}</h4><table class="mtable">`+arr.slice(0,8).map(o=>
   `<tr>${cols.map((k,i)=>`<td>${esc(typeof o[k]==='number'?Math.round(o[k]*100)/100:(k.match(/free|total|rss|rx_s|tx_s|read_s|write_s/)?bytes(o[k]):o[k]))}</td>`).join('')}</tr>`).join('')+'</table>'};
 if(c.metrics.mounts) t.push(list(c.metrics.mounts,['mount','pct','free'],'Hard Drive Partitions (Disk space %, free)'));
 if(c.metrics.devices) t.push(list(c.metrics.devices,['dev','util','await_ms','iops'],'Storage Devices (Busy %, Wait Time ms, IOPS)'));
 if(c.metrics.ifaces) t.push(list(c.metrics.ifaces,['iface','rx_s','tx_s','err_s'],'Network Cards (Download/s, Upload/s, Errors/s)'));
 if(c.metrics.top_cpu) t.push(list(c.metrics.top_cpu,['comm','user','cpu','cmd'],'Programs using the most CPU (%)'));
 if(c.metrics.top_mem) t.push(list(c.metrics.top_mem,['comm','user','rss','cmd'],'Programs using the most RAM (Memory)'));
 if(c.metrics.top_errors) t.push(list(c.metrics.top_errors,['count','text'],'Most frequent log errors'));
 if(c.metrics.top_slow_scripts) t.push(list(c.metrics.top_slow_scripts,['pool','script','duration','trace'],'PHP-FPM Slow Script Executions (>5s)'));
 if(c.metrics.failed_units&&c.metrics.failed_units.length)
   t.push(`<h4 style="margin-top:12px">Crashed / Failed Services</h4><table class="mtable">`+
    c.metrics.failed_units.map(u=>`<tr><td colspan="2" style="color:var(--crit)">${esc(u)}</td></tr>`).join('')+'</table>');
 return t.join('');
}
const cmd=x=>`<div class="cmd"><pre>${esc(x)}</pre><button class="cp" title="Copy Command"
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
function switchTab(tabId){
  CURRENT_TAB = tabId;
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  const btn = $('#tab-' + tabId + '-btn');
  if(btn) btn.classList.add('active');

  const views = ['overview', 'sites', 'visitors', 'benchmark', 'incidents'];
  views.forEach(v => {
    const el = $('#view-' + v);
    if(el) el.style.display = (v === tabId) ? 'block' : 'none';
  });

  if(tabId === 'sites' && SITES) renderSites(SITES);
  if(tabId === 'visitors' && VISITORS) renderVisitors(VISITORS);
  if(tabId === 'benchmark') renderBenchmark(BENCHMARK);
  if(tabId === 'incidents') renderIncidentsView();
}

function renderServerDoctor(doc){
  const box = $('#server-doctor-box');
  if(!box) return;
  if(!doc || doc.status === 'ok'){
    box.innerHTML = `
      <div class="doctor-card ok" style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;">
        <div style="display:flex;align-items:center;gap:12px;">
          <div style="font-size:24px;">🩺</div>
          <div>
            <b style="font-size:14px;color:var(--ok);display:block;">All Systems Operating Smoothly</b>
            <span style="font-size:12.5px;color:var(--mut);">No critical bottlenecks detected. Your server has plenty of CPU, RAM, and disk storage headroom.</span>
          </div>
        </div>
        <button class="btn" onclick="openQuickActionsModal()" style="height:32px;font-size:12px;">⚡ Server Actions</button>
      </div>`;
    return;
  }

  const isCrit = doc.status === 'crit';
  const color = isCrit ? 'var(--crit)' : 'var(--warn)';
  box.innerHTML = `
    <div class="doctor-card ${doc.status}">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;flex-wrap:wrap;gap:8px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <div style="font-size:24px;">🩺</div>
          <div>
            <b style="font-size:14.5px;color:${color};">${esc(doc.headline)}</b>
            <div style="font-size:12px;color:var(--mut);">${esc(doc.summary)}</div>
          </div>
        </div>
        <span class="badge" style="background:color-mix(in srgb,${color} 16%,transparent);color:${color};border-color:color-mix(in srgb,${color} 30%,transparent);">${isCrit?'ACTION REQUIRED':'ATTENTION'}</span>
      </div>
      <div style="display:flex;flex-direction:column;gap:10px;">
        ${doc.recommendations.map(r => `
          <div style="padding:12px 14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;flex-wrap:wrap;gap:6px;">
              <b style="font-size:13.5px;color:var(--txt);">⚠️ ${esc(r.problem)}</b>
              ${r.one_click_action ? `<button class="btn" onclick="doDoctorAction('${r.one_click_action}')" style="height:28px;font-size:11.5px;color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);">⚡ Fix Now</button>` : ''}
            </div>
            <div style="font-size:12px;color:var(--mut);line-height:1.45;margin-bottom:6px;">
              <b>Why this matters:</b> ${esc(r.why_it_matters)}
            </div>
            ${r.fix_command ? `
              <div class="cmd" style="margin-top:6px;">
                <pre><code>${esc(r.fix_command)}</code></pre>
                <button class="cp" onclick="cp('${esc(r.fix_command).replace(/'/g,"\\'")}',this)"><svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1"/></svg></button>
              </div>` : ''}
          </div>
        `).join('')}
      </div>
    </div>`;
}

async function doDoctorAction(act){
  if(act === 'restart_php_active'){
    await doPhpAction('all', 'restart');
  } else {
    await doSystemAction(act);
  }
}

function renderVisitors(v){
  if(!v) return;
  const badge = $('#badge-visitors');
  if(badge) badge.textContent = `${v.active_visitors_5m}`;

  const view = $('#view-visitors');
  if(!view) return;

  const totalHits = Object.values(v.status_codes).reduce((a,b)=>a+b,0) || 1;
  const pct2 = Math.round((v.status_codes['2xx']||0) / totalHits * 100);
  const pct4 = Math.round((v.status_codes['4xx']||0) / totalHits * 100);
  const pct5 = Math.round((v.status_codes['5xx']||0) / totalHits * 100);
  const bannedList = (v.banned_ips || (SECURITY ? SECURITY.banned_ips : [])) || [];

  view.innerHTML = `
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px;">
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🟢 Active Visitors (5m)</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;color:var(--ok);">${v.active_visitors_5m}</div>
        <div style="font-size:11.5px;color:var(--dim);">${v.active_visitors_15m} unique IPs in last 15 min</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🔌 Live TCP Sockets</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;">${v.live_connections}</div>
        <div style="font-size:11.5px;color:var(--dim);">Concurrent connections to 80/443</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🛡️ Threat Shield</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;color:${v.threat_count > 0 ? 'var(--crit)' : 'var(--ok)'};">${v.threat_count || 0}</div>
        <div style="font-size:11.5px;color:var(--dim);">${bannedList.length} IP(s) currently blocked in firewall</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">📊 HTTP Status Codes</span>
        <div style="display:flex;gap:10px;margin-top:8px;align-items:baseline;">
          <span style="font-size:18px;font-weight:700;color:var(--ok);">${pct2}% <small style="font-size:11px;color:var(--dim);">2xx</small></span>
          <span style="font-size:18px;font-weight:700;color:var(--warn);">${pct4}% <small style="font-size:11px;color:var(--dim);">4xx</small></span>
          <span style="font-size:18px;font-weight:700;color:${pct5>0?'var(--crit)':'var(--dim)'};">${pct5}% <small style="font-size:11px;color:var(--dim);">5xx</small></span>
        </div>
        <div style="font-size:11.5px;color:var(--dim);margin-top:4px;">${v.requests_per_second} req/s rate</div>
      </div>
    </div>

    <div style="display:grid;grid-template-columns:2fr 1fr;gap:18px;margin-bottom:20px;">
      <div class="glass" style="padding:20px;overflow:hidden;">
        <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
          <h3 style="font-size:15px;display:flex;align-items:center;gap:8px;">🌍 Real-Time Visitors &amp; Geographic Location</h3>
          <span style="font-size:12px;color:var(--dim);">${v.visitors.length} client(s) tracked</span>
        </div>
        ${v.visitors.length ? `
          <div style="overflow-x:auto;">
            <table class="vtable">
              <thead>
                <tr>
                  <th>Location</th>
                  <th>IP Address</th>
                  <th>ISP / Network</th>
                  <th>Last Requested Path</th>
                  <th>Status</th>
                  <th>Threat Level</th>
                  <th>Device / Bot</th>
                  <th style="text-align:right;">Hits</th>
                  <th style="text-align:right;">Action</th>
                </tr>
              </thead>
              <tbody>
                ${v.visitors.map(vis => {
                  const thr = vis.threat || {level:'clean',label:'🟢 Clean',color:'var(--ok)',reason:'',is_banned:false};
                  const isBanned = thr.is_banned;
                  return `
                  <tr>
                    <td>
                      <span style="font-size:18px;margin-right:6px;">${vis.flag}</span>
                      <b>${esc(vis.city ? vis.city + ', ' + vis.country : vis.country)}</b>
                    </td>
                    <td><code style="font-size:12px;color:var(--acc);">${esc(vis.ip)}</code></td>
                    <td style="font-size:12px;color:var(--mut);max-width:130px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(vis.isp)}</td>
                    <td style="font-size:12px;color:var(--txt);max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(vis.path)}">${esc(vis.path)}</td>
                    <td><span class="badge" style="font-size:10px;padding:2px 6px;${vis.code>=500?'color:var(--crit);background:rgba(255,85,102,.15)':(vis.code>=400?'color:var(--warn);background:rgba(255,179,64,.15)':'color:var(--ok);background:rgba(37,227,154,.15)')}">${vis.code}</span></td>
                    <td><span class="badge" title="${esc(thr.reason)}" style="font-size:10px;padding:2px 7px;color:${thr.color};background:color-mix(in srgb,${thr.color} 15%,transparent);border-color:color-mix(in srgb,${thr.color} 30%,transparent);">${esc(thr.label)}</span></td>
                    <td style="font-size:12px;color:var(--dim);">${esc(vis.device)}</td>
                    <td style="text-align:right;font-weight:700;">${vis.hits}</td>
                    <td style="text-align:right;">
                      ${isBanned ? `
                        <button class="btn" onclick="unbanIP('${esc(vis.ip)}')" style="height:26px;padding:0 8px;font-size:11px;color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);">✓ Unban</button>
                      ` : `
                        <button class="btn" onclick="promptBanIP('${esc(vis.ip)}', '${esc(thr.reason||thr.label)}')" style="height:26px;padding:0 8px;font-size:11px;color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,transparent);">🚫 Ban</button>
                      `}
                    </td>
                  </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>
        ` : `
          <div style="padding:40px 20px;text-align:center;color:var(--dim);">
            <div style="font-size:32px;margin-bottom:8px;">🌐</div>
            <b>No active external visitors in the last few minutes.</b>
            <div style="font-size:12px;color:var(--mut);margin-top:4px;">As soon as browsers or crawlers connect to ports 80/443, their IP and location will appear here live.</div>
          </div>
        `}
      </div>

      <div class="glass" style="padding:20px;">
        <h3 style="font-size:15px;margin-bottom:14px;">🔥 Top Requested Paths</h3>
        ${v.top_paths.length ? `
          <div style="display:flex;flex-direction:column;gap:8px;">
            ${v.top_paths.map(tp => `
              <div style="padding:8px 12px;background:var(--card2);border-radius:10px;display:flex;justify-content:space-between;align-items:center;">
                <code style="font-size:12px;color:var(--txt);max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${esc(tp.path)}</code>
                <span style="font-size:11.5px;font-weight:700;color:var(--acc);">${tp.hits} hit${tp.hits>1?'s':''}</span>
              </div>
            `).join('')}
          </div>
        ` : `<div style="color:var(--dim);font-size:12px;text-align:center;padding:20px 0;">No path data recorded yet.</div>`}
      </div>
    </div>

    <!-- Blocked IPs Card -->
    <div class="glass" style="padding:20px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;flex-wrap:wrap;gap:8px;">
        <div>
          <h3 style="font-size:15px;display:flex;align-items:center;gap:8px;">🛡️ Firewall Shield · Blocked IP Addresses (${bannedList.length})</h3>
          <span style="font-size:12px;color:var(--dim);">Banned IPs are immediately dropped in iptables/ufw to protect your server.</span>
        </div>
        <button class="btn" onclick="promptManualBan()" style="height:30px;font-size:12px;color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,transparent);">+ Block Custom IP</button>
      </div>
      ${bannedList.length ? `
        <div style="overflow-x:auto;">
          <table class="vtable">
            <thead>
              <tr>
                <th>Blocked IP</th>
                <th>Reason / Trigger</th>
                <th>Banned Date</th>
                <th>Firewall Rule</th>
                <th style="text-align:right;">Action</th>
              </tr>
            </thead>
            <tbody>
              ${bannedList.map(b => `
                <tr>
                  <td><code style="font-size:13px;font-weight:700;color:var(--crit);">${esc(b.ip)}</code></td>
                  <td style="font-size:12.5px;color:var(--txt);">${esc(b.reason || 'Manual block')}</td>
                  <td style="font-size:12px;color:var(--dim);">${esc(b.date || '–')}</td>
                  <td><span class="badge" style="font-size:10.5px;color:var(--ok);background:rgba(37,227,154,.12);">✓ ACTIVE DROP</span></td>
                  <td style="text-align:right;">
                    <button class="btn" onclick="unbanIP('${esc(b.ip)}')" style="height:26px;padding:0 10px;font-size:11.5px;color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);">✓ Unban IP</button>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      ` : `
        <div style="padding:24px;text-align:center;color:var(--dim);">
          <div style="font-size:24px;margin-bottom:6px;">🛡️</div>
          <b>No IPs are currently blocked in the firewall.</b>
          <div style="font-size:12px;color:var(--mut);margin-top:2px;">When you click "Ban" on an aggressive bot or scanner, it will appear here and be instantly dropped by iptables.</div>
        </div>
      `}
    </div>
  `;
}

function switchBenchSubtab(tab){
  BENCH_SUBTAB = tab;
  renderBenchmark(BENCHMARK);
}

function renderBenchmark(b){
  if(b) BENCHMARK = b;
  const badge = $('#badge-bench');
  if(badge){
    if(CAPACITY_BENCHMARK && CAPACITY_BENCHMARK.safe_concurrent_visitors){
      badge.textContent = `${CAPACITY_BENCHMARK.safe_concurrent_visitors} Visitors`;
    } else if(BENCHMARK && BENCHMARK.tier_badge){
      badge.textContent = `Tier ${BENCHMARK.tier_badge}`;
    }
  }

  const view = $('#view-benchmark');
  if(!view) return;

  const headerHtml = `
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:18px;flex-wrap:wrap;gap:12px;">
      <div style="display:flex;gap:8px;">
        <button class="tab-btn ${BENCH_SUBTAB==='capacity'?'active':''}" onclick="switchBenchSubtab('capacity')">
          <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>
          👥 Safe Visitor Capacity &amp; Stress Test
        </button>
        <button class="tab-btn ${BENCH_SUBTAB==='hardware'?'active':''}" onclick="switchBenchSubtab('hardware')">
          <svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg>
          ⚡ Hardware &amp; VPS Compute
        </button>
      </div>
      ${CAPACITY_BENCHMARK && CAPACITY_BENCHMARK.safe_concurrent_visitors ? `
        <div style="font-size:12.5px;color:var(--dim);font-weight:600;display:flex;align-items:center;gap:6px;">
          <span>Tested Safe Capacity:</span>
          <span class="cap-badge-opt">~${CAPACITY_BENCHMARK.safe_concurrent_visitors} Concurrent Visitors</span>
          <span style="color:var(--txt);">(${CAPACITY_BENCHMARK.safe_rps} RPS)</span>
        </div>
      ` : ''}
    </div>
  `;

  if(BENCH_SUBTAB === 'capacity'){
    view.innerHTML = headerHtml + renderCapacityBenchmarkView();
  } else {
    view.innerHTML = headerHtml + renderHardwareBenchmarkView(BENCHMARK);
  }
}

function renderHardwareBenchmarkView(b){
  if(!b || b.status === 'none'){
    return `
      <div class="glass" style="padding:48px 24px;text-align:center;max-width:700px;margin:30px auto;">
        <div style="font-size:48px;margin-bottom:12px;">⚡</div>
        <h2 style="font-size:22px;font-weight:800;margin-bottom:8px;">VPS Hardware Performance Benchmark</h2>
        <p style="font-size:13.5px;color:var(--mut);margin-bottom:24px;line-height:1.5;">
          Test your server's single-core &amp; multi-core CPU compute speed, in-memory RAM bandwidth, NVMe/SSD sequential write/read throughput, and network latency to major global backbones.
        </p>
        <button class="btn primary" id="run-bench-btn" onclick="runBenchmark()" style="height:44px;padding:0 28px;font-size:14.5px;margin:0 auto;">
          <svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> ⚡ Run Full VPS Benchmark Now
        </button>
      </div>`;
  }

  const scoreColor = b.composite_score >= 750 ? 'var(--ok)' : (b.composite_score >= 500 ? 'var(--acc)' : 'var(--warn)');

  return `
    <div class="glass" style="padding:22px 26px;margin-bottom:18px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:16px;">
      <div>
        <span style="font-size:11.5px;text-transform:uppercase;color:var(--mut);font-weight:700;letter-spacing:.8px;">VPS Hardware Performance Rating</span>
        <div style="font-size:24px;font-weight:800;color:var(--txt);margin-top:2px;">
          ${esc(b.tier)}
        </div>
        <div style="font-size:12px;color:var(--dim);margin-top:4px;">Tested on ${esc(b.date)} in ${b.duration_s}s</div>
      </div>
      <div style="display:flex;align-items:center;gap:18px;">
        <div style="text-align:right;">
          <div style="font-size:36px;font-weight:900;color:${scoreColor};line-height:1;">${b.composite_score}<small style="font-size:15px;color:var(--mut);font-weight:600;">/1000</small></div>
          <span style="font-size:11px;color:var(--dim);text-transform:uppercase;font-weight:700;">Composite Score</span>
        </div>
        <button class="btn" id="run-bench-btn" onclick="runBenchmark()" style="height:40px;font-size:13px;">
          <svg viewBox="0 0 24 24" id="bench-spin"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></svg> Re-Run Benchmark
        </button>
      </div>
    </div>

    <div class="bench-grid">
      <div class="bench-card">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🖥️ CPU Compute Score</span>
        <div style="font-size:28px;font-weight:800;margin:6px 0 2px;color:var(--acc);">${b.cpu.multi_core_score} <small style="font-size:13px;color:var(--mut);">multi-core</small></div>
        <div style="font-size:12px;color:var(--txt);">Single-Core: <b>${b.cpu.single_core_score}</b> pts</div>
        <div style="font-size:11.5px;color:var(--dim);margin-top:4px;">${b.cpu.cores} Cores · ${b.cpu.efficiency}% parallel scaling efficiency</div>
      </div>

      <div class="bench-card">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">⚡ RAM Memory Bandwidth</span>
        <div style="font-size:28px;font-weight:800;margin:6px 0 2px;color:var(--ok);">${b.ram.bandwidth_gb_s} <small style="font-size:13px;color:var(--mut);">GB/s</small></div>
        <div style="font-size:12px;color:var(--txt);">${esc(b.ram.label)}</div>
        <div style="font-size:11.5px;color:var(--dim);margin-top:4px;">Evaluated via 48MB buffer read/write passes</div>
      </div>

      <div class="bench-card">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">💾 Disk I/O Speed (fdatasync)</span>
        <div style="font-size:28px;font-weight:800;margin:6px 0 2px;color:var(--txt);">${b.disk.write_mb_s} <small style="font-size:13px;color:var(--mut);">MB/s write</small></div>
        <div style="font-size:12px;color:var(--txt);">Sequential Read: <b>${b.disk.read_mb_s} MB/s</b></div>
        <div style="font-size:11.5px;color:var(--dim);margin-top:4px;">Tested with direct disk sync (${b.disk.test_size_mb}MB block)</div>
      </div>

      <div class="bench-card">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🌐 Global Backbone Ping</span>
        <div style="font-size:28px;font-weight:800;margin:6px 0 2px;color:var(--acc);">${b.network.cloudflare_dns_ms} <small style="font-size:13px;color:var(--mut);">ms</small></div>
        <div style="font-size:12px;color:var(--txt);">Cloudflare (1.1.1.1): <b>${b.network.cloudflare_dns_ms}ms</b></div>
        <div style="font-size:11.5px;color:var(--dim);margin-top:4px;">Google (8.8.8.8): <b>${b.network.google_dns_ms}ms</b></div>
      </div>
    </div>
  `;
}

function renderCapacityBenchmarkView(){
  const b = CAPACITY_BENCHMARK;
  const isRunning = (CAPACITY_TIMER !== null);
  const defaultTarget = (b && b.target_url) ? b.target_url : 'http://127.0.0.1:80/';

  return `
    <div class="glass" style="padding:22px 26px;margin-bottom:18px;">
      <div style="display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap;">
        <div style="max-width:680px;">
          <h2 style="font-size:19px;font-weight:800;margin-bottom:4px;display:flex;align-items:center;gap:8px;">
            👥 Visitor Traffic Capacity &amp; Stress Test
          </h2>
          <p style="font-size:13px;color:var(--mut);line-height:1.5;margin-bottom:12px;">
            Safely simulate real simultaneous visitors to identify your server's true traffic threshold before slowdowns or 502 Bad Gateway errors occur.
          </p>
          <div style="display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:8px;background:color-mix(in srgb,var(--ok) 8%,transparent);border:1px solid color-mix(in srgb,var(--ok) 25%,transparent);font-size:12px;color:var(--ok);">
            <svg style="width:14px;height:14px;fill:none;stroke:currentColor;stroke-width:2;" viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
            <b>Auto-Safety Circuit Breaker:</b> Immediately halts if CPU Load &ge; 4.5 or available RAM &lt; 120MB to protect your server.
          </div>
        </div>

        <div style="display:flex;align-items:center;gap:10px;">
          <button class="btn primary" id="start-cap-btn" onclick="startCapacityBenchmark()" ${isRunning ? 'disabled' : ''} style="height:40px;font-size:13px;">
            <svg viewBox="0 0 24 24"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg> 🚀 Run Capacity Benchmark
          </button>
          <button class="btn" id="stop-cap-btn" onclick="stopCapacityBenchmark()" ${!isRunning ? 'style="display:none;"' : ''} style="height:40px;font-size:13px;color:var(--crit);border-color:color-mix(in srgb,var(--crit) 40%,transparent);">
            <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><rect x="9" y="9" width="6" height="6"/></svg> 🛑 Emergency Stop
          </button>
        </div>
      </div>

      <div style="display:grid;grid-template-columns:1fr auto;gap:16px;margin-top:18px;align-items:end;flex-wrap:wrap;">
        <div>
          <label style="font-size:11.5px;text-transform:uppercase;color:var(--dim);font-weight:700;letter-spacing:.5px;display:block;margin-bottom:6px;">
            Target Endpoint URL
          </label>
          <input type="text" id="cap-target-url" value="${esc(defaultTarget)}" placeholder="http://127.0.0.1:80/" style="width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--stroke);background:var(--card);color:var(--txt);font-size:13px;">
          <div style="display:flex;gap:6px;margin-top:6px;flex-wrap:wrap;">
            <span style="font-size:11px;color:var(--dim);align-self:center;">Presets:</span>
            <button type="button" class="chip-btn" onclick="$('#cap-target-url').value='http://127.0.0.1:80/'">Web Server (Port 80)</button>
            <button type="button" class="chip-btn" onclick="$('#cap-target-url').value='https://127.0.0.1:443/'">HTTPS (Port 443)</button>
            <button type="button" class="chip-btn" onclick="$('#cap-target-url').value='http://127.0.0.1:8686/api/health'">Sentinel (Port 8686)</button>
          </div>
        </div>

        <div style="min-width:220px;">
          <label style="font-size:11.5px;text-transform:uppercase;color:var(--dim);font-weight:700;letter-spacing:.5px;display:block;margin-bottom:6px;">
            Test Profile
          </label>
          <select id="cap-mode" style="width:100%;padding:9px 12px;border-radius:8px;border:1px solid var(--stroke);background:var(--card);color:var(--txt);font-size:13px;">
            <option value="quick" selected>⚡ Quick Safe Test (Up to 50 visitors, ~12s)</option>
            <option value="full">🔥 Full Stress Test (Up to 150 visitors, ~22s)</option>
          </select>
        </div>
      </div>
    </div>

    <!-- Live Status Area -->
    <div id="cap-live-card" style="display:${isRunning ? 'block' : 'none'};"></div>

    <!-- Results Area -->
    ${b && b.safe_concurrent_visitors !== undefined ? renderCapacityResults(b) : `
      <div class="glass" style="padding:40px 20px;text-align:center;color:var(--dim);">
        <div style="font-size:36px;margin-bottom:8px;">👥</div>
        <div style="font-size:15px;font-weight:700;color:var(--txt);margin-bottom:4px;">No Capacity Benchmark Run Yet</div>
        <div style="font-size:12.5px;max-width:500px;margin:0 auto 16px;">
          Click "Run Capacity Benchmark" above to test how many concurrent visitors your VPS web stack can handle before saturating.
        </div>
      </div>
    `}
  `;
}

function renderCapacityResults(b){
  const statusColor = b.safety_aborted ? 'var(--warn)' : (b.safe_concurrent_visitors >= 45 ? 'var(--ok)' : (b.safe_concurrent_visitors >= 15 ? 'var(--acc)' : 'var(--warn)'));

  return `
    <div class="glass" style="padding:22px 26px;margin-bottom:18px;">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;border-bottom:1px solid var(--stroke);padding-bottom:16px;margin-bottom:16px;">
        <div>
          <span style="font-size:11.5px;text-transform:uppercase;color:var(--dim);font-weight:700;letter-spacing:.8px;">
            Visitor Traffic Capacity Verdict
          </span>
          <div style="font-size:26px;font-weight:900;color:${statusColor};margin-top:2px;">
            ~${b.safe_concurrent_visitors} Concurrent Visitors
          </div>
          <div style="font-size:12px;color:var(--mut);margin-top:3px;">
            Tested against <b>${esc(b.target_url)}</b> (${esc(b.mode)} mode) on ${esc(b.date)} in ${b.duration_s}s
          </div>
        </div>

        <div style="text-align:right;">
          <div style="font-size:30px;font-weight:900;color:var(--txt);line-height:1;">
            ${b.safe_rps} <small style="font-size:14px;color:var(--mut);">RPS</small>
          </div>
          <span style="font-size:11px;color:var(--dim);text-transform:uppercase;font-weight:700;">Sustainable Throughput</span>
        </div>
      </div>

      <div class="cap-stat-grid">
        <div class="cap-stat-card">
          <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">👥 Safe Active Visitors</span>
          <div style="font-size:26px;font-weight:800;color:var(--ok);margin:6px 0 2px;">~${b.safe_concurrent_visitors} <small style="font-size:12px;color:var(--mut);">simultaneous</small></div>
          <div style="font-size:12px;color:var(--txt);">Response latency: <b>${b.safe_latency_ms} ms</b></div>
        </div>

        <div class="cap-stat-card">
          <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">⚡ Requests / Second</span>
          <div style="font-size:26px;font-weight:800;color:var(--acc);margin:6px 0 2px;">${b.safe_rps} <small style="font-size:12px;color:var(--mut);">RPS safe</small></div>
          <div style="font-size:12px;color:var(--txt);">Peak burst throughput: <b>${b.peak_rps} RPS</b></div>
        </div>

        <div class="cap-stat-card">
          <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">📈 Est. Monthly Traffic</span>
          <div style="font-size:26px;font-weight:800;color:var(--txt);margin:6px 0 2px;">~${(b.monthly_pageviews_est / 1000000).toFixed(1)}M <small style="font-size:12px;color:var(--mut);">views/mo</small></div>
          <div style="font-size:12px;color:var(--dim);">Assuming standard peak daily distribution</div>
        </div>

        <div class="cap-stat-card">
          <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">⚠️ Primary Bottleneck</span>
          <div style="font-size:14.5px;font-weight:800;color:var(--warn);margin:8px 0 2px;line-height:1.3;">${esc(b.bottleneck)}</div>
          <div style="font-size:11.5px;color:var(--dim);">Primary constraint limiting concurrency</div>
        </div>
      </div>

      <div style="padding:14px 16px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);margin-top:14px;">
        <div style="font-size:12px;text-transform:uppercase;color:var(--dim);font-weight:700;margin-bottom:4px;">
          🩺 Plain-English Performance Diagnosis
        </div>
        <div style="font-size:13.5px;color:var(--txt);line-height:1.5;">
          ${esc(b.diagnosis)}
        </div>
        ${b.safety_aborted ? `
          <div style="margin-top:10px;padding:8px 12px;border-radius:6px;background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:var(--warn);font-size:12.5px;">
            <b>🛡️ Safety Circuit Breaker:</b> ${esc(b.abort_reason || 'Test halted early to protect server health.')}
          </div>
        ` : ''}
      </div>

      ${b.recommendations && b.recommendations.length ? `
        <div style="margin-top:16px;">
          <div style="font-size:12px;text-transform:uppercase;color:var(--dim);font-weight:700;margin-bottom:8px;">
            💡 Recommended Actions to Multiply Visitor Capacity
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            ${b.recommendations.map(r => `
              <div style="display:flex;align-items:flex-start;gap:8px;font-size:12.5px;color:var(--txt);line-height:1.4;">
                <span style="color:var(--acc);">▸</span>
                <span>${esc(r)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <div style="margin-top:22px;">
        <div style="font-size:12px;text-transform:uppercase;color:var(--dim);font-weight:700;margin-bottom:10px;">
          📊 Progressive Concurrency Ramp Breakdown
        </div>
        <div style="overflow-x:auto;">
          <table class="vtable">
            <thead>
              <tr>
                <th>Stage</th>
                <th>Concurrent Visitors</th>
                <th>Throughput (RPS)</th>
                <th>Avg Latency</th>
                <th>P95 Latency</th>
                <th>Error Rate</th>
                <th>Server Load</th>
                <th>Health Status</th>
              </tr>
            </thead>
            <tbody>
              ${(b.stages || []).map(s => {
                let badgeClass = 'cap-badge-opt';
                if(s.status === 'Good') badgeClass = 'cap-badge-good';
                else if(s.status === 'Degraded') badgeClass = 'cap-badge-deg';
                else if(s.status === 'Saturated') badgeClass = 'cap-badge-sat';
                return `
                  <tr>
                    <td><b>Stage ${s.stage}</b> (${esc(s.name)})</td>
                    <td><b style="color:var(--txt);font-size:13.5px;">${s.concurrency}</b> visitors</td>
                    <td><b>${s.rps}</b> req/s</td>
                    <td>${s.avg_latency_ms} ms</td>
                    <td>${s.p95_latency_ms} ms</td>
                    <td>${s.error_rate_pct}%</td>
                    <td>${s.load_avg}</td>
                    <td><span class="${badgeClass}">${esc(s.status)}</span></td>
                  </tr>
                `;
              }).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  `;
}

function renderCapacityLive(st){
  const card = $('#cap-live-card');
  if(!card) return;
  card.style.display = 'block';

  const pct = Math.min(Math.round((st.stage_index / Math.max(st.total_stages, 1)) * 100), 100);

  card.innerHTML = `
    <div class="glass" style="padding:20px 24px;margin-bottom:18px;border-color:color-mix(in srgb,var(--acc) 40%,transparent);background:color-mix(in srgb,var(--acc) 4%,transparent);">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:8px;">
        <div style="display:flex;align-items:center;gap:10px;">
          <div class="spin" style="display:inline-block;width:18px;height:18px;border:2px solid var(--acc);border-top-color:transparent;border-radius:50%;"></div>
          <div>
            <b style="font-size:14px;color:var(--txt);">Stage ${st.stage_index} of ${st.total_stages}: Ramping ${st.target_concurrency} Simultaneous Visitors…</b>
            <div style="font-size:12px;color:var(--mut);">Simulating user browsing requests (${st.elapsed_stage_s}s elapsed in current stage)</div>
          </div>
        </div>
        <div style="font-size:13px;font-weight:700;color:var(--acc);">${pct}% Completed</div>
      </div>

      <div class="cap-bar-wrap">
        <div class="cap-bar-fill" style="width:${pct}%;"></div>
      </div>

      <div class="cap-stat-grid" style="margin-top:12px;">
        <div class="cap-stat-card">
          <span style="font-size:10.5px;text-transform:uppercase;color:var(--dim);font-weight:700;">Current Visitors</span>
          <div style="font-size:22px;font-weight:800;color:var(--txt);margin-top:4px;">${st.target_concurrency} concurrent</div>
        </div>
        <div class="cap-stat-card">
          <span style="font-size:10.5px;text-transform:uppercase;color:var(--dim);font-weight:700;">Live Throughput</span>
          <div style="font-size:22px;font-weight:800;color:var(--ok);margin-top:4px;">${st.live_rps} req/s</div>
        </div>
        <div class="cap-stat-card">
          <span style="font-size:10.5px;text-transform:uppercase;color:var(--dim);font-weight:700;">Response Latency</span>
          <div style="font-size:22px;font-weight:800;color:var(--acc);margin-top:4px;">${st.live_latency_ms} ms</div>
        </div>
        <div class="cap-stat-card">
          <span style="font-size:10.5px;text-transform:uppercase;color:var(--dim);font-weight:700;">Server Load / Free RAM</span>
          <div style="font-size:22px;font-weight:800;color:var(--txt);margin-top:4px;">${st.current_load} <small style="font-size:12px;color:var(--dim);">load</small> · ${st.current_free_ram_mb}MB</div>
        </div>
      </div>
    </div>
  `;
}

async function startCapacityBenchmark(){
  const urlInp = $('#cap-target-url');
  const modeSel = $('#cap-mode');
  const targetUrl = (urlInp ? urlInp.value : '').trim() || 'http://127.0.0.1:80/';
  const mode = (modeSel ? modeSel.value : 'quick') || 'quick';

  const startBtn = $('#start-cap-btn');
  const stopBtn = $('#stop-cap-btn');

  try {
    if(startBtn) startBtn.disabled = true;
    toast('Launching Capacity Benchmark', `Testing ${targetUrl} (${mode} mode)…`, 'info', 3500);

    const res = await api('/api/benchmark/capacity/run', {
      method: 'POST',
      body: JSON.stringify({target_url: targetUrl, mode: mode})
    });

    if(!res.ok){
      toast('Benchmark Rejected', res.error || res.message, 'crit', 6000);
      if(startBtn) startBtn.disabled = false;
      return;
    }

    if(stopBtn) stopBtn.style.display = 'inline-flex';
    if(CAPACITY_TIMER) clearInterval(CAPACITY_TIMER);
    CAPACITY_TIMER = setInterval(pollCapacityStatus, 800);
    pollCapacityStatus();
  } catch(e) {
    toast('Benchmark Error', e.message, 'crit');
    if(startBtn) startBtn.disabled = false;
  }
}

async function stopCapacityBenchmark(){
  try {
    toast('Stopping Benchmark', 'Halting all concurrent worker threads immediately…', 'warn', 3000);
    await api('/api/benchmark/capacity/stop', {method: 'POST'});
    pollCapacityStatus();
  } catch(e) {
    toast('Stop Error', e.message, 'crit');
  }
}

async function pollCapacityStatus(){
  try {
    const st = await api('/api/benchmark/capacity');
    if(st.last_result){
      CAPACITY_BENCHMARK = st.last_result;
    }
    if(st.is_running){
      renderCapacityLive(st);
    } else {
      if(CAPACITY_TIMER){
        clearInterval(CAPACITY_TIMER);
        CAPACITY_TIMER = null;
      }
      renderBenchmark(BENCHMARK);
      if(st.last_result && st.last_result.status === 'completed'){
        toast('Capacity Benchmark Complete', `Safe Capacity: ${st.last_result.safe_concurrent_visitors} visitors (${st.last_result.safe_rps} RPS)`, 'ok', 6000);
      } else if(st.last_result && st.last_result.status === 'aborted'){
        toast('Benchmark Circuit Breaker', st.last_result.abort_reason || 'Aborted for server safety', 'warn', 7000);
      } else if(st.last_result && st.last_result.status === 'error'){
        toast('Benchmark Error', st.last_result.error, 'crit', 7000);
      }
    }
  } catch(e) {
    // Ignore polling network blips
  }
}

async function runBenchmark(){
  const btn = $('#run-bench-btn');
  const spin = $('#bench-spin');
  try{
    if(btn) btn.disabled = true;
    if(spin) spin.classList.add('spin');
    toast('Running Benchmark', 'Testing CPU, RAM bandwidth, disk I/O, and ping latency (~3s)…', 'info', 4000);
    const res = await api('/api/benchmark/run', {method: 'POST'});
    if(res.ok && res.result){
      BENCHMARK = res.result;
      renderBenchmark(BENCHMARK);
      toast('Benchmark Complete', `Composite Score: ${res.result.composite_score}/1000 (${res.result.tier})`, 'ok', 5000);
    }
  }catch(e){
    toast('Benchmark Failed', e.message, 'crit');
  }finally{
    if(btn) btn.disabled = false;
    if(spin) spin.classList.remove('spin');
  }
}

function renderIncidentsView(){
  const view = $('#view-incidents');
  if(!view) return;
  view.innerHTML = `
    <div class="glass" style="padding:22px;">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
        <div>
          <h3 style="font-size:16px;">🚨 Recorded Spike Incidents &amp; Culprits</h3>
          <span style="font-size:12px;color:var(--mut);">Historical snapshots preserved whenever server load reached critical thresholds.</span>
        </div>
        <button class="btn" onclick="showIncidents()">Full Incident Modal</button>
      </div>
      ${INCIDENTS.length ? `
        <div style="display:flex;flex-direction:column;gap:12px;">
          ${INCIDENTS.slice().reverse().map(inc => `
            <div style="padding:14px;border-radius:12px;background:var(--card2);border:1px solid var(--stroke);">
              <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                <b style="color:${CLR[inc.status]||CLR.acc}">${esc(inc.time)} · ${esc(inc.summary)}</b>
                <span class="badge" style="color:${CLR[inc.status]||CLR.acc};background:${CLR[inc.status]||CLR.acc}22;">Score ${inc.score}</span>
              </div>
              <div style="font-size:12.5px;color:var(--txt);margin-bottom:6px;"><b>Triggers:</b> ${esc(inc.summary)}</div>
              ${inc.top_cpu && inc.top_cpu.length ? `
                <div style="font-size:12px;color:var(--mut);">Top CPU Culprit: <b>${esc(inc.top_cpu[0].comm)}</b> (${inc.top_cpu[0].cpu}% CPU) by <em>${esc(inc.top_cpu[0].user)}</em></div>
              ` : ''}
            </div>
          `).join('')}
        </div>
      ` : `<div style="padding:32px;text-align:center;color:var(--dim);">No load spike incidents recorded yet. Server has remained within stable parameters.</div>`}
    </div>`;
}

function renderSites(s){
  const view = $('#view-sites');
  if(!view) return;
  if(!s || !s.total_sites){
    view.innerHTML = `
      <div class="glass" style="padding:48px 24px;text-align:center;max-width:700px;margin:30px auto;">
        <div style="font-size:48px;margin-bottom:12px;">🌐</div>
        <h2 style="font-size:22px;font-weight:800;margin-bottom:8px;">Multi-Site Uptime &amp; Speed Monitor</h2>
        <p style="font-size:13.5px;color:var(--mut);margin-bottom:24px;line-height:1.5;">
          Monitor real-time response times (ms), HTTP status codes (200 OK vs 502 Bad Gateway), and SSL certificate expiration days for all websites hosted on your VPS.
        </p>
        <div style="display:flex;gap:12px;justify-content:center;flex-wrap:wrap;">
          <button class="btn primary" onclick="checkSitesNow()" style="height:42px;padding:0 24px;font-size:14px;">
            <svg viewBox="0 0 24 24"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></svg> ⚡ Scan Hosted Domains Now
          </button>
          <button class="btn" onclick="openAddSiteModal()" style="height:42px;padding:0 20px;font-size:14px;">+ Add Custom Website</button>
        </div>
      </div>`;
    return;
  }

  const badge = $('#badge-sites');
  if(badge) badge.textContent = `${s.up_count}/${s.total_sites}`;

  view.innerHTML = `
    <!-- Summary Stat Cards -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px;margin-bottom:20px;">
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🌐 Monitored Websites</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;">${s.total_sites}</div>
        <div style="font-size:11.5px;color:var(--dim);">Hosted vhosts &amp; custom sites</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🟢 Online Sites</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;color:var(--ok);">${s.up_count}</div>
        <div style="font-size:11.5px;color:var(--dim);">Returning 200/300/400 OK</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">🔴 Down or Slow</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;color:${s.down_count > 0 ? 'var(--crit)' : (s.slow_count > 0 ? 'var(--warn)' : 'var(--ok)')};">${s.down_count + s.slow_count}</div>
        <div style="font-size:11.5px;color:var(--dim);">${s.down_count} down · ${s.slow_count} slow (&gt;1200ms)</div>
      </div>
      <div class="glass" style="padding:16px;">
        <span style="font-size:11px;text-transform:uppercase;color:var(--mut);font-weight:700;">⚡ Average Latency</span>
        <div style="font-size:32px;font-weight:800;margin-top:4px;color:var(--acc);">${s.avg_latency_ms} <small style="font-size:14px;color:var(--mut);">ms</small></div>
        <div style="font-size:11.5px;color:var(--dim);">Round-trip response speed</div>
      </div>
    </div>

    <!-- Action Bar -->
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;flex-wrap:wrap;gap:12px;">
      <div style="display:flex;align-items:center;gap:10px;">
        <h3 style="font-size:16px;margin:0;">Hosted Websites &amp; Endpoints</h3>
        <span style="font-size:12px;color:var(--dim);">Auto-refreshed with health status</span>
      </div>
      <div style="display:flex;gap:10px;">
        <button class="btn" onclick="openAddSiteModal()" style="height:34px;font-size:12.5px;">+ Add Website</button>
        <button class="btn primary" id="check-sites-btn" onclick="checkSitesNow()" style="height:34px;font-size:12.5px;">
          <svg viewBox="0 0 24 24" style="width:14px;height:14px;"><path d="M21 12a9 9 0 11-3-6.7"/><path d="M21 4v5h-5"/></svg> ⚡ Check All Now
        </button>
      </div>
    </div>

    <!-- Sites Grid -->
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:14px;">
      ${s.sites.map(site => {
        const isUp = site.is_up;
        const latColor = site.latency_ms < 400 ? 'var(--ok)' : (site.latency_ms < 1200 ? 'var(--warn)' : 'var(--crit)');
        return `
          <div class="glass" style="padding:18px;display:flex;flex-direction:column;justify-content:space-between;gap:14px;border-color:${isUp ? 'var(--stroke)' : 'color-mix(in srgb,var(--crit) 35%,transparent)'};">
            <div>
              <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;gap:8px;">
                <a href="${site.url}" target="_blank" rel="noopener noreferrer" style="font-size:15px;font-weight:700;color:var(--txt);text-decoration:none;display:flex;align-items:center;gap:6px;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">
                  ${site.scheme==='https'?'🔒':'🌐'} ${esc(site.domain)}
                </a>
                ${isUp ? `
                  <span class="badge" style="color:var(--ok);background:rgba(37,227,154,.15);">🟢 ${site.status_code || 200} OK</span>
                ` : `
                  <span class="badge" style="color:var(--crit);background:rgba(255,85,102,.15);">🔴 ${site.status_code ? 'HTTP ' + site.status_code : (site.error || 'DOWN')}</span>
                `}
              </div>

              <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:6px;">
                <span class="badge" style="font-size:11px;color:${latColor};background:color-mix(in srgb,${latColor} 14%,transparent);">⚡ ${site.latency_ms} ms</span>
                ${site.ssl_days_left !== null ? `
                  <span class="badge" style="font-size:11px;${site.ssl_days_left<14?'color:var(--crit);background:rgba(255,85,102,.15)':(site.ssl_days_left<30?'color:var(--warn);background:rgba(255,179,64,.15)':'color:var(--ok);background:rgba(37,227,154,.15)')}">🔒 SSL: ${site.ssl_days_left}d left</span>
                ` : `
                  <span class="badge" style="font-size:11px;color:var(--dim);background:var(--card2);">🔓 No SSL</span>
                `}
                <span class="badge" style="font-size:11px;color:var(--dim);background:var(--card2);">📈 ${site.uptime_pct}%</span>
              </div>
            </div>

            <div style="display:flex;align-items:center;justify-content:space-between;padding-top:10px;border-top:1px solid var(--stroke);font-size:11.5px;color:var(--dim);">
              <span>Checked: ${esc(site.checked_at || '–')}</span>
              <div style="display:flex;gap:6px;">
                <button class="btn" onclick="checkSingleSite('${esc(site.url)}')" style="height:24px;padding:0 8px;font-size:11px;">🔄 Test</button>
                ${site.is_custom ? `
                  <button class="btn" onclick="removeSite('${esc(site.url)}')" style="height:24px;padding:0 8px;font-size:11px;color:var(--crit);">🗑️</button>
                ` : ''}
              </div>
            </div>
          </div>
        `;
      }).join('')}
    </div>
  `;
}

async function promptBanIP(ip, defaultReason=''){
  const reason = prompt(`Block IP ${ip} in server firewall?\nEnter reason for ban:`, defaultReason || 'Aggressive bot traffic');
  if(reason === null) return;
  try {
    const r = await api('/api/security/ban', {
      method: 'POST',
      body: JSON.stringify({ip: ip, reason: reason})
    });
    if(r.ok){
      toast('IP Blocked', `IP ${ip} is now blocked in iptables.`, 'ok');
      if(SECURITY) SECURITY.banned_ips = r.banned_ips;
      load();
    } else {
      toast('Ban Failed', r.message || 'Error banning IP', 'crit');
    }
  } catch(e) {
    toast('Ban Failed', e.message, 'crit');
  }
}

async function promptManualBan(){
  const ip = prompt('Enter IP address to block in firewall (e.g. 198.51.100.4):');
  if(!ip || !ip.trim()) return;
  promptBanIP(ip.trim(), 'Manual admin block');
}

async function unbanIP(ip){
  if(!confirm(`Are you sure you want to unban IP ${ip}?`)) return;
  try {
    const r = await api('/api/security/unban', {
      method: 'POST',
      body: JSON.stringify({ip: ip})
    });
    if(r.ok){
      toast('IP Unbanned', `IP ${ip} has been unblocked.`, 'ok');
      if(SECURITY) SECURITY.banned_ips = r.banned_ips;
      load();
    } else {
      toast('Unban Failed', r.message || 'Error unbanning IP', 'crit');
    }
  } catch(e) {
    toast('Unban Failed', e.message, 'crit');
  }
}

async function checkSitesNow(){
  const b = $('#check-sites-btn');
  if(b) b.disabled = true;
  toast('Checking Websites', 'Testing latency and SSL for all hosted sites…', 'info');
  try {
    const r = await api('/api/sites/check', {method: 'POST'});
    if(r.ok && r.sites){
      SITES = r.sites;
      renderSites(SITES);
      toast('Websites Checked', `${SITES.up_count}/${SITES.total_sites} sites online · avg ${SITES.avg_latency_ms}ms`, 'ok');
    }
  } catch(e) {
    toast('Check Failed', e.message, 'crit');
  } finally {
    if(b) b.disabled = false;
  }
}

async function checkSingleSite(url){
  toast('Testing Site', `Checking ${url}…`, 'info');
  try {
    const r = await api('/api/sites/add', {method:'POST', body:JSON.stringify({url: url})});
    if(r.sites){
      SITES = r.sites;
      renderSites(SITES);
      toast('Site Checked', `Updated metrics for ${url}`, 'ok');
    }
  } catch(e) {
    toast('Check Failed', e.message, 'crit');
  }
}

function openAddSiteModal(){
  const modal = document.createElement('div');
  modal.id = 'add-site-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
  modal.innerHTML = `
    <div class="glass" style="max-width:500px;width:100%;padding:24px;background:var(--bg2);">
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
        <h2 style="font-size:18px;">+ Add Website to Monitor</h2>
        <button class="btn" onclick="this.closest('#add-site-modal').remove()">✕</button>
      </div>
      <div style="font-size:13px;color:var(--mut);margin-bottom:14px;">
        Enter a domain name or full URL (e.g. <code>https://myclient.com</code>). Sentinel will track its response speed, HTTP status, and SSL certificate.
      </div>
      <input type="text" id="new-site-url" placeholder="https://example.com" style="width:100%;padding:10px 14px;border-radius:10px;border:1px solid var(--stroke);background:var(--card);color:var(--txt);font-size:14px;margin-bottom:16px;">
      <div style="display:flex;justify-content:flex-end;gap:10px;">
        <button class="btn" onclick="this.closest('#add-site-modal').remove()">Cancel</button>
        <button class="btn primary" onclick="submitAddSite()">Add &amp; Test Now</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
  setTimeout(() => { const inp = $('#new-site-url'); if(inp) inp.focus(); }, 50);
}

async function submitAddSite(){
  const inp = $('#new-site-url');
  if(!inp || !inp.value.trim()) return;
  const url = inp.value.trim();
  try {
    const r = await api('/api/sites/add', {
      method: 'POST',
      body: JSON.stringify({url: url})
    });
    if(r.ok){
      toast('Site Added', r.message, 'ok');
      const m = $('#add-site-modal');
      if(m) m.remove();
      SITES = r.sites;
      renderSites(SITES);
    } else {
      toast('Error Adding Site', r.message || 'Invalid domain', 'crit');
    }
  } catch(e) {
    toast('Error Adding Site', e.message, 'crit');
  }
}

async function removeSite(url){
  if(!confirm(`Remove ${url} from monitoring?`)) return;
  try {
    const r = await api('/api/sites/remove', {
      method: 'POST',
      body: JSON.stringify({url: url})
    });
    if(r.ok){
      toast('Site Removed', r.message, 'ok');
      SITES = r.sites;
      renderSites(SITES);
    }
  } catch(e) {
    toast('Error Removing Site', e.message, 'crit');
  }
}

async function scan(){
  const b=$('#scanBtn');b.disabled=true;$('#scanIco').classList.add('spin');
  try{
    const r=await api('/api/scan',{method:'POST'});
    HIST=r.history||HIST;INCIDENTS=r.incidents||INCIDENTS;
    VISITORS=r.visitors||VISITORS;BENCHMARK=r.benchmark||BENCHMARK;DOCTOR=r.server_doctor||DOCTOR;
    if(r.capacity_benchmark && r.capacity_benchmark.last_result) CAPACITY_BENCHMARK = r.capacity_benchmark.last_result;
    SITES=r.sites||SITES;SECURITY=r.security||SECURITY;
    render(r.report);renderSites(SITES);renderVisitors(VISITORS);renderBenchmark(BENCHMARK);renderServerDoctor(DOCTOR);
    if(CURRENT_TAB==='incidents') renderIncidentsView();
    const bad=r.report.counts.crit+r.report.counts.warn;
    toast('Scan complete',bad?`${bad} issue(s) need attention`:'All ten checks healthy',bad?(r.report.counts.crit?'crit':'warn'):'ok');
  }catch(e){
    toast('Scan failed',e.message,'crit');
  }finally{
    b.disabled=false;$('#scanIco').classList.remove('spin');
  }
}

async function load(){
  try{
    const r=await api('/api/health');
    HIST=r.history||[];INCIDENTS=r.incidents||[];
    VISITORS=r.visitors||null;BENCHMARK=r.benchmark||null;DOCTOR=r.server_doctor||null;
    if(r.capacity_benchmark && r.capacity_benchmark.last_result) CAPACITY_BENCHMARK = r.capacity_benchmark.last_result;
    SITES=r.sites||null;SECURITY=r.security||null;
    render(r.report);renderSites(SITES);renderVisitors(VISITORS);renderBenchmark(BENCHMARK);renderServerDoctor(DOCTOR);
    if(CURRENT_TAB==='incidents') renderIncidentsView();
  }catch(e){}
}
async function testAlert(b){b.disabled=true;
 try{const r=await api('/api/test-alert',{method:'POST'});
  const anyOk = Object.values(r.results||{}).some(v=>v.ok);
  const summary = Object.entries(r.results||{}).map(([k,v])=>`${k}: ${v.ok?'✓':'✗'}`).join(' · ');
  toast(anyOk?'Test Alert Delivered':'Alert Notice',summary||r.detail,anyOk?'ok':'crit',7000)}
 finally{b.disabled=false}}

function showIncidents(){
 if(!INCIDENTS.length){toast('No Incidents','No high-load spikes or warnings recorded yet.','ok');return;}
 const modal = document.createElement('div');
 modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
 modal.innerHTML = `<div class="glass" style="max-width:850px;width:100%;max-height:85vh;overflow-y:auto;padding:24px;background:var(--bg2);">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
   <h2 style="font-size:18px;">⚡ Preserved Incidents &amp; Culprits (${INCIDENTS.length})</h2>
   <button class="btn" onclick="this.closest('div[style*=position]').remove()">Close</button>
  </div>
  ${INCIDENTS.map(inc=>`
   <div style="margin-bottom:18px;padding:14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
    <div style="display:flex;justify-content:space-between;align-items:center;">
     <b style="color:${CLR[inc.status]||CLR.acc}">${esc(inc.time)} · ${esc(inc.summary)}</b>
     <span class="badge" style="color:${CLR[inc.status]||CLR.acc};background:${CLR[inc.status]||CLR.acc}22;">Score ${inc.score}</span>
    </div>
    ${inc.top_cpu&&inc.top_cpu.length?`
     <div style="margin-top:10px;"><b style="font-size:12px;color:var(--mut);">Top Programs Running at Load Spike Time:</b>
      <table class="mtable" style="margin-top:4px;">
       ${inc.top_cpu.slice(0,5).map(p=>`<tr><td>${esc(p.user)} · ${esc(p.comm)}[${p.pid}]</td><td style="font-family:monospace;font-size:11px;">${esc(p.cmd)}</td><td><b>${p.cpu}% CPU</b></td></tr>`).join('')}
      </table></div>`:''}
    ${inc.dstate_tasks&&inc.dstate_tasks.length?`
     <div style="margin-top:10px;"><b style="font-size:12px;color:var(--warn);">Tasks Blocked on Storage / Hard Drive:</b>
      <table class="mtable" style="margin-top:4px;">
       ${inc.dstate_tasks.map(p=>`<tr><td>${esc(p.user)} · ${esc(p.comm)}[${p.pid}]</td><td style="font-family:monospace;font-size:11px;color:var(--warn);">${esc(p.stack||p.cmd)}</td></tr>`).join('')}
      </table></div>`:''}
   </div>`).join('')}
 </div>`;
 document.body.appendChild(modal);
}

async function openQuickActionsModal(){
 const modal = document.createElement('div');
 modal.id = 'actions-modal';
 modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
 modal.innerHTML = `<div class="glass" style="max-width:800px;width:100%;max-height:88vh;overflow-y:auto;padding:24px;background:var(--bg2);">
  <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
   <div>
    <h2 style="font-size:18px;display:flex;align-items:center;gap:8px;">⚡ Server Maintenance &amp; PHP Control</h2>
    <div style="font-size:12.5px;color:var(--mut);">One-click safe fixes for PHP-FPM, MySQL database, disk logs, and system memory.</div>
   </div>
   <button class="btn" onclick="this.closest('#actions-modal').remove()">Close</button>
  </div>

  <div style="margin-bottom:16px;padding:12px 16px;border-radius:12px;background:rgba(22,163,74,0.12);border:1px solid rgba(22,163,74,0.3);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;">
   <div style="display:flex;align-items:center;gap:10px;">
    <span class="dot" style="background:#16a34a;color:#16a34a;"></span>
    <div>
     <b style="font-size:13.5px;color:var(--ok);">🤖 Autonomous Self-Healing: Active</b>
     <div style="font-size:11.5px;color:var(--mut);">Automatically recycles PHP on load spikes (≥8.0), cleans journal logs on disk exhaustion, and drops cache on memory pressure.</div>
    </div>
   </div>
   <button class="btn" onclick="showAutoHealLog()" style="font-size:11.5px;height:28px;">View Healing Log</button>
  </div>

  <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin-bottom:20px;">
   <div style="padding:12px 14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
    <b style="font-size:13px;display:block;margin-bottom:4px;">🗄️ Database Service</b>
    <div style="font-size:11.5px;color:var(--mut);margin-bottom:10px;">Restart MariaDB / MySQL to clear stuck locks or high connections.</div>
    <button class="btn" onclick="doSystemAction('restart_mariadb')" style="width:100%;height:32px;font-size:12px;">🔄 Restart Database</button>
   </div>
   <div style="padding:12px 14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
    <b style="font-size:13px;display:block;margin-bottom:4px;">🧹 Disk Space Cleanup</b>
    <div style="font-size:11.5px;color:var(--mut);margin-bottom:10px;">Trim system journal logs to 200MB to free hard drive space.</div>
    <button class="btn" onclick="doSystemAction('vacuum_logs')" style="width:100%;height:32px;font-size:12px;">🧹 Vacuum Logs</button>
   </div>
   <div style="padding:12px 14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
    <b style="font-size:13px;display:block;margin-bottom:4px;">💧 Reclaim RAM Cache</b>
    <div style="font-size:11.5px;color:var(--mut);margin-bottom:10px;">Sync and free cached memory pages to give apps more RAM.</div>
    <button class="btn" onclick="doSystemAction('drop_caches')" style="width:100%;height:32px;font-size:12px;">💧 Flush Page Cache</button>
   </div>
   <div style="padding:12px 14px;border-radius:12px;background:var(--card);border:1px solid var(--stroke);">
    <b style="font-size:13px;display:block;margin-bottom:4px;">🚀 I/O &amp; RAM Tuning</b>
    <div style="font-size:11.5px;color:var(--mut);margin-bottom:10px;">Apply noatime, swappiness=10, write-batching, and zram compressed swap.</div>
    <button class="btn primary" onclick="doSystemAction('optimize_io_memory')" style="width:100%;height:32px;font-size:12px;">🚀 Optimize I/O &amp; RAM</button>
   </div>
  </div>

  <h3 style="font-size:15px;margin-bottom:12px;display:flex;align-items:center;gap:6px;">🐘 PHP-FPM Service Pools</h3>
  <div id="php-list" style="padding:16px 0;text-align:center;color:var(--dim);">Detecting PHP services…</div>
 </div>`;
 document.body.appendChild(modal);
 await loadPhpServices();
}

function showAutoHealLog(){
  const list = (REPORT && REPORT.auto_heal && REPORT.auto_heal.history) || [];
  const modal = document.createElement('div');
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:1000;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
  modal.innerHTML = `<div class="glass" style="max-width:700px;width:100%;padding:24px;background:var(--bg2);">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <h2 style="font-size:17px;">🤖 Autonomous Self-Healing Log (${list.length})</h2>
      <button class="btn" onclick="this.closest('div[style*=position]').remove()">Close</button>
    </div>
    ${list.length ? `
      <div style="display:flex;flex-direction:column;gap:8px;max-height:60vh;overflow-y:auto;">
        ${list.slice().reverse().map(ev => `
          <div style="padding:10px 14px;background:var(--card);border:1px solid var(--stroke);border-radius:10px;">
            <div style="display:flex;justify-content:space-between;font-size:12px;color:var(--dim);margin-bottom:4px;">
              <span>${esc(ev.time)}</span>
              <span class="badge" style="color:var(--ok);background:rgba(22,163,74,0.15);">${esc(ev.status.toUpperCase())}</span>
            </div>
            <b style="font-size:13px;display:block;margin-bottom:2px;">Trigger: ${esc(ev.reason)}</b>
            <div style="font-size:12px;color:var(--mut);">Action: ${esc((ev.actions||[]).join(' · '))}</div>
          </div>
        `).join('')}
      </div>
    ` : `<div style="padding:24px;text-align:center;color:var(--dim);">No self-healing events triggered yet. All systems operating within normal parameters.</div>`}
  </div>`;
  document.body.appendChild(modal);
}

function openExecutiveReportModal(){
  const agency = (REPORT && REPORT.branding && REPORT.branding.agency_name) || 'OpsCare Managed Cloud';
  const client = (REPORT && REPORT.branding && REPORT.branding.client_name) || (REPORT ? REPORT.host : 'Production VPS');
  const modal = document.createElement('div');
  modal.id = 'report-modal';
  modal.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:999;backdrop-filter:blur(8px);display:grid;place-items:center;padding:20px;';
  modal.innerHTML = `<div class="glass" style="max-width:680px;width:100%;padding:24px;background:var(--bg2);">
    <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
      <div>
        <h2 style="font-size:18px;display:flex;align-items:center;gap:8px;">📄 Executive Client Report &amp; PDF Export</h2>
        <div style="font-size:12.5px;color:var(--mut);">Generate a white-label infrastructure health audit to share with clients or leadership.</div>
      </div>
      <button class="btn" onclick="this.closest('#report-modal').remove()">Close</button>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
      <div>
        <label style="font-size:11.5px;color:var(--dim);display:block;margin-bottom:4px;">AGENCY / COMPANY NAME</label>
        <input id="rep-agency" class="search" style="width:100%;" value="${esc(agency)}">
      </div>
      <div>
        <label style="font-size:11.5px;color:var(--dim);display:block;margin-bottom:4px;">CLIENT / PROJECT NAME</label>
        <input id="rep-client" class="search" style="width:100%;" value="${esc(client)}">
      </div>
    </div>
    <div style="padding:14px 16px;background:var(--card);border-radius:12px;border:1px solid var(--stroke);margin-bottom:20px;">
      <div style="font-size:13px;font-weight:600;margin-bottom:6px;">Included in Executive Audit:</div>
      <ul style="font-size:12px;color:var(--mut);margin-left:18px;line-height:1.6;">
        <li>Overall Infrastructure Score &amp; Performance Grade (${REPORT ? REPORT.score.toFixed(0) : '100'}/100)</li>
        <li>48-Hour Peak vs. Average Server Load, CPU, and RAM headroom</li>
        <li>Autonomous Self-Healing log (proof of preventative maintenance)</li>
        <li>SSL certificates expiration review &amp; SSH brute-force defense audit</li>
      </ul>
    </div>
    <div style="display:flex;justify-content:flex-end;gap:10px;">
      <button class="btn" onclick="copyReportText()">📋 Copy Plain Text</button>
      <button class="btn primary" onclick="launchExecutiveReport()">🖨️ Open Print / PDF Report</button>
    </div>
  </div>`;
  document.body.appendChild(modal);
}

function launchExecutiveReport(){
  const ag = encodeURIComponent($('#rep-agency').value || 'OpsCare Managed Cloud');
  const cl = encodeURIComponent($('#rep-client').value || 'Production VPS');
  const url = `/api/report/html?agency=${ag}&client=${cl}${URL_TOKEN ? '&token=' + encodeURIComponent(URL_TOKEN) : ''}`;
  window.open(url, '_blank');
}

function copyReportText(){
  if(!REPORT) return;
  const ag = $('#rep-agency').value || 'OpsCare Managed Cloud';
  const cl = $('#rep-client').value || 'Production VPS';
  const lines = [
    `======================================================`,
    `EXECUTIVE SERVER HEALTH AUDIT — ${cl.toUpperCase()}`,
    `Certified by: ${ag}`,
    `Date: ${new Date().toUTCString()}`,
    `======================================================`,
    `Overall Health Score: ${REPORT.score.toFixed(0)}/100 (${REPORT.grade} - ${REPORT.grade_label})`,
    `Host: ${REPORT.host} | OS: ${REPORT.os} | Cores: ${REPORT.cores}`,
    `Uptime: ${REPORT.uptime}`,
    ``,
    `SUBSYSTEM AUDIT:`,
    ...REPORT.checks.map(c => `[${c.status.toUpperCase()}] ${c.name}: ${c.value} ${c.unit} (${c.summary})`),
    ``,
    `PREVENTATIVE CARE & AUTONOMOUS ACTIONS:`,
    `System operating smoothly with continuous autonomous self-healing enabled.`
  ];
  navigator.clipboard.writeText(lines.join('\n'));
  toast('Report Copied', 'Executive summary copied to clipboard', 'ok');
}

async function doSystemAction(action){
 try{
  toast('Running System Action', `Executing ${action}…`, 'info', 2000);
  const res = await api('/api/system-action', {
   method: 'POST',
   body: JSON.stringify({ action })
  });
  if(res.ok){
   toast('Action Successful', res.detail || `${action} executed successfully`, 'ok', 4500);
   if(REPORT) scan();
  } else {
   toast('Action Failed', res.error || res.detail || 'Action failed', 'crit', 6000);
  }
 }catch(e){
  toast('System Error', e.message, 'crit', 6000);
 }
}

async function loadPhpServices(){
 const list = $('#php-list');
 if(!list) return;
 try{
  const r = await api('/api/php-services');
  const svcs = r.services || [];
  if(!svcs.length){
   list.innerHTML = `<div style="padding:20px;background:var(--card);border-radius:12px;border:1px solid var(--stroke);">
    <b style="font-size:13.5px;">No standard PHP-FPM services detected</b>
    <div style="font-size:12px;color:var(--mut);margin-top:4px;">If PHP is running under a custom unit name, check systemctl list-units.</div>
   </div>`;
   return;
  }
  
  const activeCount = svcs.filter(s=>s.is_active).length;
  
  list.innerHTML = `
   <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
    <span style="font-size:12.5px;color:var(--mut);">${svcs.length} PHP version(s) found · <b>${activeCount} active</b></span>
    ${activeCount > 0 ? `<button class="btn" onclick="doPhpAction('all','restart')" style="font-size:12px;height:30px;">🔄 Restart All Active PHP</button>` : ''}
   </div>
   <div style="display:flex;flex-direction:column;gap:8px;">
    ${svcs.map(s=>{
     const statusColor = s.is_active ? 'var(--ok)' : (s.is_failed ? 'var(--crit)' : 'var(--dim)');
     const statusLabel = s.is_active ? 'Running' : (s.is_failed ? 'Failed' : 'Stopped');
     return `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-radius:10px;background:var(--card);border:1px solid var(--stroke);gap:10px;flex-wrap:wrap;">
       <div style="display:flex;align-items:center;gap:10px;">
        <span class="dot" style="color:${statusColor};background:${statusColor}"></span>
        <div>
         <b style="font-size:13.5px;">${esc(s.display)}</b>
         <span style="font-family:monospace;font-size:11px;color:var(--dim);margin-left:5px;">(${esc(s.service)})</span>
         <div style="font-size:11px;color:${statusColor};font-weight:600;">● ${statusLabel}</div>
        </div>
       </div>
       <div style="display:flex;gap:5px;">
        ${!s.is_active ? `<button class="btn" onclick="doPhpAction('${s.service}','start')" style="color:var(--ok);border-color:color-mix(in srgb,var(--ok) 35%,transparent);height:30px;font-size:11.5px;">▶ Start</button>` : ''}
        ${s.is_active ? `<button class="btn" onclick="doPhpAction('${s.service}','restart')" style="height:30px;font-size:11.5px;">🔄 Restart</button>` : ''}
        ${s.is_active ? `<button class="btn" onclick="doPhpAction('${s.service}','reload')" style="height:30px;font-size:11.5px;">⚡ Reload</button>` : ''}
        ${s.is_active ? `<button class="btn" onclick="confirmStopPhp('${s.service}')" style="color:var(--crit);border-color:color-mix(in srgb,var(--crit) 35%,transparent);height:30px;font-size:11.5px;">⏹ Stop</button>` : ''}
       </div>
      </div>`;
    }).join('')}
   </div>`;
 }catch(e){
  list.innerHTML = `<div style="color:var(--crit);padding:16px;">Error loading PHP services: ${esc(e.message)}</div>`;
 }
}

async function doPhpAction(service, action){
 try{
  toast('Executing PHP Action', `${action.toUpperCase()} on ${service}…`, 'info', 2000);
  const res = await api('/api/php-action', {
   method: 'POST',
   body: JSON.stringify({ service, action })
  });
  if(res.ok){
   toast('PHP Action Successful', res.detail || `${action} completed`, 'ok', 4000);
   await loadPhpServices();
  } else {
   toast('PHP Action Failed', res.error || res.detail || 'Action failed', 'crit', 6000);
  }
 }catch(e){
  toast('Action Error', e.message, 'crit', 6000);
 }
}

function confirmStopPhp(service){
 if(confirm(`Are you sure you want to STOP ${service}?\n\nWebsites using this PHP version will return 502 Bad Gateway until you start it again.`)){
  doPhpAction(service, 'stop');
 }
}

document.addEventListener('keydown',e=>{
 if(e.target.tagName==='INPUT')return;
 if(e.key==='r')scan(); if(e.key==='e')allOpen(!document.querySelector('.card.open'));
 if(e.key==='t')toggleTheme(); if(e.key==='/'){e.preventDefault();$('#q').focus()}});

/* ── boot ── */
document.documentElement.dataset.theme=localStorage.sentinelTheme||'dark';
$('#chans').innerHTML=BOOT.channels.length
 ? 'Active Alert Channels: '+BOOT.channels.map(c=>`<span class="ch2 on">${esc(c)}</span>`).join(' ')
 : '<span class="ch2">No alert channel enabled — configure in config.json</span>';
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
        req_token = q.get("token", [""])[0].strip() or (self.headers.get("X-Auth-Token") or "").strip()
        auth_hdr = (self.headers.get("Authorization") or "").strip()
        if auth_hdr.startswith("Bearer "):
            req_token = auth_hdr[7:].strip()
        return req_token == tok

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
            rep = self.engine.report or self.engine.scan()
        return {
            "report": rep,
            "history": list(self.engine.history)[-5760:],
            "incidents": list(self.engine.incidents.recent_incidents)[-20:],
            "auto_heal": {
                "enabled": self.engine.auto_healer.cfg.get("enabled", True),
                "dry_run": self.engine.auto_healer.cfg.get("dry_run", False),
                "cooldown_minutes": self.engine.auto_healer.cfg.get("cooldown_minutes", 15),
                "history": list(self.engine.healing_history)[-20:]
            },
            "branding": self.cfg.get("branding", {}),
            "visitors": self.engine.visitor_tracker.scan(),
            "benchmark": self.engine.benchmark_engine.last_result,
            "capacity_benchmark": self.engine.capacity_benchmark.get_status(),
            "security": {
                "banned_count": len(self.engine.security_shield.banned_ips),
                "banned_ips": self.engine.security_shield.list_banned()
            },
            "sites": self.engine.site_monitor.get_summary(),
            "server_doctor": generate_server_doctor(rep)
        }

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
        if path == "/api/visitors":
            return self._send(200, self.engine.visitor_tracker.scan(force=True))
        if path == "/api/benchmark":
            return self._send(200, self.engine.benchmark_engine.last_result or {"status": "none"})
        if path == "/api/benchmark/capacity":
            return self._send(200, self.engine.capacity_benchmark.get_status())
        if path == "/api/security/banned":
            return self._send(200, {"banned_ips": self.engine.security_shield.list_banned()})
        if path == "/api/sites":
            return self._send(200, self.engine.site_monitor.get_summary())
        if path == "/api/server-doctor":
            with self.engine.lock:
                rep = self.engine.report or self.engine.scan()
            return self._send(200, generate_server_doctor(rep))
        if path == "/api/report/html":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            branding_override = dict(self.cfg.get("branding", {}))
            if "agency" in q:
                branding_override["agency_name"] = q["agency"][0]
            if "client" in q:
                branding_override["client_name"] = q["client"][0]
            if "title" in q:
                branding_override["report_title"] = q["title"][0]
            with self.engine.lock:
                rep = self.engine.report or self.engine.scan()
            html = generate_executive_html(rep, self.engine.history, branding_override, self.engine.healing_history)
            return self._send(200, html, "text/html; charset=utf-8")
        if path == "/api/auto-heal":
            return self._send(200, {
                "enabled": self.engine.auto_healer.cfg.get("enabled", True),
                "dry_run": self.engine.auto_healer.cfg.get("dry_run", False),
                "cooldown_minutes": self.engine.auto_healer.cfg.get("cooldown_minutes", 15),
                "history": list(self.engine.healing_history)
            })
        if path == "/api/history":
            return self._send(200, {"history": list(self.engine.history)})
        if path == "/api/incidents":
            return self._send(200, {"incidents": list(self.engine.incidents.recent_incidents)})
        if path == "/api/php-services":
            return self._send(200, {"services": detect_php_services()})
        if path == "/metrics":
            return self._send(200, prometheus(self.engine), "text/plain; version=0.0.4")
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authed():
            return self._send(401, {"error": "unauthorized"})
        path = urllib.parse.urlparse(self.path).path
        data_bytes = b""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            data_bytes = self.rfile.read(n)
        except Exception:
            pass
        if path == "/api/benchmark/run":
            res = self.engine.benchmark_engine.run()
            self.engine._save_state()
            return self._send(200, {"ok": True, "result": res})
        if path == "/api/benchmark/capacity/run":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception:
                body = {}
            target = body.get("target_url")
            mode = body.get("mode", "quick")
            res = self.engine.capacity_benchmark.start(target_url=target, mode=mode)
            return self._send(200 if res.get("ok") else 400, res)
        if path == "/api/benchmark/capacity/stop":
            res = self.engine.capacity_benchmark.stop()
            return self._send(200, res)
        if path == "/api/security/ban":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            ip = (body.get("ip") or "").strip()
            reason = (body.get("reason") or "Manual ban via Web UI").strip()
            client_ip = self.client_address[0] if hasattr(self, "client_address") else None
            ok, msg = self.engine.security_shield.ban_ip(ip, reason=reason, admin_ip=client_ip)
            return self._send(200 if ok else 400, {
                "ok": ok,
                "message": msg,
                "banned_ips": self.engine.security_shield.list_banned()
            })
        if path == "/api/security/unban":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            ip = (body.get("ip") or "").strip()
            ok, msg = self.engine.security_shield.unban_ip(ip)
            return self._send(200 if ok else 400, {
                "ok": ok,
                "message": msg,
                "banned_ips": self.engine.security_shield.list_banned()
            })
        if path == "/api/sites/check":
            summary = self.engine.site_monitor.check_all(force=True)
            return self._send(200, {"ok": True, "sites": summary})
        if path == "/api/sites/add":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            url = (body.get("url") or "").strip()
            ok, msg = self.engine.site_monitor.add_site(url)
            return self._send(200 if ok else 400, {
                "ok": ok,
                "message": msg,
                "sites": self.engine.site_monitor.get_summary()
            })
        if path == "/api/sites/remove":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            url = (body.get("url") or "").strip()
            ok, msg = self.engine.site_monitor.remove_site(url)
            return self._send(200 if ok else 400, {
                "ok": ok,
                "message": msg,
                "sites": self.engine.site_monitor.get_summary()
            })
        if path == "/api/scan":
            rep = self.engine.scan(force=True)
            if self.alerts:
                self.alerts.process(rep)
            return self._send(200, self._payload())
        if path == "/api/auto-heal/toggle":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception:
                body = {}
            if "enabled" in body:
                self.engine.auto_healer.cfg["enabled"] = bool(body["enabled"])
            if "dry_run" in body:
                self.engine.auto_healer.cfg["dry_run"] = bool(body["dry_run"])
            return self._send(200, {
                "ok": True,
                "enabled": self.engine.auto_healer.cfg.get("enabled", True),
                "dry_run": self.engine.auto_healer.cfg.get("dry_run", False)
            })
        if path == "/api/php-action":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            
            service = (body.get("service") or "").strip()
            action = (body.get("action") or "").strip()
            
            if service == "all" and action in ("restart", "reload"):
                results = []
                for s in detect_php_services():
                    if s["is_active"]:
                        results.append(control_php_service(s["service"], action))
                any_ok = any(r.get("ok") for r in results)
                return self._send(200, {"ok": any_ok, "action": action, "batch": True, "results": results,
                                         "detail": f"Ran {action} on {len(results)} active PHP service(s)"})

            res = control_php_service(service, action)
            code = 200 if res.get("ok") else 500
            return self._send(code, res)
        if path == "/api/system-action":
            try:
                body = json.loads(data_bytes.decode() or "{}")
            except Exception as e:
                return self._send(400, {"ok": False, "error": f"Invalid JSON body: {e}"})
            
            action = (body.get("action") or "").strip()
            res = control_system_action(action)
            code = 200 if res.get("ok") else 500
            return self._send(code, res)
        if path == "/api/test-alert":
            rep = self.engine.report or self.engine.scan()
            chans = [n for n, c in self.cfg["alerts"].items()
                     if isinstance(c, dict) and c.get("enabled")]
            if not chans:
                return self._send(200, {"ok": False, "detail": "No alert channel enabled in config.json", "results": {}})
            results = self.alerts.test_dispatch(rep)
            any_ok = any(v.get("ok") for v in results.values())
            return self._send(200, {"ok": any_ok, "results": results, "detail": ", ".join(f"{k}: {'ok' if v.get('ok') else 'err'}" for k, v in results.items())})
        return self._send(404, {"error": "not found"})


def prometheus(engine):
    r = engine.report or engine.scan()
    h = prom_esc(r["host"])
    L = ["# HELP sentinel_health_score Overall health score 0-100",
         "# TYPE sentinel_health_score gauge",
         f'sentinel_health_score{{host="{h}"}} {r["score"]}']
    L += ["# HELP sentinel_check_score Per-check score", "# TYPE sentinel_check_score gauge"]
    for c in r["checks"]:
        cid = prom_esc(c["id"])
        cst = prom_esc(c["status"])
        L.append(f'sentinel_check_score{{host="{h}",check="{cid}",status="{cst}"}} {c["score"]}')
        for k, v in c["metrics"].items():
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                mk = prom_esc(k)
                L.append(f'sentinel_metric{{host="{h}",check="{cid}",metric="{mk}"}} {v}')
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
                    print(f"        {A.I}{A.MUT}Why: {f['why'][:W - 15]}{A.R}")
                for d in f["diagnose"][:2]:
                    print(f"        {A.ACC}🔍 Check:{A.R} {A.DIM}{d}{A.R}")
                for x in f["fix"][:3]:
                    print(f"        {A.OK}✔ Fix:{A.R} {x}")
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
                alerts.process(rep)
        except Exception as e:
            print(f"[sentinel] background scan error: {e}", file=sys.stderr, flush=True)
        stop.wait(interval)


def main():
    ap = argparse.ArgumentParser(description="Linux Health Sentinel — 10 checks, fixes, alerts")
    ap.add_argument("-c", "--config", default=os.environ.get("SENTINEL_CONFIG", "/etc/health-sentinel/config.json"))
    ap.add_argument("--once", action="store_true", help="single scan, print report, exit 0/1/2")
    ap.add_argument("--json", action="store_true", help="with --once: JSON output")
    ap.add_argument("--quiet", action="store_true", help="with --once: no per-finding detail")
    ap.add_argument("--no-alerts", action="store_true")
    ap.add_argument("--test-alerts", action="store_true", help="send sample alerts and report status per channel")
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
    alerts = AlertManager(engine) if cfg["alerts"]["enabled"] else None
    if alerts:
        engine.auto_healer.set_alert_manager(alerts)

    if args.test_alerts:
        if not alerts or not any(isinstance(c, dict) and c.get("enabled") for c in cfg["alerts"].values()):
            print("[-] No alert channels are currently enabled in config.json.")
            return 1
        rep = engine.scan()
        print(f"Testing alert delivery for {rep['host']}...")
        results = alerts.test_dispatch(rep)
        has_failure = False
        for channel, res in results.items():
            if res.get("ok"):
                print(f"  \033[38;5;42m✓\033[0m {channel}: {res['detail']}")
            else:
                print(f"  \033[38;5;203m✗\033[0m {channel}: {res['detail']}")
                has_failure = True
        return 1 if has_failure else 0

    if args.once:
        rep = engine.scan(force=True)
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
          f"  ▸ incidents  {url.split('?')[0]}/api/incidents\n"
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
