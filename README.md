# 🛡️ Linux Health Sentinel

A **zero-dependency** (pure Python 3 stdlib) Linux server health platform featuring:

* **Top-10 Core Linux Health Probes**: CPU utilization & steal time, normalized load average, memory & swap pressure (with PSI), disk space & read-only detection, disk I/O bottlenecks & await latencies, inode exhaustion & open file handles, network drops/errors/retransmits/conntrack, processes/threads/zombies/D-state, systemd failed services/uptime/reboot flags/NTP, and journal errors/SSH brute-force detection.
* **0–100 Scoring Engine**: Linear threshold interpolation, severity caps (max 54 for critical, max 79 for warning), and letter grades (A+ through F).
* **Actionable Remediation**: Every warning or critical finding includes *Why it matters*, exact **① Diagnose** commands, and copy-pasteable **② Fix** commands with specific values.
* **Embedded Glassmorphic Web Dashboard**: Dark/Light aurora gradient themes, animated health ring gauge, live KPI sparkline charts, severity filtering, instant diagnostic expansion, and live auto-refresh.
* **Multi-Channel Alerting**: Email (HTML & plain-text via SMTP/TLS/SSL), Slack, Telegram, ntfy, custom Webhooks, and Desktop notifications with anti-flap protection (2 consecutive scans default), per-check cooldowns, and automatic recovery notices.
* **DevOps & Monitoring Ready**: Prometheus metrics exposition endpoint at `/metrics`, JSON API, and a beautiful CLI mode (`--once`) with Nagios-style exit codes (`0` = OK, `1` = WARNING, `2` = CRITICAL).

---

## 📁 Repository Structure

```
linux-health-sentinel/
├── sentinel.py              # Single-file daemon, web UI, checks, scoring & alerts
├── config.json              # Thresholds, intervals, and notification credentials
├── deploy/
│   ├── sentinel.service     # Systemd daemon service (web UI + background alerts)
│   ├── sentinel-cron.service# Systemd oneshot unit for scheduled/cron scans
│   └── sentinel-cron.timer  # Systemd 5-minute timer for periodic checks
└── README.md                # Documentation and setup guide
```

---

## 🚀 Quick Start

### 1. Requirements
* Linux OS (Ubuntu, Debian, RHEL, Rocky, Alma, CentOS, Fedora, Arch, etc.)
* Python 3.7+ (pure standard library; no `pip` or virtualenv required)

### 2. Run Instantly (CLI Mode)
```bash
# Instant formatted CLI report
sudo python3 sentinel.py --once

# JSON output for scripting / Nagios / Zabbix / CI
sudo python3 sentinel.py --once --json
```

### 3. Launch the Web Dashboard
```bash
sudo python3 sentinel.py --bind 0.0.0.0 --port 8686
```
Open `http://<server-ip>:8686` in your browser.

---

## ⚙️ Configuration (`config.json`)

```json
{
  "hostname": null,
  "scan_interval": 30,
  "state_file": "/var/lib/health-sentinel/state.json",

  "web": {
    "enabled": true,
    "bind": "0.0.0.0",
    "port": 8686,
    "token": "your-secure-auth-token"
  },

  "thresholds": {
    "cpu_warn": 85, "cpu_crit": 95,
    "steal_warn": 5, "steal_crit": 12,
    "load_warn": 1.0, "load_crit": 2.0,
    "mem_warn": 85, "mem_crit": 94,
    "swap_warn": 35, "swap_crit": 75,
    "disk_warn": 80, "disk_crit": 92,
    "inode_warn": 80, "inode_crit": 92,
    "io_util_warn": 80, "io_util_crit": 95,
    "await_warn": 25, "await_crit": 120,
    "retrans_warn": 1.5, "retrans_crit": 6,
    "authfail_warn": 30, "authfail_crit": 250
  },

  "alerts": {
    "enabled": true,
    "min_severity": "warn",
    "consecutive": 2,
    "cooldown_minutes": 60,
    "notify_recovery": true,

    "email": {
      "enabled": false,
      "host": "smtp.gmail.com",
      "port": 587,
      "tls": true,
      "ssl": false,
      "user": "alerts@example.com",
      "password": "app-specific-password",
      "from": "Health Sentinel <alerts@example.com>",
      "to": ["ops@example.com"]
    },
    "slack": {
      "enabled": false,
      "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ"
    },
    "telegram": {
      "enabled": false,
      "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
      "chat_id": "-1001234567890"
    },
    "ntfy": {
      "enabled": false,
      "server": "https://ntfy.sh",
      "topic": "my-server-alerts",
      "token": ""
    },
    "webhook": {
      "enabled": false,
      "url": "https://example.com/api/alerts",
      "headers": { "X-Key": "s3cret" }
    }
  }
}
```

### Test Alert Dispatch
Verify that your alert configurations are functioning correctly:
```bash
sudo python3 sentinel.py --test-alerts
```

---

## 🛠️ Production Deployment (Systemd)

### Option A: Web Dashboard + Daemon (`sentinel.service`)
```bash
sudo mkdir -p /opt/health-sentinel /etc/health-sentinel
sudo cp sentinel.py /opt/health-sentinel/
sudo cp config.json /etc/health-sentinel/
sudo cp deploy/sentinel.service /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel
```

### Option B: Headless Alert-Only Mode (Systemd Timer)
```bash
sudo cp deploy/sentinel-cron.service /etc/systemd/system/
sudo cp deploy/sentinel-cron.timer /etc/systemd/system/

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-cron.timer
```

---

## 🔌 API & Prometheus Endpoints

When `web.enabled` is `true`:
- `GET /` — Responsive web dashboard with dark/light themes and sparklines
- `GET /api/health` — Full JSON diagnostic report with checks, scores, and findings
- `GET /api/history` — Rolling history data points for graphs and trend analysis
- `POST /api/scan` — Force an immediate re-scan and evaluation
- `POST /api/test-alert` — Trigger a test alert to verify notification dispatch
- `GET /metrics` — Prometheus metrics format for Grafana / VictoriaMetrics / Prometheus scraping

If a token is configured in `config.json` (`web.token`), pass it via query string `?token=...`, header `X-Auth-Token: ...`, or `Authorization: Bearer ...`.

---

## 📊 Health Checks Summary

| Check ID | Probe Focus | Key Metrics |
|---|---|---|
| `cpu` | CPU utilization & hypervisor steal | User, system, iowait, steal%, PSI stall (some_avg10), top consumers |
| `load` | Run queue saturation | 1m, 5m, 15m load normalized per core, D-state vs R-state ratio |
| `memory` | RAM, Swap & OOM Killer | Available RAM%, swap in/out rate, PSI pressure, recent OOM events |
| `disk` | Filesystem capacity & flags | Mount utilization, free bytes, read-only status |
| `io` | Storage bottlenecks & latencies | Device utilization%, await times (ms), IOPS, kernel I/O errors |
| `inodes` | Inode exhaustion & file handles | Mount inode%, system-wide `fs.file-max` saturation |
| `network` | NIC health & socket state | Interface rx/tx rates, error/drop rates, TCP retrans%, conntrack usage |
| `processes` | Process limits & leak detection | Active PIDs vs `pid_max`, threads vs `threads-max`, zombies, D-state |
| `services` | Service state & system updates | `systemctl --failed`, system state, NTP sync, uptime, reboot required |
| `logs` | Security & kernel diagnostics | Journal error rate/hour, failed SSH auth attempts/hour, segfaults |

---

## 📜 Versioning
Current Version: **v1.4.0 (updated 2026-08-27 15:11)**
