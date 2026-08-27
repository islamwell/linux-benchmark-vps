# 🛡️ Linux Health Sentinel

A **production-ready**, **zero-dependency** (pure Python 3 stdlib) Linux server health platform and forensics monitor featuring:

* **Top-10 Core Linux Health Probes**: CPU utilization & steal time, normalized load average, memory & swap pressure (with PSI), disk space & read-only detection, disk I/O bottlenecks & await latencies, inode exhaustion & open file handles, network drops/errors/retransmits/conntrack, processes/threads/zombies/D-state, systemd failed services/uptime/reboot flags/NTP, and journal errors/SSH brute-force detection.
* **0–100 Scoring Engine**: Linear threshold interpolation, severity caps (max 54 for critical, max 79 for warning), and letter grades (A+ through F).
* **High-Load Incident Preservation & Culprit Forensics**: When load spikes or thresholds breach, Sentinel immediately captures an immutable snapshot of top CPU/RSS processes with full command-line arguments (`cmdline`), usernames/UIDs, cgroups/systemd units, and D-state kernel stack traces, persisting evidence to disk so culprits cannot hide even if processes exit before inspection.
* **Scan Concurrency & Mutex Protection**: Thread-safe scan engine with mutex locking, rate calculation safeguards, and smart caching to prevent corrupted delta samples from concurrent browser, API, or Prometheus requests.
* **Guaranteed Alert Delivery**: State persistence across restarts and cron timer scans, per-channel delivery validation, anti-flap streak tracking, automatic recovery notifications, and reliable `--test-alerts` verification.
* **Embedded Glassmorphic Web Dashboard**: Dark/Light aurora gradient themes, animated health ring gauge, live KPI sparkline charts, severity filtering, instant diagnostic expansion, and live auto-refresh.
* **Plesk & PHP-FPM Slow Script Tracing**: Automatic detection of slow script executions with exact script filename, pool name, execution duration, and function backtrace frames.
* **Security First**: Default binding to `127.0.0.1` with automatic cryptographically secure 24-character token generation and SSH tunnel access recommendations.

---

## 📁 Repository Structure

```
linux-health-sentinel/
├── install.sh               # Automated one-command installer and service manager
├── sentinel.py              # Single-file daemon, web UI, checks, scoring, incidents & alerts
├── config.json              # Thresholds, intervals, and notification credentials
├── deploy/
│   ├── sentinel.service     # Systemd daemon service (web UI + background alerts)
│   ├── sentinel-cron.service# Systemd oneshot unit for scheduled/cron scans
│   ├── sentinel-cron.timer  # Systemd 5-minute timer for periodic checks
│   └── enable-plesk-php-slowlog.sh # Safe script to configure slow logging across all PHP pools
└── README.md                # Documentation and setup guide
```

---

## 🚀 Quick Start (Automated Installation)

Run the installer on your server to verify Python 3, create directory structures, generate a random security token, and register the systemd daemon:

```bash
# 1. Clone the repository
git clone https://github.com/islamwell/linux-benchmark-vps.git /tmp/health-sentinel
cd /tmp/health-sentinel

# 2. Run the automated installer
sudo bash install.sh
```

### Custom Options:
```bash
# Bind to all interfaces with a custom port and password:
sudo bash install.sh --bind 0.0.0.0 --port 8686 --token "my-secret-token"

# Enable PHP-FPM slow logging across all active Plesk pools:
sudo bash install.sh --enable-php-slowlog

# Enable 5-minute systemd timer unit:
sudo bash install.sh --enable-timer

# Uninstall cleanly:
sudo bash install.sh --uninstall
```

---

## 🔒 Recommended Secure Access

By default, Sentinel binds to `127.0.0.1:8686` for security. To view the dashboard securely without exposing open ports to the internet:

### Option A: Secure SSH Port Forwarding
Run this on your local laptop:
```bash
ssh -L 8686:127.0.0.1:8686 root@<YOUR_SERVER_IP>
```
Then open: **`http://localhost:8686?token=YOUR_GENERATED_TOKEN`**

### Option B: Nginx / Plesk Reverse Proxy
Add a reverse proxy in your Nginx configuration with SSL:
```nginx
location /sentinel/ {
    proxy_pass http://127.0.0.1:8686/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

---

## ⚡ Plesk & PHP-FPM Slow Script Diagnostics

When high CPU or load spikes occur, snapshots alone don't show which user request hung. Linux Health Sentinel automatically scans Plesk and Linux PHP-FPM slow logs and pool configurations:

* **Pinpoints the Exact Script**: e.g., `/var/www/vhosts/nurulquranlive.com/httpdocs/index.php`
* **Execution Backtrace**: Identifies slow plugins, unindexed SQL queries, or remote cURL calls (e.g. `curl_exec() in /wp-content/plugins/xyz/api.php:142`).
* **Safe Configuration Script**: Configure all pools safely with automatic configuration testing (`php-fpm -t`) and instant rollback on syntax failure:
  ```bash
  sudo bash deploy/enable-plesk-php-slowlog.sh 5s 20
  ```

---

## 💻 Manual & CLI Execution

### 1. Formatted CLI Report (Nagios exit codes 0/1/2)
```bash
sudo python3 sentinel.py --once
```

### 2. JSON Output (for CI / Zabbix / custom tooling)
```bash
sudo python3 sentinel.py --once --json
```

### 3. Test Alert Notification Delivery
Verify that your alert configurations are functioning correctly:
```bash
sudo python3 /opt/health-sentinel/sentinel.py -c /etc/health-sentinel/config.json --test-alerts
```

---

## ⚙️ Configuration (`/etc/health-sentinel/config.json`)

```json
{
  "hostname": null,
  "scan_interval": 30,
  "history_points": 720,
  "state_file": "/var/lib/health-sentinel/state.json",
  "incidents_dir": "/var/lib/health-sentinel/incidents",
  "incident_history": 50,

  "web": {
    "enabled": true,
    "bind": "127.0.0.1",
    "port": 8686,
    "token": ""
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
    "authfail_warn": 30, "authfail_crit": 250,
    "php_slow_warn": 3, "php_slow_crit": 15
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

---

## 🔌 API & Prometheus Endpoints

When `web.enabled` is `true`:
- `GET /` — Responsive web dashboard with dark/light themes and sparklines
- `GET /api/health` — Full JSON diagnostic report with checks, scores, and findings
- `GET /api/history` — Rolling history data points for graphs and trend analysis
- `GET /api/incidents` — Preserved incident packets and top CPU/Memory culprits
- `POST /api/scan` — Force an immediate re-scan and evaluation (thread-safe)
- `POST /api/test-alert` — Trigger a test alert to verify notification dispatch
- `GET /metrics` — Prometheus metrics format with escaped labels

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
| `logs` | Security, kernel & PHP-FPM | Journal errors/h, failed SSH auth/h, segfaults, **PHP-FPM slow script traces** |

---

## 📜 Versioning
Current Version: **v1.5.1 (updated 2026-08-27 16:18)**
