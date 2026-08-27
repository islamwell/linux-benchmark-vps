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
17:linux-health-sentinel/
18:├── sentinel.py              # Single-file daemon, web UI, checks, scoring & alerts
19:├── config.json              # Thresholds, intervals, and notification credentials
20:├── deploy/
21:│   ├── sentinel.service     # Systemd daemon service (web UI + background alerts)
22:│   ├── sentinel-cron.service# Systemd oneshot unit for scheduled/cron scans
23:│   ├── sentinel-cron.timer  # Systemd 5-minute timer for periodic checks
24:│   └── enable-plesk-php-slowlog.sh # Script to enable slow logging across all Plesk PHP pools
25:└── README.md                # Documentation and setup guide
26:```
27:
28:---
29:
30:## ⚡ Plesk & PHP-FPM Slow Script Diagnostics
31:
32:When high CPU or load spikes occur, snapshots alone don't show which user request hung. Linux Health Sentinel automatically scans Plesk and Linux PHP-FPM slow logs and pool configurations:
33:
34:* **Pinpoints the Exact Script**: e.g., `/var/www/vhosts/nurulquranlive.com/httpdocs/index.php`
35:* **Execution Backtrace**: Identifies slow plugins, unindexed SQL queries, or remote cURL calls (e.g. `curl_exec() in /wp-content/plugins/xyz/api.php:142`).
36:* **Automated Plesk Pool Configuration**: If slow logging is disabled, Sentinel warns you and provides a one-command setup:
37:  ```bash
38:  sudo bash deploy/enable-plesk-php-slowlog.sh 5s 20
39:  ```
40:
41:---
42:
43:## 🚀 Quick Start
44:
45:### 1. Requirements
46: * Linux OS (Ubuntu, Debian, RHEL, Rocky, Alma, CentOS, Fedora, Arch, etc.)
47: * Python 3.7+ (pure standard library; no `pip` or virtualenv required)
48:
49:### 2. Run Instantly (CLI Mode)
50:```bash
51:# Instant formatted CLI report
52:sudo python3 sentinel.py --once
53:
54:# JSON output for scripting / Nagios / Zabbix / CI
55:sudo python3 sentinel.py --once --json
56:```
57:
58:### 3. Launch the Web Dashboard
59:```bash
60:sudo python3 sentinel.py --bind 0.0.0.0 --port 8686
61:```
62:Open `http://<server-ip>:8686` in your browser.
63:
64:---
65:
66:## ⚙️ Configuration (`config.json`)
67:
68:```json
69:{
70:  "hostname": null,
71:  "scan_interval": 30,
72:  "state_file": "/var/lib/health-sentinel/state.json",
73:
74:  "web": {
75:    "enabled": true,
76:    "bind": "0.0.0.0",
77:    "port": 8686,
78:    "token": "your-secure-auth-token"
79:  },
80:
81:  "thresholds": {
82:    "cpu_warn": 85, "cpu_crit": 95,
83:    "steal_warn": 5, "steal_crit": 12,
84:    "load_warn": 1.0, "load_crit": 2.0,
85:    "mem_warn": 85, "mem_crit": 94,
86:    "swap_warn": 35, "swap_crit": 75,
87:    "disk_warn": 80, "disk_crit": 92,
88:    "inode_warn": 80, "inode_crit": 92,
89:    "io_util_warn": 80, "io_util_crit": 95,
90:    "await_warn": 25, "await_crit": 120,
91:    "retrans_warn": 1.5, "retrans_crit": 6,
92:    "authfail_warn": 30, "authfail_crit": 250
93:  },
94:
95:  "alerts": {
96:    "enabled": true,
97:    "min_severity": "warn",
98:    "consecutive": 2,
99:    "cooldown_minutes": 60,
100:    "notify_recovery": true,
101:
102:    "email": {
103:      "enabled": false,
104:      "host": "smtp.gmail.com",
105:      "port": 587,
106:      "tls": true,
107:      "ssl": false,
108:      "user": "alerts@example.com",
109:      "password": "app-specific-password",
110:      "from": "Health Sentinel <alerts@example.com>",
111:      "to": ["ops@example.com"]
112:    },
113:    "slack": {
114:      "enabled": false,
115:      "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ"
116:    },
117:    "telegram": {
118:      "enabled": false,
119:      "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
120:      "chat_id": "-1001234567890"
121:    },
122:    "ntfy": {
123:      "enabled": false,
124:      "server": "https://ntfy.sh",
125:      "topic": "my-server-alerts",
126:      "token": ""
127:    },
128:    "webhook": {
129:      "enabled": false,
130:      "url": "https://example.com/api/alerts",
131:      "headers": { "X-Key": "s3cret" }
132:    }
133:  }
134:}
135:```
136:
137:### Test Alert Dispatch
138:Verify that your alert configurations are functioning correctly:
139:```bash
140:sudo python3 sentinel.py --test-alerts
141:```
142:
143:---
144:
145:## 🛠️ Production Deployment (Systemd)
146:
147:### Option A: Web Dashboard + Daemon (`sentinel.service`)
148:```bash
149:sudo mkdir -p /opt/health-sentinel /etc/health-sentinel
150:sudo cp sentinel.py /opt/health-sentinel/
151:sudo cp config.json /etc/health-sentinel/
152:sudo cp deploy/sentinel.service /etc/systemd/system/
153:
154:sudo systemctl daemon-reload
155:sudo systemctl enable --now sentinel
156:```
157:
158:### Option B: Headless Alert-Only Mode (Systemd Timer)
159:```bash
160:sudo cp deploy/sentinel-cron.service /etc/systemd/system/
161:sudo cp deploy/sentinel-cron.timer /etc/systemd/system/
162:
163:sudo systemctl daemon-reload
164:sudo systemctl enable --now sentinel-cron.timer
165:```
166:
167:---
168:
169:## 🔌 API & Prometheus Endpoints
170:
171:When `web.enabled` is `true`:
172:- `GET /` — Responsive web dashboard with dark/light themes and sparklines
173:- `GET /api/health` — Full JSON diagnostic report with checks, scores, and findings
174:- `GET /api/history` — Rolling history data points for graphs and trend analysis
175:- `POST /api/scan` — Force an immediate re-scan and evaluation
176:- `POST /api/test-alert` — Trigger a test alert to verify notification dispatch
177:- `GET /metrics` — Prometheus metrics format for Grafana / VictoriaMetrics / Prometheus scraping
178:
179:If a token is configured in `config.json` (`web.token`), pass it via query string `?token=...`, header `X-Auth-Token: ...`, or `Authorization: Bearer ...`.
180:
181:---
182:
183:## 📊 Health Checks Summary
184:
185:| Check ID | Probe Focus | Key Metrics |
186:|---|---|---|
187:| `cpu` | CPU utilization & hypervisor steal | User, system, iowait, steal%, PSI stall (some_avg10), top consumers |
188:| `load` | Run queue saturation | 1m, 5m, 15m load normalized per core, D-state vs R-state ratio |
189:| `memory` | RAM, Swap & OOM Killer | Available RAM%, swap in/out rate, PSI pressure, recent OOM events |
190:| `disk` | Filesystem capacity & flags | Mount utilization, free bytes, read-only status |
191:| `io` | Storage bottlenecks & latencies | Device utilization%, await times (ms), IOPS, kernel I/O errors |
192:| `inodes` | Inode exhaustion & file handles | Mount inode%, system-wide `fs.file-max` saturation |
193:| `network` | NIC health & socket state | Interface rx/tx rates, error/drop rates, TCP retrans%, conntrack usage |
194:| `processes` | Process limits & leak detection | Active PIDs vs `pid_max`, threads vs `threads-max`, zombies, D-state |
195:| `services` | Service state & system updates | `systemctl --failed`, system state, NTP sync, uptime, reboot required |
196:| `logs` | Security, kernel & PHP-FPM | Journal errors/h, failed SSH auth/h, segfaults, **PHP-FPM slow script traces** |
197:
198:---
199:
200:## 📜 Versioning
201:Current Version: **v1.4.1 (updated 2026-08-27 15:45)**
