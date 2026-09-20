# 🛡️ Linux Health Sentinel

A **production-ready**, **zero-dependency** (pure Python 3 stdlib) Linux server health platform, capacity benchmark, and forensics monitor featuring:

* **🌐 Multi-Server Fleet Hub**: Centralized agency dashboard monitoring all connected client VPS nodes in real time. Features multi-threaded parallel polling, aggregated fleet health grades, per-node resource vitals, and one-click drill-downs.
* **🔑 Cryptographic Licensing Engine**: Pure Python stdlib HMAC-SHA256 signature verification supporting Free Open-Core, Pro ($89/yr), and Agency ($199 lifetime) tiers. Includes offline key validator and standalone `deploy/generate-license.py` key issuer for store owners.
* **🔒 Automated SSL/TLS Reverse Proxy Deployer**: 1-click HTTPS provisioning (`deploy/setup-ssl.sh` & `install.sh --ssl`) supporting Caddy (automatic Let's Encrypt certificates), Nginx, and OpenSSL self-signed setups.
* **🎨 Custom Branding & White-Label Platform**: Rebrand Sentinel for client delivery, MSPs, or hosting agencies. Features a 1-click **White-Label Mode** (removes all vendor mentions), custom application name, company/agency name, custom logo URL, live primary/accent theme colors (`--acc`, `--acc2`), executive report titles, support email/helpdesk links, and custom footer copyrights. Accessible via the in-dashboard **`🎨 Branding`** admin modal or automated CLI installation flags.
* **👥 Safe Visitor Traffic Capacity & Stress Benchmark**: Safely tests how many simultaneous active visitors and requests/second your server can sustain. Features progressive concurrency ramping (5 → 15 → 30 → 50 → 150), real-time RPS/latency telemetry, and an **auto-abort circuit breaker** that halts immediately if load &ge; 4.5 or available RAM &lt; 120MB to guarantee zero downtime.
* **🔐 Dual-Token Role-Based Access Control (RBAC)**: Distinct credentials for **Admin** (`admin_token` with full server control, PHP recycle, 1-click firewall bans, and benchmarks) and **View-Only** (`view_token` for clients, marketing, and staff showing real-time metrics and reports while blocking all mutations with HTTP 403).
* **🛡️ Security Shield & Anti-Brute-Force Rate Limiter**: Sliding-window rate limiter (5 failed token attempts in 60s → 15-minute lockout with HTTP 429), constant-time `hmac.compare_digest` token validation, security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`), and native `iptables` & RHEL `firewalld` rich rule support.
* **📦 Universal Multi-Distro Installer (`install.sh` & `update.sh`)**: Seamless package detection and auto-installation across **Debian, Ubuntu, RHEL, CentOS, Rocky Linux, AlmaLinux, Fedora, openSUSE, and Arch Linux** with interactive prompt or automated flags.
* **🔄 Universal 1-Command Auto-Updater (`update.sh`)**: Update or install to the latest release in seconds with a single command without overwriting your tokens or custom thresholds.
* **Top-10 Core Linux Health Probes**: CPU utilization & steal time, normalized load average, memory & swap pressure (with PSI), disk space & read-only detection, disk I/O bottlenecks & await latencies, inode exhaustion & open file handles, network drops/errors/retransmits/conntrack, processes/threads/zombies/D-state, systemd failed services/uptime/reboot flags/NTP, and journal errors/SSH brute-force detection.
* **0–100 Scoring Engine**: Linear threshold interpolation, severity caps (max 54 for critical, max 79 for warning), and letter grades (A+ through F).
* **High-Load Incident Preservation & Culprit Forensics**: When load spikes or thresholds breach, Sentinel immediately captures an immutable snapshot of top CPU/RSS processes with full command-line arguments (`cmdline`), usernames/UIDs, cgroups/systemd units, and D-state kernel stack traces, persisting evidence to disk so culprits cannot hide even if processes exit before inspection.
* **Scan Concurrency & Mutex Protection**: Thread-safe scan engine with mutex locking, rate calculation safeguards, and smart caching to prevent corrupted delta samples from concurrent browser, API, or Prometheus requests.
* **Guaranteed Alert Delivery**: State persistence across restarts and cron timer scans, per-channel delivery validation, anti-flap streak tracking, automatic recovery notifications, and reliable `--test-alerts` verification.
* **Embedded Glassmorphic Web Dashboard**: Dark/Light aurora gradient themes, animated health ring gauge, live KPI sparkline charts, severity filtering, instant diagnostic expansion, and live auto-refresh.
* **Plesk & PHP-FPM Slow Script Tracing**: Automatic detection of slow script executions with exact script filename, pool name, execution duration, and function backtrace frames.
* **Security First**: Default binding to `127.0.0.1` with automatic cryptographically secure 24-character token generation and SSH tunnel access recommendations.

---

## 🚀 1-Command Universal Auto-Update or Install

To install Sentinel or upgrade an existing installation to the latest release (**v2.2.16**), simply run:

```bash
curl -fsSL https://raw.githubusercontent.com/islamwell/linux-benchmark-vps/master/update.sh | sudo bash
```

*This command safely pulls the latest code, preserves your existing `/etc/health-sentinel/config.json` security tokens and thresholds, sets correct file permissions, updates systemd services, and cleanly restarts Sentinel with zero manual editing.*

---

## 📁 Repository Structure

```
linux-health-sentinel/
├── update.sh                # 1-command universal auto-updater (preserves tokens & restarts daemon)
├── install.sh               # Automated one-command installer and service manager
├── sentinel.py              # Single-file daemon, web UI, checks, scoring, incidents & alerts
├── config.json              # Thresholds, intervals, and notification credentials
├── deploy/
│   ├── sentinel.service     # Systemd daemon service (web UI + background alerts)
│   ├── sentinel-cron.service# Systemd oneshot unit for scheduled/cron scans
│   ├── sentinel-cron.timer  # Systemd 5-minute timer for periodic checks
│   ├── optimize-io-memory.sh# 1-click script to optimize low-RAM and slow-disk VPS servers
│   └── enable-plesk-php-slowlog.sh # Safe script to configure slow logging across all PHP pools
└── README.md                # Documentation and setup guide
```

---

## 🚀 Manual Installation

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
    "telegram": {
      "enabled": false,
      "bot_token": "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
      "chat_id": "-1001234567890"
    },
    "whatsapp": {
      "enabled": false,
      "provider": "callmebot",
      "phone": "+4794441171",
      "apikey": "",
      "webhook_url": ""
    },
    "slack": {
      "enabled": false,
      "webhook_url": "https://hooks.slack.com/services/XXX/YYY/ZZZ"
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

## 📱 WhatsApp Alerting Setup (+4794441171)
Sentinel supports direct WhatsApp alerting via **CallMeBot** (free & instant):
1. On WhatsApp, send the message `I allow callmebot to send me messages` to `+34 941 01 99 99` (or the CallMeBot bot number for your region).
2. CallMeBot will reply with your personal API key (e.g. `123456`).
3. In `/etc/health-sentinel/config.json`:
   ```json
   "whatsapp": {
     "enabled": true,
     "phone": "+4794441171",
     "apikey": "YOUR_API_KEY"
   }
   ```
4. Restart Sentinel: `sudo systemctl restart sentinel`. Whenever server load reaches **8.0**, an immediate WhatsApp message is sent to `+4794441171`!

---

## 🔌 API & Prometheus Endpoints

When `web.enabled` is `true`:
- `GET /` — Responsive web dashboard with 12h/24h/48h historical charts, Y-axis units, range selectors (1m, 10m, 1h, 12h, 24h, 48h), **⚡ Quick Actions**, and **📄 Executive Reports**
- `GET /api/health` — Full JSON diagnostic report with simple language findings and metrics
- `GET /api/report/html` — Generate standalone, print-ready, white-label executive client audit report (PDF exportable)
- `GET /api/auto-heal` — View active autonomous self-healing status, configuration, and intervention audit log
- `POST /api/auto-heal/toggle` — Enable/disable autonomous healing or toggle dry-run simulation mode
- `GET /api/php-services` — List all installed PHP versions and their live systemd status
- `POST /api/php-action` — Start, stop, restart, or reload PHP services (`{"service": "plesk-php82-fpm", "action": "restart"}`)
- `POST /api/system-action` — Execute safe system maintenance (`restart_mariadb`, `vacuum_logs`, `drop_caches`, `reset_failed`, `optimize_io_memory`)
- `GET /api/history` — Rolling 48h history data points (5,760 samples) for graphs and trend analysis
- `GET /api/incidents` — Preserved incident packets and top CPU/Memory culprits
- `POST /api/scan` — Force an immediate re-scan and evaluation (thread-safe)
- `POST /api/test-alert` — Trigger a test alert to verify notification dispatch (Telegram, WhatsApp, Email)
- `GET /metrics` — Prometheus metrics format with escaped labels

---

## 🤖 Autonomous Self-Healing Engine

Linux Health Sentinel automatically recovers your server when critical bottlenecks occur—even at 3 AM while you sleep:

* **Load Spike Trigger (Load $\ge$ 8.0)**: Automatically recycles stuck PHP worker pools and flushes RAM cache.
* **Memory Saturation Trigger (RAM $\ge$ 94%)**: Drops cached memory pages and recycles heavy worker pools.
* **Disk Critical Trigger (Disk $\ge$ 92%)**: Trims system journal logs to 200MB to prevent 100% disk lockups.
* **Crashed Service Trigger**: Resets systemd failed unit counters and attempts service recovery.
* **Anti-Flap Safety**: Enforces a 15-minute cooldown per component and a 5 action/hour circuit breaker to prevent loops.
* **Instant Confirmation**: Every automated fix sends a confirmation alert directly to WhatsApp (`+4794441171`) and Telegram!

---

## 📄 White-Label Executive Client Reports & PDF Export

Generate client-ready, branded infrastructure audit reports with a single click:
* **Agency Branding**: Custom Agency Name, Report Title, Client Name, and Support Contact.
* **48-Hour Performance Audit**: Peak vs. Average load, CPU, RAM headroom, and storage utilisation.
* **Preventative Care Log**: Demonstrates the concrete value of your agency retainer by listing all autonomous fixes performed.
* **Security & SSL Verification**: Days remaining on Let's Encrypt / Plesk SSL certs and SSH brute-force defense stats.
* **One-Click Print / PDF**: Native `@media print` styling for crisp, professional client PDF delivery.

---

## 👥 Real-Time Visitors & Geographic Intelligence

Monitor active web visitors to your server in real time:
* **Live Concurrent Sockets**: Analyzes active TCP connections on HTTP/HTTPS ports (80, 443) using `ss -nt`.
* **Multi-Engine Web Log Intelligence**: Tails real-time access logs across Nginx, Apache, Plesk vhosts, LiteSpeed, and Caddy.
* **GeoIP Location & Country Flags**: Automatically identifies visitor country flags (e.g. 🇳🇴, 🇩🇪, 🇺🇸, 🇬🇧), city, ISP/Org, and active request endpoints.
* **Zero-Overhead Asynchronous Resolution**: Cached lookups handled asynchronously in background threads with local private subnet detection so request processing is never slowed down.

---

## 🛡️ 1-Click IP Ban & Bad-Bot Firewall Shield

Safeguard your server against aggressive scrapers, WordPress attackers, and exploit scanners:
* **Automatic Threat Classification**: Detects WordPress brute-force probes (`/wp-login.php`, `xmlrpc.php`), sensitive credential scans (`/.env`, `/.git/`, `phpmyadmin`), and high-frequency error flooding.
* **1-Click IP Drop**: Instant `🚫 Ban IP` button right inside the Live Visitors table that drops the attacking IP via `iptables` or `ufw`.
* **Lockout Prevention**: Strictly protects private subnets (`127.0.0.1`, `10.*`, `192.168.*`) and dynamically whitelist protects your own active admin IP so you can never accidentally lock yourself out.
* **Firewall Manager**: Inspect and manage blocked IPs directly from the dashboard with 1-click unban.

---

## 🌐 Multi-Site Uptime & Response Speed Monitor

Track the speed and availability of all client websites and virtual hosts hosted on your VPS:
* **Automatic Local Discovery**: Scans Plesk vhosts (`/var/www/vhosts/`), Nginx configs (`sites-enabled`), and Apache vhosts automatically.
* **Millisecond Precision**: Measures real-time round-trip HTTP response latency (e.g. `⚡ 120ms` vs `🐢 3,400ms`).
* **HTTP Status Code Verification**: Alerts if a site returns `500 Server Error`, `502 Bad Gateway`, or connection timeouts.
* **SSL Expiration Countdown**: Monitors TLS/SSL peer certificates and calculates remaining validity days (`🔒 SSL: 68d left`), warning before certificates expire.
* **Custom Domain Support**: Add, test, and remove custom domains or API endpoints on the fly.

---

## 👥 Safe Visitor Traffic Capacity & Stress Benchmark

Accurately find out **how many simultaneous visitors your server can handle** before slowing down or throwing 502/504 errors:

* **Three Concurrency Profiles**:
  1. **⚡ Quick Safe Test**: 5 → 15 → 30 → 50 concurrent visitors (~12s), protected by circuit breakers.
  2. **🔥 Full Stress Test**: 10 → 25 → 50 → 75 → 100 → 150 concurrent visitors (~22s), protected by circuit breakers.
  3. **💀 Max Stress — No Safety Net**: 25 → 50 → 100 → 200 → 350 → 500 concurrent visitors (~25s). All CPU load and RAM circuit breakers are intentionally bypassed to discover the absolute breaking point and maximum burst throughput of your server stack.
* **Live Telemetry & Diagnostics**: Measures real-time requests/sec (RPS), average latency (ms), 95th percentile response time, and error rates (% 4xx/5xx/timeouts).
* **🛡️ Built-in Auto-Abort Circuit Breakers (Safe Modes)**:
  1. **CPU Load Watchdog**: Instantly stops the test if CPU Load Average spikes $\ge 4.5$ (or $> 3\times$ CPU cores).
  2. **Memory Guard**: Automatically halts if available RAM drops below 120MB, protecting your system from the Linux OOM killer.
  3. **Error Spike Protection**: Freezes further escalation if error rates exceed 25% or response latency exceeds 2,200ms, designating the previous stable stage as maximum safe capacity.
  4. **Emergency Stop Button**: Stop workers in under 100ms from the web interface or Ctrl-C at any time.
* **CLI Terminal Execution**: Run benchmark directly from command line with full color progress:
  ```bash
  # Quick safe test
  python3 /opt/health-sentinel/sentinel.py --stress-test http://127.0.0.1:80/

  # Max uncapped stress test up to 500 visitors (No Safety Net)
  python3 /opt/health-sentinel/sentinel.py --stress-test http://127.0.0.1:80/ --stress-mode max
  ```
* **Plain-English Capacity Verdict**: Explains safe concurrent visitors, sustainable monthly pageviews, identifies the primary bottleneck (CPU, RAM, PHP-FPM worker pool, or I/O), and provides specific actionable optimization steps.

---

## ⚡ Built-in Safe VPS Hardware Benchmark Engine

Benchmark your VPS performance on demand without external dependencies:
* **CPU Compute**: Single-core and multi-core calculation benchmarks with safe, bounded execution (~0.6s).
* **Memory Bandwidth**: High-speed memory throughput testing (GB/s).
* **Storage Sequential I/O**: Direct sequential write throughput (MB/s with `os.fdatasync`) and read throughput, with immediate safe cleanup.
* **Network Edge Latency**: Low-overhead ping tests to Cloudflare (`1.1.1.1`) and Google (`8.8.8.8`) DNS endpoints.
* **Composite Score & Tier Classification**: Generates an overall score and rates your server tier (**Tier S**, **Tier A**, **Tier B**, or **Tier C**).
* **1-Click Execution**: Run directly from the web dashboard or via API (`POST /api/benchmark/run`).

---

## 🩺 Plain-English "Server Doctor" & Smart Recommendations

No more confusing sysadmin jargon! Sentinel translates server metrics into plain English:
* **What is Happening**: Clear explanation of any detected bottleneck (e.g., *"Disk is being overwhelmed by too many writes (iowait 91.8%)"*).
* **Why it Matters**: Explanation of the impact on your websites and visitors (e.g., *"Websites feel sluggish because the CPU is constantly waiting for the slow disk"*).
* **Actionable Solutions**: Concrete, safe advice tailored to your system (e.g., adjusting swappiness, enabling dirty page batching, restarting stuck worker pools).
* **1-Click Fixes & Copyable Commands**: Single-click fix buttons directly in the alert card or terminal-ready commands.

---

## 📊 Health Checks Summary

| Check ID | Probe Focus | Key Metrics |
|---|---|---|
| `cpu` | CPU utilization & hypervisor steal | User, system, iowait, steal%, PSI stall (some_avg10), top consumers |
| `load` | Run queue saturation & Load >= 8.0 | 1m, 5m, 15m load normalized & absolute (warn >= 8.0), D-state vs R-state |
| `memory` | RAM, Swap & OOM Killer | Available RAM%, swap in/out rate, PSI pressure, recent OOM events |
| `disk` | Filesystem capacity & flags | Mount utilization, free bytes, read-only status, growth slope forecast |
| `io` | Storage bottlenecks & latencies | Device utilization%, await times (ms), IOPS, kernel I/O errors |
| `inodes` | Inode exhaustion & file handles | Mount inode%, system-wide `fs.file-max` saturation |
| `network` | NIC health & socket state | Interface rx/tx rates, error/drop rates, TCP retrans%, conntrack usage |
| `processes` | Process limits & leak detection | Active PIDs vs `pid_max`, threads vs `threads-max`, zombies, D-state |
| `services` | Service state & system updates | `systemctl --failed`, system state, NTP sync, uptime, reboot required |
| `logs` | Security, kernel & PHP-FPM | Journal errors/h, failed SSH auth/h, segfaults, **PHP-FPM slow script traces**, SSL expiry |

---

## 🚀 Software-Level I/O & Memory Optimization

If your VPS has high `iowait` (slow disk) and limited RAM, run the automated tuning script to apply non-destructive kernel, filesystem, and database optimizations without hardware upgrades:

```bash
sudo /opt/health-sentinel/deploy/optimize-io-memory.sh
```

**What it tunes:**
1. **`noatime,nodiratime`**: Stops updating file access timestamps on every read, eliminating useless metadata writes.
2. **`vm.swappiness = 10` & `vm.vfs_cache_pressure = 50`**: Keeps file caches longer in RAM and avoids aggressive disk swapping.
3. **Dirty Writeback Batching**: Sets `dirty_background_ratio=5` and `dirty_ratio=20` to batch disk writes and prevent disk queue stalls.
4. **Compressed RAM Swap (zram)**: Sets up compressed in-RAM swap so low-memory spikes don't thrash the physical disk.
5. **MySQL / MariaDB Flush Batching**: Sets `innodb_flush_log_at_trx_commit = 2` to batch transaction disk writes once per second.

*You can also trigger this optimization with a single click from the **`⚡ Quick Actions`** dashboard modal.*

## 🎨 Custom Branding & White-Label Platform

Linux Health Sentinel includes native white-label capabilities designed specifically for agencies, Managed Service Providers (MSPs), hosting resellers, and system administrators delivering managed infrastructure services to clients.

### 🌟 White-Label Capabilities:
* **Vendor Neutrality**: Enable **White-Label Mode** to eliminate all references to "Health Sentinel" across the web dashboard, page title, favicon, and generated PDF reports.
* **Custom Platform Identity**: Set your own Application Name (e.g. *CloudGuardian* or *Acme Server Monitor*) and Company/Agency Name.
* **Custom Logo**: Display your company's logo in the dashboard header and executive client audits (supports HTTPS URLs and base64 data URIs).
* **Dynamic Brand Colors**: Customize Primary (`--acc`) and Accent (`--acc2`) theme colors with live real-time CSS variable updating and interactive color pickers.
* **Support & Helpdesk Links**: Configure direct links to your ticketing portal or support email directly in the dashboard footer and report signatures.
* **Executive Client Audits**: Generate branded executive PDF health reports stamped with `Certified by <Your Agency>` and client project tags.

### ⚙️ Managing Branding:
1. **From Dashboard (Admin)**: Click the **`🎨 Branding`** button in the header to open the live customization modal. Tweak colors, preview logos in real time, and persist directly to disk.
2. **From Installer CLI**: Deploy with preconfigured branding non-interactively:
   ```bash
   sudo bash install.sh --white-label \
     --app-name "Acme Sentinel" \
     --company "Acme Managed Hosting" \
     --brand-color "#0ea5e9"
   ```
3. **From `config.json`**:
   ```json
   "branding": {
     "white_label": true,
     "app_name": "CloudOps Monitor",
     "company_name": "Acme Cloud Services",
     "logo_url": "https://example.com/logo.png",
     "primary_color": "#0ea5e9",
     "accent_color": "#6366f1",
     "support_url": "https://help.acme.com",
     "support_email": "ops@acme.com",
     "client_name": "Acme Production Cluster",
     "report_title": "Executive Infrastructure Health Audit",
     "custom_footer_text": "Managed 24/7 by Acme Cloud Services © 2026"
   }
   ```

---

## 🌐 Multi-Server Fleet Hub (Agency Edition)

The **Multi-Server Fleet Hub** connects all your client VPS instances and droplets into a single unified control room.

* **Concurrent Parallel Polling**: Scans dozens of servers in parallel using Python thread workers without blocking your main dashboard.
* **Real-Time Node Telemetry**: Instantly see CPU load, RAM usage %, Disk usage %, uptime, active alerts, and composite health grade (A+ through F) per VPS.
* **Instant Drill-Down**: 1-click jumps directly to individual node dashboards or opens diagnostic drills.
* **Adding Nodes**: From the dashboard **`🌐 Fleet Hub`** tab, click **`+ Add VPS Node`** and provide the node name, URL, and security token. Alternatively, configure directly in `config.json`:
  ```json
  "fleet": {
    "poll_interval_seconds": 60,
    "timeout_seconds": 4.0,
    "nodes": [
      {
        "id": "node_nyc",
        "name": "Acme Client - NYC Droplet",
        "url": "https://sentinel.client1.com:8686",
        "token": "admin-token-here",
        "group": "Production"
      }
    ]
  }
  ```

---

## 🔑 Cryptographic Licensing Engine

Linux Health Sentinel uses pure-stdlib HMAC-SHA256 digital signature validation. Key validation requires **zero external network requests** or phone-home telemetry.

### Feature Matrix:
| Feature | Community (Free) | Pro ($89/yr) | Agency Fleet ($199 Lifetime) |
| :--- | :---: | :---: | :---: |
| Top-10 Linux Diagnostics | ✅ | ✅ | ✅ |
| Incident Snapshot Preservation | ✅ | ✅ | ✅ |
| Dual-Token RBAC Security | ✅ | ✅ | ✅ |
| Safe Visitor Capacity Benchmark | ❌ | ✅ | ✅ |
| Plesk PHP-FPM Slowlog Tracing | ❌ | ✅ | ✅ |
| 1-Click Autonomous Self-Healing | ❌ | ✅ | ✅ |
| Multi-Server Fleet Hub | ❌ | ❌ | ✅ (Unlimited Nodes) |
| White-Label & Custom Branding | ❌ | ❌ | ✅ |
| Executive PDF Client Audits | Basic | Full | White-Labeled |

### Issuing Licenses (Store Owner CLI):
Generate cryptographically signed license keys using `deploy/generate-license.py`:
```bash
# Generate Agency Lifetime key:
python3 deploy/generate-license.py --tier agency --email client@agency.com --nodes 50 --days 365

# Output format:
# HS-AGENCY-ey...-A1B2C3D4E5F6
```

### Activating Licenses:
* **From Web Dashboard**: Click the **`🔑 License`** button in the top navigation header and paste your key.
* **From CLI**: `sudo python3 sentinel.py --activate-license "HS-AGENCY-..."`
* **During Installation**: `sudo bash install.sh --license-key "HS-AGENCY-..."`

---

## 🔒 Automated SSL/TLS Reverse Proxy Deployer

Deploy production-grade HTTPS with automated SSL renewal in under 60 seconds:
```bash
sudo bash deploy/setup-ssl.sh
```
Or during initial installation:
```bash
sudo bash install.sh --ssl
```
Supported proxy engines:
1. **Caddy (Recommended)**: Fully automatic Let's Encrypt certificates with HTTP→HTTPS redirect and HTTP/2 + HTTP/3 support.
2. **Nginx + Certbot**: Automated virtual host configuration with reverse proxy headers.
3. **OpenSSL Self-Signed**: Instant local TLS encryption for private intranet or IP-only environments.

---

## 📜 Versioning
Current Version: **v2.2.16 (updated 2026-09-20 07:25)**


