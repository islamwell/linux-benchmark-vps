#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — Automated Installer & Service Manager
# Version: 1.5.0 (updated 2026-08-27 16:05)
# ==============================================================================

set -euo pipefail

VERSION="1.5.0"
UPDATED="2026-08-27 16:05"

# Target installation paths
INSTALL_DIR="/opt/health-sentinel"
CONFIG_DIR="/etc/health-sentinel"
CONFIG_FILE="${CONFIG_DIR}/config.json"
STATE_DIR="/var/lib/health-sentinel"
INCIDENTS_DIR="/var/lib/health-sentinel/incidents"
SERVICE_FILE="/etc/systemd/system/sentinel.service"
CRON_SERVICE_FILE="/etc/systemd/system/sentinel-cron.service"
CRON_TIMER_FILE="/etc/systemd/system/sentinel-cron.timer"

# Defaults
PORT=""
BIND=""
TOKEN=""
ENABLE_SLOWLOG=false
ENABLE_TIMER=false
UNINSTALL=false

# Colors
C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[38;5;42m"
C_BLUE="\033[38;5;111m"
C_WARN="\033[38;5;214m"
C_CRIT="\033[38;5;203m"
C_DIM="\033[38;5;245m"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --port)
            PORT="$2"
            shift 2
            ;;
        --bind)
            BIND="$2"
            shift 2
            ;;
        --token)
            TOKEN="$2"
            shift 2
            ;;
        --enable-php-slowlog)
            ENABLE_SLOWLOG=true
            shift
            ;;
        --enable-timer)
            ENABLE_TIMER=true
            shift
            ;;
        --uninstall)
            UNINSTALL=true
            shift
            ;;
        -h|--help)
            echo -e "${C_BOLD}Linux Health Sentinel — Automated Installer v${VERSION}${C_RESET}"
            echo ""
            echo "Usage: sudo bash install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --port <port>             Web dashboard port (default: 8686)"
            echo "  --bind <ip>               Bind IP address (default: 127.0.0.1 for security)"
            echo "  --token <token>           Web authentication token (auto-generated if omitted)"
            echo "  --enable-php-slowlog      Safely configure PHP-FPM / Plesk slow logging (5s threshold)"
            echo "  --enable-timer            Also enable 5-minute systemd timer (sentinel-cron.timer)"
            echo "  --uninstall               Stop service and remove Sentinel from system"
            echo "  -h, --help                Show this help message"
            echo ""
            exit 0
            ;;
        *)
            echo -e "${C_CRIT}[-] Unknown option: $1${C_RESET}" >&2
            exit 1
            ;;
    esac
done

# Root check
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_CRIT}[-] Error: This installer must be run as root (sudo bash install.sh)${C_RESET}" >&2
    exit 1
fi

# --- UNINSTALL MODE ---
if [ "$UNINSTALL" = true ]; then
    echo -e "${C_WARN}[!] Uninstalling Linux Health Sentinel...${C_RESET}"
    if systemctl is-active --quiet sentinel 2>/dev/null; then
        echo "    Stopping sentinel service..."
        systemctl stop sentinel || true
    fi
    if systemctl is-enabled --quiet sentinel 2>/dev/null; then
        echo "    Disabling sentinel service..."
        systemctl disable sentinel || true
    fi
    if systemctl is-active --quiet sentinel-cron.timer 2>/dev/null; then
        systemctl stop sentinel-cron.timer || true
        systemctl disable sentinel-cron.timer || true
    fi
    rm -f "${SERVICE_FILE}" "${CRON_SERVICE_FILE}" "${CRON_TIMER_FILE}"
    systemctl daemon-reload || true
    rm -rf "${INSTALL_DIR}"
    echo -e "${C_GREEN}[✓] Sentinel binaries and service removed.${C_RESET}"
    echo -e "${C_DIM}Note: Configuration at ${CONFIG_DIR} and state data at ${STATE_DIR} were preserved.${C_RESET}"
    exit 0
fi

# Banner
echo -e "${C_BLUE}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_BLUE}║  ${C_BOLD}🛡   LINUX HEALTH SENTINEL — AUTOMATED INSTALLER v${VERSION}${C_RESET}${C_BLUE}                  ║${C_RESET}"
echo -e "${C_BLUE}║  ${C_DIM}Zero-dependency server health monitor · dashboard · alerts · diagnostics${C_RESET}${C_BLUE}  ║${C_RESET}"
echo -e "${C_BLUE}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""

# 1. Dependency checks
echo -e "${C_BOLD}[1/6] Checking system requirements...${C_RESET}"
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${C_WARN}[!] Python 3 not found. Installing python3...${C_RESET}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq python3
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q python3
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q python3
    else
        echo -e "${C_CRIT}[-] Error: Could not install python3 automatically. Please install Python 3.7+.${C_RESET}" >&2
        exit 1
    fi
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "    ${C_GREEN}✓${C_RESET} Python ${PYTHON_VER} detected"

# 2. Determine source directory
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ ! -f "${SOURCE_DIR}/sentinel.py" ]; then
    echo -e "    ${C_WARN}[!] sentinel.py not found in current directory. Fetching from repository...${C_RESET}"
    TMP_CLONE="/tmp/health-sentinel-src"
    rm -rf "${TMP_CLONE}"
    git clone --depth=1 https://github.com/islamwell/linux-benchmark-vps.git "${TMP_CLONE}"
    SOURCE_DIR="${TMP_CLONE}"
fi

# 3. Create target directory structure
echo -e "${C_BOLD}[2/6] Setting up target directories...${C_RESET}"
mkdir -p "${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}/deploy"
mkdir -p "${CONFIG_DIR}"
mkdir -p "${STATE_DIR}"
mkdir -p "${INCIDENTS_DIR}"
chmod 750 "${INSTALL_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 750 "${STATE_DIR}"
chmod 750 "${INCIDENTS_DIR}"

# 4. Copy files
echo -e "${C_BOLD}[3/6] Installing application files into ${INSTALL_DIR}...${C_RESET}"
cp "${SOURCE_DIR}/sentinel.py" "${INSTALL_DIR}/sentinel.py"
chmod 755 "${INSTALL_DIR}/sentinel.py"

if [ -f "${SOURCE_DIR}/deploy/enable-plesk-php-slowlog.sh" ]; then
    cp "${SOURCE_DIR}/deploy/enable-plesk-php-slowlog.sh" "${INSTALL_DIR}/deploy/"
    chmod 755 "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh"
fi
if [ -f "${SOURCE_DIR}/deploy/sentinel-cron.service" ]; then
    cp "${SOURCE_DIR}/deploy/sentinel-cron.service" "${INSTALL_DIR}/deploy/"
fi
if [ -f "${SOURCE_DIR}/deploy/sentinel-cron.timer" ]; then
    cp "${SOURCE_DIR}/deploy/sentinel-cron.timer" "${INSTALL_DIR}/deploy/"
fi

# 5. Handle Configuration
echo -e "${C_BOLD}[4/6] Configuring Sentinel security and thresholds...${C_RESET}"
if [ ! -f "${CONFIG_FILE}" ]; then
    cp "${SOURCE_DIR}/config.json" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
    echo "    Created base config at ${CONFIG_FILE}"
fi

# Safely update config using Python with sys.argv
python3 - "${CONFIG_FILE}" "${BIND}" "${PORT}" "${TOKEN}" <<'PYEOF'
import sys
import json
import secrets

cfg_path = sys.argv[1]
arg_bind = sys.argv[2]
arg_port = sys.argv[3]
arg_token = sys.argv[4]

with open(cfg_path, 'r') as f:
    cfg = json.load(f)

# Ensure web dict exists
if 'web' not in cfg:
    cfg['web'] = {}

# Set secure defaults if not configured
if not cfg['web'].get('bind'):
    cfg['web']['bind'] = '127.0.0.1'
if not cfg['web'].get('port'):
    cfg['web']['port'] = 8686

# Generate a strong token if token is empty and none provided
current_token = cfg['web'].get('token', '').strip()
if not current_token and not arg_token:
    cfg['web']['token'] = secrets.token_urlsafe(24)
elif arg_token:
    cfg['web']['token'] = arg_token

# Apply explicit overrides if provided on CLI
if arg_bind:
    cfg['web']['bind'] = arg_bind
if arg_port:
    cfg['web']['port'] = int(arg_port)

with open(cfg_path, 'w') as f:
    json.dump(cfg, f, indent=2)
PYEOF

chmod 640 "${CONFIG_FILE}"

# Retrieve active settings for display
FINAL_BIND=$(python3 -c "import json; print(json.load(open('${CONFIG_FILE}'))['web'].get('bind', '127.0.0.1'))")
FINAL_PORT=$(python3 -c "import json; print(json.load(open('${CONFIG_FILE}'))['web'].get('port', 8686))")
FINAL_TOKEN=$(python3 -c "import json; print(json.load(open('${CONFIG_FILE}'))['web'].get('token', ''))")

# 6. Install and enable Systemd service
echo -e "${C_BOLD}[5/6] Registering and starting systemd service (sentinel.service)...${C_RESET}"
cat <<'EOF' > "${SERVICE_FILE}"
[Unit]
Description=Linux Health Sentinel (dashboard + alerts)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/health-sentinel/sentinel.py -c /etc/health-sentinel/config.json
Restart=always
RestartSec=5
User=root
StateDirectory=health-sentinel
Nice=10
IOSchedulingClass=idle
MemoryMax=200M
CPUQuota=25%
NoNewPrivileges=yes
ProtectHome=read-only

[Install]
WantedBy=multi-user.target
EOF

chmod 644 "${SERVICE_FILE}"
systemctl daemon-reload
systemctl enable --now sentinel
sleep 1.5

# Optional Cron Timer Setup
if [ "$ENABLE_TIMER" = true ]; then
    echo "    Enabling scheduled timer (sentinel-cron.timer)..."
    cp "${INSTALL_DIR}/deploy/sentinel-cron.service" "${CRON_SERVICE_FILE}"
    cp "${INSTALL_DIR}/deploy/sentinel-cron.timer" "${CRON_TIMER_FILE}"
    systemctl daemon-reload
    systemctl enable --now sentinel-cron.timer
fi

# 7. Optional PHP-FPM Slowlog Setup
echo -e "${C_BOLD}[6/6] Checking PHP-FPM slow logging setup...${C_RESET}"
if [ "$ENABLE_SLOWLOG" = true ]; then
    if [ -f "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh" ]; then
        echo "    Executing safe PHP-FPM slow logging configuration..."
        bash "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh" "5s" "20" || echo "    [!] Notice: PHP slowlog setup skipped or partially configured."
    fi
else
    echo -e "    ${C_DIM}PHP slowlog auto-config skipped (opt-in). Run anytime with:${C_RESET}"
    echo -e "    ${C_BLUE}sudo bash ${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh 5s 20${C_RESET}"
fi

# Server IP detection
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# Success Display
echo ""
echo -e "${C_GREEN}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_GREEN}║  ${C_BOLD}✓  INSTALLATION SUCCESSFUL · LINUX HEALTH SENTINEL v${VERSION}${C_RESET}${C_GREEN}                 ║${C_RESET}"
echo -e "${C_GREEN}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Dashboard Security:${C_RESET} Bound to ${C_GREEN}${FINAL_BIND}:${FINAL_PORT}${C_RESET}"
if [ -n "$FINAL_TOKEN" ]; then
    echo -e "  ${C_BOLD}Generated Token:${C_RESET}    ${C_WARN}${FINAL_TOKEN}${C_RESET}"
    echo -e "  ${C_BOLD}Dashboard URL:${C_RESET}      ${C_GREEN}http://${FINAL_BIND}:${FINAL_PORT}?token=${FINAL_TOKEN}${C_RESET}"
else
    echo -e "  ${C_BOLD}Dashboard URL:${C_RESET}      ${C_GREEN}http://${FINAL_BIND}:${FINAL_PORT}${C_RESET}"
fi
echo -e "  ${C_BOLD}Prometheus Metrics:${C_RESET} ${C_BLUE}http://127.0.0.1:${FINAL_PORT}/metrics${C_RESET}"
echo -e "  ${C_BOLD}Config File:${C_RESET}        ${C_DIM}${CONFIG_FILE}${C_RESET}"
echo -e "  ${C_BOLD}Service Status:${C_RESET}     ${C_DIM}systemctl status sentinel${C_RESET}"
echo ""
echo -e "  ${C_BOLD}🔒 Recommended Secure Access:${C_RESET}"
echo -e "  Since Sentinel is securely bound to ${FINAL_BIND}, access it from your laptop via SSH tunnel:"
echo -e "  ${C_BLUE}ssh -L ${FINAL_PORT}:127.0.0.1:${FINAL_PORT} root@${SERVER_IP}${C_RESET}"
echo -e "  Then open: ${C_GREEN}http://localhost:${FINAL_PORT}${FINAL_TOKEN:+?token=$FINAL_TOKEN}${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Helpful Commands:${C_RESET}"
echo -e "  • Instant CLI report:   ${C_BLUE}sudo python3 ${INSTALL_DIR}/sentinel.py --once${C_RESET}"
echo -e "  • Configure alerts:     ${C_BLUE}sudo nano ${CONFIG_FILE}${C_RESET}"
echo -e "  • Test alert channels:  ${C_BLUE}sudo python3 ${INSTALL_DIR}/sentinel.py -c ${CONFIG_FILE} --test-alerts${C_RESET}"
echo ""
