#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — One-Command Automated Installer & Service Manager
# Version: 1.4.2 (updated 2026-08-27 15:50)
#
# Automated installation for Linux servers & Plesk VPS instances.
# Usage:
#   sudo bash install.sh
#   sudo bash install.sh --port 8686 --token my-secret-pass --enable-php-slowlog
#   sudo bash install.sh --uninstall
# ==============================================================================

set -euo pipefail

VERSION="1.4.2"
UPDATED="2026-08-27 15:50"

# Target installation paths
INSTALL_DIR="/opt/health-sentinel"
CONFIG_DIR="/etc/health-sentinel"
CONFIG_FILE="${CONFIG_DIR}/config.json"
STATE_DIR="/var/lib/health-sentinel"
SERVICE_FILE="/etc/systemd/system/sentinel.service"

# Defaults
PORT=8686
BIND="0.0.0.0"
TOKEN=""
ENABLE_SLOWLOG=false
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
            echo "  --bind <ip>               Bind IP address (default: 0.0.0.0)"
            echo "  --token <token>           Optional web authentication token"
            echo "  --enable-php-slowlog      Automatically configure PHP-FPM / Plesk slow logging"
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
    rm -f "${SERVICE_FILE}"
    systemctl daemon-reload || true
    rm -rf "${INSTALL_DIR}"
    echo -e "${C_GREEN}[✓] Sentinel binaries and service removed.${C_RESET}"
    echo -e "${C_DIM}Note: Configuration at ${CONFIG_DIR} and data at ${STATE_DIR} were kept. Remove manually if desired.${C_RESET}"
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
chmod 750 "${INSTALL_DIR}"
chmod 750 "${CONFIG_DIR}"
chmod 750 "${STATE_DIR}"

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
echo -e "${C_BOLD}[4/6] Configuring Sentinel thresholds and bindings...${C_RESET}"
if [ ! -f "${CONFIG_FILE}" ]; then
    cp "${SOURCE_DIR}/config.json" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
    echo "    Created default config at ${CONFIG_FILE}"
else
    echo "    Existing config found at ${CONFIG_FILE} (preserved)"
fi

# Apply CLI overrides to config.json if provided
python3 -c "
import json
cfg_path = '${CONFIG_FILE}'
with open(cfg_path, 'r') as f:
    cfg = json.load(f)
cfg['web']['bind'] = '${BIND}'
cfg['web']['port'] = int('${PORT}')
if '${TOKEN}':
    cfg['web']['token'] = '${TOKEN}'
with open(cfg_path, 'w') as f:
    json.dump(cfg, f, indent=2)
"

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

# 7. Optional Plesk PHP-FPM slow log activation
echo -e "${C_BOLD}[6/6] Checking for Plesk / PHP-FPM slow logging...${C_RESET}"
IS_PLESK=false
if [ -d "/usr/local/psa" ] || [ -d "/opt/plesk/php" ]; then
    IS_PLESK=true
fi

if [ "$ENABLE_SLOWLOG" = true ] || [ "$IS_PLESK" = true ]; then
    if [ -f "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh" ]; then
        echo "    Configuring PHP-FPM slow logging on active pools (5s timeout)..."
        bash "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh" "5s" "20" || true
    fi
else
    echo "    Skipped (run 'sudo bash /opt/health-sentinel/deploy/enable-plesk-php-slowlog.sh' anytime)"
fi

# Detect Server IP
SERVER_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
[ -z "$SERVER_IP" ] && SERVER_IP="127.0.0.1"

# Success Display
echo ""
echo -e "${C_GREEN}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_GREEN}║  ${C_BOLD}✓  INSTALLATION SUCCESSFUL · LINUX HEALTH SENTINEL v${VERSION}${C_RESET}${C_GREEN}                 ║${C_RESET}"
echo -e "${C_GREEN}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Dashboard URL:${C_RESET}      ${C_GREEN}http://${SERVER_IP}:${PORT}${TOKEN:+?token=$TOKEN}${C_RESET}"
echo -e "  ${C_BOLD}Localhost URL:${C_RESET}      ${C_GREEN}http://127.0.0.1:${PORT}${TOKEN:+?token=$TOKEN}${C_RESET}"
echo -e "  ${C_BOLD}Prometheus Metrics:${C_RESET} ${C_BLUE}http://127.0.0.1:${PORT}/metrics${C_RESET}"
echo -e "  ${C_BOLD}Config File:${C_RESET}        ${C_DIM}${CONFIG_FILE}${C_RESET}"
echo -e "  ${C_BOLD}Service Status:${C_RESET}     ${C_DIM}systemctl status sentinel${C_RESET}"
echo -e "  ${C_BOLD}Live Logs:${C_RESET}          ${C_DIM}journalctl -u sentinel -f${C_RESET}"
echo ""
echo -e "  ${C_BOLD}Next Steps:${C_RESET}"
echo -e "  1. View instant CLI report:   ${C_BLUE}sudo python3 ${INSTALL_DIR}/sentinel.py --once${C_RESET}"
echo -e "  2. Configure Telegram/Slack:  ${C_BLUE}sudo nano ${CONFIG_FILE}${C_RESET}"
echo -e "  3. Test alert dispatch:       ${C_BLUE}sudo python3 ${INSTALL_DIR}/sentinel.py -c ${CONFIG_FILE} --test-alerts${C_RESET}"
echo ""
