#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — 1-Command Universal Auto-Updater
# Version: 2.2.20 (updated 2026-09-24 15:55)
# ==============================================================================

set -euo pipefail

VERSION="2.2.20"

C_RESET="\033[0m"
C_BOLD="\033[1m"
C_GREEN="\033[38;5;42m"
C_BLUE="\033[38;5;111m"
C_WARN="\033[38;5;214m"
C_CRIT="\033[38;5;203m"
C_DIM="\033[38;5;245m"

# Ensure root
if [ "$(id -u)" -ne 0 ]; then
    echo -e "${C_CRIT}[-] Error: This updater must be run as root.${C_RESET} Use: sudo bash $0" >&2
    exit 1
fi

echo -e "\n${C_BLUE}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_BLUE}║  ${C_BOLD}🛡   LINUX HEALTH SENTINEL — UNIVERSAL 1-COMMAND AUTO-UPDATER           ${C_RESET}${C_BLUE}║${C_RESET}"
echo -e "${C_BLUE}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}\n"

INSTALL_DIR="/opt/health-sentinel"
CONFIG_DIR="/etc/health-sentinel"
CONFIG_FILE="${CONFIG_DIR}/config.json"
REPO_URL="https://github.com/islamwell/linux-benchmark-vps.git"
TMP_DIR=$(mktemp -d /tmp/health-sentinel-update-XXXXXX)

cleanup() {
    rm -rf "${TMP_DIR}"
}
trap cleanup EXIT

echo -e "${C_BOLD}[1/4] Downloading latest release from GitHub...${C_RESET}"
if command -v git >/dev/null 2>&1; then
    git clone --depth=1 "${REPO_URL}" "${TMP_DIR}"
else
    echo -e "    ${C_WARN}git not found, installing git...${C_RESET}"
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update -qq && apt-get install -y -qq git
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y -q git
    elif command -v yum >/dev/null 2>&1; then
        yum install -y -q git
    elif command -v zypper >/dev/null 2>&1; then
        zypper --non-interactive install -y git
    elif command -v pacman >/dev/null 2>&1; then
        pacman -Sy --noconfirm git
    fi
    git clone --depth=1 "${REPO_URL}" "${TMP_DIR}"
fi
echo -e "    ${C_GREEN}✓${C_RESET} Latest files retrieved successfully"

echo -e "${C_BOLD}[2/4] Updating application files in ${INSTALL_DIR}...${C_RESET}"
mkdir -p "${INSTALL_DIR}" "${INSTALL_DIR}/deploy" "${CONFIG_DIR}"
cp "${TMP_DIR}/sentinel.py" "${INSTALL_DIR}/sentinel.py"
cp "${TMP_DIR}/install.sh" "${INSTALL_DIR}/install.sh"
cp "${TMP_DIR}/update.sh" "${INSTALL_DIR}/update.sh"
if [ -f "${TMP_DIR}/deploy/optimize-io-memory.sh" ]; then
    cp "${TMP_DIR}/deploy/optimize-io-memory.sh" "${INSTALL_DIR}/deploy/"
    chmod +x "${INSTALL_DIR}/deploy/optimize-io-memory.sh"
fi
if [ -f "${TMP_DIR}/deploy/enable-plesk-php-slowlog.sh" ]; then
    cp "${TMP_DIR}/deploy/enable-plesk-php-slowlog.sh" "${INSTALL_DIR}/deploy/"
    chmod +x "${INSTALL_DIR}/deploy/enable-plesk-php-slowlog.sh"
fi
if [ -f "${TMP_DIR}/deploy/setup-ssl.sh" ]; then
    cp "${TMP_DIR}/deploy/setup-ssl.sh" "${INSTALL_DIR}/deploy/"
    chmod +x "${INSTALL_DIR}/deploy/setup-ssl.sh"
fi
if [ -f "${TMP_DIR}/deploy/generate-license.py" ]; then
    cp "${TMP_DIR}/deploy/generate-license.py" "${INSTALL_DIR}/deploy/"
    chmod +x "${INSTALL_DIR}/deploy/generate-license.py"
fi
chmod +x "${INSTALL_DIR}/sentinel.py" "${INSTALL_DIR}/install.sh" "${INSTALL_DIR}/update.sh"

# Ensure config exists without overwriting existing settings
if [ ! -f "${CONFIG_FILE}" ]; then
    cp "${TMP_DIR}/config.json" "${CONFIG_FILE}"
    chmod 640 "${CONFIG_FILE}"
    echo -e "    ${C_GREEN}✓${C_RESET} Created default configuration at ${CONFIG_FILE}"
else
    echo -e "    ${C_GREEN}✓${C_RESET} Preserved existing configuration and tokens at ${CONFIG_FILE}"
fi

echo -e "${C_BOLD}[3/4] Restarting Sentinel system service...${C_RESET}"
if [ -f "/etc/systemd/system/sentinel.service" ]; then
    systemctl daemon-reload
    systemctl restart sentinel
    sleep 1
    if systemctl is-active --quiet sentinel; then
        echo -e "    ${C_GREEN}✓${C_RESET} Sentinel service is active and running"
    else
        echo -e "    ${C_WARN}[!] Warning: Sentinel service may have encountered an issue. Checking logs:${C_RESET}"
        journalctl -u sentinel -n 10 --no-pager
    fi
else
    echo -e "    ${C_WARN}[!] sentinel.service not registered yet. Running full installer...${C_RESET}"
    bash "${INSTALL_DIR}/install.sh" -y
fi

echo -e "${C_BOLD}[4/4] Extracting dashboard access credentials and URLs...${C_RESET}"
python3 - "${CONFIG_FILE}" "${VERSION}" <<'PYEOF'
import json, sys, socket, urllib.request

config_path = sys.argv[1]
version = sys.argv[2] if len(sys.argv) > 2 else "2.2.20"

try:
    with open(config_path) as f:
        cfg = json.load(f)
except Exception:
    cfg = {}

web = cfg.get("web", {})
port = web.get("port", 8686)
bind = web.get("bind", "127.0.0.1")
admin_token = (web.get("admin_token") or web.get("token") or "").strip()
view_token = (web.get("view_token") or "").strip()
cfg_hostname = (cfg.get("hostname") or "").strip()

# Detect public IP via fast HTTP check
public_ip = ""
for url in ["https://api.ipify.org", "https://icanhazip.com", "https://ifconfig.me/ip"]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            ip = resp.read().decode("utf-8").strip()
            if ip and (len(ip.split(".")) == 4 or ":" in ip):
                public_ip = ip
                break
    except Exception:
        pass

# Detect local IP safely
local_ip = ""
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()
except Exception:
    pass

sys_hostname = ""
try:
    sys_hostname = socket.gethostname()
except Exception:
    pass

target_host = public_ip or local_ip or cfg_hostname or sys_hostname or "127.0.0.1"

admin_query = f"/?token={admin_token}" if admin_token else ""
view_query = f"/?token={view_token}" if view_token else ""

dashboard_url = f"http://{target_host}:{port}{admin_query}"
view_url = f"http://{target_host}:{port}{view_query}"

# ANSI Colors
C_GREEN = "\033[38;5;42m"
C_BLUE = "\033[38;5;111m"
C_BOLD = "\033[1m"
C_DIM = "\033[38;5;245m"
C_RESET = "\033[0m"

print(f"\n{C_GREEN}╔════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
print(f"{C_GREEN}║  {C_BOLD}✓  UPDATE SUCCESSFUL — LINUX HEALTH SENTINEL v{version:<27}{C_RESET}{C_GREEN}║{C_RESET}")
print(f"{C_GREEN}╚════════════════════════════════════════════════════════════════════════════╝{C_RESET}\n")

print(f"  ▸ Service Status: {C_GREEN}active (running){C_RESET}")
print(f"  ▸ Network Bind  : {bind}:{port}")
if sys_hostname:
    print(f"  ▸ Hostname      : {sys_hostname}")
print()

print(f"  {C_BOLD}🚀 DIRECT DASHBOARD URL (Click to Open in Browser):{C_RESET}")
print(f"  {C_GREEN}{dashboard_url}{C_RESET}\n")

if view_token:
    print(f"  {C_BOLD}👁️ Client / View-Only Dashboard URL:{C_RESET}")
    print(f"  {C_BLUE}{view_url}{C_RESET}\n")

if bind in ("127.0.0.1", "localhost"):
    print(f"  {C_BOLD}🔒 Secure Local Access (SSH Tunnel from your laptop):{C_RESET}")
    print(f"     {C_DIM}If port {port} is not opened in your VPS firewall, run on your laptop terminal:{C_RESET}")
    print(f"     {C_BLUE}ssh -L {port}:127.0.0.1:{port} root@{target_host}{C_RESET}")
    print(f"     {C_DIM}Then open in your laptop browser:{C_RESET}")
    print(f"     {C_GREEN}http://localhost:{port}{admin_query}{C_RESET}\n")

if cfg_hostname and cfg_hostname not in (public_ip, local_ip, "127.0.0.1"):
    print(f"  {C_BOLD}🌐 Domain Access (if DNS points to this server):{C_RESET}")
    print(f"     {C_BLUE}http://{cfg_hostname}:{port}{admin_query}{C_RESET}\n")

print(f"  {C_DIM}To update anytime in the future, just run:{C_RESET}")
print(f"  {C_BOLD}curl -fsSL https://raw.githubusercontent.com/islamwell/linux-benchmark-vps/master/update.sh | sudo bash{C_RESET}\n")
PYEOF


