#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — 1-Command Universal Auto-Updater
# Version: 2.2.5 (updated 2026-09-13 19:10)
# ==============================================================================

set -euo pipefail

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

echo -e "${C_BOLD}[4/4] Extracting dashboard access credentials...${C_RESET}"
ACCESS_INFO=$(python3 - "${CONFIG_FILE}" <<'PYEOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        cfg = json.load(f)
    w = cfg.get('web', {})
    port = w.get('port', 8686)
    bind = w.get('bind', '127.0.0.1')
    admin_tok = (w.get('admin_token') or w.get('token') or '').strip()
    view_tok = (w.get('view_token') or '').strip()
    print(f"{bind}|{port}|{admin_tok}|{view_tok}")
except Exception as e:
    print("127.0.0.1|8686||")
PYEOF
)

IFS='|' read -r CFG_BIND CFG_PORT CFG_ADMIN_TOKEN CFG_VIEW_TOKEN <<< "${ACCESS_INFO}"

PUBLIC_IP=$(curl -s -m 2 https://api.ipify.org 2>/dev/null || curl -s -m 2 https://icanhazip.com 2>/dev/null || echo "${CFG_BIND}")

echo -e "\n${C_GREEN}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_GREEN}║  ${C_BOLD}✓  UPDATE SUCCESSFUL — LINUX HEALTH SENTINEL v2.1.1                    ${C_RESET}${C_GREEN}║${C_RESET}"
echo -e "${C_GREEN}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}\n"

echo -e "  ▸ Service Status: ${C_GREEN}active (running)${C_RESET}"
echo -e "  ▸ Network Bind  : ${CFG_BIND}:${CFG_PORT}\n"

if [ -n "$CFG_ADMIN_TOKEN" ]; then
    echo -e "  ${C_BOLD}⚡ Admin Dashboard (Full Access):${C_RESET}"
    echo -e "     ${C_GREEN}http://${PUBLIC_IP}:${CFG_PORT}/?token=${CFG_ADMIN_TOKEN}${C_RESET}"
fi

if [ -n "$CFG_VIEW_TOKEN" ]; then
    echo -e "  ${C_BOLD}👁️ View-Only Dashboard (Client & Team Access):${C_RESET}"
    echo -e "     ${C_BLUE}http://${PUBLIC_IP}:${CFG_PORT}/?token=${CFG_VIEW_TOKEN}${C_RESET}"
fi

if [ -z "$CFG_ADMIN_TOKEN" ] && [ -z "$CFG_VIEW_TOKEN" ]; then
    echo -e "  ▸ Dashboard URL : ${C_BOLD}${C_BLUE}http://${PUBLIC_IP}:${CFG_PORT}/${C_RESET}"
fi

echo -e "\n  ${C_DIM}To update anytime in the future, just run:${C_RESET}"
echo -e "  ${C_BOLD}curl -fsSL https://raw.githubusercontent.com/islamwell/linux-benchmark-vps/master/update.sh | sudo bash${C_RESET}\n"
