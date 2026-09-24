#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — Automated SSL/TLS Reverse Proxy Deployer
# Version: 2.2.21 (updated 2026-09-24 16:05)
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
    echo -e "${C_CRIT}[-] Error: This script must be run as root.${C_RESET} Use: sudo bash $0" >&2
    exit 1
fi

echo -e "\n${C_BLUE}╔════════════════════════════════════════════════════════════════════════════╗${C_RESET}"
echo -e "${C_BLUE}║  ${C_BOLD}🔒  LINUX HEALTH SENTINEL — AUTOMATED SSL/TLS REVERSE PROXY SETUP       ${C_RESET}${C_BLUE}║${C_RESET}"
echo -e "${C_BLUE}╚════════════════════════════════════════════════════════════════════════════╝${C_RESET}\n"

SENTINEL_PORT="8686"
DOMAIN="${1:-}"
PROXY_TYPE="${2:-auto}"

if [ -z "$DOMAIN" ]; then
    echo -e "${C_BOLD}Configure HTTPS for Linux Health Sentinel${C_RESET}"
    echo -e "Protects tokens and dashboard metrics from network eavesdropping.\n"
    read -rp "Enter your fully qualified domain (e.g. status.yourdomain.com) or IP: " DOMAIN
fi

if [ -z "$DOMAIN" ]; then
    echo -e "${C_CRIT}[-] Error: Domain name or IP is required.${C_RESET}" >&2
    exit 1
fi

detect_pkg_mgr() {
    if command -v apt-get >/dev/null 2>&1; then echo "apt"
    elif command -v dnf >/dev/null 2>&1; then echo "dnf"
    elif command -v yum >/dev/null 2>&1; then echo "yum"
    elif command -v zypper >/dev/null 2>&1; then echo "zypper"
    elif command -v pacman >/dev/null 2>&1; then echo "pacman"
    else echo "unknown"
    fi
}

PKG_MGR=$(detect_pkg_mgr)

setup_caddy() {
    echo -e "${C_BOLD}[1/2] Setting up Caddy for automatic Let's Encrypt SSL...${C_RESET}"
    if ! command -v caddy >/dev/null 2>&1; then
        echo "    Installing Caddy web server..."
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get install -y -qq debian-keyring debian-archive-keyring apt-transport-https curl
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg --yes
            curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list
            apt-get update -qq && apt-get install -y -qq caddy
        elif [ "$PKG_MGR" = "dnf" ] || [ "$PKG_MGR" = "yum" ]; then
            dnf install -y -q 'dnf-command(copr)' || yum install -y -q yum-plugin-copr || true
            dnf copr enable -y @caddy/caddy || copr enable -y @caddy/caddy || true
            dnf install -y -q caddy || yum install -y -q caddy
        fi
    fi

    cat <<EOF > /etc/caddy/Caddyfile
$DOMAIN {
    reverse_proxy 127.0.0.1:${SENTINEL_PORT}
}
EOF
    systemctl restart caddy
    echo -e "    ${C_GREEN}✓${C_RESET} Caddy configured with automatic HTTPS on https://${DOMAIN}"
}

setup_nginx() {
    echo -e "${C_BOLD}[1/2] Setting up Nginx reverse proxy...${C_RESET}"
    if ! command -v nginx >/dev/null 2>&1; then
        echo "    Installing Nginx..."
        if [ "$PKG_MGR" = "apt" ]; then
            apt-get update -qq && apt-get install -y -qq nginx certbot python3-certbot-nginx
        elif [ "$PKG_MGR" = "dnf" ]; then
            dnf install -y -q nginx certbot python3-certbot-nginx
        elif [ "$PKG_MGR" = "yum" ]; then
            yum install -y -q nginx certbot python3-certbot-nginx
        fi
    fi

    CONF_DIR="/etc/nginx/conf.d"
    if [ -d "/etc/nginx/sites-available" ]; then
        CONF_DIR="/etc/nginx/sites-available"
    fi

    cat <<EOF > "${CONF_DIR}/sentinel.conf"
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        proxy_pass http://127.0.0.1:${SENTINEL_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

    if [ -d "/etc/nginx/sites-enabled" ] && [ -f "${CONF_DIR}/sentinel.conf" ]; then
        ln -sf "${CONF_DIR}/sentinel.conf" "/etc/nginx/sites-enabled/sentinel.conf"
    fi

    nginx -t && (systemctl reload nginx || systemctl restart nginx)
    echo -e "    ${C_GREEN}✓${C_RESET} Nginx reverse proxy active for ${DOMAIN}"

    if command -v certbot >/dev/null 2>&1; then
        echo "    Attempting automated Let's Encrypt certificate with certbot..."
        certbot --nginx -d "$DOMAIN" --non-interactive --agree-tos --register-unsafely-without-email || echo -e "    ${C_WARN}[!] Certbot setup can be completed manually: certbot --nginx -d $DOMAIN${C_RESET}"
    fi
}

setup_self_signed() {
    echo -e "${C_BOLD}[1/2] Generating self-signed SSL certificate...${C_RESET}"
    SSL_DIR="/etc/health-sentinel/ssl"
    mkdir -p "$SSL_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "${SSL_DIR}/sentinel.key" \
        -out "${SSL_DIR}/sentinel.crt" \
        -subj "/CN=${DOMAIN}/O=Linux Health Sentinel" 2>/dev/null
    chmod 600 "${SSL_DIR}/sentinel.key"
    echo -e "    ${C_GREEN}✓${C_RESET} Certificate created at ${SSL_DIR}/sentinel.crt"
    echo -e "    ${C_GREEN}✓${C_RESET} Private key created at ${SSL_DIR}/sentinel.key"
}

if [ "$PROXY_TYPE" = "caddy" ]; then
    setup_caddy
elif [ "$PROXY_TYPE" = "nginx" ]; then
    setup_nginx
elif [ "$PROXY_TYPE" = "self-signed" ]; then
    setup_self_signed
else
    if command -v caddy >/dev/null 2>&1; then
        setup_caddy
    elif command -v nginx >/dev/null 2>&1; then
        setup_nginx
    else
        echo -e "Available SSL setups:\n  1) Caddy (Recommended — 100% automatic Let's Encrypt HTTPS)\n  2) Nginx + Certbot\n  3) Self-signed SSL certificate\n"
        read -rp "Select option [1-3, default 1]: " CHO || CHO="1"
        case "$CHO" in
            2) setup_nginx ;;
            3) setup_self_signed ;;
            *) setup_caddy ;;
        esac
    fi
fi

echo -e "\n${C_GREEN}✓ SSL/TLS reverse proxy setup complete!${C_RESET}"
echo -e "Your Sentinel dashboard is securely accessible at: ${C_BOLD}${C_GREEN}https://${DOMAIN}/${C_RESET}\n"
