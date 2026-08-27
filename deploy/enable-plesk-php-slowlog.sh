#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — Plesk PHP-FPM Slowlog Auto-Configuration Script
# Version: 1.4.1 (updated 2026-08-27 15:45)
#
# Enables PHP-FPM slow logging across all installed Plesk PHP handlers (7.x / 8.x)
# and custom vhost pools, pinpointing exact slow scripts, runtimes, and backtraces.
# ==============================================================================

set -euo pipefail

SLOW_TIMEOUT="${1:-5s}"
TRACE_DEPTH="${2:-20}"

echo "========================================================"
echo " 🛡  Configuring PHP-FPM Slow Logging for Plesk"
echo "    Slow request threshold: ${SLOW_TIMEOUT}"
echo "    Stack trace depth:      ${TRACE_DEPTH}"
echo "========================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

COUNT=0

# 1. Scan Plesk PHP handler pool directories
for PLESK_PHP_DIR in /opt/plesk/php/*/etc/php-fpm.d; do
    if [ -d "$PLESK_PHP_DIR" ]; then
        PHP_VER=$(basename "$(dirname "$(dirname "$PLESK_PHP_DIR")")")
        LOG_DIR="/var/log/plesk-php${PHP_VER//./}-fpm"
        mkdir -p "$LOG_DIR"
        chmod 750 "$LOG_DIR"

        SLOW_LOG_FILE="${LOG_DIR}/slow.log"
        touch "$SLOW_LOG_FILE"
        chmod 640 "$SLOW_LOG_FILE"

        echo "[+] Processing Plesk PHP ${PHP_VER} pools in ${PLESK_PHP_DIR}..."

        for CONF_FILE in "$PLESK_PHP_DIR"/*.conf; do
            [ -e "$CONF_FILE" ] || continue
            
            # Check if slowlog directives already exist
            if grep -q "request_slowlog_timeout" "$CONF_FILE"; then
                sed -i "s/^[; ]*request_slowlog_timeout\s*=.*/request_slowlog_timeout = ${SLOW_TIMEOUT}/" "$CONF_FILE"
                sed -i "s|^[; ]*slowlog\s*=.*|slowlog = ${SLOW_LOG_FILE}|" "$CONF_FILE"
            else
                cat <<EOF >> "$CONF_FILE"

; --- Linux Health Sentinel Slowlog ---
slowlog = ${SLOW_LOG_FILE}
request_slowlog_timeout = ${SLOW_TIMEOUT}
request_slowlog_trace_depth = ${TRACE_DEPTH}
EOF
            fi
            COUNT=$((COUNT + 1))
        done

        # Reload the specific Plesk PHP-FPM service
        SERVICE_NAME="plesk-php${PHP_VER//./}-fpm"
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            echo "    Reloading service: ${SERVICE_NAME}"
            systemctl reload "$SERVICE_NAME" || systemctl restart "$SERVICE_NAME"
        fi
    fi
done

# 2. Standard system PHP-FPM pools (/etc/php/*/fpm/pool.d and /etc/php-fpm.d)
for SYS_POOL_DIR in /etc/php/*/fpm/pool.d /etc/php-fpm.d; do
    if [ -d "$SYS_POOL_DIR" ]; then
        echo "[+] Processing system PHP pools in ${SYS_POOL_DIR}..."
        for CONF_FILE in "$SYS_POOL_DIR"/*.conf; do
            [ -e "$CONF_FILE" ] || continue
            SYS_LOG="/var/log/php-fpm-slow.log"
            touch "$SYS_LOG" && chmod 640 "$SYS_LOG"

            if grep -q "request_slowlog_timeout" "$CONF_FILE"; then
                sed -i "s/^[; ]*request_slowlog_timeout\s*=.*/request_slowlog_timeout = ${SLOW_TIMEOUT}/" "$CONF_FILE"
                sed -i "s|^[; ]*slowlog\s*=.*|slowlog = ${SYS_LOG}|" "$CONF_FILE"
            else
                cat <<EOF >> "$CONF_FILE"

; --- Linux Health Sentinel Slowlog ---
slowlog = ${SYS_LOG}
request_slowlog_timeout = ${SLOW_TIMEOUT}
request_slowlog_trace_depth = ${TRACE_DEPTH}
EOF
            fi
            COUNT=$((COUNT + 1))
        done
    fi
done

echo ""
echo "[✓] Successfully configured slow logging on ${COUNT} PHP-FPM pool(s)."
echo "[✓] Slow script executions will be logged with full stack traces."
echo "    Monitor live logs with: tail -f /var/log/plesk-php*-fpm/slow.log"
echo "========================================================"
