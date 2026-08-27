#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — Plesk & Linux PHP-FPM Slowlog Safe Configuration
# Version: 1.5.0 (updated 2026-08-27 16:05)
#
# Safely configures PHP-FPM slow logging with:
#  - Automatic configuration backups
#  - Robust directive parsing & updating
#  - Syntax verification (php-fpm -t) before reload
#  - Automatic rollback on validation failure
# ==============================================================================

set -euo pipefail

SLOW_TIMEOUT="${1:-5s}"
TRACE_DEPTH="${2:-20}"
BACKUP_SUFFIX=".sentinel-bak.$(date +%s)"

echo "========================================================"
echo " 🛡  Configuring PHP-FPM Slow Logging"
echo "    Slow request threshold: ${SLOW_TIMEOUT}"
echo "    Stack trace depth:      ${TRACE_DEPTH}"
echo "========================================================"

if [ "$(id -u)" -ne 0 ]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

MODIFIED_FILES=()
SERVICES_TO_RELOAD=()

# Helper function to configure a single pool file
configure_pool_file() {
    local CONF="$1"
    local SLOW_LOG="$2"

    [ -f "$CONF" ] || return 0

    # Create backup
    cp "$CONF" "${CONF}${BACKUP_SUFFIX}"
    MODIFIED_FILES+=("$CONF")

    # Update or add slowlog
    if grep -qE "^\s*;?\s*slowlog\s*=" "$CONF"; then
        sed -i "s|^\s*;*\s*slowlog\s*=.*|slowlog = ${SLOW_LOG}|" "$CONF"
    else
        echo "slowlog = ${SLOW_LOG}" >> "$CONF"
    fi

    # Update or add request_slowlog_timeout
    if grep -qE "^\s*;?\s*request_slowlog_timeout\s*=" "$CONF"; then
        sed -i "s|^\s*;*\s*request_slowlog_timeout\s*=.*|request_slowlog_timeout = ${SLOW_TIMEOUT}|" "$CONF"
    else
        echo "request_slowlog_timeout = ${SLOW_TIMEOUT}" >> "$CONF"
    fi

    # Update or add request_slowlog_trace_depth
    if grep -qE "^\s*;?\s*request_slowlog_trace_depth\s*=" "$CONF"; then
        sed -i "s|^\s*;*\s*request_slowlog_trace_depth\s*=.*|request_slowlog_trace_depth = ${TRACE_DEPTH}|" "$CONF"
    else
        echo "request_slowlog_trace_depth = ${TRACE_DEPTH}" >> "$CONF"
    fi
}

rollback_all() {
    echo ""
    echo "[-] Configuration validation failed! Rolling back all modified pool files..." >&2
    for F in "${MODIFIED_FILES[@]}"; do
        if [ -f "${F}${BACKUP_SUFFIX}" ]; then
            cp "${F}${BACKUP_SUFFIX}" "$F"
            rm -f "${F}${BACKUP_SUFFIX}"
        fi
    done
    echo "[!] Rollback complete. No services were reloaded." >&2
    exit 1
}

# 1. Process Plesk PHP Handlers
for PLESK_PHP_DIR in /opt/plesk/php/*/etc/php-fpm.d; do
    if [ -d "$PLESK_PHP_DIR" ]; then
        PHP_ROOT="$(dirname "$(dirname "$PLESK_PHP_DIR")")"
        PHP_VER="$(basename "$PHP_ROOT")"
        BIN_NAME="plesk-php${PHP_VER//./}-fpm"
        LOG_DIR="/var/log/${BIN_NAME}"
        mkdir -p "$LOG_DIR" && chmod 750 "$LOG_DIR"
        SLOW_LOG="${LOG_DIR}/slow.log"
        touch "$SLOW_LOG" && chmod 640 "$SLOW_LOG"

        echo "[+] Processing Plesk PHP ${PHP_VER} in ${PLESK_PHP_DIR}..."

        for CONF in "$PLESK_PHP_DIR"/*.conf; do
            [ -e "$CONF" ] || continue
            configure_pool_file "$CONF" "$SLOW_LOG"
        done

        # Syntax test for Plesk PHP
        FPM_BIN="${PHP_ROOT}/sbin/php-fpm"
        FPM_INI="${PHP_ROOT}/etc/php-fpm.conf"
        if [ -x "$FPM_BIN" ] && [ -f "$FPM_INI" ]; then
            echo "    Testing configuration: ${FPM_BIN} -t -y ${FPM_INI}"
            if ! "$FPM_BIN" -t -y "$FPM_INI" >/dev/null 2>&1; then
                "$FPM_BIN" -t -y "$FPM_INI" || true
                rollback_all
            fi
        fi

        SERVICES_TO_RELOAD+=("$BIN_NAME")
    fi
done

# 2. Process Distro / System PHP-FPM Handlers (/etc/php/*/fpm/pool.d and /etc/php-fpm.d)
for SYS_POOL_DIR in /etc/php/*/fpm/pool.d /etc/php-fpm.d; do
    if [ -d "$SYS_POOL_DIR" ]; then
        echo "[+] Processing System PHP pools in ${SYS_POOL_DIR}..."
        SYS_LOG="/var/log/php-fpm-slow.log"
        touch "$SYS_LOG" && chmod 640 "$SYS_LOG"

        for CONF in "$SYS_POOL_DIR"/*.conf; do
            [ -e "$CONF" ] || continue
            configure_pool_file "$CONF" "$SYS_LOG"
        done

        # Detect service name
        if [[ "$SYS_POOL_DIR" =~ /etc/php/([0-9.]+)/fpm/pool.d ]]; then
            VER="${BASH_REMATCH[1]}"
            FPM_BIN=$(command -v "php-fpm${VER}" || command -v php-fpm || echo "")
            if [ -n "$FPM_BIN" ] && [ -x "$FPM_BIN" ]; then
                echo "    Testing configuration: ${FPM_BIN} -t"
                if ! "$FPM_BIN" -t >/dev/null 2>&1; then
                    "$FPM_BIN" -t || true
                    rollback_all
                fi
            fi
            SERVICES_TO_RELOAD+=("php${VER}-fpm")
        elif [ -d "/etc/php-fpm.d" ]; then
            FPM_BIN=$(command -v php-fpm || echo "")
            if [ -n "$FPM_BIN" ] && [ -x "$FPM_BIN" ]; then
                echo "    Testing configuration: ${FPM_BIN} -t"
                if ! "$FPM_BIN" -t >/dev/null 2>&1; then
                    "$FPM_BIN" -t || true
                    rollback_all
                fi
            fi
            SERVICES_TO_RELOAD+=("php-fpm")
        fi
    fi
done

# 3. Reload services safely
for SVC in $(printf "%s\n" "${SERVICES_TO_RELOAD[@]}" | sort -u); do
    if systemctl is-active --quiet "$SVC" 2>/dev/null; then
        echo "    Reloading active service: ${SVC}"
        systemctl reload "$SVC" || echo "    [!] Warning: Could not reload ${SVC}"
    fi
done

# Clean up backups on success
for F in "${MODIFIED_FILES[@]}"; do
    rm -f "${F}${BACKUP_SUFFIX}"
done

echo ""
echo "[✓] Successfully configured slow logging across ${#MODIFIED_FILES[@]} pool file(s)."
echo "[✓] Slow script executions will record script paths, durations, and backtraces."
echo "========================================================"
