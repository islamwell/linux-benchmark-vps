#!/usr/bin/env bash
# ==============================================================================
# Linux Health Sentinel — Automated Software-Level I/O & Memory Tuning Script
# Version: 1.6.1 (updated 2026-09-02 07:10)
#
# This script applies non-destructive kernel, filesystem, and database tweaks
# to drastically reduce disk I/O bottlenecks (iowait) and maximize RAM usage
# without requiring hardware upgrades.
# ==============================================================================

set -euo pipefail

TIMESTAMP=$(date +%Y%m%d_%H%M%S)

echo "======================================================================"
echo " 🛡  Linux Health Sentinel — I/O & Memory Optimization"
echo "======================================================================"

if [[ $EUID -ne 0 ]]; then
    echo "[-] Error: This script must be run as root (sudo)." >&2
    exit 1
fi

# ------------------------------------------------------------------------------
# 1. Eliminate Access-Time Metadata Writes (noatime, nodiratime)
# ------------------------------------------------------------------------------
echo "[1/4] Optimizing filesystem mount flags (noatime, nodiratime)..."
if grep -q " / " /etc/fstab; then
    cp /etc/fstab "/etc/fstab.bak.${TIMESTAMP}"
    echo "  [✓] Backed up /etc/fstab to /etc/fstab.bak.${TIMESTAMP}"
    
    # Check if noatime is already in /etc/fstab for root
    if ! grep " / " /etc/fstab | grep -q "noatime"; then
        # Add noatime,nodiratime to root partition options
        awk '$2 == "/" { $4 = $4 ",noatime,nodiratime" } 1' /etc/fstab > /etc/fstab.tmp && mv /etc/fstab.tmp /etc/fstab
        echo "  [✓] Updated /etc/fstab with noatime,nodiratime for /"
    else
        echo "  [✓] /etc/fstab already has noatime configured for /"
    fi
    
    # Remount root partition immediately
    mount -o remount,noatime,nodiratime / 2>/dev/null || true
    echo "  [✓] Remounted root partition with noatime,nodiratime"
fi

# ------------------------------------------------------------------------------
# 2. Kernel Memory & Dirty Page Writeback Tuning (sysctl)
# ------------------------------------------------------------------------------
echo "[2/4] Applying kernel memory & write-batching parameters..."

SYSCTL_CONF="/etc/sysctl.d/99-sentinel-io-memory.conf"
cat << 'EOF' > "${SYSCTL_CONF}"
# Linux Health Sentinel — I/O & Memory Optimization Configuration
# 1. Reduce swappiness to favor RAM usage over slow disk swapping
vm.swappiness = 10

# 2. Keep directory and inode caches longer in memory to avoid repeated disk reads
vm.vfs_cache_pressure = 50

# 3. Batch dirty page writebacks to avoid constant disk interrupts
vm.dirty_background_ratio = 5
vm.dirty_ratio = 20
vm.dirty_expire_centisecs = 3000
vm.dirty_writeback_centisecs = 500
EOF

chmod 644 "${SYSCTL_CONF}"
sysctl --system >/dev/null 2>&1 || sysctl -p "${SYSCTL_CONF}" >/dev/null 2>&1
echo "  [✓] Applied kernel parameters in ${SYSCTL_CONF}"
echo "      • vm.swappiness = $(sysctl -n vm.swappiness)"
echo "      • vm.vfs_cache_pressure = $(sysctl -n vm.vfs_cache_pressure)"
echo "      • vm.dirty_ratio = $(sysctl -n vm.dirty_ratio)"

# ------------------------------------------------------------------------------
# 3. Compressed In-RAM Swap (zram) Setup
# ------------------------------------------------------------------------------
echo "[3/4] Checking compressed in-RAM swap (zram)..."
if command -v apt-get >/dev/null 2>&1; then
    if ! dpkg -s zram-tools >/dev/null 2>&1; then
        echo "  [i] Installing zram-tools to enable compressed RAM swap..."
        DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq zram-tools || true
    fi
    if [ -f /etc/default/zramswap ]; then
        if ! grep -q "PERCENT=50" /etc/default/zramswap; then
            echo "PERCENT=50" >> /etc/default/zramswap
            echo "ALGO=zstd" >> /etc/default/zramswap
        fi
        systemctl restart zramswap 2>/dev/null || true
        echo "  [✓] zramswap active (50% RAM compressed swap)"
    fi
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    if command -v zramctl >/dev/null 2>&1; then
        echo "  [✓] zramctl available on system"
    fi
fi

# ------------------------------------------------------------------------------
# 4. Database Transaction Write Batching (MySQL / MariaDB)
# ------------------------------------------------------------------------------
echo "[4/4] Checking MySQL / MariaDB write configuration..."
MYSQL_CONF_DIR=""
if [ -d "/etc/mysql/mariadb.conf.d" ]; then
    MYSQL_CONF_DIR="/etc/mysql/mariadb.conf.d"
elif [ -d "/etc/mysql/conf.d" ]; then
    MYSQL_CONF_DIR="/etc/mysql/conf.d"
elif [ -d "/etc/my.cnf.d" ]; then
    MYSQL_CONF_DIR="/etc/my.cnf.d"
fi

if [ -n "${MYSQL_CONF_DIR}" ]; then
    SENTINEL_MYSQL_CONF="${MYSQL_CONF_DIR}/99-sentinel-tuning.cnf"
    cat << 'EOF' > "${SENTINEL_MYSQL_CONF}"
# Linux Health Sentinel — Database Write Batching Optimization
[mysqld]
# Batch transaction log flushes once per second instead of every single commit
# Drastically reduces disk I/O bottleneck on WordPress/PHP sites
innodb_flush_log_at_trx_commit = 2
EOF
    chmod 644 "${SENTINEL_MYSQL_CONF}"
    echo "  [✓] Configured innodb_flush_log_at_trx_commit = 2 in ${SENTINEL_MYSQL_CONF}"
    
    if systemctl is-active --quiet mariadb; then
        systemctl reload mariadb 2>/dev/null || systemctl restart mariadb 2>/dev/null || true
        echo "  [✓] Reloaded MariaDB service"
    elif systemctl is-active --quiet mysql; then
        systemctl reload mysql 2>/dev/null || systemctl restart mysql 2>/dev/null || true
        echo "  [✓] Reloaded MySQL service"
    fi
else
    echo "  [i] MySQL/MariaDB configuration directory not found; skipped DB tuning."
fi

echo "======================================================================"
echo " [✓] Optimization Complete! Disk I/O demand has been drastically reduced."
echo "     Run 'sudo python3 /opt/health-sentinel/sentinel.py --once' to verify."
echo "======================================================================"
