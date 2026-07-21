#!/bin/bash
# Post-update migration script — runs automatically after each update is applied.
# Every block must be idempotent (safe to run multiple times).

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Ensure wg0 INPUT rule exists ─────────────────────────────────────────────
# Added in v1.0.4: WireGuard traffic arriving on wg0 must be accepted in INPUT
if ! iptables -C INPUT -i wg0 -j ACCEPT 2>/dev/null; then
    iptables -I INPUT -i wg0 -j ACCEPT 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ── Install / update WireGuard DDNS watchdog ─────────────────────────────────
# Added in v1.0.4: auto-updates peer endpoints when public IP changes (DDNS or dynamic IP)
# and restarts stale tunnels — prevents VPN outages after ISP IP rotation.
if [[ -f "${BASE_DIR}/build/wg-watchdog.sh" ]]; then
    install -m 755 "${BASE_DIR}/build/wg-watchdog.sh" /usr/local/sbin/wg-watchdog
    cp "${BASE_DIR}/build/wg-watchdog.service" /etc/systemd/system/wg-watchdog.service
    cp "${BASE_DIR}/build/wg-watchdog.timer"   /etc/systemd/system/wg-watchdog.timer
    systemctl daemon-reload
    systemctl enable wg-watchdog.timer  2>/dev/null || true
    systemctl restart wg-watchdog.timer 2>/dev/null || true
fi
