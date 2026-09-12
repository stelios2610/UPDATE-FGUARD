#!/bin/bash
# Post-update migration script — runs automatically after each update is applied.
# Every block must be idempotent (safe to run multiple times).

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── Ensure LAN→WAN MASQUERADE exists ─────────────────────────────────────────
# Added in v1.0.13: nft/iptables restore can drop LAN NAT after reboot.
WAN_IF=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
WAN_IF="${WAN_IF:-ens1}"
if ! iptables -t nat -C POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null; then
    iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE 2>/dev/null || true
    nft insert rule ip nat POSTROUTING oifname "$WAN_IF" masquerade 2>/dev/null || true
    netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
fi

# ── IPSec vs WireGuard route steal ───────────────────────────────────────────
# Added in v1.0.14: wg0 AllowedIPs must not hide StrongSwan table 220.
if ip route show table 220 2>/dev/null | grep -q .; then
    while read -r dest _; do
        [ -n "$dest" ] || continue
        ip rule add to "$dest" lookup 220 priority 220 2>/dev/null || true
        ip route del "$dest" dev wg0 2>/dev/null || true
    done < <(ip route show table 220 | awk '{print $1}')
fi

# ── Drop invalid IPv4 dhcp-range relay that crashes dnsmasq 2.92 ─────────────
if [ -f /etc/dnsmasq.d/aegisguard.conf ]; then
    if grep -q 'dhcp-range=.*,relay,' /etc/dnsmasq.d/aegisguard.conf 2>/dev/null; then
        sed -i '/dhcp-range=.*,relay,/d' /etc/dnsmasq.d/aegisguard.conf
        systemctl try-restart dnsmasq 2>/dev/null || true
    fi
fi

# ── Restore GeoIP chain ──────────────────────────────────────────────────────
# v1.0.14: persist WAN lock. v1.0.15: OpenVPN 1194 is ACCEPT again.
if [ -f "${BASE_DIR}/core/geoblock.py" ]; then
    ( cd "${BASE_DIR}" && python3 -c "from core.geoblock import restore_geoblock; restore_geoblock()" ) 2>/dev/null || true
fi

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
