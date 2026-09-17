#!/bin/bash
# Post-update migration script — runs automatically after each update is applied.
# Every block must be idempotent (safe to run multiple times).

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── v1.0.19 branding: names change to fguard, live boxes keep working ─────────
# Real install dir is BASE_DIR (today /opt/aegisguard). Symlink /opt/fguard to it.
# Never remove aegisguard.service: that is what the running box already uses.
if [ -d /opt/aegisguard ] && [ ! -e /opt/fguard ]; then
    ln -sfn /opt/aegisguard /opt/fguard
fi
if [ -d /opt/fguard ] && [ ! -e /opt/aegisguard ]; then
    ln -sfn /opt/fguard /opt/aegisguard
fi
if [ "$BASE_DIR" != "/opt/fguard" ] && [ ! -e /opt/fguard ]; then
    ln -sfn "$BASE_DIR" /opt/fguard
fi

mkdir -p /etc/fguard
if [ -d /etc/aegisguard ]; then
    cp -an /etc/aegisguard/. /etc/fguard/ 2>/dev/null || true
fi
if [ -f "${BASE_DIR}/build/server-configs/vpn-auth.sh" ]; then
    install -m 755 "${BASE_DIR}/build/server-configs/vpn-auth.sh" /etc/fguard/vpn-auth.sh
    install -m 755 "${BASE_DIR}/build/server-configs/vpn_auth_check.py" /etc/fguard/vpn_auth_check.py
    if [ -d /etc/aegisguard ]; then
        install -m 755 "${BASE_DIR}/build/server-configs/vpn-auth.sh" /etc/aegisguard/vpn-auth.sh
        install -m 755 "${BASE_DIR}/build/server-configs/vpn_auth_check.py" /etc/aegisguard/vpn_auth_check.py
    fi
fi

if [ -f /etc/nginx/ssl/aegisguard.crt ] && [ ! -f /etc/nginx/ssl/fguard.crt ]; then
    cp -a /etc/nginx/ssl/aegisguard.crt /etc/nginx/ssl/fguard.crt 2>/dev/null || true
    cp -a /etc/nginx/ssl/aegisguard.key /etc/nginx/ssl/fguard.key 2>/dev/null || true
fi
# Do not add a second :8080 vhost if the old aegisguard site is already enabled.
if [ ! -e /etc/nginx/sites-enabled/aegisguard ] && [ -f "${BASE_DIR}/build/server-configs/nginx-fguard.conf" ]; then
    cp "${BASE_DIR}/build/server-configs/nginx-fguard.conf" /etc/nginx/sites-available/fguard
    ln -sf /etc/nginx/sites-available/fguard /etc/nginx/sites-enabled/fguard
    nginx -t >/dev/null 2>&1 && systemctl reload nginx 2>/dev/null || true
fi

if [ -f /etc/netplan/50-aegisguard.yaml ] && [ ! -f /etc/netplan/50-fguard.yaml ]; then
    cp -a /etc/netplan/50-aegisguard.yaml /etc/netplan/50-fguard.yaml
    rm -f /etc/netplan/50-aegisguard.yaml
fi
if [ -f /etc/dnsmasq.d/aegisguard.conf ] && [ ! -f /etc/dnsmasq.d/fguard.conf ]; then
    cp -a /etc/dnsmasq.d/aegisguard.conf /etc/dnsmasq.d/fguard.conf
    rm -f /etc/dnsmasq.d/aegisguard.conf
fi
if [ -f /etc/dnsmasq.d/aegisguard-filter.conf ] && [ ! -f /etc/dnsmasq.d/fguard-filter.conf ]; then
    cp -a /etc/dnsmasq.d/aegisguard-filter.conf /etc/dnsmasq.d/fguard-filter.conf
    rm -f /etc/dnsmasq.d/aegisguard-filter.conf
fi
if [ -f /etc/dnsmasq.d/aegisguard-appblock.conf ] && [ ! -f /etc/dnsmasq.d/fguard-appblock.conf ]; then
    cp -a /etc/dnsmasq.d/aegisguard-appblock.conf /etc/dnsmasq.d/fguard-appblock.conf
    rm -f /etc/dnsmasq.d/aegisguard-appblock.conf
fi

rename_chain() {
    local old="$1" new="$2" bin="$3"
    $bin -L "$old" >/dev/null 2>&1 || return 0
    $bin -L "$new" >/dev/null 2>&1 && return 0
    $bin -E "$old" "$new" 2>/dev/null || true
}
rename_chain AEGISGUARD_INPUT FGUARD_INPUT iptables
rename_chain AEGISGUARD_FORWARD FGUARD_FORWARD iptables
rename_chain AEGISGUARD_OUTPUT FGUARD_OUTPUT iptables
rename_chain AEGISGUARD_WEBFILTER FGUARD_WEBFILTER iptables
rename_chain AEGISGUARD_INPUT6 FGUARD_INPUT6 ip6tables
rename_chain AEGISGUARD_INPUT6 FGUARD_INPUT6 iptables

# Point both unit names at the real install dir. Do not drop aegisguard.service.
FGUARD_UNIT=$(cat <<EOF
[Unit]
Description=FGUARD Network Security Suite
After=network.target network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=${BASE_DIR}
ExecStart=${BASE_DIR}/venv/bin/python -m uvicorn web.api:app --host 127.0.0.1 --port 8888 --workers 1
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fguard
NoNewPrivileges=false
PrivateTmp=false

[Install]
WantedBy=multi-user.target
EOF
)
printf '%s\n' "$FGUARD_UNIT" > /etc/systemd/system/fguard.service
printf '%s\n' "$FGUARD_UNIT" > /etc/systemd/system/aegisguard.service
systemctl daemon-reload
if systemctl is-enabled aegisguard >/dev/null 2>&1; then
    systemctl enable aegisguard.service 2>/dev/null || true
    systemctl disable --now fguard.service 2>/dev/null || true
elif systemctl is-enabled fguard >/dev/null 2>&1; then
    systemctl enable fguard.service 2>/dev/null || true
    systemctl disable --now aegisguard.service 2>/dev/null || true
else
    systemctl enable aegisguard.service 2>/dev/null || systemctl enable fguard.service 2>/dev/null || true
fi

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
if [ -f /etc/dnsmasq.d/fguard.conf ]; then
    if grep -q 'dhcp-range=.*,relay,' /etc/dnsmasq.d/fguard.conf 2>/dev/null; then
        sed -i '/dhcp-range=.*,relay,/d' /etc/dnsmasq.d/fguard.conf
        systemctl try-restart dnsmasq 2>/dev/null || true
    fi
fi
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

# ── DNS watchdog: patch VLAN ifaces, never restart dnsmasq on google probe ───
# Added in v1.0.16
if [[ -f "${BASE_DIR}/build/dns-watchdog.sh" ]]; then
    install -m 755 "${BASE_DIR}/build/dns-watchdog.sh" /usr/local/bin/dns-watchdog.sh
    if [[ -f "${BASE_DIR}/build/dns-watchdog.service" ]]; then
        cp "${BASE_DIR}/build/dns-watchdog.service" /etc/systemd/system/dns-watchdog.service
        cp "${BASE_DIR}/build/dns-watchdog.timer"   /etc/systemd/system/dns-watchdog.timer
        systemctl daemon-reload
        systemctl enable dns-watchdog.timer 2>/dev/null || true
        systemctl restart dns-watchdog.timer 2>/dev/null || true
    fi
fi

# ── v1.0.20: ISP-intercepted 8.8.8.8 must not stall LAN DNS ───────────────────
# Cosmote (and similar CGNAT) answers ICMP to 8.8.8.8 but delays UDP/53.
# dnsmasq then hits concurrent-query max; ping works, websites do not.
# dhcp-relay / VLAN interface= lines are left untouched.
DNSMASQ_RESTART=0
mkdir -p /root/fguard-backups
shopt -s nullglob
for bak in /etc/dnsmasq.d/*.bak /etc/dnsmasq.d/*.bak-* /etc/dnsmasq.d/*~; do
    mv "$bak" /root/fguard-backups/ 2>/dev/null || true
    DNSMASQ_RESTART=1
done
shopt -u nullglob

patch_dnsmasq_upstream() {
    local conf="$1"
    [ -f "$conf" ] || return 0
    if ! grep -q '^dns-forward-max=' "$conf"; then
        sed -i '/^no-poll$/a dns-forward-max=2500\ncache-size=10000\nstrict-order' "$conf"
        DNSMASQ_RESTART=1
    fi
    if grep -qE '^server=8\.8\.[48]\.8$' "$conf"; then
        sed -i 's/^server=8\.8\.8\.8$/server=1.0.0.1/; s/^server=8\.8\.4\.4$/server=1.0.0.1/' "$conf"
        DNSMASQ_RESTART=1
    fi
}
patch_dnsmasq_upstream /etc/dnsmasq.d/fguard.conf
patch_dnsmasq_upstream /etc/dnsmasq.d/aegisguard.conf

if [ -f "${BASE_DIR}/firewall.db" ]; then
    python3 - "${BASE_DIR}/firewall.db" <<'PY' || true
import sqlite3, sys
con = sqlite3.connect(sys.argv[1])
try:
    con.execute("UPDATE dns_settings SET secondary_dns='1.0.0.1' WHERE secondary_dns IN ('8.8.8.8','8.8.4.4')")
    con.execute("UPDATE dns_settings SET primary_dns='1.1.1.1' WHERE primary_dns IN ('8.8.8.8','8.8.4.4')")
    con.commit()
except Exception:
    pass
con.close()
PY
fi

if [ "$DNSMASQ_RESTART" -eq 1 ]; then
    systemctl try-restart dnsmasq 2>/dev/null || true
fi
