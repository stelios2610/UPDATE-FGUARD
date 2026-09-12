#!/bin/bash
# DNS watchdog: keep VLAN interfaces listed in dnsmasq. Do NOT restart
# dnsmasq because an external probe failed (web filter / AD / google).
CONF="/etc/dnsmasq.d/aegisguard.conf"
CHANGED=0

for VIFACE in eth1.10 eth1.20; do
    ip link show "$VIFACE" >/dev/null 2>&1 || continue
    if ! grep -q "^interface=${VIFACE}$" "$CONF" 2>/dev/null; then
        echo "interface=${VIFACE}" >> "$CONF"
        CHANGED=1
        logger -t dns-watchdog "Added missing interface=${VIFACE}"
    fi
done

if [ "$CHANGED" -eq 1 ]; then
    systemctl try-reload-or-restart dnsmasq
    logger -t dns-watchdog "Reloaded dnsmasq after config patch"
fi

if ! systemctl is-active --quiet dnsmasq; then
    logger -t dns-watchdog "dnsmasq not active — starting"
    systemctl start dnsmasq
fi
