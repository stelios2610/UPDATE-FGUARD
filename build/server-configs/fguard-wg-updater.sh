#!/bin/bash
# FGUARD - WireGuard endpoint auto-updater
# Resolves peer hostname via DNS and updates WG endpoint if IP changed.
# Run via cron every 2 minutes.
#
# Site-specific vars — set these per deployment:
PEER_PUBKEY="CHANGE_ME_PEER_PUBLIC_KEY"
PEER_HOSTNAME="CHANGE_ME_PEER_HOSTNAME"   # e.g. home.fitsolutions.gr
WG_IFACE="wg0"
PORT=51820
LOG="/var/log/fguard-wg-updater.log"
CACHE="/var/lib/fguard-wg-lastip"

NEW_IP=$(dig +short "$PEER_HOSTNAME" A 2>/dev/null | head -1)
if [ -z "$NEW_IP" ]; then
    NEW_IP=$(host "$PEER_HOSTNAME" 2>/dev/null | grep 'has address' | head -1 | awk '{print $NF}')
fi
if [ -z "$NEW_IP" ]; then
    echo "$(date '+%Y-%m-%d %H:%M:%S'): ERROR - could not resolve $PEER_HOSTNAME" >> "$LOG"
    exit 1
fi

LAST_IP=$(cat "$CACHE" 2>/dev/null)
CURRENT_EP_IP=$(wg show "$WG_IFACE" endpoints 2>/dev/null | awk '{print $2}' | cut -d: -f1)

if [ "$NEW_IP" != "$LAST_IP" ] || [ "$CURRENT_EP_IP" != "$NEW_IP" ]; then
    wg set "$WG_IFACE" peer "$PEER_PUBKEY" endpoint "${NEW_IP}:${PORT}"
    echo "$(date '+%Y-%m-%d %H:%M:%S'): Updated WG endpoint: ${LAST_IP:-unknown} -> $NEW_IP" >> "$LOG"
    echo "$NEW_IP" > "$CACHE"
fi
