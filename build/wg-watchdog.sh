#!/bin/bash
# WireGuard DDNS watchdog — re-resolves peer hostnames and restarts stale tunnels.
# Runs every 2 minutes via wg-watchdog.timer.

CONF_DIR="/etc/wireguard"
MAX_HANDSHAKE_AGE=180  # seconds — restart if no handshake for 3 minutes

for conf in "$CONF_DIR"/wg*.conf; do
    [[ -f "$conf" ]] || continue
    iface=$(basename "$conf" .conf)
    ip link show "$iface" &>/dev/null || continue

    # --- Re-resolve DDNS hostnames and update peer endpoints if IP changed ---
    in_peer=0
    current_key=""
    while IFS= read -r raw; do
        line="${raw%%#*}"                         # strip inline comments
        line="${line#"${line%%[! ]*}"}"           # ltrim whitespace

        if [[ "$line" == "[Peer]" ]]; then
            in_peer=1; current_key=""; continue
        elif [[ "$line" == "["* ]]; then
            in_peer=0; current_key=""; continue
        fi
        [[ "$in_peer" -eq 0 ]] && continue

        if [[ "$line" =~ ^PublicKey[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
            current_key="${BASH_REMATCH[1]}"

        elif [[ "$line" =~ ^Endpoint[[:space:]]*=[[:space:]]*([^[:space:]]+) ]]; then
            [[ -z "$current_key" ]] && continue
            val="${BASH_REMATCH[1]}"
            host="${val%:*}"
            port="${val##*:}"

            # Skip plain IPs — nothing to resolve
            [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] && continue

            new_ip=$(getent hosts "$host" 2>/dev/null | awk 'NR==1{print $1}')
            [[ -z "$new_ip" ]] && continue

            cur_ep=$(wg show "$iface" endpoints 2>/dev/null \
                     | awk -v k="$current_key" '$1==k{print $2}')
            cur_ip="${cur_ep%:*}"

            if [[ "$cur_ip" != "$new_ip" ]]; then
                logger -t wg-watchdog "$iface: $host changed $cur_ip -> $new_ip, updating peer"
                wg set "$iface" peer "$current_key" endpoint "$new_ip:$port"
            fi
        fi
    done < "$conf"

    # --- Restart interface if all peers have stale handshakes ---
    now=$(date +%s)
    total=0; stale=0
    while read -r _ ts; do
        total=$((total + 1))
        if [[ "$ts" == "0" ]] || [[ $(( now - ts )) -gt $MAX_HANDSHAKE_AGE ]]; then
            stale=$((stale + 1))
        fi
    done < <(wg show "$iface" latest-handshakes 2>/dev/null)

    if [[ $total -gt 0 && $stale -eq $total ]]; then
        logger -t wg-watchdog "$iface: all $total peer(s) stale (>${MAX_HANDSHAKE_AGE}s), restarting"
        systemctl restart "wg-quick@$iface"
    fi
done
