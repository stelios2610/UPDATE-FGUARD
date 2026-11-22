#!/bin/bash
# WireGuard DDNS watchdog — re-resolves peer hostnames and restarts stale tunnels.
# Runs every 2 minutes via wg-watchdog.timer.

CONF_DIR="/etc/wireguard"
MAX_HANDSHAKE_AGE=180  # seconds — restart if no handshake for 3 minutes

sync_peer_allow() {
    local new_ip="$1"
    [[ "$new_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 0
    if iptables -S FGUARD_INPUT 2>/dev/null | grep -q -- "-s ${new_ip}/32 .*multiport --dports 500,4500,51820 -j ACCEPT"; then
        return 0
    fi

    local rules count old wan num dropnum
    rules=$(iptables -S FGUARD_INPUT 2>/dev/null | grep "multiport --dports 500,4500,51820 -j ACCEPT" || true)
    count=$(printf '%s\n' "$rules" | awk 'NF{n++} END{print n+0}')
    if [[ "$count" -eq 1 ]]; then
        old=$(printf '%s\n' "$rules" | awk '{for(i=1;i<=NF;i++) if($i=="-s"){print $(i+1); exit}}')
        old="${old%/32}"
        wan=$(printf '%s\n' "$rules" | awk '{for(i=1;i<=NF;i++) if($i=="-i"){print $(i+1); exit}}')
        num=$(iptables -L FGUARD_INPUT -n --line-numbers | awk -v ip="$old" '$0 ~ ip && /500,4500,51820/ && /ACCEPT/ {print $1; exit}')
        if [[ -n "$num" && -n "$wan" && "$old" != "$new_ip" ]]; then
            iptables -R FGUARD_INPUT "$num" -s "${new_ip}/32" -i "$wan" -p udp -m multiport --dports 500,4500,51820 -j ACCEPT
            logger -t wg-watchdog "peer allow ${old} -> ${new_ip}"
            netfilter-persistent save >/dev/null 2>&1 || true
            return 0
        fi
    fi

    wan=$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
    [[ -z "$wan" ]] && return 0
    dropnum=$(iptables -L FGUARD_INPUT -n --line-numbers | awk '/500,4500,51820/ && /DROP/ {print $1; exit}')
    if [[ -n "$dropnum" ]]; then
        iptables -I FGUARD_INPUT "$dropnum" -s "${new_ip}/32" -i "$wan" -p udp -m multiport --dports 500,4500,51820 -j ACCEPT
    else
        iptables -A FGUARD_INPUT -s "${new_ip}/32" -i "$wan" -p udp -m multiport --dports 500,4500,51820 -j ACCEPT
    fi
    logger -t wg-watchdog "peer allow added ${new_ip}"
    netfilter-persistent save >/dev/null 2>&1 || true
}

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

            new_ip=$(getent ahostsv4 "$host" 2>/dev/null | awk 'NR==1{print $1}')
            if [[ -z "$new_ip" ]]; then
                new_ip=$(getent hosts "$host" 2>/dev/null | awk '/^[0-9]+\./{print $1; exit}')
            fi
            [[ -z "$new_ip" ]] && continue

            cur_ep=$(wg show "$iface" endpoints 2>/dev/null \
                     | awk -v k="$current_key" '$1==k{print $2}')
            cur_ip="${cur_ep%:*}"

            if [[ "$cur_ip" != "$new_ip" ]]; then
                logger -t wg-watchdog "$iface: $host changed $cur_ip -> $new_ip, updating peer"
                wg set "$iface" peer "$current_key" endpoint "$new_ip:$port"
            fi
            # The WAN allow is a copied address. DNS can move on while it stays.
            sync_peer_allow "$new_ip"
        fi
    done < "$conf"

    # Restart only if we *had* a handshake and it went stale.
    # ts=0 means never connected (IPSec is often the live path) — bouncing
    # wg-quick would reinstall stolen LAN routes and spam logs.
    now=$(date +%s)
    total=0; stale=0; ever=0
    while read -r _ ts; do
        total=$((total + 1))
        if [[ "$ts" != "0" ]]; then
            ever=$((ever + 1))
            if [[ $(( now - ts )) -gt $MAX_HANDSHAKE_AGE ]]; then
                stale=$((stale + 1))
            fi
        fi
    done < <(wg show "$iface" latest-handshakes 2>/dev/null)

    if [[ $ever -gt 0 && $stale -eq $ever ]]; then
        logger -t wg-watchdog "$iface: all $ever connected peer(s) stale (>${MAX_HANDSHAKE_AGE}s), restarting"
        systemctl restart "wg-quick@$iface"
    fi
done
