#!/bin/bash
# FGUARD Firewall Reset
# Resets iptables to correct state: internet + VPN ports open, WAN otherwise blocked
# Safe to run at any time without touching network config/DHCP/DB

set -e

WAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
LAN_IF=$(ip link | grep -v "$WAN_IF" | grep -v lo | grep 'state UP' | awk '{print $2}' | tr -d ':' | head -1)

[ -z "$WAN_IF" ] && WAN_IF="eth0"
[ -z "$LAN_IF" ] && LAN_IF="eth1"

echo "[→] WAN: $WAN_IF | LAN: $LAN_IF"

# Flush everything
iptables -F
iptables -F -t nat
iptables -F -t mangle
iptables -X 2>/dev/null || true

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT

# INPUT
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 500 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p 50 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1701 -j ACCEPT

# INPUT: allow VPN tunnel traffic
iptables -A INPUT -i tun0 -j ACCEPT

# FORWARD: LAN → WAN + VPN ↔ LAN + established return traffic
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i tun0 -o "$LAN_IF" -j ACCEPT
iptables -A FORWARD -i "$LAN_IF" -o tun0 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT: masquerade LAN traffic + VPN clients
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$LAN_IF" -j MASQUERADE

# IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Save so rules survive reboot
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true

echo ""
echo "================================================"
echo " Firewall reset complete!"
echo " Internet: OK (LAN → WAN masquerade)"
echo " VPN ports: 1194 (OpenVPN), 51820 (WG), 500/4500 (IPSec)"
echo "================================================"
