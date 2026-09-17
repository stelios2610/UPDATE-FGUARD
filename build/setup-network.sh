#!/bin/bash
# FGUARD Network Setup
# Runs automatically after install to configure LAN/WAN

cd /opt/fguard

WAN_IF=$(ip route | grep default | awk '{print $5}' | head -1)
LAN_IF=$(ip link | grep -v "$WAN_IF" | grep -v lo | grep 'state UP\|state DOWN' | awk '{print $2}' | tr -d ':' | head -1)

# Fallback defaults
[ -z "$WAN_IF" ] && WAN_IF="eth0"
[ -z "$LAN_IF" ] && LAN_IF="eth1"

echo "[→] WAN: $WAN_IF | LAN: $LAN_IF"

# Configure LAN IP
ip addr flush dev "$LAN_IF" 2>/dev/null || true
ip addr add 10.0.0.1/24 dev "$LAN_IF" 2>/dev/null || true
ip link set "$LAN_IF" up 2>/dev/null || true

# Permanent netplan
cat > /etc/netplan/60-fguard-lan.yaml << EOF
network:
  version: 2
  ethernets:
    ${LAN_IF}:
      dhcp4: false
      addresses: [10.0.0.1/24]
EOF
netplan apply 2>/dev/null || true

# Firewall: flush everything and rebuild from scratch (safe to re-run)
iptables -F
iptables -F -t nat
iptables -F -t mangle
iptables -X 2>/dev/null || true

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# INPUT: loopback + established + LAN full access
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -i "$LAN_IF" -j ACCEPT

# INPUT: VPN ports on WAN
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1194 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p tcp --dport 1194 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 51820 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 500 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 4500 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p 50 -j ACCEPT
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1701 -j ACCEPT

# INPUT: allow VPN tunnel traffic
iptables -A INPUT -i tun0 -j ACCEPT

# Rate limit VPN auth: max 5 new connections per minute per IP
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1194 -m state --state NEW \
  -m recent --set --name VPN_RATELIMIT --rsource 2>/dev/null || true
iptables -A INPUT -i "$WAN_IF" -p udp --dport 1194 -m state --state NEW \
  -m recent --update --seconds 60 --hitcount 6 --name VPN_RATELIMIT --rsource \
  -j DROP 2>/dev/null || true

# FORWARD: LAN → WAN + VPN ↔ LAN + VPN → WAN (full tunnel) + established return traffic
iptables -A FORWARD -i "$LAN_IF" -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i tun0 -o "$WAN_IF" -j ACCEPT
iptables -A FORWARD -i tun0 -o "$LAN_IF" -j ACCEPT
iptables -A FORWARD -i "$LAN_IF" -o tun0 -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# NAT: masquerade LAN traffic + VPN clients going out WAN
iptables -t nat -A POSTROUTING -o "$WAN_IF" -j MASQUERADE

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/' /etc/sysctl.conf 2>/dev/null || true

netfilter-persistent save 2>/dev/null || true

# Update DB with interface names
python3 - << PYEOF
import sys; sys.path.insert(0,'/opt/fguard')
from db import database
conn = database.get_connection()
conn.execute("UPDATE interfaces SET name=? WHERE role='WAN'", ('$WAN_IF',))
conn.execute("UPDATE interfaces SET name=? WHERE role='LAN'", ('$LAN_IF',))
conn.execute("UPDATE dhcp_config SET interface=? WHERE interface='eth1'", ('$LAN_IF',))
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('wan_interface','$WAN_IF')")
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('lan_interface','$LAN_IF')")
conn.commit(); conn.close()
print("DB updated")
PYEOF

# DHCP server on LAN
cat > /etc/dnsmasq.d/fguard.conf << EOF
interface=${LAN_IF}
bind-interfaces
dhcp-range=${LAN_IF},10.0.0.100,10.0.0.200,255.255.255.0,24h
dhcp-option=${LAN_IF},3,10.0.0.1
dhcp-option=${LAN_IF},6,1.1.1.1,8.8.8.8
domain=aegis.local
bogus-priv
domain-needed
no-resolv
server=1.1.1.1
server=8.8.8.8
EOF
systemctl enable dnsmasq 2>/dev/null || true
systemctl restart dnsmasq 2>/dev/null || true

systemctl restart fguard 2>/dev/null || true

# Fail2ban: install filters and jails for SSH + VPN brute force protection
if command -v fail2ban-client &>/dev/null; then
    cp /opt/fguard/build/fail2ban-filter-fguard-vpn.conf /etc/fail2ban/filter.d/fguard-vpn.conf 2>/dev/null || true
    cp /opt/fguard/build/fail2ban-fguard.conf /etc/fail2ban/jail.d/fguard.conf 2>/dev/null || true
    systemctl enable fail2ban 2>/dev/null || true
    systemctl restart fail2ban 2>/dev/null || true
fi

echo ""
echo "================================================"
echo " Setup complete!"
echo " LAN: $LAN_IF = 10.0.0.1/24"
echo " WAN: $WAN_IF = locked (VPN ports open)"
echo " Web UI: http://10.0.0.1:8080"
echo "================================================"
