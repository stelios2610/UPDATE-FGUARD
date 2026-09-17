#!/bin/bash
# FGUARD First Boot Setup
# Runs once after ISO install via fguard-firstboot.service

LOGFILE="/var/log/fguard-firstboot.log"
DONE_FLAG="/etc/fguard/.firstboot_done"

exec > >(tee -a "$LOGFILE") 2>&1
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

if [ -f "$DONE_FLAG" ]; then
    log "First-boot already completed. Skipping."
    exit 0
fi

log "=== FGUARD First Boot Setup ==="
mkdir -p /etc/fguard

# ── 1. Detect interfaces ──────────────────────────────────────────────────────
IFACES=($(ls /sys/class/net | grep -v lo | sort))
WAN_IF="${IFACES[0]:-eth0}"
LAN_IF="${IFACES[1]:-eth1}"
log "Interfaces: WAN=$WAN_IF  LAN=$LAN_IF"

# ── 2. Netplan ────────────────────────────────────────────────────────────────
rm -f /etc/netplan/00-installer-config.yaml /etc/netplan/50-cloud-init.yaml 2>/dev/null || true

cat > /etc/netplan/50-fguard.yaml << EOF
network:
  version: 2
  ethernets:
    ${WAN_IF}:
      dhcp4: true
    ${LAN_IF}:
      dhcp4: false
      addresses: [10.0.0.1/24]
EOF
chmod 600 /etc/netplan/50-fguard.yaml
log "Netplan written"

# ── 3. Apply network ──────────────────────────────────────────────────────────
netplan generate 2>/dev/null || true
netplan apply 2>/dev/null || true
sleep 2
ip link set "${LAN_IF}" up 2>/dev/null || true
ip addr flush dev "${LAN_IF}" 2>/dev/null || true
ip addr add 10.0.0.1/24 dev "${LAN_IF}" 2>/dev/null || true
ip link set "${WAN_IF}" up 2>/dev/null || true
log "Network applied: LAN=${LAN_IF} 10.0.0.1/24, WAN=${WAN_IF} DHCP"

# ── 4. IP forwarding ─────────────────────────────────────────────────────────
cat > /etc/sysctl.d/99-fguard.conf << 'SYSCTL'
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv4.conf.all.rp_filter = 1
SYSCTL
sysctl -p /etc/sysctl.d/99-fguard.conf 2>/dev/null || true
log "IP forwarding enabled"

# ── 5. NAT ───────────────────────────────────────────────────────────────────
mkdir -p /etc/iptables
iptables -t nat -A POSTROUTING -o "${WAN_IF}" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i "${LAN_IF}" -o "${WAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
log "NAT configured"

# ── 6. Firewall ───────────────────────────────────────────────────────────────
iptables -F INPUT 2>/dev/null || true
iptables -A INPUT -i lo -j ACCEPT 2>/dev/null || true
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${LAN_IF}" -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p tcp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -p udp --dport 51820 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i tun0 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i wg0 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -i "${WAN_IF}" -j DROP 2>/dev/null || true
iptables -P INPUT DROP 2>/dev/null || true
netfilter-persistent save 2>/dev/null || iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
log "Firewall: WAN locked, LAN open"

# ── 7. Policy routing rules (survive reboot via systemd) ─────────────────────
cat > /usr/local/sbin/fguard-ip-rules.sh << 'IPRULES'
#!/bin/bash
# Re-apply ip rules on every boot so SSL VPN traffic is routed via main
# table (bypassing ISP L3VPN table 220) when WireGuard tunnels are present.
ip rule add from 10.8.0.0/24 lookup main priority 210 2>/dev/null || true
IPRULES
chmod 755 /usr/local/sbin/fguard-ip-rules.sh

cat > /etc/systemd/system/fguard-ip-rules.service << 'SVC'
[Unit]
Description=FGUARD policy routing rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fguard-ip-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SVC

systemctl daemon-reload 2>/dev/null || true
systemctl enable fguard-ip-rules.service 2>/dev/null || true
systemctl start  fguard-ip-rules.service 2>/dev/null || true
log "Policy routing rules installed and enabled"

# ── 9. dnsmasq ───────────────────────────────────────────────────────────────
sed -i 's/#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
sed -i 's/DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf 2>/dev/null || true
systemctl restart systemd-resolved 2>/dev/null || true
sed -i '/# FGUARD DHCP/,$ d' /etc/dnsmasq.conf 2>/dev/null || true
cat >> /etc/dnsmasq.conf << EOF
# FGUARD DHCP config
listen-address=10.0.0.1
bind-interfaces
no-resolv
no-poll
bogus-priv
domain-needed
server=1.1.1.1
server=8.8.8.8
interface=${LAN_IF}
dhcp-range=${LAN_IF},10.0.0.100,10.0.0.200,255.255.255.0,86400s
dhcp-option=${LAN_IF},3,10.0.0.1
dhcp-option=${LAN_IF},6,10.0.0.1
EOF
systemctl enable dnsmasq 2>/dev/null || true
systemctl restart dnsmasq 2>/dev/null || true
log "dnsmasq: LAN DHCP 10.0.0.100-200"

# ── 10. Python venv (only if missing — existing servers skip this) ───────────
if [ ! -d /opt/fguard/venv ]; then
    log "Creating Python venv..."
    python3 -m venv /opt/fguard/venv

    WHEELS_DIR="/opt/fguard-wheels"
    if [ -d "$WHEELS_DIR" ] && [ "$(ls -A "$WHEELS_DIR" 2>/dev/null)" ]; then
        log "Installing packages from embedded wheels..."
        /opt/fguard/venv/bin/pip install --quiet \
            --no-index --find-links "$WHEELS_DIR" \
            fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
            psutil bcrypt qrcode pillow python-dotenv PyYAML 2>/dev/null || \
        /opt/fguard/venv/bin/pip install --quiet \
            fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
            psutil bcrypt qrcode pillow python-dotenv PyYAML
    else
        log "Installing packages from PyPI..."
        /opt/fguard/venv/bin/pip install --quiet \
            fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
            psutil bcrypt qrcode pillow python-dotenv PyYAML
    fi
    log "Python packages installed"
fi

# ── 11. Initialize DB + update interface names ───────────────────────────────
PYTHON_BIN="/opt/fguard/venv/bin/python"
[ ! -f "$PYTHON_BIN" ] && PYTHON_BIN="python3"

cd /opt/fguard
$PYTHON_BIN -c 'from db import database; database.initialize()' 2>/dev/null || true

$PYTHON_BIN - << PYEOF || log "DB interface update skipped"
import sys
sys.path.insert(0, '/opt/fguard')
from db import database
database.initialize()
conn = database.get_connection()
conn.execute("UPDATE interfaces SET name=? WHERE role='WAN'", ('${WAN_IF}',))
conn.execute("UPDATE interfaces SET name=? WHERE role='LAN'", ('${LAN_IF}',))
conn.execute("UPDATE dhcp_config SET interface=? WHERE interface='eth1'", ('${LAN_IF}',))
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('wan_interface','${WAN_IF}')")
conn.execute("INSERT OR REPLACE INTO settings (key,value) VALUES ('lan_interface','${LAN_IF}')")
conn.commit()
conn.close()
print("DB updated: WAN=${WAN_IF} LAN=${LAN_IF}")
PYEOF

# ── 12. SSL cert for nginx ───────────────────────────────────────────────────
if [ ! -f /etc/nginx/ssl/fguard.crt ]; then
    mkdir -p /etc/nginx/ssl
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/fguard.key \
        -out    /etc/nginx/ssl/fguard.crt \
        -subj   "/CN=FGUARD/O=FGUARD/C=GR" 2>/dev/null || true
    chmod 640 /etc/nginx/ssl/fguard.key 2>/dev/null || true
    log "SSL cert generated"
fi

# ── 13. Start services ───────────────────────────────────────────────────────
systemctl enable ssh openssh-server fguard nginx fail2ban 2>/dev/null || true
systemctl start ssh 2>/dev/null || systemctl start openssh-server 2>/dev/null || true
systemctl restart nginx 2>/dev/null || true
systemctl start fguard 2>/dev/null || true
log "Services started"

# ── 14. MOTD ─────────────────────────────────────────────────────────────────
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════════╗
  ║           FGUARD Network Security v1.0           ║
  ║                                                      ║
  ║  Web UI:  https://10.0.0.1:8080  (LAN only)          ║
  ║  SSH:     ssh stelios@10.0.0.1   (LAN only)          ║
  ║  Login:   admin / admin                              ║
  ║                                                      ║
  ║  Connect a PC to the LAN port to access the GUI      ║
  ╚══════════════════════════════════════════════════════╝

MOTD

# ── 15. Done ─────────────────────────────────────────────────────────────────
touch "$DONE_FLAG"
log "=== FGUARD first boot complete ==="
log "Web UI: https://10.0.0.1:8080"
log "Log: $LOGFILE"
