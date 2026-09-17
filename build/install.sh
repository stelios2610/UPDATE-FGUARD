#!/bin/bash
# FGUARD Installer
# Run this on a fresh Debian 12 system (as root).
# Usage: curl -fsSL http://... | bash
#    or: bash install.sh

set -e

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

[ "$(id -u)" -eq 0 ] || err "Run as root: sudo bash install.sh"

echo ""
echo "  ╔══════════════════════════════════════╗"
echo "  ║    FGUARD Network Security       ║"
echo "  ║    Installer v1.0 — Debian 12        ║"
echo "  ╚══════════════════════════════════════╝"
echo ""

INSTALL_DIR="/opt/fguard"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ── 1. System packages ────────────────────────────────────────────────────────
log "Updating package lists..."
apt-get update -qq

log "Installing system dependencies..."
PACKAGES=(
    python3 python3-pip python3-venv
    openvpn openssl
    wireguard wireguard-tools
    strongswan strongswan-swanctl charon-systemd
    dnsmasq
    iptables iptables-persistent netfilter-persistent
    nmap
    net-tools iproute2 iproute2 iputils-ping
    curl wget
    clamav clamav-daemon
    fail2ban
    unzip git
    dhcpcd5
)
apt-get install -y --no-install-recommends "${PACKAGES[@]}" 2>/dev/null || \
apt-get install -y "${PACKAGES[@]}"
log "System packages installed"

# ── 2. Copy FGUARD files ──────────────────────────────────────────────────
log "Installing FGUARD to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"
rsync -a --exclude=".git" --exclude="__pycache__" --exclude="*.pyc" \
    --exclude="build/fguard.iso" \
    "${SOURCE_DIR}/" "${INSTALL_DIR}/" 2>/dev/null || \
cp -r "${SOURCE_DIR}/." "${INSTALL_DIR}/"

# ── 3. Python virtual environment ────────────────────────────────────────────
log "Creating Python virtual environment..."
python3 -m venv "${INSTALL_DIR}/venv"
"${INSTALL_DIR}/venv/bin/pip" install --upgrade pip -q
"${INSTALL_DIR}/venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt" -q
log "Python dependencies installed"

# Update service to use venv
sed -i "s|ExecStart=.*|ExecStart=${INSTALL_DIR}/venv/bin/python -m uvicorn web.api:app --host 0.0.0.0 --port 8080 --workers 1|" \
    "${INSTALL_DIR}/build/fguard.service"

# ── 4. Install systemd services ───────────────────────────────────────────────
log "Installing systemd services..."
cp "${INSTALL_DIR}/build/fguard.service" /etc/systemd/system/
cp "${INSTALL_DIR}/build/fguard-firstboot.service" /etc/systemd/system/

systemctl daemon-reload
systemctl enable fguard-firstboot
systemctl enable fguard
log "Services installed"

# ── 5. Create /etc/fguard directory ───────────────────────────────────────
mkdir -p /etc/fguard
mkdir -p /var/log/fguard
chmod 750 /etc/fguard

# ── 6. Initialize database ────────────────────────────────────────────────────
log "Initializing FGUARD database..."
cd "${INSTALL_DIR}"
"${INSTALL_DIR}/venv/bin/python" -c "
from db import database
database.initialize()
print('Database initialized')
"

# ── 7. Configure fail2ban ─────────────────────────────────────────────────────
cat > /etc/fail2ban/jail.d/fguard.conf << 'EOF'
[sshd]
enabled = true
maxretry = 5
bantime = 3600
findtime = 600
EOF
systemctl enable fail2ban 2>/dev/null || true

# ── 8. Disable unneeded services ──────────────────────────────────────────────
for svc in bluetooth avahi-daemon cups; do
    systemctl disable "$svc" 2>/dev/null || true
    systemctl stop "$svc" 2>/dev/null || true
done

# ── 9. Set hostname ───────────────────────────────────────────────────────────
hostnamectl set-hostname fguard
echo "127.0.1.1 fguard" >> /etc/hosts

# ── 10. WireGuard DDNS watchdog ──────────────────────────────────────────────
log "Installing WireGuard DDNS watchdog..."
install -m 755 "${INSTALL_DIR}/build/wg-watchdog.sh" /usr/local/sbin/wg-watchdog
cp "${INSTALL_DIR}/build/wg-watchdog.service" /etc/systemd/system/
cp "${INSTALL_DIR}/build/wg-watchdog.timer"   /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now wg-watchdog.timer
log "WireGuard watchdog installed"

# ── 11. Banner ────────────────────────────────────────────────────────────────
cat > /etc/motd << 'EOF'

  ╔══════════════════════════════════════════════════════╗
  ║              FGUARD Network Security             ║
  ║                                                      ║
  ║  Web UI:  http://10.0.0.1:8080                       ║
  ║  Connect a PC to the LAN port to manage this device  ║
  ╚══════════════════════════════════════════════════════╝

EOF

echo ""
log "═══════════════════════════════════════════"
log " FGUARD installed successfully!"
log "═══════════════════════════════════════════"
echo ""
warn "Reboot to complete setup:"
echo "    sudo reboot"
echo ""
warn "After reboot, connect a PC to the LAN interface"
warn "and open: http://10.0.0.1:8080"
echo ""
