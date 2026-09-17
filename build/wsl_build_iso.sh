#!/bin/bash
# FGUARD Firewall ISO Builder (WSL2)
# Uses Ubuntu 26.04 autoinstall + GitHub clone
# Run from PowerShell: wsl -u root bash build/wsl_build_iso.sh
set -e

ISO='/mnt/c/Users/stelakis-pc/Downloads/ubuntu-26.04-live-server-amd64.iso'
OUTPUT='/mnt/c/Users/stelakis-pc/Projects/firewall-gui/build/FGUARD-1.0.0-amd64.iso'
WORK='/tmp/fguard-iso-build'
SRC="$WORK/src"
CUSTOM="$WORK/custom"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${G}[✓]${NC} $*"; }
info() { echo -e "${C}[→]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*"; exit 1; }

echo ""
echo -e "${C}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${C}  ║   FGUARD Firewall ISO Builder            ║${NC}"
echo -e "${C}  ║   Ubuntu 26.04 + GitHub clone                ║${NC}"
echo -e "${C}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

[ -f "$ISO" ] || err "Ubuntu ISO not found at $ISO"

# ── Step 1: Dependencies ──────────────────────────────────────────────────────
info "[1/7] Installing build dependencies..."
apt-get update -qq
apt-get install -y xorriso p7zip-full rsync -qq
log "Dependencies ready"

# ── Step 2: Extract ISO ───────────────────────────────────────────────────────
info "[2/7] Extracting Ubuntu ISO..."
rm -rf "$WORK"
mkdir -p "$SRC" "$CUSTOM"
7z x "$ISO" -o"$SRC" -y > /dev/null
cp -a "$SRC/." "$CUSTOM/"
log "ISO extracted"

# ── Step 3: Bootloader ────────────────────────────────────────────────────────
info "[3/7] Configuring bootloader..."
for f in "$CUSTOM/boot/grub/grub.cfg" "$CUSTOM/grub/grub.cfg"; do
    [ -f "$f" ] || continue
    cat > "$f" << 'GRUBCFG'
set default=0
set timeout=10

menuentry "Install FGUARD Network Security" --class ubuntu --class os {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}
menuentry "Install FGUARD (Safe Mode)" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}
GRUBCFG
    log "Updated: $f"
done

# ── Step 4: Autoinstall config ────────────────────────────────────────────────
info "[4/7] Writing autoinstall configuration..."
mkdir -p "$CUSTOM/nocloud"

cat > "$CUSTOM/nocloud/meta-data" << 'META'
instance-id: fguard-1
local-hostname: fguard
META

PASS_HASH=$(python3 -c "import crypt; print(crypt.crypt('FGUARD2024!', crypt.mksalt(crypt.METHOD_SHA512)))" 2>/dev/null \
           || echo '$6$fguard$placeholder')

cat > "$CUSTOM/nocloud/user-data" << USERDATA
#cloud-config
autoinstall:
  version: 1
  locale: en_US.UTF-8
  keyboard:
    layout: us
    variant: ''
  identity:
    hostname: fguard
    username: admin
    password: "${PASS_HASH}"
  storage:
    layout:
      name: lvm
      sizing-policy: all
  network:
    network:
      version: 2
      ethernets:
        enp0s3: {dhcp4: true}
        eth0:   {dhcp4: true}
        ens3:   {dhcp4: true}
        ens33:  {dhcp4: true}
  ssh:
    install-server: true
    allow-pw: true
  packages:
    - python3
    - python3-pip
    - python3-venv
    - nginx
    - openssl
    - git
    - curl
    - wget
    - iptables
    - iptables-persistent
    - netfilter-persistent
    - iproute2
    - net-tools
    - dnsmasq
    - openvpn
    - fail2ban
    - clamav
    - clamav-daemon
    - keepalived
    - strongswan
    - wireguard
    - htop
    - ufw
    - whiptail
  user-data:
    chpasswd:
      expire: false
  late-commands:
    - curtin in-target --target=/target -- bash /cdrom/fguard_setup/install.sh
    - "echo 'admin ALL=(ALL) NOPASSWD: ALL' > /target/etc/sudoers.d/admin"
    - chmod 440 /target/etc/sudoers.d/admin
USERDATA

# ── Step 5: Post-install script ───────────────────────────────────────────────
info "[5/7] Writing post-install script (GitHub clone)..."
mkdir -p "$CUSTOM/fguard_setup"

cat > "$CUSTOM/fguard_setup/install.sh" << 'INSTALLSCRIPT'
#!/bin/bash
set -e
exec >> /var/log/fguard-install.log 2>&1
echo "=== FGUARD Install: $(date) ==="

# ── Clone from GitHub ─────────────────────────────────────────────────────────
git clone --depth=1 https://github.com/stelios2610/AegisGuard.git /opt/fguard
cd /opt/fguard

# ── Python venv — exact packages as running server ────────────────────────────
python3 -m venv /opt/fguard/venv
/opt/fguard/venv/bin/pip install --quiet --upgrade pip
/opt/fguard/venv/bin/pip install --quiet \
    fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
    psutil bcrypt qrcode pillow python-dotenv PyYAML

# ── SSL certificate (same path as server: /etc/nginx/ssl/) ───────────────────
mkdir -p /etc/nginx/ssl /etc/fguard
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/fguard.key \
    -out    /etc/nginx/ssl/fguard.crt \
    -subj   "/CN=FGUARD/O=FGUARD/C=GR" 2>/dev/null
chmod 640 /etc/nginx/ssl/fguard.key

# ── nginx — EXACT copy from server ───────────────────────────────────────────
cp /cdrom/server-configs/nginx-fguard.conf /etc/nginx/sites-available/fguard
ln -sf /etc/nginx/sites-available/fguard /etc/nginx/sites-enabled/fguard
rm -f /etc/nginx/sites-enabled/default

# ── systemd services — EXACT copies from server ───────────────────────────────
cp /cdrom/server-configs/fguard.service \
   /etc/systemd/system/fguard.service
cp /cdrom/server-configs/fguard-firstboot.service \
   /etc/systemd/system/fguard-firstboot.service

# ── first-boot.sh — EXACT copy from server ───────────────────────────────────
cp /cdrom/server-configs/first-boot.sh \
   /opt/fguard/build/first-boot.sh
chmod +x /opt/fguard/build/first-boot.sh

# ── VPN auth scripts — EXACT copies from server ───────────────────────────────
cp /cdrom/server-configs/vpn-auth.sh       /etc/fguard/vpn-auth.sh
cp /cdrom/server-configs/vpn_auth_check.py /etc/fguard/vpn_auth_check.py
chmod +x /etc/fguard/vpn-auth.sh /etc/fguard/vpn_auth_check.py

# ── dnsmasq — EXACT copy from server ─────────────────────────────────────────
mkdir -p /etc/dnsmasq.d
cp /cdrom/server-configs/dnsmasq-fguard.conf \
   /etc/dnsmasq.d/fguard.conf

# ── fail2ban — EXACT copies from server ───────────────────────────────────────
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
cp /cdrom/server-configs/fail2ban-jail-fguard.conf \
   /etc/fail2ban/jail.d/fguard.conf 2>/dev/null || true
cp /cdrom/server-configs/fail2ban-filter-fguard-vpn.conf \
   /etc/fail2ban/filter.d/fguard-vpn.conf 2>/dev/null || true

# ── logrotate ─────────────────────────────────────────────────────────────────
cp /opt/fguard/build/fguard-logrotate \
   /etc/logrotate.d/fguard 2>/dev/null || true

# ── Initialize database ───────────────────────────────────────────────────────
cd /opt/fguard
/opt/fguard/venv/bin/python -c \
    'from db import database; database.initialize()' 2>/dev/null || true

# ── Enable services ───────────────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable fguard fguard-firstboot nginx fail2ban dnsmasq ssh

# ── MOTD ──────────────────────────────────────────────────────────────────────
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════════╗
  ║           FGUARD Network Security v1.0           ║
  ║                                                      ║
  ║  Web UI:  https://10.0.0.1:8080  (LAN only)          ║
  ║  SSH:     ssh admin@10.0.0.1     (LAN only)          ║
  ║                                                      ║
  ║  Connect a PC to the LAN port to access the GUI      ║
  ╚══════════════════════════════════════════════════════╝

MOTD

echo "=== Install complete: $(date) ==="
INSTALLSCRIPT

chmod +x "$CUSTOM/fguard_setup/install.sh"
log "Post-install script written"

# ── Step 5b: Embed server configs into ISO ────────────────────────────────────
info "[5b] Embedding server configs (copied directly from running server)..."
SCONF="$(dirname "$0")/server-configs"
mkdir -p "$CUSTOM/server-configs"
cp "$SCONF/"* "$CUSTOM/server-configs/" 2>/dev/null || true
log "Server configs embedded: $(ls "$CUSTOM/server-configs/" | wc -l) files"

# ── Step 6: Checksums ─────────────────────────────────────────────────────────
info "[6/7] Updating checksums..."
cd "$CUSTOM"
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
cd -
log "Checksums updated"

# ── Step 7: Build ISO ─────────────────────────────────────────────────────────
info "[7/7] Building bootable ISO..."

MBR="" EFI=""
[ -f "$SRC/[BOOT]/1-Boot-NoEmul.img" ] && MBR="$SRC/[BOOT]/1-Boot-NoEmul.img"
[ -f "$SRC/[BOOT]/2-Boot-NoEmul.img" ] && EFI="$SRC/[BOOT]/2-Boot-NoEmul.img"
if [ -z "$MBR" ]; then
    for f in "$SRC/boot/grub/i386-pc/boot_hybrid.img" "$SRC/isolinux/isohdpfx.bin"; do
        [ -f "$f" ] && MBR="$f" && break
    done
fi
if [ -z "$EFI" ]; then
    for f in "$SRC/boot/grub/efi.img" "$SRC/EFI/efi.img"; do
        [ -f "$f" ] && EFI="$f" && break
    done
fi

[ -z "$MBR" ] && err "MBR boot image not found"
[ -z "$EFI" ] && err "EFI boot image not found"

xorriso -as mkisofs \
    -r -V "FGUARD-1.0.0" \
    --grub2-mbr "$MBR" \
    -partition_offset 16 \
    --mbr-force-bootable \
    -append_partition 2 28732ac11ff8d211ba4b00a0c93ec93b "$EFI" \
    -appended_part_as_gpt \
    -iso_mbr_part_type a2a0d0ebe5b9334487c068b6b72699c7 \
    -c '/boot/boot.catalog' \
    -b '/boot/grub/i386-pc/eltorito.img' \
    -no-emul-boot -boot-load-size 4 -boot-info-table --grub2-boot-info \
    -eltorito-alt-boot \
    -e '--interval:appended_partition_2:::' \
    -no-emul-boot \
    -o "$OUTPUT" "$CUSTOM/" 2>&1 | tail -3

SIZE=$(du -sh "$OUTPUT" | cut -f1)
rm -rf "$WORK"

echo ""
echo -e "${G}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   FGUARD ISO built successfully!         ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   File: build/FGUARD-1.0.0-amd64.iso    ║${NC}"
echo -e "${G}  ║   Size: ${SIZE}                                  ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Boot → installs → first reboot:           ║${NC}"
echo -e "${G}  ║   https://10.0.0.1:8080  (LAN only)         ║${NC}"
echo -e "${G}  ║   SSH:  admin@10.0.0.1 / FGUARD2024!    ║${NC}"
echo -e "${G}  ╚══════════════════════════════════════════════╝${NC}"
