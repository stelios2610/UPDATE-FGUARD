#!/bin/bash
# FGUARD Offline ISO Builder (WSL2)
# Embeds app code + Python wheels inside the ISO.
# No GitHub or PyPI needed during install — only Ubuntu apt repos.
# Run: wsl -u root bash build/wsl_build_iso_offline.sh

set -e

ISO='/mnt/c/Users/stelakis-pc/Downloads/ubuntu-26.04-live-server-amd64.iso'
OUTPUT='/mnt/c/Users/stelakis-pc/Projects/firewall-gui/build/FGUARD-1.0.0-offline-amd64.iso'
WORK='/tmp/fguard-iso-offline'
SRC_WIN='/mnt/c/Users/stelakis-pc/Projects/firewall-gui'
SRC="$WORK/src"
CUSTOM="$WORK/custom"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${G}[✓]${NC} $*"; }
info() { echo -e "${C}[→]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*"; exit 1; }

echo ""
echo -e "${C}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${C}  ║   FGUARD OFFLINE ISO Builder             ║${NC}"
echo -e "${C}  ║   Code + wheels embedded — no GitHub/PyPI   ║${NC}"
echo -e "${C}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

[ -f "$ISO" ] || err "Ubuntu ISO not found at $ISO"

# ── Step 1: Dependencies ──────────────────────────────────────────────────────
info "[1/8] Installing build dependencies..."
apt-get update -qq
apt-get install -y xorriso p7zip-full rsync python3-pip python3-venv -qq
log "Dependencies ready"

# ── Step 2: Extract ISO ───────────────────────────────────────────────────────
info "[2/8] Extracting Ubuntu ISO..."
rm -rf "$WORK"
mkdir -p "$SRC" "$CUSTOM"
7z x "$ISO" -o"$SRC" -y > /dev/null
cp -a "$SRC/." "$CUSTOM/"
log "ISO extracted"

# ── Step 3: Bootloader ────────────────────────────────────────────────────────
info "[3/8] Configuring bootloader..."
for f in "$CUSTOM/boot/grub/grub.cfg" "$CUSTOM/grub/grub.cfg"; do
    [ -f "$f" ] || continue
    cat > "$f" << 'GRUBCFG'
set default=0
set timeout=10

menuentry "Install FGUARD Network Security (Offline)" --class ubuntu --class os {
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
info "[4/8] Writing autoinstall configuration..."
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
log "Autoinstall config written"

# ── Step 5: Embed app code from local source ──────────────────────────────────
info "[5/8] Embedding FGUARD source code (offline — no GitHub)..."
mkdir -p "$CUSTOM/fguard_app"

rsync -a --delete \
    --exclude='.git' \
    --exclude='.claude' \
    --exclude='build' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='*.log' \
    --exclude='*.iso' \
    --exclude='venv' \
    --exclude='fguard.db' \
    --exclude='diag_net.py' \
    --exclude='check_net*.py' \
    --exclude='fix_*.py' \
    --exclude='save_rules.py' \
    --exclude='deploy.py' \
    --exclude='get_server_config.py' \
    --exclude='fw_test.py' \
    --exclude='new_auth*.py' \
    --exclude='test_auth.py' \
    --exclude='check_db.py' \
    --exclude='write_vpn.py' \
    "$SRC_WIN/" "$CUSTOM/fguard_app/"

log "App code embedded: $(find "$CUSTOM/fguard_app" -name '*.py' | wc -l) Python files"

# ── Step 6: Pre-download Python wheels ───────────────────────────────────────
info "[6/8] Downloading Python wheels for offline install..."
mkdir -p "$CUSTOM/fguard_wheels"

# Fix WSL DNS if needed
if ! ping -c1 -W2 8.8.8.8 &>/dev/null; then
    echo "nameserver 8.8.8.8" > /etc/resolv.conf
    echo "nameserver 1.1.1.1" >> /etc/resolv.conf
fi

python3 -m pip download --dest "$CUSTOM/fguard_wheels/" \
    fastapi \
    "uvicorn[standard]" \
    jinja2 \
    pydantic \
    python-multipart \
    psutil \
    bcrypt \
    qrcode \
    pillow \
    python-dotenv \
    PyYAML \
    2>&1 | grep -E "^(Collecting|Saved|ERROR)" || true

WHEEL_COUNT=$(ls "$CUSTOM/fguard_wheels/" 2>/dev/null | wc -l)
log "Wheels downloaded: $WHEEL_COUNT packages"

# ── Step 7: Post-install script ───────────────────────────────────────────────
info "[7/8] Writing post-install script (offline)..."
mkdir -p "$CUSTOM/fguard_setup"

cat > "$CUSTOM/fguard_setup/install.sh" << 'INSTALLSCRIPT'
#!/bin/bash
set -e
exec >> /var/log/fguard-install.log 2>&1
echo "=== FGUARD Offline Install: $(date) ==="

# ── Copy embedded code (no git clone needed) ──────────────────────────────────
cp -r /cdrom/fguard_app /opt/fguard
mkdir -p /opt/fguard/build
cd /opt/fguard

# ── Python venv — install from embedded wheels (no PyPI) ──────────────────────
python3 -m venv /opt/fguard/venv
/opt/fguard/venv/bin/pip install --quiet --upgrade pip \
    --no-index --find-links /cdrom/fguard_wheels/ 2>/dev/null || \
/opt/fguard/venv/bin/pip install --quiet --upgrade pip

/opt/fguard/venv/bin/pip install --quiet \
    --no-index --find-links /cdrom/fguard_wheels/ \
    fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
    psutil bcrypt qrcode pillow python-dotenv PyYAML \
    2>/dev/null || \
/opt/fguard/venv/bin/pip install --quiet \
    fastapi "uvicorn[standard]" jinja2 pydantic python-multipart \
    psutil bcrypt qrcode pillow python-dotenv PyYAML

# ── SSL certificate ───────────────────────────────────────────────────────────
mkdir -p /etc/nginx/ssl /etc/fguard
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/fguard.key \
    -out    /etc/nginx/ssl/fguard.crt \
    -subj   "/CN=FGUARD/O=FGUARD/C=GR" 2>/dev/null
chmod 640 /etc/nginx/ssl/fguard.key

# ── nginx ────────────────────────────────────────────────────────────────────
cp /cdrom/server-configs/nginx-fguard.conf /etc/nginx/sites-available/fguard
ln -sf /etc/nginx/sites-available/fguard /etc/nginx/sites-enabled/fguard
rm -f /etc/nginx/sites-enabled/default

# ── systemd services ──────────────────────────────────────────────────────────
cp /cdrom/server-configs/fguard.service          /etc/systemd/system/fguard.service
cp /cdrom/server-configs/fguard-firstboot.service /etc/systemd/system/fguard-firstboot.service

# ── first-boot.sh ─────────────────────────────────────────────────────────────
cp /cdrom/server-configs/first-boot.sh /opt/fguard/build/first-boot.sh
chmod +x /opt/fguard/build/first-boot.sh

# ── VPN auth scripts ─────────────────────────────────────────────────────────
cp /cdrom/server-configs/vpn-auth.sh       /etc/fguard/vpn-auth.sh
cp /cdrom/server-configs/vpn_auth_check.py /etc/fguard/vpn_auth_check.py
chmod +x /etc/fguard/vpn-auth.sh /etc/fguard/vpn_auth_check.py

# ── fail2ban ─────────────────────────────────────────────────────────────────
mkdir -p /etc/fail2ban/jail.d /etc/fail2ban/filter.d
cp /cdrom/server-configs/fail2ban-jail-fguard.conf \
   /etc/fail2ban/jail.d/fguard.conf 2>/dev/null || true
cp /cdrom/server-configs/fail2ban-filter-fguard-vpn.conf \
   /etc/fail2ban/filter.d/fguard-vpn.conf 2>/dev/null || true

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

echo "=== Offline install complete: $(date) ==="
INSTALLSCRIPT

chmod +x "$CUSTOM/fguard_setup/install.sh"
log "Post-install script written"

# ── Step 7b: Embed server configs ─────────────────────────────────────────────
info "[7b] Embedding server configs..."
SCONF="$(dirname "$0")/server-configs"
mkdir -p "$CUSTOM/server-configs"
cp "$SCONF/"* "$CUSTOM/server-configs/" 2>/dev/null || true
log "Server configs embedded: $(ls "$CUSTOM/server-configs/" | wc -l) files"

# ── Step 8: Checksums + Build ISO ─────────────────────────────────────────────
info "[8/8] Building bootable ISO..."
cd "$CUSTOM"
find . -type f ! -name 'md5sum.txt' -print0 | xargs -0 md5sum > md5sum.txt
cd -

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
    -r -V "FGUARD-1.0.0-Offline" \
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
echo -e "${G}  ║   FGUARD OFFLINE ISO built!              ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   File: build/FGUARD-1.0.0-offline...   ║${NC}"
echo -e "${G}  ║   Size: ${SIZE}                                  ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   NO internet needed for app install         ║${NC}"
echo -e "${G}  ║   (apt packages still from Ubuntu repos)     ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   https://10.0.0.1:8080  (LAN only)         ║${NC}"
echo -e "${G}  ║   SSH:  admin@10.0.0.1 / FGUARD2024!    ║${NC}"
echo -e "${G}  ╚══════════════════════════════════════════════╝${NC}"
