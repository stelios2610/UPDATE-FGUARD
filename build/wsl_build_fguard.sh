#!/bin/bash
# FGUARD ISO Builder — Offline (WSL2)
# App code + Python wheels embedded in ISO — no internet needed during install.
#
# FIX vs old scripts: late-commands copy files directly to /target/ WITHOUT
# "curtin in-target", because inside the chroot /cdrom is not accessible.
#
# Run from PowerShell: wsl -u root bash build/wsl_build_fguard.sh
set -e

ISO='/mnt/c/Users/stelakis-pc/Downloads/ubuntu-26.04-live-server-amd64.iso'
OUTPUT='/mnt/c/Users/stelakis-pc/Documents/FGUARD-1.0.iso'
WORK='/tmp/fguard-iso'
SRC_WIN='/mnt/c/Users/stelakis-pc/Projects/firewall-gui'
SRC="$WORK/src"
CUSTOM="$WORK/custom"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${G}[✓]${NC} $*"; }
info() { echo -e "${C}[→]${NC} $*"; }
warn() { echo -e "${Y}[!]${NC} $*"; }
err()  { echo -e "${R}[✗]${NC} $*"; exit 1; }

echo ""
echo -e "${C}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${C}  ║   FGUARD ISO Builder — Offline           ║${NC}"
echo -e "${C}  ║   App + wheels embedded — no internet needed ║${NC}"
echo -e "${C}  ╚══════════════════════════════════════════════╝${NC}"
echo ""

[ "$(id -u)" -eq 0 ] || err "Run as root: wsl -u root bash build/wsl_build_fguard.sh"
[ -f "$ISO" ] || err "Ubuntu ISO not found: $ISO"

# ── Step 1: Build dependencies ────────────────────────────────────────────────
info "[1/8] Installing build dependencies..."
apt-get update -qq
apt-get install -y xorriso p7zip-full rsync python3-pip python3-venv -qq
log "Dependencies ready"

# ── Step 2: Extract Ubuntu ISO ────────────────────────────────────────────────
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
set timeout=5

menuentry "Install FGUARD Network Security" --class ubuntu --class os {
    set gfxpayload=keep
    linux   /casper/vmlinuz quiet autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}
menuentry "Install FGUARD (verbose — shows progress)" --class ubuntu {
    set gfxpayload=keep
    linux   /casper/vmlinuz autoinstall ds=nocloud;s=/cdrom/nocloud/ ---
    initrd  /casper/initrd
}
GRUBCFG
    log "Bootloader updated: $f"
done

# ── Step 4: Autoinstall config ────────────────────────────────────────────────
info "[4/8] Writing autoinstall config..."
mkdir -p "$CUSTOM/nocloud"

cat > "$CUSTOM/nocloud/meta-data" << 'META'
instance-id: fguard-utc-1
local-hostname: fguard
META

PASS_HASH=$(python3 -c "
import crypt
print(crypt.crypt('FGuard2024!', crypt.mksalt(crypt.METHOD_SHA512)))
" 2>/dev/null || echo '$6$fguard$placeholder')

# IMPORTANT: late-commands copy files directly to /target/ (no curtin in-target).
# Inside the chroot that curtin in-target creates, /cdrom is NOT accessible.
# Running without in-target gives access to both /cdrom (ISO) and /target (installed system).
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
    username: stelios
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
        ens18:  {dhcp4: true}
  ssh:
    install-server: true
    allow-pw: true
  packages:
    - python3
    - python3-pip
    - python3-venv
    - nginx
    - openssl
    - curl
    - wget
    - git
    - iptables
    - iptables-persistent
    - netfilter-persistent
    - iproute2
    - net-tools
    - dnsmasq
    - openvpn
    - fail2ban
    - keepalived
    - strongswan
    - wireguard
    - htop
  user-data:
    chpasswd:
      expire: false
  late-commands:
    # Copy FGUARD app + wheels directly to /target (no chroot — /cdrom accessible here)
    - mkdir -p /target/opt/fguard /target/opt/fguard-wheels /target/etc/fguard
    - cp -r /cdrom/fguard_app/. /target/opt/fguard/
    - cp -r /cdrom/fguard_wheels/. /target/opt/fguard-wheels/
    # nginx config
    - mkdir -p /target/etc/nginx/sites-available /target/etc/nginx/sites-enabled
    - cp /cdrom/server-configs/nginx-fguard.conf /target/etc/nginx/sites-available/fguard
    - ln -sf /etc/nginx/sites-available/fguard /target/etc/nginx/sites-enabled/fguard
    - rm -f /target/etc/nginx/sites-enabled/default
    # systemd services
    - cp /cdrom/server-configs/fguard.service /target/etc/systemd/system/fguard.service
    - cp /cdrom/server-configs/fguard-firstboot.service /target/etc/systemd/system/fguard-firstboot.service
    # first-boot.sh (does venv + packages + services on first reboot)
    - mkdir -p /target/opt/fguard/build
    - cp /cdrom/server-configs/first-boot.sh /target/opt/fguard/build/first-boot.sh
    - chmod +x /target/opt/fguard/build/first-boot.sh
    # Enable firstboot service via symlink (no systemctl needed)
    - mkdir -p /target/etc/systemd/system/multi-user.target.wants
    - ln -sf /etc/systemd/system/fguard-firstboot.service /target/etc/systemd/system/multi-user.target.wants/fguard-firstboot.service
    # VPN auth scripts
    - cp /cdrom/server-configs/vpn-auth.sh /target/etc/fguard/vpn-auth.sh
    - cp /cdrom/server-configs/vpn_auth_check.py /target/etc/fguard/vpn_auth_check.py
    - chmod +x /target/etc/fguard/vpn-auth.sh /target/etc/fguard/vpn_auth_check.py
    # fail2ban
    - mkdir -p /target/etc/fail2ban/jail.d /target/etc/fail2ban/filter.d
    - cp /cdrom/server-configs/fail2ban-jail-fguard.conf /target/etc/fail2ban/jail.d/fguard.conf
    - cp /cdrom/server-configs/fail2ban-filter-fguard-vpn.conf /target/etc/fail2ban/filter.d/fguard-vpn.conf
    # Disable automatic apt updates (caused ClamAV disk-fill incident)
    - curtin in-target --target=/target -- systemctl disable apt-daily.timer apt-daily-upgrade.timer apt-daily.service apt-daily-upgrade.service
    - curtin in-target --target=/target -- apt-get remove --purge -y unattended-upgrades
    # sudoers
    - "echo 'stelios ALL=(ALL) NOPASSWD: ALL' > /target/etc/sudoers.d/stelios"
    - chmod 440 /target/etc/sudoers.d/stelios
USERDATA

log "Autoinstall config written"

# ── Step 5: Embed app code ────────────────────────────────────────────────────
info "[5/8] Embedding FGUARD app code..."
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
    --exclude='Documents' \
    "$SRC_WIN/" "$CUSTOM/fguard_app/"

PY_COUNT=$(find "$CUSTOM/fguard_app" -name '*.py' | wc -l)
log "App embedded: $PY_COUNT Python files"

# ── Step 6: Download Python wheels ───────────────────────────────────────────
info "[6/8] Downloading Python wheels for offline install..."
mkdir -p "$CUSTOM/fguard_wheels"

# Fix WSL DNS if needed
if ! ping -c1 -W2 8.8.8.8 &>/dev/null; then
    warn "No network — trying to fix DNS..."
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
    2>&1 | grep -E "^(Collecting|Saved|ERROR|error)" || true

WHEEL_COUNT=$(ls "$CUSTOM/fguard_wheels/" 2>/dev/null | wc -l)
log "Wheels downloaded: $WHEEL_COUNT packages"
[ "$WHEEL_COUNT" -eq 0 ] && warn "No wheels downloaded — install will fall back to PyPI on first boot"

# ── Step 7: Embed server-configs ─────────────────────────────────────────────
info "[7/8] Embedding server configs..."
mkdir -p "$CUSTOM/server-configs"
cp "$SCRIPT_DIR/server-configs/"* "$CUSTOM/server-configs/"
log "Server configs embedded: $(ls "$CUSTOM/server-configs/" | wc -l) files"

# ── Step 8: Build ISO ─────────────────────────────────────────────────────────
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

[ -z "$MBR" ] && err "MBR boot image not found in ISO"
[ -z "$EFI" ] && err "EFI boot image not found in ISO"

xorriso -as mkisofs \
    -r -V "FGUARD-1.0" \
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
    -o "$OUTPUT" "$CUSTOM/" 2>&1 | tail -5

rm -rf "$WORK"

SIZE=$(du -sh "$OUTPUT" 2>/dev/null | cut -f1 || echo "?")

echo ""
echo -e "${G}  ╔══════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   FGUARD ISO built successfully!         ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   File: Documents/FGUARD-1.0.iso         ║${NC}"
echo -e "${G}  ║   Size: ${SIZE}                                  ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Boot → Ubuntu installs → reboot:           ║${NC}"
echo -e "${G}  ║   first-boot.sh: network + venv + services   ║${NC}"
echo -e "${G}  ║                                              ║${NC}"
echo -e "${G}  ║   Web UI:  https://10.0.0.1:8080             ║${NC}"
echo -e "${G}  ║   SSH:     stelios@10.0.0.1 / FGuard2024!    ║${NC}"
echo -e "${G}  ║   Login:   admin / admin                     ║${NC}"
echo -e "${G}  ╚══════════════════════════════════════════════╝${NC}"
echo ""
