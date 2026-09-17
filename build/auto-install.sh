#!/bin/bash
# FGUARD Auto Installer
# Runs automatically when booting from the ISO.
# Detects disk, partitions, installs, configures GRUB and reboots.

exec > /dev/tty1 2>&1
export TERM=linux

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'; C='\033[0;36m'; B='\033[1m'; NC='\033[0m'

clear
echo -e "${C}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║            FGUARD Network Security               ║"
echo "  ║                   Auto Installer                     ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
sleep 2

# ── Find target disk ──────────────────────────────────────────────────────────
echo -e "${C}[→]${NC} Detecting disk..."

TARGET_DISK=""
for disk in /dev/sda /dev/vda /dev/nvme0n1 /dev/xvda /dev/hda; do
    if [ -b "$disk" ]; then
        TARGET_DISK="$disk"
        break
    fi
done

# Hyper-V uses /dev/sdb sometimes if ISO is on sda
if [ -z "$TARGET_DISK" ]; then
    TARGET_DISK=$(lsblk -dpno NAME,TYPE | awk '$2=="disk"{print $1}' | head -1)
fi

[ -z "$TARGET_DISK" ] && { echo -e "${R}[✗] No disk found!${NC}"; sleep 10; exit 1; }

DISK_SIZE=$(lsblk -dno SIZE "$TARGET_DISK" 2>/dev/null || echo "?")
echo -e "${G}[✓]${NC} Target disk: ${B}${TARGET_DISK}${NC} (${DISK_SIZE})"
echo ""
echo -e "${Y}[!] WARNING: ALL DATA on ${TARGET_DISK} will be ERASED!${NC}"
echo ""
echo -n "    Installing in 10 seconds... (Ctrl+C to cancel) "
for i in $(seq 10 -1 1); do printf "\b%d" $i; sleep 1; done
echo ""
echo ""

# ── Partition ─────────────────────────────────────────────────────────────────
echo -e "${C}[→]${NC} Partitioning ${TARGET_DISK}..."

# Detect if UEFI or BIOS
UEFI=0
[ -d /sys/firmware/efi ] && UEFI=1

# Unmount anything on target disk
umount ${TARGET_DISK}* 2>/dev/null || true
swapoff -a 2>/dev/null || true

if [ "$UEFI" -eq 1 ]; then
    # GPT: EFI (512MB) + root (rest)
    parted -s "$TARGET_DISK" mklabel gpt
    parted -s "$TARGET_DISK" mkpart primary fat32 1MiB 513MiB
    parted -s "$TARGET_DISK" set 1 esp on
    parted -s "$TARGET_DISK" mkpart primary ext4 513MiB 100%
    # Partitions
    if [[ "$TARGET_DISK" == *"nvme"* ]]; then
        EFI_PART="${TARGET_DISK}p1"
        ROOT_PART="${TARGET_DISK}p2"
    else
        EFI_PART="${TARGET_DISK}1"
        ROOT_PART="${TARGET_DISK}2"
    fi
    mkfs.fat -F32 -n "AEGIS_EFI" "$EFI_PART"
else
    # MBR: root only
    parted -s "$TARGET_DISK" mklabel msdos
    parted -s "$TARGET_DISK" mkpart primary ext4 1MiB 100%
    parted -s "$TARGET_DISK" set 1 boot on
    ROOT_PART="${TARGET_DISK}1"
fi

mkfs.ext4 -q -L "AEGIS_ROOT" "$ROOT_PART"
echo -e "${G}[✓]${NC} Disk partitioned"

# ── Mount + copy squashfs ─────────────────────────────────────────────────────
echo -e "${C}[→]${NC} Installing system..."

INSTALL_MNT="/mnt/aegisinstall"
SQUASHFS_MNT="/mnt/squashfs"
mkdir -p "$INSTALL_MNT" "$SQUASHFS_MNT"

mount "$ROOT_PART" "$INSTALL_MNT"
if [ "$UEFI" -eq 1 ]; then
    mkdir -p "${INSTALL_MNT}/boot/efi"
    mount "$EFI_PART" "${INSTALL_MNT}/boot/efi"
fi

# Find squashfs
SQUASHFS=""
for p in /run/live/medium/live /live/image/live /cdrom/live; do
    [ -f "${p}/filesystem.squashfs" ] && SQUASHFS="${p}/filesystem.squashfs" && break
done
[ -z "$SQUASHFS" ] && SQUASHFS=$(find /run /mnt /media -name "filesystem.squashfs" 2>/dev/null | head -1)
[ -z "$SQUASHFS" ] && { echo -e "${R}[✗] Cannot find filesystem.squashfs!${NC}"; sleep 10; exit 1; }

echo -e "${C}[→]${NC} Copying files from squashfs (2-5 min)..."
mount -o loop,ro "$SQUASHFS" "$SQUASHFS_MNT"
rsync -a --info=progress2 \
    --exclude="/proc/*" --exclude="/sys/*" \
    --exclude="/dev/*" --exclude="/run/*" \
    --exclude="/tmp/*" \
    "${SQUASHFS_MNT}/" "${INSTALL_MNT}/"
umount "$SQUASHFS_MNT"
echo -e "${G}[✓]${NC} Files copied"

# ── Setup chroot environment ──────────────────────────────────────────────────
for dir in dev dev/pts proc sys run; do
    mount --bind "/$dir" "${INSTALL_MNT}/$dir"
done

# ── fstab ─────────────────────────────────────────────────────────────────────
ROOT_UUID=$(blkid -s UUID -o value "$ROOT_PART")
{
    echo "UUID=${ROOT_UUID}  /       ext4  errors=remount-ro  0  1"
    echo "proc              /proc   proc  defaults           0  0"
    if [ "$UEFI" -eq 1 ]; then
        EFI_UUID=$(blkid -s UUID -o value "$EFI_PART")
        echo "UUID=${EFI_UUID}   /boot/efi  vfat  umask=0077  0  1"
    fi
} > "${INSTALL_MNT}/etc/fstab"

# ── Remove live-only services ─────────────────────────────────────────────────
chroot "$INSTALL_MNT" systemctl disable fguard-autoinstall 2>/dev/null || true
rm -f "${INSTALL_MNT}/etc/systemd/system/fguard-autoinstall.service"
rm -f "${INSTALL_MNT}/installed" 2>/dev/null || true
# Signal that install is done (prevents re-install loop)
touch "${INSTALL_MNT}/installed"

# ── Install GRUB ──────────────────────────────────────────────────────────────
echo -e "${C}[→]${NC} Installing bootloader..."
if [ "$UEFI" -eq 1 ]; then
    chroot "$INSTALL_MNT" grub-install \
        --target=x86_64-efi \
        --efi-directory=/boot/efi \
        --bootloader-id=FGUARD \
        --recheck 2>/dev/null
else
    chroot "$INSTALL_MNT" grub-install \
        --target=i386-pc \
        --recheck \
        "$TARGET_DISK" 2>/dev/null
fi
chroot "$INSTALL_MNT" update-grub 2>/dev/null
echo -e "${G}[✓]${NC} Bootloader installed"

# ── Unmount ───────────────────────────────────────────────────────────────────
for dir in run sys proc dev/pts dev; do
    umount -lf "${INSTALL_MNT}/$dir" 2>/dev/null || true
done
[ "$UEFI" -eq 1 ] && umount "${INSTALL_MNT}/boot/efi" 2>/dev/null || true
umount "$INSTALL_MNT"
sync

# ── Done ─────────────────────────────────────────────────────────────────────
echo ""
echo -e "${G}  ╔═════════════════════════════════════════════════════╗${NC}"
echo -e "${G}  ║   FGUARD installed successfully!                 ║${NC}"
echo -e "${G}  ║                                                      ║${NC}"
echo -e "${G}  ║   Remove USB/ISO and reboot.                         ║${NC}"
echo -e "${G}  ║   Then connect a PC to the LAN port                  ║${NC}"
echo -e "${G}  ║   and open: http://10.0.0.1:8080                     ║${NC}"
echo -e "${G}  ║                                                      ║${NC}"
echo -e "${G}  ║   Root password: FGUARD2024!                     ║${NC}"
echo -e "${G}  ╚═════════════════════════════════════════════════════╝${NC}"
echo ""
echo -n "  Rebooting in 15 seconds... "
for i in $(seq 15 -1 1); do printf "\b%d " $i; sleep 1; done
echo ""
reboot
