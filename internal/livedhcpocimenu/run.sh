#!/usr/bin/env bash
# Phase-2 M9.0 live smoke under QEMU+EDK2. One arch per invocation
# (only arm64 wired for the first sprint; the other arches reuse the
# same Go source — adding them is a one-line case extension).
#
#     bash internal/livedhcpocimenu/run.sh arm64
#
# Builds:
#   1. A tiny FAT ESP-disk with the per-arch BOOT*-DHCPOCIMENU.EFI
#      under \EFI\BOOT\.
#   2. Publishes a sample HCL boot-menu config to ttl.sh anonymously
#      via the pushbootmenu host helper, getting back a per-run OCI
#      ref like ttl.sh/cloudboot-m90-<rand>:24h.
#   3. Boots qemu-system-<arch> with EDK2 firmware + virtio-net under
#      user-mode networking with `-netdev user,bootfile=<oci-ref>` to
#      inject the OCI ref as DHCP option 67.
#   4. Captures stdout for up to 90 s and asserts:
#        - "phase2-dhcp-oci-menu: lease acquired"
#        - "phase2-dhcp-oci-menu: bootfile-name = ttl.sh/..."
#        - "phase2-dhcp-oci-menu: parsed BootConfig" + "title = "
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_ARM64_CODE: EDK2 .fd path
#   M9_LIVE_TIMEOUT:           per-run wall-clock cap (default 90)
#   M9_LIVE_KEEPRUN:           1 → keep ESP + qemu logs in /tmp
#   M9_LIVE_HCL:               path to sample HCL (default = the
#                              inline sample below; useful for
#                              quick iteration without editing this
#                              script)
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {arm64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M9_LIVE_TIMEOUT:-90}"

case "$ARCH" in
    arm64)
        EFI_NAME="BOOTAA64-DHCPOCIMENU.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        ;;
    *)
        echo "unsupported arch: $ARCH (M9.0 live wired for arm64 only in this sprint)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
[[ -f "$EFI_PATH" ]] || { echo "missing $EFI_PATH; run 'task dhcpocimenu:efi:$ARCH' first" >&2; exit 1; }
[[ -f "$FW_CODE" ]] || { echo "missing OVMF at $FW_CODE (set CLOUDBOOT_OVMF_ARM64_CODE)" >&2; exit 1; }

WORK="$(mktemp -d -t cloudboot-m90-live-XXXXXX)"
trap 'if [[ "${M9_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# 1) ESP image with the M9.0 probe
ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=16 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"
cat > "$WORK/startup.nsh" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$WORK/startup.nsh" "::/startup.nsh"

# 2) Publish a sample HCL config to ttl.sh anonymously
if [[ -n "${M9_LIVE_HCL:-}" ]]; then
    HCL_PATH="$M9_LIVE_HCL"
else
    HCL_PATH="$WORK/bootconfig.hcl"
    cat > "$HCL_PATH" <<'EOF'
title   = "cloud-boot M9.0 smoke menu"
timeout = 10
default = "alpine-latest"

entry "alpine-latest" {
  kernel_ref = "ghcr.io/myorg/alpine-kernel:latest"
  cmdline    = "console=ttyAMA0,115200 root=/dev/ram0"
  initrd_ref = "ghcr.io/myorg/alpine-initrd:latest"
}

entry "rescue" {
  kernel_ref = "ghcr.io/myorg/rescue-kernel:latest"
  cmdline    = "console=ttyAMA0,115200 single"
}
EOF
fi

# Random per-run tag to avoid colliding with concurrent runs.
# `dd | tr` instead of `tr | head -c` because the latter trips
# `set -o pipefail` (tr gets SIGPIPE when head exits early).
RAND="$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z0-9' | cut -c1-8)"
OCI_REF="ttl.sh/cloudboot-m90-${RAND}:24h"

echo "[live-dhcpocimenu:$ARCH] publishing $HCL_PATH to $OCI_REF" >&2
(cd "$REPO_DIR/internal/livedhcpocimenu/pushbootmenu" && \
    GOWORK=off go run . -src "$HCL_PATH" -dst "$OCI_REF") >&2

# 3) Boot QEMU with -netdev user,bootfile=<oci-ref>
#    bootfile= maps directly to DHCP option 67 in QEMU's SLIRP stack.
QEMU_ARGS=(
    -machine virt -cpu cortex-a72 -m 4096
    -display none -no-reboot
    -bios "$FW_CODE"
    -drive "file=$ESP,format=raw,if=none,id=esp"
    -device "virtio-blk-pci,drive=esp"
    -netdev "user,id=net0,bootfile=$OCI_REF"
    -object "filter-dump,id=f0,netdev=net0,file=$WORK/net.pcap"
    -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
    -chardev "stdio,id=char0,mux=off,signal=off"
    -serial "chardev:char0"
)

echo "[live-dhcpocimenu:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QPID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QPID" 2>/dev/null && sleep 1 && kill -KILL "$QPID" 2>/dev/null ) &
KILLER=$!
while kill -0 "$QPID" 2>/dev/null; do sleep 1; done
kill "$KILLER" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# 4) Verify gates
PASS=1
grep -q "phase2-dhcp-oci-menu: lease acquired" "$LOG" || PASS=0
grep -q "phase2-dhcp-oci-menu: bootfile-name = ttl.sh/cloudboot-m90-" "$LOG" || PASS=0
grep -q "phase2-dhcp-oci-menu: parsed BootConfig" "$LOG" || PASS=0
grep -q "title =" "$LOG" || PASS=0

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-dhcpocimenu:$ARCH] PASS — wall=${ELAPSED_MS}ms, ref=$OCI_REF"
    grep -E "phase2-dhcp-oci-menu:|title =|entry " "$LOG" || true
    exit 0
fi

echo "[live-dhcpocimenu:$ARCH] FAIL — missing one of 'lease acquired' / 'bootfile-name =' / 'parsed BootConfig' / 'title =' after ${ELAPSED_MS}ms" >&2
echo "[live-dhcpocimenu:$ARCH] tail of qemu log (last 80 lines):" >&2
tail -80 "$LOG" >&2 || true
exit 1
