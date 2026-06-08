#!/usr/bin/env bash
# Phase-2 M3 live ICMP-ping smoke under QEMU+EDK2 with
# user-mode networking. One arch per invocation:
#
#     bash internal/livenetstack/run.sh amd64
#     bash internal/livenetstack/run.sh arm64
#     bash internal/livenetstack/run.sh riscv64
#
# Builds a tiny FAT ESP-disk containing the per-arch
# BOOT*-NETSTACK.EFI under \EFI\BOOT\, runs the matching
# qemu-system-<arch> with EDK2 firmware + virtio-net-pci on
# `-netdev user` (10.0.2.0/24 NAT), captures stdout for up to
# 30 s, and matches on "ROUND-TRIP OK". Exit 0 on PASS, 1
# otherwise.
#
# Boot-media plumbing mirrors cloud-boot/iso's multiarchboot:
#   - amd64    → ide-cd (the ISO9660 path; QEMU's q35 default)
#   - arm64    → virtio-blk-pci
#   - riscv64  → virtio-blk-device (riscv64 virt machine quirk)
#
# loong64 is intentionally not supported by this script —
# tamago-pie's loong64 syscall overlay is incomplete (R-M3'b)
# so no BOOTLOONGARCH64-NETSTACK.EFI exists.
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M3_LIVE_TIMEOUT: per-run wall-clock cap (default 30)
#   M3_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {amd64|arm64|riscv64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M3_LIVE_TIMEOUT:-30}"

case "$ARCH" in
    amd64)
        EFI_NAME="BOOTX64-NETSTACK.EFI"
        EFI_BOOT_NAME="BOOTX64.EFI"
        QEMU_BIN="qemu-system-x86_64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    arm64)
        EFI_NAME="BOOTAA64-NETSTACK.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-NETSTACK.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    *)
        echo "unsupported arch: $ARCH (M3 supports amd64/arm64/riscv64; loong64 blocked by R-M3'b)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task netstack:efi:$ARCH' first" >&2
    exit 1
fi
if [[ ! -f "$FW_CODE" ]]; then
    echo "missing EDK2 firmware code at $FW_CODE (set CLOUDBOOT_OVMF_${ARCH^^}_CODE)" >&2
    exit 1
fi
if [[ -n "$FW_VARS" && ! -f "$FW_VARS" ]]; then
    echo "missing EDK2 firmware vars at $FW_VARS (set CLOUDBOOT_OVMF_${ARCH^^}_VARS)" >&2
    exit 1
fi

WORK="$(mktemp -d -t cloudboot-m3-live-XXXXXX)"
trap 'if [[ "${M3_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
# QEMU EDK2 sees this as a removable FAT volume; BDS falls
# back to the \EFI\BOOT\<DEFAULT>.EFI path when no boot entry
# matches. No GPT partition table needed for the bare FAT layout.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
mformat -i "$ESP" -F ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

# Per-arch QEMU args. virtio-net-pci on -netdev user gives
# the guest 10.0.2.0/24 with 10.0.2.2 as the gateway — the
# exact addresses the M3 probe is configured for.
case "$ARCH" in
    amd64)
        # Two pflash drives (code RO + vars RW). The vars
        # file is opened RW so EDK2 can persist BootOrder
        # state between boots; we copy it into the work dir
        # so we don't trip on a host-locked read-only copy.
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine q35 -cpu max -m 2048
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
            -device "ide-hd,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,bus=pcie.0,addr=03.0"
            -serial stdio
        )
        ;;
    arm64)
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -bios "$FW_CODE"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0"
            -serial stdio
        )
        ;;
    riscv64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE,unit=0"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd,unit=1"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-device,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0"
            -serial stdio
        )
        ;;
esac

echo "[live-netstack:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
# Run QEMU under a wall-clock cap; we don't need the SIGTERM
# graceful path because the probe halts in a spin loop on
# success/failure. macOS doesn't ship GNU coreutils `timeout`,
# so we drive the cap with a background sleep killer.
"$QEMU_BIN" "${QEMU_ARGS[@]}" 2>&1 | tee "$LOG" &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
wait "$QEMU_PID" 2>/dev/null || true
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

if grep -q "ROUND-TRIP OK" "$LOG"; then
    echo "[live-netstack:$ARCH] PASS — wall=${ELAPSED_MS}ms"
    exit 0
fi
echo "[live-netstack:$ARCH] FAIL — no ROUND-TRIP OK in stdout after ${ELAPSED_MS}ms" >&2
echo "[live-netstack:$ARCH] tail of qemu log (last 60 lines):" >&2
tail -60 "$LOG" >&2 || true
exit 1
