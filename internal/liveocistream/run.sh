#!/usr/bin/env bash
# Phase-2 M7.1a live streaming-OCI-fetch smoke under QEMU+EDK2 with
# user-mode networking. One arch per invocation:
#
#     bash internal/liveocistream/run.sh arm64
#     bash internal/liveocistream/run.sh riscv64
#     bash internal/liveocistream/run.sh loong64
#
# amd64 is in scope to BUILD (so the symbol exercises every arch's
# compiler), but NOT to run live — M6.1/M6.2 currently blocks amd64.
# Invoked with `amd64` the script prints a clear "skipped pending
# M6.2" line and exits 0.
#
# Builds a tiny FAT ESP-disk containing the per-arch BOOT*-OCISTREAM.EFI
# under \EFI\BOOT\, runs the matching qemu-system-<arch> with EDK2
# firmware + virtio-net-pci on `-netdev user` (10.0.2.0/24 NAT, SLIRP
# DHCP server at 10.0.2.2), captures stdout for up to 240 s (the
# alpine arm64 layer is ~3.6 MiB → streaming may take a minute over
# user-mode NAT), and matches on:
#   1. "lease acquired"                — DHCPv4 DORA completed.
#   2. "embedded roots ="              — CA bundle parsed.
#   3. "streaming layer digest ="      — manifest walked + layer picked.
#   4. "SHA-256 OK"                    — streaming verified.
#   5. "OCI-STREAM OK"                 — full path OK.
# Exit 0 on PASS (all five matched), 1 otherwise.
#
# Boot-media plumbing mirrors `liveoci/run.sh` 1:1.
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M71A_LIVE_TIMEOUT: per-run wall-clock cap (default 240 — generous,
#                     streaming a 3.6 MiB blob over SLIRP can take
#                     much longer than the buffered M7 ~10 KiB walk)
#   M71A_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {amd64|arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M71A_LIVE_TIMEOUT:-240}"

if [[ "$ARCH" == "amd64" ]]; then
    echo "[live-ocistream:amd64] skipped pending M6.2 (UPX-go) — amd64 EFI build itself is exercised by ocistream:efi:amd64 but not live-run yet"
    exit 0
fi

case "$ARCH" in
    arm64)
        EFI_NAME="BOOTAA64-OCISTREAM.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-OCISTREAM.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-OCISTREAM.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    *)
        echo "unsupported arch: $ARCH (M7.1a supports arm64/riscv64/loong64; amd64 is build-only)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task ocistream:efi:$ARCH' first" >&2
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

WORK="$(mktemp -d -t cloudboot-m71a-live-XXXXXX)"
trap 'if [[ "${M71A_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

NSH_PATH="$WORK/startup.nsh"
cat > "$NSH_PATH" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$NSH_PATH" "$ESP" ::/startup.nsh 2>/dev/null || \
  mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

case "$ARCH" in
    arm64)
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -bios "$FW_CODE"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
    riscv64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE,unit=0"
            -drive "if=pflash,format=raw,file=$FW_VARS,unit=1"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-device,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
    loong64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
esac

echo "[live-ocistream:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

if grep -q "lease acquired" "$LOG" \
   && grep -q "embedded roots =" "$LOG" \
   && grep -q "streaming layer digest =" "$LOG" \
   && grep -q "SHA-256 OK" "$LOG" \
   && grep -q "OCI-STREAM OK" "$LOG"; then
    echo "[live-ocistream:$ARCH] PASS — wall=${ELAPSED_MS}ms"
    grep -E "phase2-oci-stream:" "$LOG" || true
    exit 0
fi
echo "[live-ocistream:$ARCH] FAIL — missing one of 'lease acquired' / 'embedded roots =' / 'streaming layer digest =' / 'SHA-256 OK' / 'OCI-STREAM OK' after ${ELAPSED_MS}ms" >&2
echo "[live-ocistream:$ARCH] tail of qemu log (last 200 lines):" >&2
tail -200 "$LOG" >&2 || true
exit 1
