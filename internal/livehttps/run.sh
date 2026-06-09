#!/usr/bin/env bash
# Phase-2 M6 live HTTPS-GET smoke under QEMU+EDK2 with user-mode
# networking. One arch per invocation:
#
#     bash internal/livehttps/run.sh amd64
#     bash internal/livehttps/run.sh arm64
#     bash internal/livehttps/run.sh riscv64
#     bash internal/livehttps/run.sh loong64
#
# Builds a tiny FAT ESP-disk containing the per-arch
# BOOT*-HTTPS.EFI under \EFI\BOOT\, runs the matching
# qemu-system-<arch> with EDK2 firmware + virtio-net-pci on
# `-netdev user` (10.0.2.0/24 NAT, SLIRP DHCP server at 10.0.2.2,
# SLIRP DNS forwarder at 10.0.2.3, host network reachable via NAT),
# captures stdout for up to 90 s, and matches on:
#   1. "lease acquired"        — DHCPv4 DORA completed.
#   2. "resolved example.com"  — DNS A-record lookup succeeded.
#   3. "embedded roots ="      — CA bundle parsed by NewRootCAs.
#   4. "HTTPS-GET OK"          — full TLS handshake + HTTPS round-trip.
# Exit 0 on PASS (all four matched), 1 otherwise.
#
# Boot-media plumbing mirrors `livehttp/run.sh` 1:1:
#   - amd64    → ide-hd (q35 default)
#   - arm64    → virtio-blk-pci
#   - riscv64  → virtio-blk-device
#   - loong64  → virtio-blk-pci
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M6_LIVE_TIMEOUT: per-run wall-clock cap (default 90 — TLS handshake
#                    + crypto/x509 cert validation costs an extra 20-30s
#                    on top of the M5 baseline on slower QEMU targets)
#   M6_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {amd64|arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M6_LIVE_TIMEOUT:-90}"

case "$ARCH" in
    amd64)
        EFI_NAME="BOOTX64-HTTPS.EFI"
        EFI_BOOT_NAME="BOOTX64.EFI"
        QEMU_BIN="qemu-system-x86_64"
        # Prefer the patched OVMF (edk2-stable202605, carries the three
        # M6.2 amd64 #GP fixes — see docs/m6-2-edk2-upstream-investigation.md
        # § "Patched OVMF integration"); fall back to pkgx-bundled buggy
        # blob if the patched build is not installed on this host.
        if [[ -f "$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd" ]]; then
            FW_CODE_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd"
            FW_VARS_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-i386-vars.fd"
        else
            FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
            FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
        fi
        FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    arm64)
        EFI_NAME="BOOTAA64-HTTPS.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-HTTPS.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-HTTPS.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    *)
        echo "unsupported arch: $ARCH (M6 supports amd64/arm64/riscv64/loong64)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task https:efi:$ARCH' first" >&2
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

WORK="$(mktemp -d -t cloudboot-m6-live-XXXXXX)"
trap 'if [[ "${M6_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
# NOTE: do NOT pass `-F` — at 16 MiB the volume is too small for a
# valid FAT32 layout, EDK2 refuses to mount it, and BDS falls back to
# PXE. Let mformat pick FAT12/16 automatically.
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

# Drop a startup.nsh at the FAT root that the EDK2 Internal Shell
# auto-runs. Same shape as the M3 / M4 / M5 live runners.
NSH_PATH="$WORK/startup.nsh"
cat > "$NSH_PATH" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

case "$ARCH" in
    amd64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine q35 -cpu max -m 2048
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
            -device "ide-hd,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,bus=pcie.0,addr=03.0,disable-legacy=on,disable-modern=off"
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

echo "[live-https:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
# Run QEMU under a wall-clock cap. macOS doesn't ship GNU coreutils
# `timeout`, so we drive the cap with a background sleep killer.
# NOTE: do NOT pipe through `tee` — $! returns tee's PID, not QEMU's,
# and the watchdog ends up killing tee while QEMU keeps running
# forever (same bug as the M2-B / M3-minimal / M4 / M5 live runners).
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
# Poll for QEMU exit (kill -0 probe) — `wait` may not work when the
# shell loses job-control tracking under task/interactive contexts.
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

if grep -q "lease acquired" "$LOG" \
   && grep -q "resolved example.com" "$LOG" \
   && grep -q "embedded roots =" "$LOG" \
   && grep -q "HTTPS-GET OK" "$LOG"; then
    echo "[live-https:$ARCH] PASS — wall=${ELAPSED_MS}ms"
    grep -E "phase2-https:" "$LOG" || true
    exit 0
fi
echo "[live-https:$ARCH] FAIL — missing 'lease acquired' / 'resolved example.com' / 'embedded roots =' / 'HTTPS-GET OK' after ${ELAPSED_MS}ms" >&2
echo "[live-https:$ARCH] tail of qemu log (last 80 lines):" >&2
tail -80 "$LOG" >&2 || true
exit 1
