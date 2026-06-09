#!/usr/bin/env bash
# Phase-2 M8.0 live chain-boot smoke under QEMU+EDK2. One arch per
# invocation:
#
#     bash internal/liveefihandover/run.sh amd64
#     bash internal/liveefihandover/run.sh arm64
#     bash internal/liveefihandover/run.sh riscv64
#     bash internal/liveefihandover/run.sh loong64
#
# Builds a tiny FAT ESP-disk containing the per-arch
# BOOT*-EFIHANDOVER.EFI under \EFI\BOOT\, runs the matching
# qemu-system-<arch> with EDK2 firmware (NO networking — M8.0 is
# pure LoadImage + StartImage), captures stdout for up to 30 s, and
# matches on:
#   1. "phase2-efi-handover: embed length ="        — payload made it through.
#   2. "phase2-efi-handover: LoadImage OK"          — firmware parsed PE32+.
#   3. "phase2-efi-handover: StartImage entering child" — about to jump.
#   4. ">>> M8.0 chained payload — Hello from <ARCH> <<<" — child banner.
#   5. "phase2-efi-handover: chain-boot returned exit_status=" — clean return.
#      (If TamaGo's runtime halts the child at end-of-main instead of
#      returning via gBS->Exit, this last line will be missing — see
#      M8.0a finding in the design doc. The first four still prove
#      mechanism: LoadImage + StartImage entry into the child.)
# Exit 0 on PASS (the first four matched, last one optional but
# preferred); 1 otherwise.
#
# Boot-media plumbing mirrors `liveoci/run.sh` 1:1 minus the
# networking lines:
#   - amd64    → ide-hd (q35 default)
#   - arm64    → virtio-blk-pci
#   - riscv64  → virtio-blk-device
#   - loong64  → virtio-blk-pci
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M8_LIVE_TIMEOUT: per-run wall-clock cap (default 30 — no network
#                    means the chain-boot completes in well under
#                    10s on every supported arch)
#   M8_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {amd64|arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M8_LIVE_TIMEOUT:-30}"

case "$ARCH" in
    amd64)
        EFI_NAME="BOOTX64-EFIHANDOVER.EFI"
        EFI_BOOT_NAME="BOOTX64.EFI"
        QEMU_BIN="qemu-system-x86_64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="amd64"
        ;;
    arm64)
        EFI_NAME="BOOTAA64-EFIHANDOVER.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        BANNER_ARCH="arm64"
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-EFIHANDOVER.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="riscv64"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-EFIHANDOVER.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="loong64"
        ;;
    *)
        echo "unsupported arch: $ARCH (M8.0 supports amd64/arm64/riscv64/loong64)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task efihandover:efi:$ARCH' first" >&2
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

WORK="$(mktemp -d -t cloudboot-m8-live-XXXXXX)"
trap 'if [[ "${M8_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
# NOTE: do NOT pass `-F` — at 16 MiB the volume is too small for a
# valid FAT32 layout, EDK2 refuses to mount it, and BDS falls back
# to PXE. Let mformat pick FAT12/16 automatically.
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

# Drop a startup.nsh at the FAT root that the EDK2 Internal Shell
# auto-runs. Same shape as the M3 / M4 / M5 / M6 / M7 live runners.
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
        # The dummy virtio-net device is REQUIRED on amd64 q35 even
        # though M8.0 has no networking probe. Without ANY -netdev
        # backed PCI device, EDK2 stable202408's BDS on q35 skips the
        # ESP entirely and falls straight to PXE (empirically verified
        # 2026-06-09). Adding a unused user-mode NIC on pcie.0:03.0
        # restores the normal ESP boot path. Same shape as the M5/M6/
        # M7 amd64 runners — they need a NIC for their probes; we just
        # piggy-back on the side-effect.
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
            -serial stdio
        )
        ;;
esac

echo "[live-efihandover:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
# Run QEMU under a wall-clock cap. macOS doesn't ship GNU coreutils
# `timeout`, so we drive the cap with a background sleep killer.
# NOTE: do NOT pipe through `tee` — $! returns tee's PID, not
# QEMU's, and the watchdog ends up killing tee while QEMU keeps
# running forever (same bug as previous live runners).
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
# Poll for QEMU exit (kill -0 probe) — `wait` may not work when
# the shell loses job-control tracking under task/interactive
# contexts.
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# Match on the four mandatory lines + the (optional) clean-return
# line. The chained-payload banner uses the same en-dash character
# the Go source emits (U+2014 EM DASH) — keep the search byte-string
# in sync.
EXPECT_BANNER=">>> M8.0 chained payload -- Hello from ${BANNER_ARCH} <<<"

PASS=1
# Note: the probe prints "embed length (decompressed) = N" since the
# M6.1 gzip-embed mitigation; the looser pattern below matches both
# the pre-M6.1 ("embed length =") and post-M6.1 wording.
grep -q "phase2-efi-handover: embed length" "$LOG" || PASS=0
grep -q "phase2-efi-handover: LoadImage OK" "$LOG" || PASS=0
grep -q "phase2-efi-handover: StartImage entering child" "$LOG" || PASS=0
grep -qF "$EXPECT_BANNER" "$LOG" || PASS=0

CLEAN_RETURN=0
if grep -q "phase2-efi-handover: chain-boot returned exit_status=" "$LOG"; then
    CLEAN_RETURN=1
fi

if [[ "$PASS" -eq 1 ]]; then
    if [[ "$CLEAN_RETURN" -eq 1 ]]; then
        echo "[live-efihandover:$ARCH] PASS — wall=${ELAPSED_MS}ms, clean return via gBS->Exit"
    else
        echo "[live-efihandover:$ARCH] PASS (mechanism only) — wall=${ELAPSED_MS}ms, no clean gBS->Exit return (child halted at end-of-main; M8.0a)"
    fi
    grep -E "phase2-efi-handover:|M8\.0 chained payload" "$LOG" || true
    exit 0
fi
echo "[live-efihandover:$ARCH] FAIL — missing one of 'embed length' / 'LoadImage OK' / 'StartImage entering child' / chained banner after ${ELAPSED_MS}ms" >&2
echo "[live-efihandover:$ARCH] tail of qemu log (last 120 lines):" >&2
tail -120 "$LOG" >&2 || true
exit 1
