#!/usr/bin/env bash
# Phase-2 M8.1-minimal live smoke under QEMU+EDK2. One arch per
# invocation:
#
#     bash internal/livekernelboot/run.sh arm64
#     bash internal/livekernelboot/run.sh riscv64
#     bash internal/livekernelboot/run.sh loong64
#
# (amd64 deferred to its own debug sprint per the M8.1 brief —
# blocked behind the M6.1 OVMF >4 MiB threshold + parallel amd64
# debug sprint on the m6-2-pr2-amd64-wip branch.)
#
# Builds a tiny FAT ESP-disk containing the per-arch
# BOOT*-KERNELBOOT.EFI under \EFI\BOOT\, runs the matching
# qemu-system-<arch> with EDK2 firmware (no networking required in
# MODE B — the default in this build — because the in-process
# oci.Transport serves the embedded chained EFI bytes), captures
# stdout for up to 120 s, and matches on:
#   1. "phase2-oci-kernel-boot: synthetic descriptor digest =" — descriptor built.
#   2. "phase2-oci-kernel-boot: streaming blob via in-process Transport (MODE B)"
#                                                              — streaming leg entered.
#   3. "phase2-oci-kernel-boot: streamed N bytes; SHA-256 verified OK"
#                                                              — streaming + digest check passed.
#   4. "phase2-oci-kernel-boot: LoadImage OK"                  — firmware parsed PE32+.
#   5. "phase2-oci-kernel-boot: StartImage entering loaded image"
#                                                              — about to jump.
#   6. ">>> M8.0 chained payload -- Hello from <ARCH> <<<"     — loaded image banner.
#   7. "phase2-oci-kernel-boot: KERNEL-BOOT OK"                — full mechanism proven.
# Exit 0 on PASS (all seven matched); 1 otherwise.
#
# Per the brief: the timeout cap is intentionally larger (120s) than
# the M8.0 efihandover runner's 30s — a real Linux EFI-stub on MODE A
# might take 30+ s just to print its banner. MODE B is sub-10s on
# every arch but we leave headroom for MODE A drop-in.
#
# Boot-media plumbing mirrors `liveefihandover/run.sh` 1:1:
#   - arm64    → virtio-blk-pci
#   - riscv64  → virtio-blk-device
#   - loong64  → virtio-blk-pci
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M81_LIVE_TIMEOUT: per-run wall-clock cap (default 120)
#   M81_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M81_LIVE_TIMEOUT:-120}"

case "$ARCH" in
    arm64)
        EFI_NAME="BOOTAA64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        BANNER_ARCH="arm64"
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="riscv64"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="loong64"
        ;;
    *)
        echo "unsupported arch: $ARCH (M8.1 minimal supports arm64/riscv64/loong64; amd64 deferred)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task kernelboot:efi:$ARCH' first" >&2
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

WORK="$(mktemp -d -t cloudboot-m81-live-XXXXXX)"
trap 'if [[ "${M81_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

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
# auto-runs. Same shape as the other live runners.
NSH_PATH="$WORK/startup.nsh"
cat > "$NSH_PATH" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

case "$ARCH" in
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

echo "[live-kernelboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

# The loaded payload is the M8.0 chainedhello PE32+, so its on-entry
# banner uses the same wording the M8.0 live runner checks for.
EXPECT_BANNER=">>> M8.0 chained payload -- Hello from ${BANNER_ARCH} <<<"

PASS=1
grep -q "phase2-oci-kernel-boot: synthetic descriptor digest" "$LOG" || PASS=0
grep -q "phase2-oci-kernel-boot: streaming blob via in-process Transport" "$LOG" || PASS=0
# The streaming-OK line is printed as
#   "phase2-oci-kernel-boot: streamed N bytes; SHA-256 verified OK"
# — match on the digest-verification tail to keep the check tight
# without hard-coding N.
grep -q "phase2-oci-kernel-boot: streamed .*SHA-256 verified OK" "$LOG" || PASS=0
grep -q "phase2-oci-kernel-boot: LoadImage OK" "$LOG" || PASS=0
grep -q "phase2-oci-kernel-boot: StartImage entering loaded image" "$LOG" || PASS=0
grep -qF "$EXPECT_BANNER" "$LOG" || PASS=0
grep -q "phase2-oci-kernel-boot: KERNEL-BOOT OK" "$LOG" || PASS=0

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-kernelboot:$ARCH] PASS — wall=${ELAPSED_MS}ms"
    grep -E "phase2-oci-kernel-boot:|M8\.0 chained payload" "$LOG" || true
    exit 0
fi
echo "[live-kernelboot:$ARCH] FAIL — missing one of 'synthetic descriptor digest' / 'streaming blob via in-process Transport' / 'streamed N bytes; SHA-256 verified OK' / 'LoadImage OK' / 'StartImage entering loaded image' / chained banner / 'KERNEL-BOOT OK' after ${ELAPSED_MS}ms" >&2
echo "[live-kernelboot:$ARCH] tail of qemu log (last 120 lines):" >&2
tail -120 "$LOG" >&2 || true
exit 1
