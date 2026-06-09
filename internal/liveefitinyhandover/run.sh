#!/usr/bin/env bash
# Phase-2 M6.2 de-risk: live chained LoadImage+StartImage threshold
# sweep under QEMU+EDK2 (edk2-stable202408 in pkgx qemu 9.2.0).
# amd64 ONLY — M6.2 targets the EDK2 OVMF CpuPageTableLib bug that
# fires #GP at CpuDxe.dll +0x110C on PE32+ over some size threshold.
#
#     bash internal/liveefitinyhandover/run.sh amd64
#
# Builds a tiny FAT ESP-disk with BOOTX64-EFITINY.EFI at
# \EFI\BOOT\BOOTX64.EFI, runs qemu-system-x86_64 with EDK2 firmware,
# captures stdout for up to 60 s (variant C never returns from its
# StartImage so we MUST let the runner reach its hard cap to harvest
# the per-variant PASS/FAIL lines printed before it).
#
# The dummy virtio-net device is required on amd64 q35 even though
# M6.2 has no networking probe (same workaround as M8.0 — see
# liveefihandover/run.sh comment).
#
# Output: the script prints a one-line summary per variant + the full
# M6.2-tagged log slice + a HIT line if the CpuDxe.dll #GP block
# appears. Exits 0 if it could capture per-variant lines for every
# variant (even FAILs) — for this de-risk experiment we WANT the
# fail signal, not a green light.
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_AMD64_{CODE,VARS}: EDK2 .fd paths
#   M62_LIVE_TIMEOUT: per-run wall-clock cap (default 60 — needs to
#                     exceed the parent's wait for variant C, which
#                     spins forever in the TamaGo halt loop on the
#                     child side)
#   M62_LIVE_KEEPRUN: 1 → keep ESP + qemu log in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ "$ARCH" != "amd64" ]]; then
    echo "usage: $0 amd64   (M6.2 is amd64-only)" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M62_LIVE_TIMEOUT:-60}"

EFI_NAME="BOOTX64-EFITINY.EFI"
EFI_BOOT_NAME="BOOTX64.EFI"
QEMU_BIN="qemu-system-x86_64"
FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task efitiny:efi:amd64' first" >&2
    exit 1
fi
if [[ ! -f "$FW_CODE" ]]; then
    echo "missing EDK2 firmware code at $FW_CODE (set CLOUDBOOT_OVMF_AMD64_CODE)" >&2
    exit 1
fi
if [[ ! -f "$FW_VARS" ]]; then
    echo "missing EDK2 firmware vars at $FW_VARS (set CLOUDBOOT_OVMF_AMD64_VARS)" >&2
    exit 1
fi

WORK="$(mktemp -d -t cloudboot-m62-live-XXXXXX)"
trap 'if [[ "${M62_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\BOOTX64.EFI.
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
mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

cp "$FW_VARS" "$WORK/vars.fd"
# Dummy virtio-net device — same workaround as M8.0 / M5 / M6 / M7
# amd64 runners (without ANY -netdev backed PCI device EDK2's BDS
# skips the ESP entirely on q35 and falls through to PXE).
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

echo "[live-efitiny:amd64] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

echo "[live-efitiny:amd64] wall=${ELAPSED_MS}ms" >&2
echo "============= M6.2 PROBE LINES ============="
grep -E "phase2-efi-tiny-handover:" "$LOG" || echo "(no M6.2 probe lines found — parent likely never reached the sweep)"
echo "============= CPUDXE #GP DETECTION ============="
if grep -q "X64 Exception Type" "$LOG"; then
    grep -E "X64 Exception Type|CpuDxe.dll|RIP  - |!!!! Find image" "$LOG" || true
    echo "[live-efitiny:amd64] CpuDxe #GP block present in log"
else
    echo "[live-efitiny:amd64] no CpuDxe #GP block detected"
fi
echo "============= TAIL OF QEMU LOG (last 80 lines) ============="
tail -80 "$LOG" || true

# Always exit 0 — for the M6.2 de-risk experiment we care about the
# captured signals, not a green/red gate. The caller (Taskfile) just
# needs to see the lines.
exit 0
