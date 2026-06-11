#!/usr/bin/env bash
# Phase-3 DOOM bare-metal demo live smoke under QEMU+EDK2.
#
#     bash internal/livedoomboot/run.sh amd64
#
# Builds a tiny FAT ESP-disk containing the BOOTX64-DOOMBOOT.EFI under
# \EFI\BOOT\BOOTX64.EFI, launches qemu-system-x86_64 with EDK2 OVMF +
# virtio-gpu-pci + virtio-sound-pci + virtio-keyboard-pci, captures
# stdout for up to 60 s, and asserts that the godoom engine's main loop
# ran by matching on one of the canonical engine prints:
#
#   - "phase3-oci-doom-boot: handing off to gore.Run"
#   - "Z_Init: Init zone memory allocation daemon"
#   - "DOOM Shareware Startup"
#   - "D_DoomLoop"
#   - "V_Init: allocate screens"
#
# Honest failure expectations (documented in
# phase3_oci_doom_boot.go header):
#
#   - virtio-gpu may not auto-bind under EDK2 OVMF until ExitBootServices
#     hands control over; the probe prints "OpenVirtioGPU FAILED:" and
#     continues, so the engine still runs (headless / mute / no input
#     as needed).
#
#   - TamaGo GC pauses may stutter the 35 Hz tic; the runner only
#     measures "main loop ran at all," not frame-rate fidelity.
#
#   - Heap budget at 320 MiB (Sprint 2E bump): 28 MiB WAD + 32 MiB
#     working set + virtio rings + Go runtime ≈ 96 MiB high-water; we
#     should fit comfortably.
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_AMD64_CODE / _VARS: EDK2 .fd paths
#   DOOMBOOT_LIVE_TIMEOUT: per-run wall-clock cap (default 60s)
#   DOOMBOOT_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
#
# Exit 0 on PASS (engine main loop ran), 1 otherwise.

set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 amd64" >&2
    exit 2
fi
if [[ "$ARCH" != "amd64" ]]; then
    echo "doomboot live: only amd64 is wired in the first demo (other arches follow-up)" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${DOOMBOOT_LIVE_TIMEOUT:-60}"

EFI_NAME="BOOTX64-DOOMBOOT.EFI"
EFI_BOOT_NAME="BOOTX64.EFI"
QEMU_BIN="qemu-system-x86_64"

# Prefer the patched OVMF (edk2-stable202605, carries the three M6.2
# amd64 #GP fixes — see docs/m6-2-edk2-upstream-investigation.md);
# fall back to pkgx-bundled blob if the patched build is not installed.
if [[ -f "$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd" ]]; then
    FW_CODE_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-i386-vars.fd"
else
    FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
fi
FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task doomboot:efi:amd64' first" >&2
    exit 1
fi
if [[ ! -f "$FW_CODE" ]]; then
    echo "missing EDK2 firmware code at $FW_CODE (set CLOUDBOOT_OVMF_AMD64_CODE)" >&2
    exit 1
fi
if [[ -n "$FW_VARS" && ! -f "$FW_VARS" ]]; then
    echo "missing EDK2 firmware vars at $FW_VARS (set CLOUDBOOT_OVMF_AMD64_VARS)" >&2
    exit 1
fi

WORK="$(mktemp -d -t cloudboot-doomboot-live-XXXXXX)"
trap 'if [[ "${DOOMBOOT_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 64-MiB FAT ESP-disk with \EFI\BOOT\BOOTX64.EFI. The EFI
# itself is ~50 MiB (engine + WAD + runtime) so we cannot use the
# 16 MiB minimum the other live runners use.
ESP="$WORK/esp.img"
ESP_SIZE_MB=128
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

cp "$FW_VARS" "$WORK/vars.fd"

# Two pflash drives (code RO + vars RW). virtio-gpu-pci for the DOOM
# framebuffer, virtio-sound-pci for SFX, virtio-keyboard-pci for player
# input. `-display none` keeps the run headless on CI; -vnc :0 (commented)
# is the interactive alternative for an operator who wants to actually
# play the demo.
QEMU_ARGS=(
    -machine q35 -cpu max -m 2048
    -display none -no-reboot
    -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
    -drive "if=pflash,format=raw,file=$WORK/vars.fd"
    -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
    -device "ide-hd,drive=esp"
    -device "virtio-gpu-pci"
    -device "virtio-sound-pci,audiodev=snd0"
    -audiodev "none,id=snd0"
    -device "virtio-keyboard-pci"
    -serial stdio
)

echo "[live-doomboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

# Engine-startup banners we recognise as "main loop actually ran." Any
# match → PASS. Ordered most-canonical-first.
PASS_PATTERNS=(
    "handing off to gore.Run"
    "Z_Init: Init zone memory"
    "DOOM Shareware Startup"
    "DOOM Registered Startup"
    "DOOM 2: Hell on Earth"
    "Final DOOM"
    "D_DoomLoop"
    "V_Init: allocate screens"
    "M_LoadDefaults"
    "P_Init: Init Playloop state"
)

for pat in "${PASS_PATTERNS[@]}"; do
    if grep -q "$pat" "$LOG"; then
        echo "[live-doomboot:$ARCH] PASS — matched \"$pat\" — wall=${ELAPSED_MS}ms"
        exit 0
    fi
done

echo "[live-doomboot:$ARCH] FAIL — no engine-startup banner in stdout after ${ELAPSED_MS}ms" >&2
echo "[live-doomboot:$ARCH] tail of qemu log (last 80 lines):" >&2
tail -80 "$LOG" >&2 || true
exit 1
