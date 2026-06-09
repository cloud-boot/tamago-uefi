#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026, cloud-boot contributors.
#
# Phase-2 VZ (Apple Virtualization.framework via vfkit) compatibility
# smoke runner. arm64-only — VZ is Apple-Silicon arm64-only.
#
#     bash internal/live_vz/run.sh <binary>
#
# Where <binary> is one of:
#     probe       — M0 GetMemoryMap         (BOOTAA64-PROBE.EFI)
#     pcienum     — M1 PCI walk             (BOOTAA64-PCIENUM.EFI)
#     pcisnp      — M1.5 SNP walk           (BOOTAA64-PCISNP.EFI)
#     blkprint    — M1.6 Block-IO probe     (BOOTAA64-BLKPRINT.EFI)
#     efihandover — M8.0 chain-boot         (BOOTAA64-EFIHANDOVER.EFI)
#     kernelboot  — M8.1 MODE B self-test   (BOOTAA64-KERNELBOOT.EFI)
#     efipackstub — M6.2 PR2 self-extract   (BOOTAA64-EFIPACKSTUB.EFI)
#
# Why this runner exists vs the QEMU+EDK2 runners
# ===============================================
#
# vfkit's Apple-bundled EFI firmware writes ConOut to the graphical
# framebuffer ONLY — there is no PL011/UART or "serial" backend that
# is wired through to virtio-serial. Concretely:
#
#   - `--device virtio-serial,logFilePath=…` produces a 0-byte log
#     during the entire firmware stage (verified 2026-06-09 with
#     BOOTAA64-PROBE.EFI). The virtio-serial endpoint is for guest
#     userland (`/dev/hvc0`), and Apple's EFI driver stack does not
#     bind ConOut to it.
#   - Every Phase-2 probe ends with `for {}` (spin) instead of a
#     `gBS->Exit` call (see main.go line 53), so clean exit cannot
#     be used as a PASS signal either.
#
# What we CAN observe headlessly is the inverse: when the firmware
# cannot find anything to boot, or when the loaded EFI panics during
# initialisation, Apple VZ stops the VM with
#     "VM is stopped"
# in vfkit's stderr after ~1 second. A binary that runs successfully
# stays in its `for {}` spin until the watchdog fires.
#
# So the observable signals are:
#
#     PASS_HEADLESS — VM still running when watchdog fires
#                     (firmware loaded the EFI, no crash before spin)
#     FAIL          — "VM is stopped" appears in stderr BEFORE the
#                     watchdog deadline (firmware refused to boot, or
#                     loaded EFI panicked).
#
# For positive verification of probe OUTPUT (e.g. "phase2-probe:
# done"), run with VZ_LIVE_GUI=1 and visually confirm the framebuffer
# console; see the §VZ-Observability-Gap finding in
# cloud-boot/docs/vz-compatibility-audit.md.
#
# Environment overrides:
#
#     VZ_LIVE_TIMEOUT   per-run wall-clock cap (default 25s)
#     VZ_LIVE_KEEPRUN   1 → keep ESP + vfkit logs in /tmp
#     VZ_LIVE_GUI       1 → pass --gui to vfkit (for manual visual
#                       verification of framebuffer ConOut output)
#     VZ_LIVE_MEMORY    guest RAM in MiB (default 4096; smaller helps
#                       smoke the R-M8.3a 128 MiB heap-bump under low
#                       RAM)
set -euo pipefail

BINARY="${1:-}"
if [[ -z "$BINARY" ]]; then
    echo "usage: $0 {probe|pcienum|pcisnp|blkprint|efihandover|kernelboot|efipackstub}" >&2
    exit 2
fi

# VZ is Apple-Silicon arm64-only.
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "[live_vz:$BINARY] SKIP — host is not Apple Silicon Darwin (need arm64 macOS for VZ)" >&2
    exit 0
fi

if ! command -v vfkit >/dev/null 2>&1; then
    echo "[live_vz:$BINARY] SKIP — vfkit not installed (brew install vfkit)" >&2
    exit 0
fi

for tool in mformat mcopy mmd dd; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "[live_vz:$BINARY] SKIP — missing $tool (brew install mtools dosfstools)" >&2
        exit 0
    }
done

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${VZ_LIVE_TIMEOUT:-25}"
MEMORY_MIB="${VZ_LIVE_MEMORY:-4096}"

case "$BINARY" in
    probe)        EFI_NAME="BOOTAA64-PROBE.EFI"       ; PACKED=0 ;;
    pcienum)      EFI_NAME="BOOTAA64-PCIENUM.EFI"     ; PACKED=0 ;;
    pcisnp)       EFI_NAME="BOOTAA64-PCISNP.EFI"      ; PACKED=0 ;;
    blkprint)     EFI_NAME="BOOTAA64-BLKPRINT.EFI"    ; PACKED=0 ;;
    efihandover)  EFI_NAME="BOOTAA64-EFIHANDOVER.EFI" ; PACKED=0 ;;
    kernelboot)   EFI_NAME="BOOTAA64-KERNELBOOT.EFI"  ; PACKED=0 ;;
    # `efipackstub` is the bare stub WITHOUT a payload — useful only to
    # test whether VZ firmware accepts the modified PE layout from
    # peln/appender.AppendBefore. It is NOT expected to "boot" because
    # it has no `.payload` to extract; behaviour should be a clean
    # gBS->Exit when the CBP0-magic check fails.
    efipackstub)  EFI_NAME="BOOTAA64-EFIPACKSTUB.EFI" ; PACKED=0 ;;
    # `efipack_probe` is the M6.2 PR2 end-to-end test: pack PROBE.EFI
    # via `pectl pack` and boot the resulting self-extracting EFI
    # under VZ. This is the test the brief actually asks for.
    efipack_probe)
        EFI_NAME="BOOTAA64-EFIPACK-PROBE.EFI"
        PACKED=1
        PACK_SRC_EFI="BOOTAA64-PROBE.EFI"
        PACK_STUB="BOOTAA64-EFIPACKSTUB.EFI"
        ;;
    *)
        echo "unsupported binary: $BINARY" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"

if [[ "$PACKED" == "1" ]]; then
    PACK_SRC_PATH="$REPO_DIR/$PACK_SRC_EFI"
    PACK_STUB_PATH="$REPO_DIR/$PACK_STUB"
    [[ -f "$PACK_SRC_PATH" ]] || { echo "[live_vz:$BINARY] missing $PACK_SRC_PATH; build $PACK_SRC_EFI first" >&2; exit 1; }
    [[ -f "$PACK_STUB_PATH" ]] || { echo "[live_vz:$BINARY] missing $PACK_STUB_PATH; build it first" >&2; exit 1; }
    PECTL_DIR="${PECTL_DIR:-$REPO_DIR/../../go-coff/pectl}"
    [[ -d "$PECTL_DIR" ]] || { echo "[live_vz:$BINARY] missing pectl at $PECTL_DIR (set PECTL_DIR)" >&2; exit 1; }
    EFIPACK_DIR="${EFIPACK_DIR:-$REPO_DIR/../../go-coff/efipack}"
    [[ -d "$EFIPACK_DIR" ]] || { echo "[live_vz:$BINARY] missing efipack at $EFIPACK_DIR (set EFIPACK_DIR)" >&2; exit 1; }
    # Stage the stub blob the packer expects, then invoke `pectl pack`.
    mkdir -p "$EFIPACK_DIR/stub/blobs"
    cp "$PACK_STUB_PATH" "$EFIPACK_DIR/stub/blobs/arm64.efi.bin"
    EFI_PATH="$(mktemp -t vz-pack-XXXXXX).efi"
    echo "[live_vz:$BINARY] packing $PACK_SRC_EFI via pectl pack" >&2
    ( cd "$PECTL_DIR" && go run . pack -o "$EFI_PATH" "$PACK_SRC_PATH" ) || {
        echo "[live_vz:$BINARY] FAIL — pectl pack failed for $PACK_SRC_EFI" >&2
        exit 1
    }
fi

if [[ ! -f "$EFI_PATH" ]]; then
    echo "[live_vz:$BINARY] missing $EFI_PATH; build it first (see Taskfile)" >&2
    exit 1
fi

WORK="$(mktemp -d -t cloudboot-vz-XXXXXX)"
trap 'if [[ "${VZ_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\BOOTAA64.EFI. The arm64
# VZ firmware honours the EFI removable-media boot path the same way
# QEMU+EDK2 does. Same shape as liveefihandover/run.sh.
ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=16 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/BOOTAA64.EFI"

LOG="$WORK/serial.log"
STDERR_LOG="$WORK/vfkit.stderr"
STDOUT_LOG="$WORK/vfkit.stdout"

VFKIT_ARGS=(
    --memory "$MEMORY_MIB"
    --cpus 2
    --bootloader "efi,variable-store=$WORK/vars.fd,create"
    --device "virtio-blk,path=$ESP"
    --device "virtio-serial,logFilePath=$LOG"
)
if [[ "${VZ_LIVE_GUI:-0}" == "1" ]]; then
    VFKIT_ARGS+=(--gui)
fi

echo "[live_vz:$BINARY] launching vfkit (timeout ${TIMEOUT_SECONDS}s, mem ${MEMORY_MIB}MiB)" >&2
START_NS="$(date +%s%N)"
# Suppress the shell's "Killed: 9" line that prints when our watchdog
# SIGKILLs a still-running vfkit (the expected PASS path: our binary
# is spinning in for{} so vfkit never exits on its own).
{
    vfkit "${VFKIT_ARGS[@]}" >"$STDOUT_LOG" 2>"$STDERR_LOG" &
    VPID=$!
    ( sleep "$TIMEOUT_SECONDS" && kill -TERM "$VPID" 2>/dev/null && sleep 1 && kill -KILL "$VPID" 2>/dev/null ) &
    KPID=$!
    while kill -0 "$VPID" 2>/dev/null; do sleep 1; done
    kill "$KPID" 2>/dev/null || true
    wait "$VPID" 2>/dev/null || true
} 2>/dev/null
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
ELAPSED_S=$(( ELAPSED_MS / 1000 ))

# Decision logic.
#
# Apple VZ stops the guest within ~1s if the firmware can't find a
# bootable medium OR if our loaded image crashes during initialisation.
# If our binary entered its `for {}` spin, the VM will still be running
# at watchdog time → ELAPSED_S >= TIMEOUT_SECONDS - 2.
EARLY_STOP=0
if [[ "$ELAPSED_S" -lt $(( TIMEOUT_SECONDS - 3 )) ]]; then
    EARLY_STOP=1
fi
HAS_VM_STOPPED=0
if grep -q "VM is stopped" "$STDERR_LOG" 2>/dev/null; then
    HAS_VM_STOPPED=1
fi

# Note the optional serial log content (will be 0 bytes on current
# vfkit/VZ — see header). When VZ_LIVE_GUI=1 was set, the user is
# expected to have eyeballed the framebuffer.
SERIAL_BYTES=$(wc -c < "$LOG" 2>/dev/null | tr -d ' ' || echo 0)

if [[ "$EARLY_STOP" -eq 1 && "$HAS_VM_STOPPED" -eq 1 ]]; then
    echo "[live_vz:$BINARY] FAIL — VM stopped early (${ELAPSED_MS}ms < watchdog ${TIMEOUT_SECONDS}s); firmware refused boot or loaded EFI panicked"
    echo "[live_vz:$BINARY] vfkit stderr tail:"
    tail -30 "$STDERR_LOG" >&2 || true
    exit 1
fi

# PASS_HEADLESS = ran the full window without an early stop.
if [[ "${VZ_LIVE_GUI:-0}" == "1" ]]; then
    echo "[live_vz:$BINARY] PASS_GUI — ran ${ELAPSED_MS}ms (verify probe output visually in vfkit window)"
else
    echo "[live_vz:$BINARY] PASS_HEADLESS — ran ${ELAPSED_MS}ms without early stop (firmware loaded EFI; loaded image entered spin; serial=${SERIAL_BYTES}B — see header §observability gap)"
fi
exit 0
