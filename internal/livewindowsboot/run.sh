#!/usr/bin/env bash
# Phase-3 sprint-4 live Windows-boot smoke under QEMU+EDK2 — SCAFFOLDING
# ONLY. This runner is wired the same way the FreeBSD runner is, but
# every "live" stage past the EFI build is gated behind a
# CLOUDBOOT_WINDOWS_LIVE=1 environment variable because the chain CANNOT
# complete end-to-end this sprint:
#
#   - go-filesystems/ntfs is the synthetic NTFSIMG1 format (per its
#     ntfs_compat_test.go: real-NTFS images are explicitly rejected,
#     ntfsfix rejects this driver's output). So an NTFS rootfs cannot
#     be exposed to bootmgfw.efi via PublishSFS yet.
#   - OVMF stable202605 ships NO NTFS DXE driver. PartitionDxe will
#     discover the Windows NTFS partitions but cannot mount them; the
#     SFS-discovery step finds the ESP child only.
#   - bootmgfw.efi without a BCD = "BCD store could not be opened"
#     (Windows error 0xc0000034) within seconds of LoadImage.
#
# What this script CAN do today (default mode):
#
#   1. Validate the BOOTX64-WINDOWSBOOT.EFI builds under the sprint-4
#      tag and prints the documented gap status when invoked in QEMU
#      under a stub ESP (no Windows disk image).
#   2. Be a known-good runner harness for sprint 4.1+ to plug into when
#      a real NTFS path lands.
#
# Set CLOUDBOOT_WINDOWS_LIVE=1 AND CLOUDBOOT_WINDOWS_IMAGE=<path-to-iso>
# to attempt the real live path. The runner will still likely fail at
# the NTFS step — that is the precise sprint-4-to-4.1 gap and the
# failure mode is exactly what the gap-status section is documenting.
#
# Usage:
#
#       bash internal/livewindowsboot/run.sh amd64
#
# Pipeline (default, scaffolding gate):
#
#   1. Verify BOOTX64-WINDOWSBOOT.EFI exists in the repo (built via
#      `task windowsboot:efi:amd64`).
#   2. Build a stub ESP carrying just BOOTX64-WINDOWSBOOT.EFI.
#   3. Boot qemu-system-x86_64 + OVMF, no disk image attached.
#   4. Capture serial; assert the sprint-4 gates:
#        - "phase3-oci-windows-boot: Sprint 4 SCAFFOLDING"
#        - "phase3-oci-windows-boot: NTFS rootfs driver: GAP"
#        - "phase3-oci-windows-boot: BCD store: GAP"
#        - "phase3-oci-windows-boot: WINDOWS-BOOT SCAFFOLDING COMPLETE"
#
# Environment overrides:
#
#   CLOUDBOOT_WINDOWS_LIVE:   default 0; set 1 to try the live OCI
#                             stream + BlockIO publish + LoadImage chain
#                             (will fail at NTFS — that is expected).
#   CLOUDBOOT_WINDOWS_IMAGE:  path to a Windows install or LTSC IoT 2021
#                             ESP/install image (only consulted when
#                             CLOUDBOOT_WINDOWS_LIVE=1).
#   CLOUDBOOT_OVMF_AMD64_CODE / _VARS: EDK2 .fd paths (same as
#                             freebsdboot:live:amd64).
#   WINDOWS_LIVE_TIMEOUT:     per-run wall-clock cap (default 60s —
#                             scaffolding mode exits in <5s).
#   WINDOWS_LIVE_KEEPRUN:     1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 amd64  (sprint 4 is amd64-only)" >&2
    exit 2
fi
if [[ "$ARCH" != "amd64" ]]; then
    echo "[live-windowsboot] sprint 4 is amd64-only; arm64/riscv64/loong64 deferred (no Windows-on-arm scaffolding yet)" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${WINDOWS_LIVE_TIMEOUT:-60}"
LIVE_MODE="${CLOUDBOOT_WINDOWS_LIVE:-0}"

EFI_NAME="BOOTX64-WINDOWSBOOT.EFI"
EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "[live-windowsboot:$ARCH] missing $EFI_PATH — run 'task windowsboot:efi:amd64' first" >&2
    exit 1
fi

# OVMF firmware (same selection logic as the FreeBSD runner)
QEMU_BIN="qemu-system-x86_64"
if [[ -f "$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd" ]]; then
    FW_CODE_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-i386-vars.fd"
else
    FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
fi
FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"
[[ -f "$FW_CODE" ]] || { echo "missing OVMF at $FW_CODE (set CLOUDBOOT_OVMF_AMD64_CODE)" >&2; exit 1; }
[[ -f "$FW_VARS" ]] || { echo "missing OVMF vars at $FW_VARS (set CLOUDBOOT_OVMF_AMD64_VARS)" >&2; exit 1; }

WORK="$(mktemp -d -t cloudboot-windows-live-XXXXXX)"
trap 'if [[ "${WINDOWS_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Stub ESP carrying just the probe EFI.
ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=16 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" ::/EFI/BOOT/BOOTX64.EFI
cat > "$WORK/startup.nsh" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\BOOTX64.EFI
EOF
mcopy -i "$ESP" "$WORK/startup.nsh" "::/startup.nsh"

cp "$FW_VARS" "$WORK/vars.fd"
QEMU_ARGS=(
    -machine q35 -cpu max -m 4096
    -display none -no-reboot
    -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
    -drive "if=pflash,format=raw,file=$WORK/vars.fd"
    -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
    -device "ide-hd,drive=esp"
    -netdev "user,id=n0"
    -device "virtio-net-pci,netdev=n0,bus=pcie.0,addr=03.0,disable-legacy=on,disable-modern=off"
    -chardev "stdio,id=char0,mux=off,signal=off"
    -serial "chardev:char0"
)

if [[ "$LIVE_MODE" == "1" ]]; then
    echo "[live-windowsboot:$ARCH] LIVE MODE — attempting full chain (expected NTFS failure)" >&2
    if [[ -z "${CLOUDBOOT_WINDOWS_IMAGE:-}" || ! -f "${CLOUDBOOT_WINDOWS_IMAGE:-}" ]]; then
        echo "[live-windowsboot:$ARCH] CLOUDBOOT_WINDOWS_LIVE=1 but CLOUDBOOT_WINDOWS_IMAGE is unset or missing" >&2
        exit 1
    fi
    # sprint 4.1: implement OCI push + relink with -X
    # main.windowsBootTargetRef=<ref>. For now the live mode just
    # boots the scaffolding EFI on a real-disk-image-attached QEMU so
    # operators can see how far the chain gets manually.
    QEMU_ARGS+=( -drive "file=${CLOUDBOOT_WINDOWS_IMAGE},format=raw,if=none,id=winimg,media=disk" )
    QEMU_ARGS+=( -device "ide-hd,drive=winimg" )
fi

echo "[live-windowsboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

# Verify gates — sprint 4 scaffolding only.
PASS=1
MISSING=()
check_gate() {
    local pattern="$1"
    local name="$2"
    if ! grep -q "$pattern" "$LOG"; then
        PASS=0
        MISSING+=("$name")
    fi
}

check_gate "phase3-oci-windows-boot: Sprint 4 SCAFFOLDING"                    "scaffolding banner"
check_gate "phase3-oci-windows-boot: NTFS rootfs driver: GAP"                 "NTFS gap documented"
check_gate "phase3-oci-windows-boot: BCD store: GAP"                          "BCD gap documented"
check_gate "phase3-oci-windows-boot: Secure Boot: GAP"                        "Secure Boot gap documented"
check_gate "phase3-oci-windows-boot: WINDOWS-BOOT SCAFFOLDING COMPLETE"       "scaffolding complete"

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-windowsboot:$ARCH] PASS (sprint 4 scaffolding) — wall=${ELAPSED_MS}ms"
    grep -E "phase3-oci-windows-boot:" "$LOG" || true
    exit 0
fi

echo "[live-windowsboot:$ARCH] FAIL — missing gate(s): ${MISSING[*]} after ${ELAPSED_MS}ms" >&2
echo "[live-windowsboot:$ARCH] tail of log:" >&2
tail -50 "$LOG" >&2 || true
exit 1
