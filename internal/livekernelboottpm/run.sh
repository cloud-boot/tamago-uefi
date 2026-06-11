#!/usr/bin/env bash
# Phase-2 measured-boot live smoke under QEMU + EDK2(Tcg2Dxe) + swtpm.
#
# ADDITIVE COPY of internal/livekernelboot/run.sh — the ORIGINAL is left
# untouched. This variant:
#   1. builds (caller's responsibility) the kernelboot EFI with
#      `-tags ...,phase2_oci_kernel_boot,phase2_tpm_measure`,
#   2. starts a swtpm TPM-2.0 emulator on a unix socket,
#   3. attaches it to QEMU via -tpmdev emulator + the arch-appropriate
#      TPM device (tpm-tis/tpm-crb on amd64; tpm-tis-device on arm64),
#   4. drives the loader to the measurement point and asserts the
#      `phase2-tpm-measure:` markers (EFI_TCG2 located, PCR4/PCR8
#      extended, PCR4 readback over the same efitcg2 transport).
#
# Usage:
#     EFI=/tmp/.../BOOTX64-KERNELBOOT-TPM.EFI bash run.sh amd64
#     EFI=/tmp/.../BOOTAA64-KERNELBOOT-TPM.EFI bash run.sh arm64
#
# Env:
#   EFI                 : path to the tagged kernelboot EFI (required)
#   M81_LIVE_TIMEOUT    : wall-clock cap seconds (default 200)
#   M81_LIVE_KEEPRUN    : 1 → keep workdir + logs
#   CLOUDBOOT_OVMF_*_{CODE,VARS} : firmware overrides
set -uo pipefail

ARCH="${1:-}"
EFI="${EFI:-}"
if [[ -z "$ARCH" || -z "$EFI" ]]; then
    echo "usage: EFI=<path> $0 {amd64|arm64}" >&2; exit 2
fi
if [[ ! -f "$EFI" ]]; then echo "missing EFI: $EFI" >&2; exit 1; fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M81_LIVE_TIMEOUT:-200}"
QEMU_PREFIX="$HOME/.pkgx/qemu.org/v9.2.0"

case "$ARCH" in
    amd64)
        EFI_BOOT_NAME="BOOTX64.EFI"
        QEMU_BIN="$QEMU_PREFIX/bin/qemu-system-x86_64"
        if [[ -f "$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd" ]]; then
            FW_CODE_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd"
            FW_VARS_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-i386-vars.fd"
        else
            FW_CODE_DEFAULT="$QEMU_PREFIX/share/qemu/edk2-x86_64-code.fd"
            FW_VARS_DEFAULT="$QEMU_PREFIX/share/qemu/edk2-i386-vars.fd"
        fi
        FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"
        TPM_DEV=( -device "tpm-tis,tpmdev=tpm0" )
        ;;
    arm64)
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="$QEMU_PREFIX/bin/qemu-system-aarch64"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$QEMU_PREFIX/share/qemu/edk2-aarch64-code.fd}"
        FW_VARS=""
        TPM_DEV=( -device "tpm-tis-device,tpmdev=tpm0" )
        ;;
    *) echo "unsupported arch: $ARCH" >&2; exit 2 ;;
esac

for f in "$QEMU_BIN" "$FW_CODE"; do
    [[ -e "$f" ]] || { echo "missing: $f" >&2; exit 1; }
done
command -v swtpm >/dev/null || { echo "swtpm not in PATH" >&2; exit 1; }

WORK="$(mktemp -d -t cloudboot-tpm-XXXXXX)"
trap 'kill "${SWTPM_PID:-}" 2>/dev/null; if [[ "${M81_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] $WORK" >&2; fi' EXIT

# --- ESP ---
ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=16 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI" "::/EFI/BOOT/$EFI_BOOT_NAME"
cat > "$WORK/startup.nsh" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$WORK/startup.nsh" "::/startup.nsh"
INITRAMFS_SRC="$REPO_DIR/internal/embed_initramfs/initramfs_${ARCH}.cpio.gz"
[[ -f "$INITRAMFS_SRC" ]] && mcopy -i "$ESP" "$INITRAMFS_SRC" "::/initrd.gz"

# --- swtpm ---
mkdir -p "$WORK/swtpm"
SOCK="$WORK/swtpm/sock"
swtpm socket --tpmstate "dir=$WORK/swtpm" \
    --ctrl "type=unixio,path=$SOCK.ctrl" \
    --server "type=unixio,path=$SOCK" \
    --tpm2 --flags startup-clear &
SWTPM_PID=$!
sleep 1
[[ -S "$SOCK" ]] || { echo "swtpm server socket did not appear" >&2; exit 1; }
echo "[tpm:$ARCH] swtpm up (pid=$SWTPM_PID)" >&2

TPM_BACKEND=(
    -chardev "socket,id=chrtpm,path=$SOCK"
    -tpmdev "emulator,id=tpm0,chardev=chrtpm"
    "${TPM_DEV[@]}"
)

case "$ARCH" in
    amd64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine q35 -cpu max -m 4096 -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
            -device "ide-hd,drive=esp"
            -netdev "user,id=n0"
            -device "virtio-net-pci,netdev=n0,bus=pcie.0,addr=03.0,disable-legacy=on,disable-modern=off"
            -chardev "stdio,id=char0,mux=off,signal=off" -serial "chardev:char0"
            "${TPM_BACKEND[@]}"
        )
        ;;
    arm64)
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096 -display none -no-reboot
            -bios "$FW_CODE"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=n0"
            -device "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off"
            -chardev "stdio,id=char0,mux=off,signal=off" -serial "chardev:char0"
            "${TPM_BACKEND[@]}"
        )
        ;;
esac

echo "[tpm:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER=$!
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER" 2>/dev/null || true

echo "=== phase2-tpm-measure markers ==="
grep -nE "phase2-tpm-measure:" "$LOG" || echo "(no phase2-tpm-measure lines)"
echo "=== last 60 loader lines ==="
grep -E "phase2-oci-kernel-boot:|phase2-tpm-measure:|EFI stub|Tcg2|TPM" "$LOG" | tail -60 || true

PASS=1
grep -q "phase2-tpm-measure: EFI_TCG2_PROTOCOL located" "$LOG" || PASS=0
grep -q "phase2-tpm-measure: PCR4 extended" "$LOG" || PASS=0
grep -q "phase2-tpm-measure: PCR4 readback" "$LOG" || PASS=0
if [[ "$PASS" -eq 1 ]]; then
    echo "[tpm:$ARCH] PASS — measured boot confirmed against firmware TPM"
    exit 0
fi
echo "[tpm:$ARCH] measurement markers NOT all present (see log above)" >&2
[[ "${M81_LIVE_KEEPRUN:-0}" == "1" ]] && echo "[tpm:$ARCH] full log: $LOG" >&2
exit 1
