#!/usr/bin/env bash
# Phase-3 sprint-3 live NetBSD-boot smoke under QEMU+EDK2. amd64-only —
# EFI_BLOCK_IO_PROTOCOL publish-side trampolines validated on amd64
# alone; arm64/riscv64/loong64 ports tracked under sprint 1.3 / 2E.
#
# Sprint 3 architectural scope: prove the same Block IO + SFS publish
# + ConnectController + LoadImage chain reaches NetBSD's amd64 EFI
# bootloader (bootx64.efi). UFS root is OUT of scope for sprint 3 —
# follow-up sprint 3.x (mirrors FreeBSD sprint 2C/2D path).
#
# Pipeline:
#   1. Verify a NetBSD source image is available (cached under
#      $CLOUDBOOT_NETBSD_IMAGE or ~/Downloads/NetBSD-*.iso).
#   2. Extract NetBSD's amd64 bootx64.efi from the source ISO.
#   3. Build a 16 MiB FAT16 ESP-disk holding \EFI\BOOT\BOOTX64.EFI =
#      NetBSD's bootx64.efi, wrapped in PMBR + GPT via buildespimg
#      (reused from livefreebsdboot — shape-identical).
#   4. Push that disk image to ttl.sh anonymously via pushfreebsd.
#      The OCI artifact mediaType is shape-identical to FreeBSD's;
#      we reuse pushfreebsd directly.
#   5. Re-build BOOTX64-NETBSDBOOT.EFI with -X
#      main.netbsdBootTargetRef=<oci-ref>.
#   6. Boot qemu-system-x86_64 with EDK2 firmware + virtio-net.
#      Capture stdout for up to NETBSD_LIVE_TIMEOUT seconds.
#   7. Assert the sprint 3 PASS gate (same shape as sprint-1.1 for FreeBSD):
#        - "phase3-oci-netbsd-boot: lease acquired"
#        - "phase3-oci-netbsd-boot: streamed N bytes; SHA-256 verified OK"
#        - "phase3-oci-netbsd-boot: streamed image header OK"
#        - "phase3-oci-netbsd-boot: PublishBlockIO OK"
#        - "phase3-oci-netbsd-boot: ConnectController OK"
#        - "phase3-oci-netbsd-boot: LocateHandleBuffer(SFS) found"
#        - "phase3-oci-netbsd-boot: matching SFS child handle"
#        - "phase3-oci-netbsd-boot: LoadImage(.*BOOTX64.EFI) OK"
#        - "phase3-oci-netbsd-boot: NETBSD-BOOT CHAIN COMPLETE"
#      Stretch (informational): NetBSD bootx64.efi banner reached.
#
# Environment overrides:
#   CLOUDBOOT_NETBSD_IMAGE:   path to a local NetBSD .iso (default:
#                             $HOME/Downloads/NetBSD-10.0-amd64.iso)
#   CLOUDBOOT_OVMF_AMD64_CODE / _VARS: EDK2 .fd paths.
#   NETBSD_LIVE_TIMEOUT:      per-run wall-clock cap (default 240)
#   NETBSD_LIVE_KEEPRUN:      1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 amd64  (sprint 3 is amd64-only)" >&2
    exit 2
fi
if [[ "$ARCH" != "amd64" ]]; then
    echo "[live-netbsdboot] sprint 3 is amd64-only" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${NETBSD_LIVE_TIMEOUT:-240}"

DEFAULT_IMG_PATHS=(
    "$HOME/Downloads/NetBSD-10.0-amd64.iso"
    "$HOME/Downloads/NetBSD-9.3-amd64.iso"
    "/tmp/netbsd/NetBSD-10.0-amd64.iso"
)
SRC_PATH="${CLOUDBOOT_NETBSD_IMAGE:-}"
if [[ -z "$SRC_PATH" ]]; then
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do
        if [[ -f "$cand" ]]; then SRC_PATH="$cand"; break; fi
    done
fi
if [[ -z "$SRC_PATH" || ! -f "$SRC_PATH" ]]; then
    echo "[live-netbsdboot] no NetBSD image found; set CLOUDBOOT_NETBSD_IMAGE or download to one of:" >&2
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do echo "    $cand" >&2; done
    echo "    e.g. curl -fL -o /tmp/netbsd/NetBSD-10.0-amd64.iso https://cdn.netbsd.org/pub/NetBSD/NetBSD-10.0/images/NetBSD-10.0-amd64.iso" >&2
    exit 1
fi
echo "[live-netbsdboot:$ARCH] NetBSD source image: $SRC_PATH" >&2

WORK_PRE="$(mktemp -d -t cloudboot-netbsd-pre-XXXXXX)"
trap 'rm -rf "$WORK_PRE"' EXIT

# 1) Extract bootx64.efi from the NetBSD source ISO. NetBSD distributes
#    its amd64 EFI loader at /EFI/BOOT/BOOTX64.EFI on the install ISO
#    (UEFI fallback path). xorriso reads it via the path inside the
#    ISO9660 / Joliet volume.
echo "[live-netbsdboot:$ARCH] extracting /EFI/BOOT/BOOTX64.EFI from $SRC_PATH" >&2
if ! xorriso -osirrox on -indev "$SRC_PATH" -extract /EFI/BOOT/BOOTX64.EFI "$WORK_PRE/bootx64.efi" 2>&1 | tail -3 >&2; then
    # Alternative NetBSD path naming on some releases — try lowercase.
    xorriso -osirrox on -indev "$SRC_PATH" -extract /efi/boot/bootx64.efi "$WORK_PRE/bootx64.efi" 2>&1 | tail -3 >&2 || true
fi
if [[ ! -f "$WORK_PRE/bootx64.efi" ]]; then
    echo "[live-netbsdboot] failed to extract bootx64.efi from $SRC_PATH (NetBSD EFI path varies by release — verify with: xorriso -indev $SRC_PATH -find / -name 'bootx64*')" >&2
    exit 1
fi

# 2) Build the 16 MiB FAT16 ESP holding bootx64.efi at the canonical
#    UEFI fallback path. Reuses livefreebsdboot/buildespimg — the GPT
#    + PMBR + FAT16 ESP layout is OS-agnostic.
IMG_PATH="$WORK_PRE/disk.img"
echo "[live-netbsdboot:$ARCH] building 16 MiB FAT16 ESP" >&2
dd if=/dev/zero of="$WORK_PRE/fat.img" bs=1m count=16 status=none
mformat -i "$WORK_PRE/fat.img" :: >&2
mmd -i "$WORK_PRE/fat.img" ::/EFI ::/EFI/BOOT >&2
mcopy -i "$WORK_PRE/fat.img" "$WORK_PRE/bootx64.efi" ::/EFI/BOOT/BOOTX64.EFI >&2

echo "[live-netbsdboot:$ARCH] wrapping FAT in PMBR + GPT via buildespimg (reused from livefreebsdboot)" >&2
(cd "$REPO_DIR/internal/livefreebsdboot/buildespimg" && \
    GOWORK=off go run . -fat "$WORK_PRE/fat.img" -out "$IMG_PATH") >&2
[[ -f "$IMG_PATH" ]] || { echo "[live-netbsdboot] buildespimg failed to produce $IMG_PATH" >&2; exit 1; }
echo "[live-netbsdboot:$ARCH] disk image ready: $IMG_PATH ($(stat -f %z "$IMG_PATH" 2>/dev/null || stat -c %s "$IMG_PATH") bytes)" >&2

# OVMF firmware
EFI_NAME="BOOTX64-NETBSDBOOT.EFI"
EFI_BOOT_NAME="BOOTX64.EFI"
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

WORK="$(mktemp -d -t cloudboot-netbsd-live-XXXXXX)"
trap 'rm -rf "$WORK_PRE"; if [[ "${NETBSD_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# 3) Push image to ttl.sh — pushfreebsd is content-agnostic; the OCI
#    artifact shape (single-layer, mediaType application/vnd.cloud-boot.diskimage.raw.v1)
#    matches what the NetBSD probe expects, so we reuse the helper.
RAND="$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z0-9' | cut -c1-8)"
OCI_REF="ttl.sh/cloudboot-netbsd-${RAND}:24h"
echo "[live-netbsdboot:$ARCH] publishing $IMG_PATH to $OCI_REF" >&2
(cd "$REPO_DIR/internal/livefreebsdboot/pushfreebsd" && \
    GOWORK=off go run . -src "$IMG_PATH" -dst "$OCI_REF") >&2

# 4) Re-build the probe EFI with the OCI ref baked in.
echo "[live-netbsdboot:$ARCH] re-building $EFI_NAME with netbsdBootTargetRef=$OCI_REF" >&2
TAMAGO="${TAMAGO:-$REPO_DIR/../../../localhost/tamago-pie}"
GOWORK=off GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64 CGO_ENABLED=0 \
    "$TAMAGO/bin/go" build \
    -tags linkcpuinit,linkramstart,phase2_pcienum,phase2_snpenum,phase2_blkprintk,phase3_oci_netbsd_boot \
    -trimpath -buildmode=pie \
    -ldflags "-E cpuinit -X main.netbsdBootTargetRef=$OCI_REF" \
    -o "$WORK/app_amd64_netbsdboot.elf" "$REPO_DIR"
(cd "$REPO_DIR/../../go-coff/pectl" && \
    GOWORK=off go run . link-pie -o "$REPO_DIR/$EFI_NAME" "$WORK/app_amd64_netbsdboot.elf") >&2

# 5) ESP image with our probe
ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=16 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$REPO_DIR/$EFI_NAME" "::/EFI/BOOT/$EFI_BOOT_NAME"
cat > "$WORK/startup.nsh" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$WORK/startup.nsh" "::/startup.nsh"

# 6) Boot QEMU
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

echo "[live-netbsdboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

# 7) Verify gates
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

check_gate "phase3-oci-netbsd-boot: lease acquired"                          "lease acquired"
check_gate "phase3-oci-netbsd-boot: streamed .*SHA-256 verified OK"          "image streamed + verified"
check_gate "phase3-oci-netbsd-boot: streamed image header OK"                "image header OK"
check_gate "phase3-oci-netbsd-boot: PublishBlockIO OK"                       "PublishBlockIO"
check_gate "phase3-oci-netbsd-boot: ConnectController OK"                    "ConnectController"
check_gate "phase3-oci-netbsd-boot: LocateHandleBuffer(SFS) found"           "SFS surfaced"
check_gate "phase3-oci-netbsd-boot: matching SFS child handle"               "SFS-parent filter"
check_gate "phase3-oci-netbsd-boot: LoadImage.*EFI.*BOOT.*BOOTX64.EFI.* OK"  "LoadImage(bootx64.efi)"
check_gate "phase3-oci-netbsd-boot: NETBSD-BOOT CHAIN COMPLETE"              "chain complete"

# Stretch (informational): NetBSD bootx64.efi banner. NetBSD's loader
# prints "NetBSD/x86 efiboot" or similar.
if grep -qE "NetBSD/x86 efiboot|NetBSD efiboot|>> NetBSD" "$LOG"; then
    echo "[live-netbsdboot:$ARCH] BONUS: NetBSD efiboot banner reached" >&2
fi

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-netbsdboot:$ARCH] PASS — wall=${ELAPSED_MS}ms, ref=$OCI_REF"
    grep -E "phase3-oci-netbsd-boot:" "$LOG" || true
    exit 0
fi

echo "[live-netbsdboot:$ARCH] FAIL — missing gate(s): ${MISSING[*]} after ${ELAPSED_MS}ms" >&2
echo "[live-netbsdboot:$ARCH] tail of log:" >&2
tail -50 "$LOG" >&2 || true
exit 1
