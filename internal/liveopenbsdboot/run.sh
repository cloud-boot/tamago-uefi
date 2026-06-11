#!/usr/bin/env bash
# Phase-3 sprint-3 live OpenBSD-boot smoke under QEMU+EDK2. amd64-only.
#
# Sprint 3 architectural scope: prove the same Block IO + SFS publish
# + ConnectController + LoadImage chain reaches OpenBSD's amd64 EFI
# bootloader (BOOTX64.EFI). UFS root is OUT of scope (sprint 3.x).
#
# Pipeline:
#   1. Verify an OpenBSD source image is available (cached under
#      $CLOUDBOOT_OPENBSD_IMAGE or ~/Downloads/install*.iso /
#      ~/Downloads/installXX.img).
#   2. Extract OpenBSD's BOOTX64.EFI from the install ISO (lives at
#      /efi/boot/bootx64.efi). For .img miniroots the path is the
#      same on the embedded MS-DOS ESP partition (mtools-mounted).
#   3. Build a 16 MiB FAT16 ESP-disk holding \EFI\BOOT\BOOTX64.EFI =
#      OpenBSD's BOOTX64.EFI, wrapped in PMBR + GPT via the shared
#      livefreebsdboot/buildespimg helper.
#   4. Push that disk image to ttl.sh via pushfreebsd (content-agnostic).
#   5. Re-build BOOTX64-OPENBSDBOOT.EFI with -X
#      main.openbsdBootTargetRef=<oci-ref>.
#   6. Boot qemu-system-x86_64 with EDK2 firmware + virtio-net.
#   7. Assert the sprint 3 PASS gate.
#      Stretch: OpenBSD boot> prompt or efiboot banner reached.
#
# Environment overrides:
#   CLOUDBOOT_OPENBSD_IMAGE:   path to a local OpenBSD .iso or .img
#                              (default search paths below)
#   CLOUDBOOT_OVMF_AMD64_CODE / _VARS: EDK2 .fd paths.
#   OPENBSD_LIVE_TIMEOUT:      per-run wall-clock cap (default 240)
#   OPENBSD_LIVE_KEEPRUN:      1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 amd64  (sprint 3 is amd64-only)" >&2
    exit 2
fi
if [[ "$ARCH" != "amd64" ]]; then
    echo "[live-openbsdboot] sprint 3 is amd64-only" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${OPENBSD_LIVE_TIMEOUT:-240}"

DEFAULT_IMG_PATHS=(
    "$HOME/Downloads/install76.iso"
    "$HOME/Downloads/install75.iso"
    "$HOME/Downloads/install74.iso"
    "$HOME/Downloads/install76.img"
    "$HOME/Downloads/install75.img"
    "/tmp/openbsd/install76.iso"
)
SRC_PATH="${CLOUDBOOT_OPENBSD_IMAGE:-}"
if [[ -z "$SRC_PATH" ]]; then
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do
        if [[ -f "$cand" ]]; then SRC_PATH="$cand"; break; fi
    done
fi
if [[ -z "$SRC_PATH" || ! -f "$SRC_PATH" ]]; then
    echo "[live-openbsdboot] no OpenBSD image found; set CLOUDBOOT_OPENBSD_IMAGE or download to one of:" >&2
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do echo "    $cand" >&2; done
    echo "    e.g. curl -fL -o /tmp/openbsd/install76.iso https://cdn.openbsd.org/pub/OpenBSD/7.6/amd64/install76.iso" >&2
    exit 1
fi
echo "[live-openbsdboot:$ARCH] OpenBSD source image: $SRC_PATH" >&2

WORK_PRE="$(mktemp -d -t cloudboot-openbsd-pre-XXXXXX)"
trap 'rm -rf "$WORK_PRE"' EXIT

# 1) Extract bootx64.efi from the OpenBSD source. OpenBSD lays it at
#    /efi/boot/bootx64.efi (lowercase) on the install ISO's ISO9660
#    volume. For .img miniroots the file sits inside the ESP partition
#    of the partitioned image; mtools can read it directly given the
#    raw image is dd-mountable.
echo "[live-openbsdboot:$ARCH] extracting bootx64.efi from $SRC_PATH" >&2
EXTRACTED=""
case "$SRC_PATH" in
    *.iso)
        if xorriso -osirrox on -indev "$SRC_PATH" -extract /efi/boot/bootx64.efi "$WORK_PRE/bootx64.efi" 2>&1 | tail -3 >&2; then
            EXTRACTED=1
        else
            # Some OpenBSD releases use uppercase in Joliet
            xorriso -osirrox on -indev "$SRC_PATH" -extract /EFI/BOOT/BOOTX64.EFI "$WORK_PRE/bootx64.efi" 2>&1 | tail -3 >&2 && EXTRACTED=1 || true
        fi
        ;;
    *.img)
        # OpenBSD miniroot.img is a partitioned image; the first
        # partition is an MS-DOS ESP carrying /efi/boot/bootx64.efi.
        # We let mtools auto-detect via mformat-style probing on the
        # image with the MBR offset (sector 1 = 1 MiB typical for
        # OpenBSD). Fallback: a plain offset scan.
        if ! mcopy -i "$SRC_PATH@@1M" ::/efi/boot/bootx64.efi "$WORK_PRE/bootx64.efi" 2>/dev/null; then
            mcopy -i "$SRC_PATH@@$((512*64))" ::/efi/boot/bootx64.efi "$WORK_PRE/bootx64.efi" 2>/dev/null || true
        fi
        [[ -f "$WORK_PRE/bootx64.efi" ]] && EXTRACTED=1
        ;;
esac
if [[ -z "$EXTRACTED" || ! -f "$WORK_PRE/bootx64.efi" ]]; then
    echo "[live-openbsdboot] failed to extract bootx64.efi from $SRC_PATH (check ESP partition offset; OpenBSD lays it at /efi/boot/bootx64.efi)" >&2
    exit 1
fi

# 2) Build the 16 MiB FAT16 ESP holding BOOTX64.EFI at the canonical
#    UEFI fallback path. Reuses livefreebsdboot/buildespimg.
IMG_PATH="$WORK_PRE/disk.img"
echo "[live-openbsdboot:$ARCH] building 16 MiB FAT16 ESP" >&2
dd if=/dev/zero of="$WORK_PRE/fat.img" bs=1m count=16 status=none
mformat -i "$WORK_PRE/fat.img" :: >&2
mmd -i "$WORK_PRE/fat.img" ::/EFI ::/EFI/BOOT >&2
mcopy -i "$WORK_PRE/fat.img" "$WORK_PRE/bootx64.efi" ::/EFI/BOOT/BOOTX64.EFI >&2

echo "[live-openbsdboot:$ARCH] wrapping FAT in PMBR + GPT via buildespimg" >&2
(cd "$REPO_DIR/internal/livefreebsdboot/buildespimg" && \
    GOWORK=off go run . -fat "$WORK_PRE/fat.img" -out "$IMG_PATH") >&2
[[ -f "$IMG_PATH" ]] || { echo "[live-openbsdboot] buildespimg failed to produce $IMG_PATH" >&2; exit 1; }
echo "[live-openbsdboot:$ARCH] disk image ready: $IMG_PATH ($(stat -f %z "$IMG_PATH" 2>/dev/null || stat -c %s "$IMG_PATH") bytes)" >&2

# OVMF firmware
EFI_NAME="BOOTX64-OPENBSDBOOT.EFI"
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

WORK="$(mktemp -d -t cloudboot-openbsd-live-XXXXXX)"
trap 'rm -rf "$WORK_PRE"; if [[ "${OPENBSD_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# 3) Push image to ttl.sh.
RAND="$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z0-9' | cut -c1-8)"
OCI_REF="ttl.sh/cloudboot-openbsd-${RAND}:24h"
echo "[live-openbsdboot:$ARCH] publishing $IMG_PATH to $OCI_REF" >&2
(cd "$REPO_DIR/internal/livefreebsdboot/pushfreebsd" && \
    GOWORK=off go run . -src "$IMG_PATH" -dst "$OCI_REF") >&2

# 4) Re-build the probe EFI with the OCI ref baked in.
echo "[live-openbsdboot:$ARCH] re-building $EFI_NAME with openbsdBootTargetRef=$OCI_REF" >&2
TAMAGO="${TAMAGO:-$REPO_DIR/../../../localhost/tamago-pie}"
GOWORK=off GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64 CGO_ENABLED=0 \
    "$TAMAGO/bin/go" build \
    -tags linkcpuinit,linkramstart,phase2_pcienum,phase2_snpenum,phase2_blkprintk,phase3_oci_openbsd_boot \
    -trimpath -buildmode=pie \
    -ldflags "-E cpuinit -X main.openbsdBootTargetRef=$OCI_REF" \
    -o "$WORK/app_amd64_openbsdboot.elf" "$REPO_DIR"
(cd "$REPO_DIR/../../go-coff/pectl" && \
    GOWORK=off go run . link-pie -o "$REPO_DIR/$EFI_NAME" "$WORK/app_amd64_openbsdboot.elf") >&2

# 5) ESP image
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

echo "[live-openbsdboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

check_gate "phase3-oci-openbsd-boot: lease acquired"                          "lease acquired"
check_gate "phase3-oci-openbsd-boot: streamed .*SHA-256 verified OK"          "image streamed + verified"
check_gate "phase3-oci-openbsd-boot: streamed image header OK"                "image header OK"
check_gate "phase3-oci-openbsd-boot: PublishBlockIO OK"                       "PublishBlockIO"
check_gate "phase3-oci-openbsd-boot: ConnectController OK"                    "ConnectController"
check_gate "phase3-oci-openbsd-boot: LocateHandleBuffer(SFS) found"           "SFS surfaced"
check_gate "phase3-oci-openbsd-boot: matching SFS child handle"               "SFS-parent filter"
check_gate "phase3-oci-openbsd-boot: LoadImage.*EFI.*BOOT.*BOOTX64.EFI.* OK"  "LoadImage(bootx64.efi)"
check_gate "phase3-oci-openbsd-boot: OPENBSD-BOOT CHAIN COMPLETE"             "chain complete"

# Stretch: OpenBSD boot> prompt or banner reached.
if grep -qE "OpenBSD/amd64|>> OpenBSD|boot>" "$LOG"; then
    echo "[live-openbsdboot:$ARCH] BONUS: OpenBSD bootloader banner / boot> prompt reached" >&2
fi

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-openbsdboot:$ARCH] PASS — wall=${ELAPSED_MS}ms, ref=$OCI_REF"
    grep -E "phase3-oci-openbsd-boot:" "$LOG" || true
    exit 0
fi

echo "[live-openbsdboot:$ARCH] FAIL — missing gate(s): ${MISSING[*]} after ${ELAPSED_MS}ms" >&2
echo "[live-openbsdboot:$ARCH] tail of log:" >&2
tail -50 "$LOG" >&2 || true
exit 1
