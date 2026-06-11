#!/usr/bin/env bash
# Phase-3 live FreeBSD-boot smoke under QEMU+EDK2 (sprint-1 → sprint-
# 2C-Integration). amd64-only — EFI_BLOCK_IO_PROTOCOL publish-side
# trampolines validated on amd64 alone; arm64/riscv64/loong64 ports
# tracked in sprint 1.3 / 2E.
#
# Sprint 2C-Integration (this revision):
#   - buildespimg now lays down a 2-partition disk: FAT16 ESP +
#     FreeBSD-UFS, the latter populated via go-filesystems/ufs.Mkfs
#     from extractufs/bootroot.tar.
#   - SFS publish trampoline (sprint 2B) now finds a real UFS
#     partition, parses it via go-filesystems/ufs, publishes an SFS
#     on a synthetic handle; FreeBSD loader.efi enumerates /boot and
#     reads /boot/loader.conf from our SFS-UFS surface.
#   - Kernel load is the next boundary (sprint 2D scope — see
#     phase3-multi-os-oci-boot.md).
#
#     bash internal/livefreebsdboot/run.sh amd64
#
# Pipeline:
#   1. Verify a FreeBSD bootable disk image is available (cached under
#      $CLOUDBOOT_FREEBSD_IMAGE or ~/Downloads/FreeBSD-*.iso) — the
#      runner does NOT download it implicitly because the image is
#      ~412 MiB and a re-download per run would saturate the network.
#   2. Build a tiny FAT ESP-disk holding BOOTX64-FREEBSDBOOT.EFI.
#   3. Push the FreeBSD image to ttl.sh anonymously via the
#      pushfreebsd helper. Get a per-run ref like
#      ttl.sh/cloudboot-freebsd-XXXX:24h.
#   4. Re-build BOOTX64-FREEBSDBOOT.EFI with -X
#      main.freebsdBootTargetRef=<oci-ref> so the probe knows where
#      to stream from.
#   5. Boot qemu-system-x86_64 with EDK2 firmware + virtio-net under
#      user-mode networking. Capture stdout for up to FREEBSD_LIVE_TIMEOUT
#      seconds.
#   6. Assert the Sprint 1 MVP gate:
#        - "phase3-oci-freebsd-boot: lease acquired"            (network up)
#        - "phase3-oci-freebsd-boot: streamed N bytes; SHA-256 verified OK"
#        - "phase3-oci-freebsd-boot: streamed image header OK"
#        - "phase3-oci-freebsd-boot: PublishBlockIO OK"
#        - "phase3-oci-freebsd-boot: ConnectController OK"
#        - "phase3-oci-freebsd-boot: LocateHandleBuffer(SFS) found"
#        - "phase3-oci-freebsd-boot: FREEBSD-BOOT MVP CHAIN COMPLETE"
#
# Environment overrides:
#
#   CLOUDBOOT_FREEBSD_IMAGE: path to a local FreeBSD .iso (default:
#                            $HOME/Downloads/FreeBSD-14.3-RELEASE-amd64-bootonly.iso,
#                            falls back to /tmp/fbsd/FreeBSD-*.iso)
#   CLOUDBOOT_OVMF_AMD64_CODE / _VARS: EDK2 .fd paths (same as
#                            kernelboot:live:amd64).
#   FREEBSD_LIVE_TIMEOUT:    per-run wall-clock cap (default 240,
#                            generous because a 412 MiB stream over
#                            ttl.sh through SLIRP is slow).
#   FREEBSD_LIVE_KEEPRUN:    1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 amd64  (sprint 1 is amd64-only)" >&2
    exit 2
fi
if [[ "$ARCH" != "amd64" ]]; then
    echo "[live-freebsdboot] sprint 1 is amd64-only; arm64/riscv64/loong64 deferred to sprint 2" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${FREEBSD_LIVE_TIMEOUT:-240}"

# 1) Locate the FreeBSD source image. Sprint 1.1 finding: the 412 MiB
#    bootonly ISO does NOT fit in tamago's 256 MiB heap reservation
#    (board_amd64.go heapReserveSize), so streaming it OOMs the runtime
#    during the OCI fetch. Pivot: extract /boot/loader.efi from the ISO
#    and synthesise a minimal (~16 MiB) GPT+FAT16 ESP image carrying
#    just \EFI\BOOT\BOOTX64.EFI. The probe still proves the publish +
#    ConnectController + SFS-discovery + SFS-parent-filter +
#    LoadImage(loader.efi) chain end-to-end; loader.efi itself fails
#    later at the "find a bootable partition" step because the image
#    has no UFS rootfs — sprint 2 lands UFS via go-filesystems/ufs.
DEFAULT_IMG_PATHS=(
    "$HOME/Downloads/FreeBSD-14.3-RELEASE-amd64-bootonly.iso"
    "/tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso"
    "$HOME/Downloads/FreeBSD-14.2-RELEASE-amd64-bootonly.iso"
)
SRC_PATH="${CLOUDBOOT_FREEBSD_IMAGE:-}"
if [[ -z "$SRC_PATH" ]]; then
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do
        if [[ -f "$cand" ]]; then SRC_PATH="$cand"; break; fi
    done
fi
if [[ -z "$SRC_PATH" || ! -f "$SRC_PATH" ]]; then
    echo "[live-freebsdboot] no FreeBSD image found; set CLOUDBOOT_FREEBSD_IMAGE or download to one of:" >&2
    for cand in "${DEFAULT_IMG_PATHS[@]}"; do echo "    $cand" >&2; done
    echo "    curl -fL -o /tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso https://download.freebsd.org/releases/amd64/amd64/ISO-IMAGES/14.3/FreeBSD-14.3-RELEASE-amd64-bootonly.iso" >&2
    exit 1
fi
echo "[live-freebsdboot:$ARCH] FreeBSD source image: $SRC_PATH" >&2

WORK_PRE="$(mktemp -d -t cloudboot-freebsd-pre-XXXXXX)"
trap 'rm -rf "$WORK_PRE"' EXIT

# 1a) Mint a bootable disk image:
#       PMBR + GPT + FAT16 ESP partition (+ optional FreeBSD-UFS partition)
#       ESP contents: \EFI\BOOT\BOOTX64.EFI = FreeBSD loader.efi
#       UFS contents (if extractufs/bootroot.tar exists): a freshly-minted
#       UFS2 filesystem populated with /boot/{loader.conf, kernel/*.ko, ...}
#       — gates the SFS-UFS publish surface end-to-end and expects
#       FreeBSD-loader.efi to find the kernel via our UFS SFS.
#
#     - xorriso pulls /boot/loader.efi from the FreeBSD source ISO.
#     - mformat (mtools) makes the 16 MiB FAT16 image. NB: 16 MiB +
#       no `-F` makes mtools pick FAT16. Empirically OVMF stable202605
#       did NOT load FreeBSD's loader.efi off a 32 MiB FAT32 ESP
#       (BdsDxe "Not Found"); FAT16 worked first try.
#     - buildespimg (Go helper in this dir) wraps the FAT in PMBR + GPT
#       and, when -ufs is passed, appends a 2nd FreeBSD-UFS partition.
BOOTROOT_TAR="$REPO_DIR/internal/livefreebsdboot/extractufs/bootroot.tar"
IMG_PATH="$WORK_PRE/disk.img"
if [[ "${CLOUDBOOT_FREEBSD_DISK_PREBUILT:-}" == "1" && -f "${CLOUDBOOT_FREEBSD_DISK:-}" ]]; then
    IMG_PATH="$CLOUDBOOT_FREEBSD_DISK"
    echo "[live-freebsdboot:$ARCH] using pre-built disk image: $IMG_PATH" >&2
else
    echo "[live-freebsdboot:$ARCH] extracting /boot/loader.efi from $SRC_PATH" >&2
    xorriso -osirrox on -indev "$SRC_PATH" -extract /boot/loader.efi "$WORK_PRE/loader.efi" 2>&1 | tail -3 >&2
    [[ -f "$WORK_PRE/loader.efi" ]] || { echo "[live-freebsdboot] failed to extract loader.efi from $SRC_PATH" >&2; exit 1; }

    # Sprint 2D: keep ESP at 16 MiB (proven FAT16 + OVMF stable202605
    # compat). The tamago streaming pipeline OOMs above ~30 MiB total
    # disk image regardless of UFS contents — that's a separate
    # streaming-refactor blocker tracked outside sprint 2D.
    echo "[live-freebsdboot:$ARCH] building 16 MiB FAT16 ESP" >&2
    dd if=/dev/zero of="$WORK_PRE/fat.img" bs=1m count=16 status=none
    mformat -i "$WORK_PRE/fat.img" :: >&2
    mmd -i "$WORK_PRE/fat.img" ::/EFI ::/EFI/BOOT >&2
    mcopy -i "$WORK_PRE/fat.img" "$WORK_PRE/loader.efi" ::/EFI/BOOT/BOOTX64.EFI >&2

    UFS_FLAGS=()
    if [[ -f "$BOOTROOT_TAR" ]]; then
        echo "[live-freebsdboot:$ARCH] sprint 2C-Integration: appending FreeBSD-UFS partition from $BOOTROOT_TAR" >&2
        UFS_FLAGS=( -ufs "$BOOTROOT_TAR" )
    else
        echo "[live-freebsdboot:$ARCH] (diagnostic) extractufs/bootroot.tar not present — falling back to FAT16-only path; sprint-2C-Integration SFS-UFS gate will architectural-skip" >&2
    fi
    echo "[live-freebsdboot:$ARCH] wrapping FAT (+UFS) in PMBR + GPT via buildespimg" >&2
    (cd "$REPO_DIR/internal/livefreebsdboot/buildespimg" && \
        GOWORK=off go run . -fat "$WORK_PRE/fat.img" "${UFS_FLAGS[@]}" -out "$IMG_PATH") >&2
    [[ -f "$IMG_PATH" ]] || { echo "[live-freebsdboot] buildespimg failed to produce $IMG_PATH" >&2; exit 1; }

    # 1b) Cross-validate the UFS partition slice via the pinned
    # go-filesystems/ufs read-only verifier (extractufs/verify). This
    # catches regressions where buildespimg's UFS layout silently
    # diverges from what the read driver accepts. We extract the UFS
    # slice via the partition entry's start LBA + sector count.
    if [[ -f "$BOOTROOT_TAR" ]]; then
        echo "[live-freebsdboot:$ARCH] cross-validating UFS partition via extractufs/verify" >&2
        # Parse the second GPT entry (offset 1024 + 128 = LBA 2 +
        # entry-1 = byte 2*512+128 = 1152). StartingLBA at +32,
        # EndingLBA at +40.
        UFS_START_LBA=$(od -An -tu8 -N8 -j 1184 "$IMG_PATH" | tr -d ' ')
        UFS_END_LBA=$(od -An -tu8 -N8 -j 1192 "$IMG_PATH" | tr -d ' ')
        UFS_SECTORS=$(( UFS_END_LBA - UFS_START_LBA + 1 ))
        echo "[live-freebsdboot:$ARCH] UFS partition: LBA $UFS_START_LBA..$UFS_END_LBA ($UFS_SECTORS sectors)" >&2
        dd if="$IMG_PATH" of="$WORK_PRE/ufs-part.img" bs=512 skip="$UFS_START_LBA" count="$UFS_SECTORS" status=none
        # Sprint 2D: kernel now lands (bsize=32768 + double-indirect).
        # Require it so the cross-check fails fast if Mkfs ever drops
        # back to the legacy small-block defaults.
        (cd "$REPO_DIR/internal/livefreebsdboot/extractufs/verify" && \
            GOWORK=off go run . -img "$WORK_PRE/ufs-part.img" \
                -require-kernel=true -require-loader-conf=true) >&2 || \
            { echo "[live-freebsdboot] FATAL: buildespimg's UFS partition fails extractufs/verify cross-check" >&2; exit 1; }
    fi
fi
echo "[live-freebsdboot:$ARCH] disk image ready: $IMG_PATH ($(stat -f %z "$IMG_PATH" 2>/dev/null || stat -c %s "$IMG_PATH") bytes)" >&2

# OVMF firmware
EFI_NAME="BOOTX64-FREEBSDBOOT.EFI"
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

WORK="$(mktemp -d -t cloudboot-freebsd-live-XXXXXX)"
trap 'rm -rf "$WORK_PRE"; if [[ "${FREEBSD_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# 2) Push image to ttl.sh first.
RAND="$(dd if=/dev/urandom bs=64 count=1 2>/dev/null | LC_ALL=C tr -dc 'a-z0-9' | cut -c1-8)"
OCI_REF="ttl.sh/cloudboot-freebsd-${RAND}:24h"
echo "[live-freebsdboot:$ARCH] publishing $IMG_PATH to $OCI_REF (this may take ~1 min for 412 MiB)" >&2
(cd "$REPO_DIR/internal/livefreebsdboot/pushfreebsd" && \
    GOWORK=off go run . -src "$IMG_PATH" -dst "$OCI_REF") >&2

# 3) Re-build the probe EFI with the OCI ref baked in.
#    Mirrors kernelboot_*.go's per-arch constant override pattern.
echo "[live-freebsdboot:$ARCH] re-building $EFI_NAME with freebsdBootTargetRef=$OCI_REF" >&2
TAMAGO="${TAMAGO:-$REPO_DIR/../../../localhost/tamago-pie}"
GOWORK=off GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64 CGO_ENABLED=0 \
    "$TAMAGO/bin/go" build \
    -tags linkcpuinit,linkramstart,phase2_pcienum,phase2_snpenum,phase2_blkprintk,phase3_oci_freebsd_boot \
    -trimpath -buildmode=pie \
    -ldflags "-E cpuinit -X main.freebsdBootTargetRef=$OCI_REF" \
    -o "$WORK/app_amd64_freebsdboot.elf" "$REPO_DIR"
(cd "$REPO_DIR/../../go-coff/pectl" && \
    GOWORK=off go run . link-pie -o "$REPO_DIR/$EFI_NAME" "$WORK/app_amd64_freebsdboot.elf") >&2

# 4) ESP image
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

# 5) Boot QEMU
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

echo "[live-freebsdboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
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

# 6) Verify gates
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

# Sprint 1.1 PASS gates — full chain to FreeBSD loader.efi banner.
check_gate "phase3-oci-freebsd-boot: lease acquired"                          "lease acquired"
check_gate "phase3-oci-freebsd-boot: streamed .*SHA-256 verified OK"          "image streamed + verified"
check_gate "phase3-oci-freebsd-boot: streamed image header OK"                "image header OK"
check_gate "phase3-oci-freebsd-boot: PublishBlockIO OK"                       "PublishBlockIO"
check_gate "phase3-oci-freebsd-boot: ConnectController OK"                    "ConnectController"
check_gate "phase3-oci-freebsd-boot: LocateHandleBuffer(SFS) found"           "SFS surfaced"
check_gate "phase3-oci-freebsd-boot: matching SFS child handle"               "SFS-parent filter"
check_gate "phase3-oci-freebsd-boot: LoadImage.*EFI.*BOOT.*BOOTX64.EFI.* OK"  "LoadImage(loader.efi)"
# Sprint 2C-Integration: SFS publish surface MUST be PublishSFS OK
# (UFS partition present from buildespimg -ufs). The architectural-skip
# is only acceptable when bootroot.tar is absent.
if [[ -f "$BOOTROOT_TAR" ]]; then
    check_gate "phase3-oci-freebsd-boot: PublishSFS OK"  "PublishSFS OK (sprint 2C-Integration)"
else
    if ! grep -qE "phase3-oci-freebsd-boot: (PublishSFS OK|SFS-UFS skip)" "$LOG"; then
        PASS=0
        MISSING+=("sprint-2B SFS publish surface (PublishSFS or skip-with-rationale)")
    fi
fi
check_gate "phase3-oci-freebsd-boot: FREEBSD-BOOT CHAIN COMPLETE"             "chain complete"
# Stretch: FreeBSD loader.efi banner reached (the real sprint-1.1 PASS).
check_gate "FreeBSD/amd64 EFI loader"                                          "FreeBSD loader.efi banner"

# Sprint 2C-Integration PASS: kernel banner / mountroot / init reached.
# The kernel itself is currently absent from buildespimg's UFS partition
# (29 MiB > sprint-2C-A writer cap of 2 MiB; sprint 2D extends Mkfs to
# bsize=32768 + double-indirect). So loader.efi will reach our SFS,
# enumerate /boot, find loader.conf, and then fail at kernel load.
# That fail point IS the new boundary documented for sprint 2D.
if grep -qE "Welcome to FreeBSD|FreeBSD/amd64 \(|^init:|mountroot>|Trying to mount root from" "$LOG"; then
    echo "[live-freebsdboot:$ARCH] BONUS: kernel-boot evidence in log" >&2
fi

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-freebsdboot:$ARCH] PASS — wall=${ELAPSED_MS}ms, ref=$OCI_REF"
    grep -E "phase3-oci-freebsd-boot:" "$LOG" || true
    exit 0
fi

echo "[live-freebsdboot:$ARCH] FAIL — missing gate(s): ${MISSING[*]} after ${ELAPSED_MS}ms" >&2
echo "[live-freebsdboot:$ARCH] tail of log:" >&2
tail -50 "$LOG" >&2 || true
exit 1
