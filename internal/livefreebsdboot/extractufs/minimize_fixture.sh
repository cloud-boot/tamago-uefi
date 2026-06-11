#!/usr/bin/env bash
# Copyright (c) 2026, cloud-boot
# SPDX-License-Identifier: BSD-3-Clause
#
# minimize_fixture.sh — produce a minimal /boot tree from the
# extracted full UFS2 image, ready to be packed into a tiny UFS by
# the sibling genufs package (Phase 3 sprint 2C, Agent 2C-C).
#
# Pipeline:
#   1. ./verify/export_boot reads /boot from freebsd-ufs2-full.img.
#   2. We prune kernel modules down to the small subset the cloud-boot
#      live test actually needs (just kernel + a handful of always-loaded
#      drivers, kept under MIN_BUDGET_BYTES). The full 851-module set is
#      ~120 MiB — too big for streaming-from-ttl.sh.
#   3. We drop a synthetic loader.conf into bootroot/boot/loader.conf
#      so sprint 2B's EFI_SIMPLE_FILE_SYSTEM_PROTOCOL ListDir surface
#      can find it during integration tests.
#   4. We emit a tar archive (bootroot.tar) that genufs ingests.
#
# This script does NOT itself build a UFS image; that is genufs' job.
# Once genufs lands, wire `genufs pack bootroot.tar -o freebsd-ufs2-min.img`
# into this script's tail.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC_IMG="${HERE}/freebsd-ufs2-full.img"
DST_DIR="${HERE}/bootroot"
TAR_OUT="${HERE}/bootroot.tar"
LOADER_CONF_SRC="${HERE}/loader.conf"

if [[ ! -f "${SRC_IMG}" ]]; then
  echo "[minimize_fixture.sh] need ${SRC_IMG}; run extract_ufs.sh first" >&2
  exit 1
fi
if [[ ! -x "${HERE}/verify/export_boot" ]]; then
  echo "[minimize_fixture.sh] building export_boot" >&2
  (cd "${HERE}/verify" && GOWORK=off go build -tags export -o export_boot .)
fi

rm -rf "${DST_DIR}"
mkdir -p "${DST_DIR}"

echo "[minimize_fixture.sh] exporting /boot from ${SRC_IMG}" >&2
"${HERE}/verify/export_boot" -img "${SRC_IMG}" -root /boot -out "${DST_DIR}"

# Prune modules. Keep ONLY: kernel itself + virtio family + isp/scsi-
# free console drivers. cloud-boot's live test boots in QEMU with
# virtio, so this is sufficient.
KEEP_MODULES=(
  "kernel" "linker.hints"
  "virtio.ko" "virtio_blk.ko" "virtio_console.ko" "virtio_pci.ko"
  "virtio_random.ko" "virtio_scsi.ko" "vtnet.ko"
  "if_vtnet.ko"
)
KMOD_DIR="${DST_DIR}/boot/kernel"
if [[ -d "${KMOD_DIR}" ]]; then
  echo "[minimize_fixture.sh] pruning $(ls "${KMOD_DIR}" | wc -l | tr -d ' ') kernel modules to virtio subset" >&2
  pushd "${KMOD_DIR}" >/dev/null
  for f in *; do
    keep=0
    for k in "${KEEP_MODULES[@]}"; do
      [[ "$f" == "$k" ]] && keep=1 && break
    done
    if [[ $keep -eq 0 ]]; then
      rm -f -- "$f"
    fi
  done
  popd >/dev/null
fi

# Synthesise /boot/loader.conf if not present (stock VM image lacks one).
if [[ ! -f "${DST_DIR}/boot/loader.conf" ]]; then
  cp "${LOADER_CONF_SRC}" "${DST_DIR}/boot/loader.conf"
fi

# Optionally also prune obviously-irrelevant files at /boot top-level
# that the loader never touches in a UEFI-microVM boot path.
PRUNE_FILES=(
  beastie.4th brand-fbsd.4th brand.4th cdboot check-password.4th
  color.4th delay.4th efi.4th frames.4th
  loader.help.bios loader.help.efi loader.help.userboot
  loader_4th loader_4th.efi loader_ia32.efi loader_lua loader_lua.efi
  loader_simp loader_simp.efi
  logo-beastie.4th logo-beastiebw.4th logo-fbsdbw.4th logo-orb.4th logo-orbbw.4th
  menu-commands.4th menu.4th menusets.4th screen.4th shortcuts.4th support.4th
  userboot.so userboot_4th.so userboot_lua.so
  boot0 boot0sio boot1 boot1.efi boot2 gptboot gptboot.efi gptzfsboot
  isoboot mbr pmbr pxeboot zfsboot zfsloader
)
for p in "${PRUNE_FILES[@]}"; do
  rm -f "${DST_DIR}/boot/${p}"
done

du -sh "${DST_DIR}"
echo "[minimize_fixture.sh] producing tar archive at ${TAR_OUT}" >&2
(cd "${DST_DIR}" && tar -cf "${TAR_OUT}" boot)
ls -lh "${TAR_OUT}"

# Once genufs (Phase 3 sprint 2C, sibling pkg) lands, replace the
# placeholder symlink below with: `genufs pack bootroot.tar -o freebsd-ufs2-min.img`
MIN_IMG="${HERE}/freebsd-ufs2-min.img"
if [[ ! -e "${MIN_IMG}" ]]; then
  ln -sf freebsd-ufs2-full.img "${MIN_IMG}"
  echo "[minimize_fixture.sh] freebsd-ufs2-min.img symlinked to full image (genufs not yet wired)" >&2
fi
echo "[minimize_fixture.sh] OK"
