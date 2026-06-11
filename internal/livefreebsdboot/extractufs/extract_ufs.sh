#!/usr/bin/env bash
# Copyright (c) 2026, cloud-boot
# SPDX-License-Identifier: BSD-3-Clause
#
# extract_ufs.sh — locate the freebsd-ufs partition (GUID
# 516e7cb6-6ecf-11d6-8ff8-00022d09712b) inside the raw FreeBSD VM
# image fetched by install.sh, then `dd` it out byte-for-byte.
#
# Output: ./freebsd-ufs2-full.img — the full ~5 GiB rootfs partition.
#         ./freebsd-ufs2-min.img  — a symlink to the same file for now;
#                                   minimize_fixture.sh can replace it
#                                   with a smaller crafted UFS image.
#
# Requires: sgdisk (brew install gptfdisk), dd, awk.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
CACHE_DIR="${CACHE_DIR:-/tmp/fbsd}"
FBSD_VER="${FBSD_VER:-14.3-RELEASE}"
FBSD_ARCH="${FBSD_ARCH:-amd64}"
RAW="${CACHE_DIR}/FreeBSD-${FBSD_VER}-${FBSD_ARCH}.raw"
FREEBSD_UFS_GUID="516E7CB6-6ECF-11D6-8FF8-00022D09712B"
OUT_FULL="${HERE}/freebsd-ufs2-full.img"

if [[ ! -f "${RAW}" ]]; then
  echo "[extract_ufs.sh] missing ${RAW}; run install.sh first" >&2
  exit 1
fi

# Walk the GPT, pick the first partition whose type GUID is FreeBSD-UFS.
PART_INFO="$(
  for n in 1 2 3 4 5 6 7 8; do
    if sgdisk -i "${n}" "${RAW}" 2>/dev/null | grep -qi "${FREEBSD_UFS_GUID}"; then
      first=$(sgdisk -i "${n}" "${RAW}" | awk '/^First sector/ {print $3}')
      last=$(sgdisk -i "${n}" "${RAW}"  | awk '/^Last sector/  {print $3}')
      echo "${n} ${first} ${last}"
      break
    fi
  done
)"
if [[ -z "${PART_INFO}" ]]; then
  echo "[extract_ufs.sh] no freebsd-ufs partition found in ${RAW}" >&2
  exit 1
fi
read -r PART FIRST LAST <<<"${PART_INFO}"
COUNT=$(( LAST - FIRST + 1 ))
echo "[extract_ufs.sh] partition ${PART}: first=${FIRST} last=${LAST} (${COUNT} sectors, $((COUNT/2048)) MiB)"

# dd at sector granularity (512 B). bs=1m + iseek-in-MiB only works
# when the partition starts on a MiB boundary; FreeBSD release images
# put rootfs at sector 2163892 (offset 1107912704 B), which is NOT a
# MiB boundary, so we'd skip 616448 bytes of header and read zeros.
dd if="${RAW}" of="${OUT_FULL}" bs=512 \
   iseek="${FIRST}" \
   count="${COUNT}" \
   status=progress

ls -lh "${OUT_FULL}"
echo "[extract_ufs.sh] OK — UFS2 image at ${OUT_FULL}"
