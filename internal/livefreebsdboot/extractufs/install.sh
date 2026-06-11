#!/usr/bin/env bash
# Copyright (c) 2026, cloud-boot
# SPDX-License-Identifier: BSD-3-Clause
#
# install.sh — produce a real FreeBSD UFS2 partition fixture.
#
# Strategy (fast path): download the upstream FreeBSD pre-built
# raw VM image (`FreeBSD-14.3-RELEASE-amd64.raw.xz`), which is a
# GPT-partitioned disk produced by FreeBSD release engineering. It
# already contains a freebsd-ufs root partition (GUID
# 516e7cb6-6ecf-11d6-8ff8-00022d09712b), so we do not need to run
# `bsdinstall` ourselves. Then `extract_ufs.sh` carves out the UFS2
# partition into a standalone image consumable by go-filesystems/ufs.
#
# The previously-considered bsdinstall-in-QEMU path is documented in
# README.md but unused: release engineering already ran that procedure
# upstream and shipped the result, so we re-use their artifact.
#
# Usage:  ./install.sh
# Output: /tmp/fbsd/FreeBSD-14.3-RELEASE-amd64.raw (uncompressed)
#         (then call ./extract_ufs.sh to get the UFS2 image)
set -euo pipefail

CACHE_DIR="${CACHE_DIR:-/tmp/fbsd}"
FBSD_VER="${FBSD_VER:-14.3-RELEASE}"
FBSD_ARCH="${FBSD_ARCH:-amd64}"
RAW_BASENAME="FreeBSD-${FBSD_VER}-${FBSD_ARCH}.raw"
URL="https://download.freebsd.org/releases/VM-IMAGES/${FBSD_VER}/${FBSD_ARCH}/Latest/${RAW_BASENAME}.xz"

mkdir -p "${CACHE_DIR}"
cd "${CACHE_DIR}"

if [[ ! -f "${RAW_BASENAME}.xz" ]]; then
  echo "[install.sh] downloading ${URL}" >&2
  curl -fSL --retry 3 -o "${RAW_BASENAME}.xz" "${URL}"
fi

if [[ ! -f "${RAW_BASENAME}" ]]; then
  echo "[install.sh] decompressing ${RAW_BASENAME}.xz" >&2
  xz -dk "${RAW_BASENAME}.xz"
fi

ls -lh "${RAW_BASENAME}.xz" "${RAW_BASENAME}"
echo "[install.sh] OK — raw image at ${CACHE_DIR}/${RAW_BASENAME}"
