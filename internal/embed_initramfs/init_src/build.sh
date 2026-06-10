#!/usr/bin/env bash
# Copyright 2026 The cloud-boot Authors.
# SPDX-License-Identifier: BSD-3-Clause
#
# Reproducible rebuild of the embedded initramfs.cpio.gz used by
# the cloud-boot tamago-uefi M8.4/M8.5 MODE C kernel-boot path.
#
# Run from inside this directory:
#
#     cd internal/embed_initramfs/init_src
#     ./build.sh
#
# Output: ../initramfs.cpio.gz (overwrites the embedded blob).
#
# The build is bit-reproducible for a given Go toolchain version
# thanks to:
#   - -trimpath strips host paths from the Go binary
#   - -ldflags='-s -w' strips symbol + DWARF tables
#   - LC_ALL=C sort gives a deterministic cpio entry order
#   - gzip -n drops the embedded filename + mtime header
#
# Cross-arch note: the resulting /init is an aarch64 static ELF.
# Today the M8.x kernel-boot path is arm64-only (the only public
# OCI kernel artifact we ship against is multi-arch but only arm64
# has live coverage). When riscv64 / loong64 / amd64 join, we'll
# fan this out to per-arch initramfs blobs or one shared multiarch
# blob with /init.<arch> + a tiny posix-sh shim — TBD per M8.x.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

# 1. Build the static aarch64 ELF /init.
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
    go build -trimpath -ldflags='-s -w' -o init ./init.go

# 2. Stage a root/ tree containing only /init (executable).
rm -rf root
mkdir root
cp init root/init
chmod 0755 root/init

# 3. Pack as newc cpio + gzip, reproducibly.
( cd root && find . | LC_ALL=C sort | cpio -o -H newc 2>/dev/null ) \
    | gzip -9n > ../initramfs.cpio.gz

echo "ok: ../initramfs.cpio.gz ($(stat -f%z ../initramfs.cpio.gz 2>/dev/null \
    || stat -c%s ../initramfs.cpio.gz) bytes)"
