#!/usr/bin/env bash
# Copyright 2026 The cloud-boot Authors.
# SPDX-License-Identifier: BSD-3-Clause
#
# Reproducible rebuild of the embedded initramfs.cpio.gz blobs used
# by the cloud-boot tamago-uefi M8.4/M8.5/M8.10/M8.11/M8.12 MODE C
# kernel-boot path.
#
# Run from inside this directory:
#
#     cd internal/embed_initramfs/init_src
#     ./build.sh
#
# Output: ../initramfs_<arch>.cpio.gz for each ARCHES entry. Each
# blob is embedded by the matching initramfs_<arch>.go file under
# //go:build <arch>.
#
# The build is bit-reproducible for a given Go toolchain version
# thanks to:
#   - -trimpath strips host paths from the Go binary
#   - -ldflags='-s -w' strips symbol + DWARF tables
#   - LC_ALL=C sort gives a deterministic cpio entry order
#   - gzip -n drops the embedded filename + mtime header
#
# Multi-arch (M8.11/M8.12): the initramfs is per-arch because the
# Linux kernel execs /init as a native ELF for the running arch.
# A single multi-arch blob doesn't work — a riscv64 kernel cannot
# exec an aarch64 binary, etc. Each arch ships its own /init.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

ARCHES=(arm64 riscv64 loong64)

for ARCH in "${ARCHES[@]}"; do
    echo "[$ARCH] building static ELF /init..."
    GOOS=linux GOARCH="$ARCH" CGO_ENABLED=0 \
        go build -trimpath -ldflags='-s -w' -o "init.$ARCH" ./init.go

    STAGE="root_$ARCH"
    rm -rf "$STAGE"
    mkdir "$STAGE"
    cp "init.$ARCH" "$STAGE/init"
    chmod 0755 "$STAGE/init"

    ( cd "$STAGE" && find . | LC_ALL=C sort | cpio -o -H newc 2>/dev/null ) \
        | gzip -9n > "../initramfs_$ARCH.cpio.gz"

    SIZE=$(stat -f%z "../initramfs_$ARCH.cpio.gz" 2>/dev/null \
        || stat -c%s "../initramfs_$ARCH.cpio.gz")
    echo "[$ARCH] ok: ../initramfs_$ARCH.cpio.gz ($SIZE bytes)"
done

echo "all archs built: ${ARCHES[*]}"
