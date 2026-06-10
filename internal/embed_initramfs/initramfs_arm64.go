// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build arm64

package embed_initramfs

import _ "embed"

// initramfsCPIOGz holds the arm64 minimal initramfs (gzip-compressed
// cpio newc) — a single statically-linked aarch64 ELF /init that
// brings up the standard pseudo-filesystems, prints the Path D
// banner, and powers off via reboot(2). See init_src/init.go.
//
//go:embed initramfs_arm64.cpio.gz
var initramfsCPIOGz []byte
