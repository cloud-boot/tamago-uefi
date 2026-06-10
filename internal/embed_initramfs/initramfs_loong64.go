// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build loong64

package embed_initramfs

import _ "embed"

// initramfsCPIOGz holds the loong64 minimal initramfs (gzip-compressed
// cpio newc) — a single statically-linked LoongArch64 ELF /init that
// brings up the standard pseudo-filesystems, prints the Path D
// banner, and powers off via reboot(2). See init_src/init.go.
//
//go:embed initramfs_loong64.cpio.gz
var initramfsCPIOGz []byte
