// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !arm64 && !riscv64 && !loong64 && !amd64

package embed_initramfs

import _ "embed"

// initramfsCPIOGz: fallback embed for non-live-target builds (amd64
// hosts running `go test`, CI runners building artifacts, etc.). The
// arm64 blob is the canonical fixture — it's both the largest and
// the one M8.10 SHIPPED against, so the test corpus exercises it on
// the maintainer's day-to-day host without arch-gated tags.
//
//go:embed initramfs_arm64.cpio.gz
var initramfsCPIOGz []byte
