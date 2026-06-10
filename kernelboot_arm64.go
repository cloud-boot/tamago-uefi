// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for arm64 (M8.3 per-arch split,
// 2026-06-10). Documentation for each variable lives next to its
// shared consumer in phase2_oci_kernel_boot.go.
//
// Arm64 is the ONLY arch with a validated public EFI-stub kernel OCI
// artifact in M8.3: ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc
// (multi-arch index, anonymous bearer-token pull). The per-arch
// manifest's first layer is a tar.gz containing boot/vmlinuz as a
// PE32+ image with MZ + 'ARMd' magic at offset 0x38 and machine type
// 0xaa64. Verified end-to-end against the artifact pulled
// 2026-06-09 (commit 00bc8f0).

//go:build phase2_oci_kernel_boot && tamago && arm64

package main

var (
	kernelBootTargetRef         = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"
	kernelBootCmdline           = "console=ttyAMA0,115200 earlyprintk=ttyAMA0,115200"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
