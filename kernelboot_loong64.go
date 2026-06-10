// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for loong64 (LoongArch64, M8.4
// self-publish, 2026-06-10). Documentation for each variable lives
// next to its shared consumer in phase2_oci_kernel_boot.go.
//
// Loong64 status (M8.4 self-publish): MODE C active against a
// cloud-boot self-published EFI-stub kernel.
//
// History:
//
//   - The 2026-06-10 60-min OCI hunt confirmed NO public anonymous
//     OCI artifact ships an EFI-stub loong64 kernel, and no public
//     rootfs OCI image ships /boot/vmlinuz inside its layer
//     (verified directly against every ghcr.io/loong64/openeuler
//     tag — default/init/base/toolbox/minimal/micro across all
//     dates from 2025-08 through 2026-02).
//   - The kernel however DOES exist as a PE32+ EFI-stub binary inside
//     Debian's `linux-binary-7.0.12+deb14-loong64` .deb under
//     /boot/vmlinuz-* (`file` reports "PE32+ executable
//     (EFI application)"; COFF Machine 0x6264 = LoongArch64).
//   - We therefore extract that file with cmd/cloudboot-oci-extract
//     and re-publish as a single-blob OCI artifact under ttl.sh.
//     See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.4
//     "self-publish" for the toolchain doc.
//
// ttl.sh is 24h-anonymous; the constant below is valid until ~24h
// after the last publish. For permanence, re-publish via:
//
//   /tmp/cb-extract/cloudboot-oci-extract \
//     -src 'deb:https://deb.debian.org/debian/pool/main/l/linux/linux-binary-7.0.12+deb14-loong64_7.0.12-1_loong64.deb' \
//     -arch loong64 \
//     -dst 'ttl.sh/cloudboot-vmlinuz-loong64:24h' \
//     -cmdline-hint 'console=ttyS0,115200'
//
// Follow-up: nightly GitHub Action under cloud-boot/ops, or
// PAT-authenticated push to ghcr.io/cloud-boot/vmlinuz-loong64 for
// permanence.

//go:build phase2_oci_kernel_boot && tamago && loong64

package main

var (
	kernelBootTargetRef = "https://ttl.sh/cloudboot-vmlinuz-loong64:24h"
	kernelBootCmdline   = "console=ttyS0,115200 " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
