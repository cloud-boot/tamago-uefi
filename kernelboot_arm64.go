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
//
// M8.5 cmdline notes (2026-06-10)
//
// The M8.5 DTB-probe enhancement (GUID dump) showed that EDK2's
// arm64 firmware on -machine virt publishes ACPI 2.0 tables under
// `8868e871-e4f1-11d3-bc22-0080c73c8881` but does NOT publish a DTB
// under EFI_DTB_TABLE_GUID. The Linux EFI-stub therefore falls
// back to "Generating empty DTB", which has no UART node, so the
// post-EFI-stub kernel cannot find ttyAMA0 by symbolic name and
// goes silent (and then trips a firmware Data Abort because the
// empty DTB has no PSCI/ACPI roots either).
//
// To work around without having to publish a DTB ourselves (a much
// larger M8.6 task), we:
//   1. Force ACPI discovery via `acpi=force` — tells the kernel to
//      use the ACPI 2.0 tables EDK2 already publishes.
//   2. Hardcode the QEMU virt PL011 UART MMIO base in earlycon so
//      the kernel can talk to the serial before any device-tree /
//      ACPI walk has run.
//   3. Set root=/dev/ram0 + rdinit=/init so the kernel knows its
//      rootfs is the initramfs ramdisk and where to find PID 1.
//   4. loglevel=8 for verbose kernel printk in the live test log.
//   5. panic=10 so a panic-on-init-exit auto-reboots and QEMU
//      exits cleanly inside the test timeout instead of hanging.

//go:build phase2_oci_kernel_boot && tamago && arm64

package main

var (
	kernelBootTargetRef = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"
	kernelBootCmdline   = "console=ttyAMA0,115200 " +
		"earlycon=pl011,mmio32,0x9000000 " +
		"acpi=force " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
