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
//
// M8.7 RNG cmdline workaround (2026-06-10) — R-M8.6a
//
// After M8.6 closed (DTB published; EFI-stub reached "Using DTB
// from configuration table" + "Loaded initrd from
// LINUX_EFI_INITRD_MEDIA_GUID device path"), the next observed
// failure was a Data Abort inside EDK2's `RngDxe.dll` on the
// kernel's RETRY of `efi_get_random_bytes`. The first call
// returned EFI_INVALID_PARAMETER cleanly; the kernel then retried
// (KASLR seed gather) and the retry path null-deref'd inside
// RngDxe. Approach A: disable every kernel path that calls into
// EFI_RNG_PROTOCOL so the abort can never be triggered.
//
//   - nokaslr                  : disable KASLR (the main caller of
//                                efi_get_random_bytes from the
//                                EFI stub).
//   - random.trust_bootloader=0: don't seed the entropy pool from
//                                any EFI/bootloader RNG.
//   - random.trust_cpu=0       : don't seed from CPU RNG either —
//                                belt + braces in case the kernel
//                                re-enters efi_get_random_bytes
//                                via random_init().
//
// If approach A is insufficient (the kernel retries despite the
// trust= knobs), the fallback is approach B: publish our own
// EFI_RNG_PROTOCOL (GUID 3152bca5-eade-433d-862e-c01cdc291f44)
// backed by crypto/rand so the FIRST call succeeds and no retry
// happens. Approach C is upstream-Linux investigation.

//go:build phase2_oci_kernel_boot && tamago && arm64

package main

var (
	kernelBootTargetRef = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"
	kernelBootCmdline   = "console=ttyAMA0,115200 " +
		"earlycon=pl011,mmio32,0x9000000 " +
		"acpi=force " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10 " +
		"nokaslr random.trust_bootloader=0 random.trust_cpu=0"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
