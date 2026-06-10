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
//
// M8.8 post-EBS serial routing — cmdline cleanup + new pre-EBS
// crash uncovered (2026-06-10)
//
// After M8.7 the EFI-stub trace ended cleanly on
// "Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID device path"
// followed by ~180s silence to the watchdog (treated as PASS by
// the existing runner gates). M8.8 investigation: ran the live
// test with M81_LIVE_KEEPRUN=1 and inspected the full qemu log
// past the runner's "kernel-side output" marker. Found:
//
//   Synchronous Exception at 0x000000013C0FF9DC
//   ESR 0x96000047  FAR 0x0000000000000040
//   ASSERT [ArmCpuDxe] DefaultExceptionHandler.c(343): 0==1
//
// FAR=0x40 + ESR=0x96000047 = Translation fault, third level (a
// null+0x40 deref). ELR lands inside the EDK2 DXE region, so the
// fault fires WHILE EDK2 boot services are still active — i.e.
// the kernel/EFI-stub is calling into a firmware service that
// dereferences a null string or struct pointer at offset 0x40.
// This is therefore PRE-ExitBootServices: zero kernel `[ x.xxx]`
// output ever reaches the PL011 because the kernel never actually
// transitions to its own console subsystem.
//
// QEMU side: `-serial stdio` IS routing PL011 to the runner — the
// EFI-stub's 4 lines reach us cleanly, proving the chardev path
// works. The blocker is 100% kernel↔firmware: a new pre-EBS Data
// Abort tracked as R-M8.8a (different LR than M8.6a's RngDxe;
// PublishRNG already neutralised the firmware's RngDxe handle).
//
// Cmdline cleanup landed in M8.8 (these stay even though they
// don't unblock R-M8.8a — they're correct on their own merits and
// will let post-EBS output flow the moment R-M8.8a is unblocked
// in M8.9):
//   - drop `acpi=force`: M8.6 PublishDTB now installs a proper
//     QEMU-virt DTB under EFI_DTB_TABLE_GUID with pl011@9000000 +
//     serial0 alias + chosen/stdout-path; with BOTH `acpi=force`
//     AND a DTB present the kernel was picking ACPI (EDK2's
//     MADT/GTDT has no PL011 UART description) — so even if the
//     pre-EBS crash were fixed, the late console hand-off from
//     earlycon to ttyAMA0 would silently never initialise. Drop
//     the override; kernel auto-picks DTB when present;
//   - add `keep_bootcon`: keep earlycon alive until ttyAMA0 is
//     fully registered;
//   - add `earlyprintk=keep`: symmetry for kernels that gate on
//     `earlyprintk` instead of (or in addition to) `earlycon`;
//   - add `printk.time=y`: kernel `[ x.xxx]` timestamp prefix.
//
// R-M8.8a (CLOSED 2026-06-10, M8.9): pre-EBS Data Abort
// downstream of our PublishRNG'd EFI_RNG_PROTOCOL handler.
// Diagnosis: with PublishRNG ENABLED the abort fires inside the
// EFI-stub's `efi_random_get_seed()` post-GetRNG flow
// (install_configuration_table + memory-map walk); with PublishRNG
// DISABLED but RngDxe still present the abort REVERTS to R-M8.6a
// inside RngDxe.dll +0x3220. The only path that closes BOTH is
// "no EFI_RNG_PROTOCOL reachable at all" — UninstallAllRNG yanks
// the firmware's interface AND skips installing ours, so
// gBS->LocateProtocol(RNG, NULL, &iface) returns EFI_NOT_FOUND,
// efi_random_get_seed() takes its `seed_size = 0 + no nvram seed
// → return early` path, and the EFI-stub continues into "Exiting
// boot services and installing virtual address map..." (the line
// immediately preceding ExitBootServices). See the M8.9 entry in
// cloud-boot/docs/tamago-uefi-phase2-oci-loader.md for the full
// trace + register dump differential.
//
// The kernel's own entropy pool is seeded from CPU + interrupt
// timing post-boot (random.trust_*=0 cmdline ensures even if RNG
// were available the EFI seed wouldn't be trusted) — losing the
// EFI seed is a defence-in-depth concern, not a hard requirement.

//go:build phase2_oci_kernel_boot && tamago && arm64

package main

var (
	kernelBootTargetRef = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"
	kernelBootCmdline   = "console=ttyAMA0,115200 " +
		"earlycon=pl011,mmio32,0x9000000 keep_bootcon earlyprintk=keep " +
		"printk.time=y " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10 " +
		"nokaslr random.trust_bootloader=0 random.trust_cpu=0"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
