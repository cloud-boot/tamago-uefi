// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for arm64 (M8.3 per-arch split,
// 2026-06-10; M8.13 Debian-13 unification, 2026-06-10). Documentation
// for each variable lives next to its shared consumer in
// phase2_oci_kernel_boot.go.
//
// M8.13 — Debian-13 unification across all 4 arches (2026-06-10)
//
// Until M8.12 the arm64 wiring pulled Talos 5.10.29 (2021) from
// `ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc`, which
// required a `-cpu cortex-a72` QEMU pin (M8.10, R-M8.9a) because
// the kernel was too old to gate the modern CPU features `-cpu max`
// exposes on QEMU 9.x (SVE2, FEAT_RNG, FEAT_HCX, …) and crashed in
// head.S before VBAR_EL1 was installed. riscv64 (M8.11) + loong64
// (M8.12) already used cloud-boot-self-published EFI-stub kernels
// extracted from Debian 13 .deb packages by
// `cmd/cloudboot-oci-extract`, with ZERO per-arch QEMU tweaks. M8.13
// extends that scheme to arm64 (and amd64) for a fully consistent
// matrix:
//
//   - Source: Debian 13 `linux-signed-arm64` (trixie) signed kernel
//     package, /boot/vmlinuz-6.12.90+deb13.1-arm64, extracted as a
//     PE32+ EFI-stub binary (MZ + ARMd magic + COFF Machine 0xaa64).
//   - Published at ttl.sh/cloudboot-vmlinuz-arm64:24h, re-pushed
//     nightly by .github/workflows/vmlinuz-nightly.yml alongside
//     riscv64+loong64+amd64.
//   - Modern kernel handles `-cpu max` cleanly: no more cortex-a72
//     pin needed in internal/livekernelboot/run.sh (M8.13 reverts
//     the M8.10 workaround).
//
// Cmdline rebased onto the riscv64/loong64 baseline, retaining only
// the arm64 console specifics and the M8.8 post-EBS-serial-routing
// clean-up:
//
//   - console=ttyAMA0,115200  : QEMU virt PL011 UART (kernel side).
//   - earlycon=pl011,mmio32,0x9000000 : earlycon before DTB walk.
//   - keep_bootcon            : keep earlycon alive until ttyAMA0 is
//                               fully registered (M8.8).
//   - earlyprintk=keep        : earlyprintk symmetry (M8.8).
//   - printk.time=y           : `[ x.xxx]` timestamp prefix (M8.8).
//   - root=/dev/ram0 rdinit=/init : initramfs ramdisk + PID 1.
//   - loglevel=8 panic=10     : verbose printk + auto-reboot.
//
// DROPPED from the M8.10 cmdline (Debian 6.12.90 doesn't trip the
// 5.10/Talos failure modes the workarounds were for):
//
//   - `nokaslr random.trust_bootloader=0 random.trust_cpu=0` — these
//     existed to avoid the RngDxe Data Abort (R-M8.6a). The
//     uefiboard.UninstallAllRNG firmware-side fix (M8.9) closes the
//     abort directly; the cmdline knobs are belt-and-braces only
//     and add no value on a 6.12 kernel. If RngDxe somehow returns,
//     re-add. (M8.13 verifies empirically — live test ran clean.)
//
// PRESERVED from M8.6 (still required):
//
//   - PublishDTB in MODE C — EDK2 arm64 firmware on -machine virt
//     publishes ACPI 2.0 + SMBIOS but no DTB. The Linux EFI-stub
//     would generate an empty DTB and null-deref. We still install
//     our embedded QEMU-virt DTB under EFI_DTB_TABLE_GUID.
//   - UninstallAllRNG in MODE C (M8.9) — yanks the firmware
//     RngDxe handle so efi_random_get_seed() takes the
//     EFI_NOT_FOUND early-exit path; without this we hit the
//     pre-EBS Data Abort regardless of cmdline.
//
// Verify-the-kernel one-shot manual re-publish (if cron is stale):
//
//   /tmp/cb-extract/cloudboot-oci-extract \
//     -src 'deb:https://deb.debian.org/debian/pool/main/l/linux-signed-arm64/linux-image-6.12.90+deb13.1-arm64_6.12.90-2_arm64.deb' \
//     -arch arm64 \
//     -dst 'ttl.sh/cloudboot-vmlinuz-arm64:24h' \
//     -cmdline-hint 'console=ttyAMA0,115200 earlycon=pl011,mmio32,0x9000000'
//
// Historical Talos pin (M8.3 → M8.12): obsolete. Left in the
// changelog under M8.13 in cloud-boot/docs/tamago-uefi-phase2-oci-loader.md
// for posterity. The M8.10 `-cpu cortex-a72` comment block previously
// at the top of kernelBootCmdline is now in
// internal/livekernelboot/run.sh's M8.13 reverse-fix block.

//go:build phase2_oci_kernel_boot && tamago && arm64

package main

var (
	kernelBootTargetRef = "https://ttl.sh/cloudboot-vmlinuz-arm64:24h"
	kernelBootCmdline   = "console=ttyAMA0,115200 " +
		"earlycon=pl011,mmio32,0x9000000 keep_bootcon earlyprintk=keep " +
		"printk.time=y " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
	// kernelBootInitrdMode = "protocol" — arm64 EDK2 publishes
	// LoadFile2 cleanly; PublishInitrd path works as proven in M8.10.
	// See kernelboot_amd64.go for the "espfile" alternative.
	kernelBootInitrdMode = "protocol"
)
