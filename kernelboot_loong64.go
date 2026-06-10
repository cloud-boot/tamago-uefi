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
// ttl.sh is 24h-anonymous; the constant below references a tag that
// is REPUBLISHED nightly by .github/workflows/vmlinuz-nightly.yml
// (cron 04:00 UTC). The tag URL is stable across runs — the
// underlying blob digest rotates with each upstream Debian rebuild,
// but the in-tree consumer discovers the digest from the manifest at
// boot so the rotation is transparent.
//
// Manual re-publish (one-shot, if the cron is stale):
//
//   /tmp/cb-extract/cloudboot-oci-extract \
//     -src 'deb:https://deb.debian.org/debian/pool/main/l/linux/linux-binary-7.0.12+deb14-loong64_7.0.12-1_loong64.deb' \
//     -arch loong64 \
//     -dst 'ttl.sh/cloudboot-vmlinuz-loong64:24h' \
//     -cmdline-hint 'console=ttyS0,115200'
//
// Stable-tag alternative (no TTL): once GHCR_TOKEN repo secret is
// provisioned (see cloud-boot/docs §M8.4 self-publish "Secret
// provisioning"), the same workflow ALSO pushes to
// ghcr.io/cloud-boot/vmlinuz-loong64:latest. To switch the boot
// consumer over, change kernelBootTargetRef below to that ref.

//
// M8.12 end-to-end (2026-06-10)
//
// First full end-to-end Linux kernel boot from OCI on loong64:
// streamed `https://ttl.sh/cloudboot-vmlinuz-loong64:24h` (Linux
// 7.0.12 from Debian) via MODE C, EFI-stub jumped straight into
// the kernel (loong64's EFI-stub is quieter — no "Booting Linux
// Kernel..." line), kernel proper unpacked the initramfs, exec'd
// /init, printed the Phase 2 Path D banner, powered off cleanly
// via reboot(2). Wall: 17.1s end-to-end. ZERO per-arch QEMU or
// cmdline tweaks needed vs. M8.4 dormant scaffolding — the only
// change was per-arch /init binary (initramfs_loong64.cpio.gz
// embed gated by //go:build loong64).
//
// Why no `-cpu` pin like arm64 needed: the Debian 7.0.12 loong64
// kernel is brand new (2026-06-09 build) and works cleanly with
// QEMU 9.x's `-cpu max`. No analogue of arm64's stale 5.10.29
// Talos kernel incompat.
//
// Why no DTB/RNG fixes like arm64 needed: loong64 EDK2 firmware
// publishes ACPI 2.0 tables (8868e871-... GUID present in our
// probe dump at index 9) which the kernel auto-discovers, and
// does not publish EFI_RNG_PROTOCOL (verified — none of the 10
// GUIDs match 3152bca5-...), so efi_random_get_seed() takes its
// EFI_NOT_FOUND early-exit path naturally.
//
// Cmdline: identical to the M8.4 baseline. `console=ttyS0,115200`
// is the loong64 virt machine's 16550-style UART (different from
// arm64's PL011 and riscv64's SBI debug console). The kernel
// auto-discovers it via ACPI SPCR + the embedded firmware DTB.

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
