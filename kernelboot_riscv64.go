// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for riscv64 (M8.4 self-publish,
// 2026-06-10). Documentation for each variable lives next to its
// shared consumer in phase2_oci_kernel_boot.go.
//
// Riscv64 status (M8.4 self-publish): MODE C active against a
// cloud-boot self-published EFI-stub kernel.
//
// History:
//
//   - The 2026-06-10 60-min OCI hunt confirmed NO public anonymous
//     OCI artifact ships an EFI-stub riscv64 kernel standalone, and
//     no public rootfs OCI image ships /boot/vmlinuz inside its layer
//     (verified directly against riscv64/debian:sid, openeuler rv64,
//     ubuntu rv64, alpine rv64, opensuse rv64, etc.).
//   - The kernel however DOES exist as a PE32+ EFI-stub binary inside
//     Debian's `linux-image-6.12.90+deb13.1-riscv64` .deb under
//     /boot/vmlinux-* (yes, "vmlinux" — Debian builds riscv64 with
//     CONFIG_EFI_ZBOOT=n so the EFI-stub wrapping IS the vmlinux
//     itself; `file` reports "PE32+ executable (EFI application)
//     RISC-V 64-bit").
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
//     -src 'deb:https://deb.debian.org/debian/pool/main/l/linux/linux-image-6.12.90+deb13.1-riscv64_6.12.90-2_riscv64.deb' \
//     -arch riscv64 \
//     -dst 'ttl.sh/cloudboot-vmlinuz-riscv64:24h' \
//     -cmdline-hint 'console=hvc0 earlycon=sbi'
//
// Stable-tag alternative (no TTL): once GHCR_TOKEN repo secret is
// provisioned (see cloud-boot/docs §M8.4 self-publish "Secret
// provisioning"), the same workflow ALSO pushes to
// ghcr.io/cloud-boot/vmlinuz-riscv64:latest. To switch the boot
// consumer over, change kernelBootTargetRef below to that ref.

//go:build phase2_oci_kernel_boot && tamago && riscv64

package main

var (
	kernelBootTargetRef = "https://ttl.sh/cloudboot-vmlinuz-riscv64:24h"
	kernelBootCmdline   = "console=hvc0 earlycon=sbi " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
