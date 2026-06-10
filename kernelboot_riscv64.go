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

//
// M8.11 end-to-end (2026-06-10)
//
// First full end-to-end Linux kernel boot from OCI on riscv64:
// streamed `https://ttl.sh/cloudboot-vmlinuz-riscv64:24h` (Linux
// 6.12.90 from Debian) via MODE C, EFI-stub reached ExitBootServices,
// kernel proper unpacked the initramfs, exec'd /init, printed the
// Phase 2 Path D banner, powered off cleanly via reboot(2). Wall:
// 18.1s end-to-end. ZERO per-arch QEMU or cmdline tweaks needed
// vs. M8.4 dormant scaffolding — the only change was per-arch
// /init binary (initramfs_riscv64.cpio.gz embed gated by
// //go:build riscv64; the arm64 /init the earlier sprint shipped
// fails to exec on a riscv64 kernel with "No working init found").
//
// Why no `-cpu` pin like arm64 needed: the Debian 6.12.90 riscv64
// kernel is recent enough to gate every CPU feature QEMU 9.x's
// default exposes. No analogue of arm64's `-cpu max` vs 5.10.29
// Talos kernel incompat.
//
// Why no DTB publish like arm64 needed: riscv64 EDK2 firmware
// provides hardware discovery via SBI + the firmware's own DTB
// (passed to the EFI-stub via `ConfigurationTable`, even when our
// probe reports "EFI_DTB_TABLE_GUID NOT FOUND" — the EFI-stub
// generates an empty DTB and the kernel auto-discovers via SBI
// hartid + memory probing). Empty-DTB doesn't null-deref on
// riscv64 the way it did on arm64 (M8.5 R-M8.5a).
//
// Why no UninstallAllRNG like arm64 needed: riscv64 EDK2 firmware
// on QEMU `-machine virt` does not publish an EFI_RNG_PROTOCOL
// at all (verified via the DTB probe GUID dump — none of the 9
// GUIDs match 3152bca5-eade-433d-862e-c01cdc291f44). The
// efi_random_get_seed() path takes its EFI_NOT_FOUND early-exit
// branch naturally.
//
// Cmdline: identical to the M8.4 baseline. `console=hvc0` for the
// virtio-console kernel path (QEMU's `virtio-mmio` exposes hvc0
// before any device-tree walk completes); `earlycon=sbi` is the
// Linux 6.12 riscv64 generic earlycon that goes through the SBI
// debug-console call, available before any PCI/MMIO discovery.

//go:build phase2_oci_kernel_boot && tamago && riscv64

package main

var (
	kernelBootTargetRef = "https://ttl.sh/cloudboot-vmlinuz-riscv64:24h"
	kernelBootCmdline   = "console=hvc0 earlycon=sbi " +
		"root=/dev/ram0 rdinit=/init initrd=\\initrd.gz " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
	// kernelBootInitrdMode (M8.15, 2026-06-11): unified onto the
	// "espfile" path. See kernelboot_arm64.go M8.15 block for the
	// unification rationale. Historical: M8.11 proved the "protocol"
	// LoadFile2 path on riscv64.
	kernelBootInitrdMode = "espfile"
)
