// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for amd64 (M8.3 per-arch split,
// 2026-06-10; M8.13 Debian-13 unification, 2026-06-10). Documentation
// for each variable lives next to its shared consumer in
// phase2_oci_kernel_boot.go.
//
// M8.13 — Debian-13 unification across all 4 arches (2026-06-10)
//
// Until M8.12 the amd64 wiring was DORMANT — `kernelBootTargetRef`
// was an empty string because amd64 live tests are blocked behind
// the OVMF >4 MiB firmware-size sprint on the m6-2-pr2-amd64-wip
// branch. M8.13 populates the amd64 const constants so that the
// moment the firmware-size blocker closes, MODE C works
// automatically — same flow as arm64/riscv64/loong64, single
// source-of-truth Debian-13 kernel.
//
// Source: Debian 13 `linux-signed-amd64` (trixie) signed kernel
// package, /boot/vmlinuz-6.12.90+deb13.1-amd64, extracted as a
// PE32+ EFI-stub binary (MZ + PE\0\0 + COFF Machine 0x8664). The
// amd64 vmlinuz is the standard Debian bzImage + EFI-stub header
// (12 MiB raw; 12 MiB layer because already-zlib-compressed bzImage
// barely shrinks under outer gzip — ratio 98%, vs 38% for the
// uncompressed arm64 Image).
//
// Published at ttl.sh/cloudboot-vmlinuz-amd64:24h, re-pushed nightly
// by .github/workflows/vmlinuz-nightly.yml alongside arm64 + riscv64
// + loong64.
//
// Cmdline: amd64-specific console (16550 ttyS0 vs ARM PL011 + RISC-V
// hvc0/SBI + loong64 ttyS0):
//
//   - console=ttyS0,115200    : QEMU virt 16550 UART.
//   - earlyprintk=ttyS0,115200: early-boot output before serial-line
//                               discipline registers.
//   - keep_bootcon            : keep earlycon alive (parallel to arm64).
//   - printk.time=y           : `[ x.xxx]` timestamp prefix.
//   - root=/dev/ram0 rdinit=/init : initramfs ramdisk + PID 1.
//   - loglevel=8 panic=10     : verbose printk + auto-reboot.
//
// Verify-the-kernel one-shot manual re-publish (if cron is stale):
//
//   /tmp/cb-extract/cloudboot-oci-extract \
//     -src 'deb:https://deb.debian.org/debian/pool/main/l/linux-signed-amd64/linux-image-6.12.90+deb13.1-amd64_6.12.90-2_amd64.deb' \
//     -arch amd64 \
//     -dst 'ttl.sh/cloudboot-vmlinuz-amd64:24h' \
//     -cmdline-hint 'console=ttyS0,115200 earlyprintk=ttyS0,115200'
//
// amd64 live test gating: still blocked behind the OVMF >4 MiB
// firmware-size sprint (m6-2-pr2-amd64-wip). When that sprint lands,
// `task kernelboot:live:amd64` should reach `Run /init as init process`
// and the Path D banner with ZERO further wiring changes — the
// per-arch initramfs (initramfs_amd64.cpio.gz embed gated by
// //go:build amd64) follows the same pattern as the riscv64+loong64
// M8.11/M8.12 fan-out.

//go:build phase2_oci_kernel_boot && tamago && amd64

package main

var (
	kernelBootTargetRef = "https://ttl.sh/cloudboot-vmlinuz-amd64:24h"
	kernelBootCmdline   = "console=ttyS0,115200 earlyprintk=ttyS0,115200 " +
		"keep_bootcon printk.time=y " +
		"root=/dev/ram0 rdinit=/init " +
		"loglevel=8 panic=10"
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = true
)
