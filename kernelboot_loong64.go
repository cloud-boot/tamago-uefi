// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for loong64 (LoongArch64, M8.3
// per-arch split, 2026-06-10). Documentation for each variable lives
// next to its shared consumer in phase2_oci_kernel_boot.go.
//
// Loong64 status (M8.3): DORMANT. LoongArch64 is younger than
// riscv64 and the public OCI kernel ecosystem is even sparser:
//
//   - siderolabs/kernel multi-arch index: no loong64 entry across
//     latest, v0.6.0-alpha.0-1-…, v1.11.0.
//   - tinkerbell/hook: no loong64 release artifact.
//   - Kairos / k0sproject: no loong64 build.
//   - cr.loongnix.cn (the closest loong64-specific registry):
//     refuses anonymous access (HTTP 401 on /v2/_catalog and on
//     bearer-token requests). Pull would require a Loongnix
//     account; not viable for anonymous CI.
//   - docker.io/loongarch64/debian:sid: present but is a rootfs
//     image without /boot/vmlinuz (same shape as the amd64 base
//     image — kernel ships separately).
//
// The wiring below stays at "" so the runtime path collapses to
// MODE B (self-test against the in-process Transport using the
// embedded chained EFI bytes for loong64). The split + constants
// remain in tree so flipping to MODE C is a one-line change the
// day a public anonymous loong64 EFI-stub kernel OCI artifact
// appears.
//
// Suggested values once a public ref exists:
//   kernelBootTargetRef = "https://<host>/<repo>:<tag>"
//   kernelBootCmdline   = "console=ttyS0,115200"  (QEMU virt loong64;
//                                                   the LoongArch
//                                                   `virt` machine
//                                                   exposes a single
//                                                   16550-compatible
//                                                   UART at the
//                                                   default address).
//
// See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.3 for
// the per-arch matrix.

//go:build phase2_oci_kernel_boot && tamago && loong64

package main

var (
	kernelBootTargetRef         = ""
	kernelBootCmdline           = ""
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = false
)
