// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for riscv64 (M8.3 per-arch split,
// 2026-06-10). Documentation for each variable lives next to its
// shared consumer in phase2_oci_kernel_boot.go.
//
// Riscv64 status (M8.3): DORMANT. The 30-min OCI hunt on 2026-06-10
// surfaced no publicly-anonymous-pullable EFI-stub Linux kernel
// suitable for the streaming + LoadImage + StartImage path:
//
//   - siderolabs/kernel multi-arch index ships ONLY amd64 + arm64
//     (probed 2026-06-10 against tags latest, v0.6.0-alpha.0-1-…,
//     v1.11.0).
//   - siderolabs/talos releases publish a talosctl-linux-riscv64
//     CLI binary but no kernel artifact.
//   - tinkerbell/hook releases (the closest OCI-style kernel
//     publisher) ship arm64 + x86_64 only — no riscv64 tarball.
//   - Kairos releases (kairos-io/kairos) are amd64-only at v4.1.0.
//   - cr.loongnix.cn (proximity check) refuses anonymous access.
//   - opensuse / fedora-coreos riscv64 entries returned 404 at the
//     expected v2 paths.
//
// The wiring below stays at "" so the runtime path collapses to
// MODE B (self-test against the in-process Transport using the
// embedded chained EFI bytes for riscv64). The split + constants
// remain in tree so flipping to MODE C is a one-line change the
// day a public anonymous riscv64 EFI-stub kernel OCI artifact
// appears.
//
// Suggested values once a public ref exists:
//   kernelBootTargetRef = "https://<host>/<repo>:<tag>"
//   kernelBootCmdline   = "console=hvc0 earlycon=sbi"   (QEMU virt
//                                                        riscv64;
//                                                        SBI early-
//                                                        console
//                                                        works
//                                                        before
//                                                        any UART
//                                                        is up).
//
// See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.3 for
// the per-arch matrix.

//go:build phase2_oci_kernel_boot && tamago && riscv64

package main

var (
	kernelBootTargetRef         = ""
	kernelBootCmdline           = ""
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = false
)
