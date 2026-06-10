// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for riscv64 (M8.4 per-arch
// landscape, 2026-06-10). Documentation for each variable lives
// next to its shared consumer in phase2_oci_kernel_boot.go.
//
// Riscv64 status (M8.4): DORMANT. A second 60-min OCI hunt on
// 2026-06-10 (following the initial 30-min hunt) probed 20+ public
// OCI registries / orgs / namespaces and surfaced NO publicly-
// anonymous-pullable EFI-stub Linux kernel suitable for the
// streaming + LoadImage + StartImage path. Findings summary:
//
//   - siderolabs/kernel: amd64 + arm64 only across `latest`,
//     `v1.11.0`, and `v1.14.0-alpha.0-76-g09cb04e` (latest nightly).
//     No `kernel-riscv64` / `installer-riscv64` arch-suffixed repos
//     exist (HTTP 401 = nonexistent under anonymous ghcr.io scope).
//   - siderolabs/talos: same shape (amd64 + arm64). The
//     `talosctl-linux-riscv64` artefact is a CLI binary, NOT a
//     kernel OCI layer.
//   - tinkerbell/hook + hook-kernel: MANIFEST_UNKNOWN for `:latest`
//     across ghcr.io and quay.io. Hook releases ship arm64 +
//     x86_64 tarballs only.
//   - bootc images (quay.io/fedora/fedora-bootc, centos-bootc) DO
//     ship `/usr/lib/modules/<ver>/vmlinuz` but multi-arch index
//     covers amd64/arm64/ppc64le/s390x only.
//   - Bottlerocket (public.ecr.aws/bottlerocket/*): no rv64.
//   - distro base rootfs images (debian:sid, ubuntu:noble,
//     alpine:latest, opensuse/tumbleweed) DO include rv64 manifests
//     (46 MB / 26 MB / 3.6 MB / 37.6 MB respectively) but ship as
//     pure rootfs WITHOUT `/boot/vmlinuz` — kernel comes from a
//     follow-on `apt install linux-image-riscv64` / `apk add
//     linux-virt`, neither reachable from a non-running TamaGo EFI.
//   - ghcr.io/loong64/openeuler rv64 variant (the only multi-arch
//     openEuler with rv64 entries) is dnf rootfs only, 87.7 MB.
//   - quay.io/fedora-coreos + registry.fedoraproject.org/fedora:
//     no rv64 in multi-arch index.
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
// See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.4
// "Public ref landscape" for the full candidate table + upstream
// trackers where requests can be filed.

//go:build phase2_oci_kernel_boot && tamago && riscv64

package main

var (
	kernelBootTargetRef         = ""
	kernelBootCmdline           = ""
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = false
)
