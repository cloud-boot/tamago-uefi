// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for loong64 (LoongArch64, M8.4
// per-arch landscape, 2026-06-10). Documentation for each variable
// lives next to its shared consumer in phase2_oci_kernel_boot.go.
//
// Loong64 status (M8.4): DORMANT. LoongArch64 is younger than
// riscv64 and the public OCI kernel ecosystem is even sparser. The
// expanded 60-min hunt on 2026-06-10 probed every known LoongArch-
// adjacent registry / org and found NO public anonymous OCI artifact
// shipping `/boot/vmlinuz` for loong64:
//
//   - siderolabs/kernel + installer + imager + talos: no loong64
//     entry across `latest`, `v1.11.0`, `v1.14.0-alpha.0-76-g09cb04e`
//     (latest nightly). No `*-loong64` arch-suffixed siderolabs
//     repos exist.
//   - tinkerbell/hook + bottlerocket + bootc images: no loong64.
//   - Kairos / k0sproject / oneblock-ai: no loong64 build.
//   - cr.loongnix.cn (the closest loong64-specific registry):
//     refuses anonymous access (HTTP 401 on /v2/_catalog and on
//     bearer-token requests). Pull requires a Loongnix account;
//     not viable for anonymous CI.
//   - ghcr.io/loong64/openeuler:24.03-{default,init,base}-20260426:
//     reachable, loong64 manifest present (94 / 92 / 92 MB), but
//     all three variants are dnf rootfs WITHOUT `/boot/vmlinuz`.
//   - ghcr.io/loong64/loongnix:23.1-default-20250822: reachable
//     (40 MB zstd) but AFS-overlay rootfs only, no kernel.
//   - ghcr.io/loong64/{anolis,opencloudos,kylin,alpine,debian}:
//     all rootfs-only variants of their respective distros.
//   - docker.io/openeuler/openeuler:24.03-lts: amd64 + arm64 only
//     (no loong64 in upstream Docker Hub index).
//   - docker.io/loongarch64/{debian,ubuntu}:* : MANIFEST_UNKNOWN.
//   - swr.cn-north-4.myhuaweicloud.com/openeuler/* and
//     dr.openkylin.top/*: not anonymously OCI-pullable (Huawei
//     Cloud auth + openKylin distributes ISO/squashfs over HTTP).
//   - registry.gitlab.com/loongarchlinux/*: GitLab registry
//     refuses anonymous reads.
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
// See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.4
// "Public ref landscape" for the full candidate table + upstream
// trackers where requests can be filed.

//go:build phase2_oci_kernel_boot && tamago && loong64

package main

var (
	kernelBootTargetRef         = ""
	kernelBootCmdline           = ""
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = false
)
