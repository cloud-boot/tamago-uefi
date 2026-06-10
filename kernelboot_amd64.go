// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Per-arch kernel-boot constants for amd64 (M8.3 per-arch split,
// 2026-06-10). Documentation for each variable lives next to its
// shared consumer in phase2_oci_kernel_boot.go.
//
// Amd64 status (M8.3): the siderolabs/kernel multi-arch index DOES
// ship an amd64 per-arch manifest (sha256:a64e528f... at
// v0.6.0-alpha.0-1-ge8ed5bc), and the layer shape is presumed to
// match arm64 (boot/vmlinuz, PE32+ MZ). Wiring is left DORMANT
// (kernelBootTargetRef = "") in this file because amd64 live tests
// are blocked behind the parallel OVMF >4 MiB threshold debug sprint
// on the m6-2-pr2-amd64-wip branch (per the M8.1 brief). Flip to
// the siderolabs ref + the cmdline below once that sprint lands.
//
// Suggested values once unblocked:
//   kernelBootTargetRef = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"
//   kernelBootCmdline   = "console=ttyS0,115200 earlyprintk=ttyS0,115200"

//go:build phase2_oci_kernel_boot && tamago && amd64

package main

var (
	kernelBootTargetRef         = ""
	kernelBootCmdline           = ""
	kernelBootInitrdRef         = ""
	kernelBootUseEmbeddedInitrd = false
)
