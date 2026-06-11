// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCINetBSDBootProbe` when the `phase3_oci_netbsd_boot`
// build tag is NOT set, or the binary is not built for tamago/amd64.
// Sprint 3 is amd64-only — arm64, riscv64, and loong64 don't yet
// have publisher trampolines for EFI_BLOCK_IO_PROTOCOL, so this stub
// also catches those tamago builds.

//go:build !phase3_oci_netbsd_boot || !tamago || !amd64

package main

// runOCINetBSDBootProbe is a no-op in any build that doesn't have
// `phase3_oci_netbsd_boot` set (or isn't a tamago/amd64 build).
func runOCINetBSDBootProbe() {}
