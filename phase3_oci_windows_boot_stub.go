// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCIWindowsBootProbe` when the
// `phase3_oci_windows_boot` build tag is NOT set, or the binary is
// not built for tamago/amd64. Sprint 4 is amd64-only — arm64,
// riscv64, and loong64 don't yet have publisher trampolines for
// EFI_BLOCK_IO_PROTOCOL, so this stub also catches those tamago
// builds.

//go:build !phase3_oci_windows_boot || !tamago || !amd64

package main

// runOCIWindowsBootProbe is a no-op in any build that doesn't have
// `phase3_oci_windows_boot` set (or isn't a tamago/amd64 build).
func runOCIWindowsBootProbe() {}
