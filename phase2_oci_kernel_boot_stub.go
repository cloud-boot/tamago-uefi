// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCIKernelBootProbe` when the `phase2_oci_kernel_boot`
// build tag is NOT set or the binary is not built for tamago.
//
// Matches the shape of the M8.0 / M7 / M6 / M5 / M4 / M3 / M2 / M1.6
// stubs: a no-op function the dispatcher (phase2_dispatch.go) can
// call unconditionally so the call-site doesn't need `#ifdef`-style
// noise.

//go:build !phase2_oci_kernel_boot || !tamago

package main

// runOCIKernelBootProbe is a no-op in any build that doesn't have
// `phase2_oci_kernel_boot` set (or isn't a tamago build).
func runOCIKernelBootProbe() {}
