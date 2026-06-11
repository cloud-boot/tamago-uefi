// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side no-op stub for the Phase-3 DOOM bare-metal demo probe. When
// the `phase3_oci_doom_boot` build tag is NOT set (or the target arch
// is not amd64), runOCIDOOMBootProbe resolves to this no-op so the
// dispatcher's compile keeps shape across build variants.

//go:build !phase3_oci_doom_boot || !tamago || !amd64

package main

// runOCIDOOMBootProbe is a no-op when phase3_oci_doom_boot is not in
// effect for this build (wrong tag or non-amd64 GOARCH).
func runOCIDOOMBootProbe() {}
