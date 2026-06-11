// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCIOpenBSDBootProbe` when the `phase3_oci_openbsd_boot`
// build tag is NOT set, or the binary is not built for tamago/amd64.
// Sprint 3 is amd64-only.

//go:build !phase3_oci_openbsd_boot || !tamago || !amd64

package main

// runOCIOpenBSDBootProbe is a no-op in any build that doesn't have
// `phase3_oci_openbsd_boot` set (or isn't a tamago/amd64 build).
func runOCIOpenBSDBootProbe() {}
