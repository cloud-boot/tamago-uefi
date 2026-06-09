// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCIORASFetchProbe` when the `phase2_oci_oras_fetch`
// build tag is NOT set or the binary is not built for tamago. Same
// shape as phase2_oci_fetch_stub.go.

//go:build !phase2_oci_oras_fetch || !tamago

package main

// runOCIORASFetchProbe is a no-op in any build without
// `phase2_oci_oras_fetch` set (or non-tamago).
func runOCIORASFetchProbe() {}
