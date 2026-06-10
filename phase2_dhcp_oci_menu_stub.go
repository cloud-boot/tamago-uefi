// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runDHCPOCIMenuProbe` when the `phase2_dhcp_oci_menu`
// build tag is NOT set or the binary is not built for tamago.
//
// Matches the shape of the other phase2 stubs: a no-op the dispatcher
// (phase2_dispatch.go) can call unconditionally so the call-site
// doesn't need `#ifdef`-style noise.

//go:build !phase2_dhcp_oci_menu || !tamago

package main

// runDHCPOCIMenuProbe is a no-op in any build that doesn't have
// `phase2_dhcp_oci_menu` set (or isn't a tamago build).
func runDHCPOCIMenuProbe() {}
