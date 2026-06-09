// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runOCICosignVerifyProbe` when the
// `phase2_oci_cosign_verify` build tag is NOT set or the binary is
// not built for tamago.
//
// Matches the shape of the other phase-2 stubs: a no-op function the
// dispatcher (phase2_dispatch.go) can call unconditionally so the
// call-site doesn't need `#ifdef`-style noise.

//go:build !phase2_oci_cosign_verify || !tamago

package main

// runOCICosignVerifyProbe is a no-op in any build that doesn't have
// `phase2_oci_cosign_verify` set (or isn't a tamago build).
func runOCICosignVerifyProbe() {}
