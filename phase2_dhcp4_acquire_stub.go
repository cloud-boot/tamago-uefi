// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runDHCP4AcquireProbe` when the `phase2_dhcp4_acquire`
// build tag is NOT set or the binary is not built for tamago.
//
// Matches the shape of the M3 / M2 / M1.6 / M1.5 stubs: a no-op
// function the dispatcher (phase2_dispatch.go) can call
// unconditionally so the call-site doesn't need `#ifdef`-style noise.

//go:build !phase2_dhcp4_acquire || !tamago

package main

// runDHCP4AcquireProbe is a no-op in any build that doesn't have
// `phase2_dhcp4_acquire` set (or isn't a tamago build).
func runDHCP4AcquireProbe() {}
