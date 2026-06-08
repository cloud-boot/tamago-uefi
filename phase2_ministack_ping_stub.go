// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runMinistackPingProbe` when the
// `phase2_ministack_ping` build tag is NOT set or the binary is not
// built for tamago.
//
// Matches the shape of the M2 / M1.6 / M1.5 stubs: a no-op function
// the dispatcher (phase2_dispatch.go) can call unconditionally so
// the call-site doesn't need `#ifdef`-style noise.

//go:build !phase2_ministack_ping || !tamago

package main

// runMinistackPingProbe is a no-op in any build that doesn't have
// `phase2_ministack_ping` set (or isn't a tamago build).
func runMinistackPingProbe() {}
