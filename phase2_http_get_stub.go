// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runHTTPGetProbe` when the `phase2_http_get` build tag is
// NOT set or the binary is not built for tamago.
//
// Matches the shape of the M4 / M3 / M2 / M1.6 stubs: a no-op function
// the dispatcher (phase2_dispatch.go) can call unconditionally so the
// call-site doesn't need `#ifdef`-style noise.

//go:build !phase2_http_get || !tamago

package main

// runHTTPGetProbe is a no-op in any build that doesn't have
// `phase2_http_get` set (or isn't a tamago build).
func runHTTPGetProbe() {}
