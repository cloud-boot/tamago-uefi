// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for the M8.4 R-M8.4a
// ConOut tracer. The live tamago bodies live in
// initrd_protocol_trace_tamago.go; host builds only need symbol
// presence so the host tests of loadFileGo (which conditionally call
// loadFileTraceLine) compile and skip the trace at runtime.

//go:build !tamago

package uefiboard

// LoadFileTraceEnabled is the package-global gate the tamago build
// reads from inside loadFileGo to decide whether to emit a per-call
// ConOut trace. On host builds the trace is unconditionally off — no
// ConOut exists and the unit tests in initrd_protocol_test.go
// exercise the pure logic.
var LoadFileTraceEnabled bool

// loadFileTraceLine is a no-op on host. The tamago build emits a
// ConOut diagnostic line; host tests simply do not exercise the
// trace path.
func loadFileTraceLine(tag string, labels []string, vals []uint64) {
	_ = tag
	_ = labels
	_ = vals
}
