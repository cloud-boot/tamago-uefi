// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for the COM1 serial debug
// helpers. The live tamago bodies live in serial_debug.go (plus
// per-arch serialOutB asm files); host builds only need symbol
// presence so test binaries that transitively import uefiboard can
// link.

//go:build !tamago

package uefiboard

// DbgChar is a no-op on host.
func DbgChar(c byte) { _ = c }

// DbgString is a no-op on host.
func DbgString(s string) { _ = s }

// DbgHex64 is a no-op on host.
func DbgHex64(v uint64) { _ = v }

// DbgLine is a no-op on host.
func DbgLine(prefix string, v uint64) {
	_ = prefix
	_ = v
}
