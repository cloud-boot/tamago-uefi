// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- host stub for the exported raw-call thunk.
// EFICall has no meaning on a non-firmware target; the host build
// panics to surface the misuse loudly. See eficall_export.go for the
// tamago-side implementation.

//go:build !tamago

package uefiboard

// EFICall panics on the host build -- there is no firmware to call.
// See eficall_export.go for the tamago-side implementation.
func EFICall(fn, a0, a1, a2, a3, a4, a5 uint64) uint64 {
	panic("uefi: EFICall not supported on host")
}
