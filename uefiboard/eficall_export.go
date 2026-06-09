// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- exported raw-call thunk for protocol
// interfaces obtained dynamically at runtime (e.g.
// EFI_FILE_PROTOCOL handles returned by SimpleFileSystem.OpenVolume).
//
// The internal efiCall is package-private (board.go) and used by every
// in-package wrapper. Some callers -- the M6.2 self-extracting stub in
// particular -- need to invoke function-pointer slots on protocol
// interfaces this package doesn't pre-wrap (EFI_FILE_PROTOCOL.Open,
// EFI_FILE_PROTOCOL.Read, etc). Rather than wrap every such protocol
// here, we expose the raw 6-arg thunk so out-of-package callers can
// drive arbitrary firmware-side function pointers using the same
// MS x64 / AAPCS64 / LP64 calling convention every other wrapper relies
// on.
//
// Usage:
//
//	// status := EFI_FILE_PROTOCOL->Read(file, &size, buffer)
//	status := uefiboard.EFICall(
//	    filePtr + 32, // Read slot offset
//	    filePtr,
//	    uint64(uintptr(unsafe.Pointer(&size))),
//	    uint64(uintptr(unsafe.Pointer(&buf[0]))),
//	    0, 0, 0,
//	)
//
// The fn argument is the *absolute* address of the function-pointer
// SLOT (i.e. base + offset); the thunk reads the pointer at that slot
// and jumps to it. This matches every other call shape in the package.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// EFICall invokes a UEFI service through its function-pointer slot.
// Thin exported wrapper around the package-private efiCall thunk.
// Returns the raw EFI_STATUS in the low 64 bits.
func EFICall(fn, a0, a1, a2, a3, a4, a5 uint64) uint64 {
	return efiCall(fn, a0, a1, a2, a3, a4, a5)
}
