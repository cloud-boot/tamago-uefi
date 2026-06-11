// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — amd64 RNG trampoline-PC resolver.
//
// Sprint 1.3 split-out (R-fbsd1c): this file preserves the legacy
// funcval-first-word deref the M8.7 amd64 RNG path has shipped with
// since R-M8.6a. Sprint 1.2's amd64 fix scope was deliberately
// limited to the block_io_publish + sfs_publish trampolines (which
// PartitionDxe's driver-binding probe exercises heavily and
// reliably surfaces the ABIInternal-wrapper XMM/R14 clobber). The
// RNG path is invoked by the EFI-stub once at boot and has not
// manifested the symptom under M8.x, so we leave the existing
// resolution mechanism in place here and only switch to the
// LEAQ-direct asm helper on the 3 non-amd64 arches that Sprint 1.3
// patched defensively.
//
// If a future amd64-side RNG crash is diagnosed to the same
// ABIInternal-wrapper trailer pattern, the fix is to (a) add
// ·rngGetRNG_trampolinePC / ·rngGetInfo_trampolinePC asm helpers
// to rng_protocol_amd64.s (LEAQ form), and (b) replace this file's
// body with the same shape as
// rng_protocol_trampolinepc_arm64.go.

//go:build tamago && amd64

package uefiboard

import "unsafe"

// Function-value indirections so we can fish the asm entry PC out
// by reading the *funcval first word (same trick as
// loadFile_trampolineFV in initrd_protocol_tamago.go).
var (
	rngGetRNG_trampolineFV  = rngGetRNG_trampoline
	rngGetInfo_trampolineFV = rngGetInfo_trampoline
)

// rngTrampolinePCs returns (GetRNG, GetInfo) trampoline entry PCs
// via funcval-deref. See file docstring for the amd64-only
// rationale.
func rngTrampolinePCs() (uintptr, uintptr) {
	getRNGPC := **(**uintptr)(unsafe.Pointer(&rngGetRNG_trampolineFV))
	getInfoPC := **(**uintptr)(unsafe.Pointer(&rngGetInfo_trampolineFV))
	return getRNGPC, getInfoPC
}
