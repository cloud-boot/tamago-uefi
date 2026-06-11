// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — arm64 RNG trampoline-PC resolver
// (Sprint 1.3 R-fbsd1c).
//
// Calls the per-arch asm helpers rngGetRNG_trampolinePC +
// rngGetInfo_trampolinePC defined in rng_protocol_arm64.s. Those
// use the assembler's `MOVD $sym(SB),Rn` pseudo (ADRP+ADD on arm64,
// the LEAQ-direct equivalent) to resolve directly to the asm
// trampoline's .abi0 entry — bypassing any Go ABIInternal wrapper.

//go:build tamago && arm64

package uefiboard

// Defined in rng_protocol_arm64.s.
func rngGetRNG_trampolinePC() uintptr
func rngGetInfo_trampolinePC() uintptr

// rngTrampolinePCs returns (GetRNG, GetInfo) trampoline entry PCs.
func rngTrampolinePCs() (uintptr, uintptr) {
	return rngGetRNG_trampolinePC(), rngGetInfo_trampolinePC()
}
