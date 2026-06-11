// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — loong64 RNG trampoline-PC resolver
// (Sprint 1.3 R-fbsd1c).
//
// Calls the per-arch asm helpers rngGetRNG_trampolinePC +
// rngGetInfo_trampolinePC defined in rng_protocol_loong64.s. Those
// use the assembler's `MOVV $sym(SB),Rn` pseudo (PCADDU12I+ADDI on
// loong64, the LEAQ-direct equivalent) to resolve directly to the
// asm trampoline's .abi0 entry — bypassing any Go ABIInternal
// wrapper.

//go:build tamago && loong64

package uefiboard

// Defined in rng_protocol_loong64.s.
func rngGetRNG_trampolinePC() uintptr
func rngGetInfo_trampolinePC() uintptr

// rngTrampolinePCs returns (GetRNG, GetInfo) trampoline entry PCs.
func rngTrampolinePCs() (uintptr, uintptr) {
	return rngGetRNG_trampolinePC(), rngGetInfo_trampolinePC()
}
