// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — arm64 BlockIO trampoline-PC resolvers
// (Phase 3 sprint 1.4 multi-arch port, R-fbsd1d).
//
// Declares the asm-defined per-trampoline PC helpers from
// block_io_publish_arm64.s. Each helper uses the assembler's
// `MOVD $sym(SB),Rn` pseudo (ADRP+ADD on arm64, the LEAQ-direct
// equivalent) to resolve directly to the asm trampoline's .abi0
// entry — bypassing any Go ABIInternal wrapper whose epilogue
// might clobber callee-saved regs AFTER our .abi0 epilogue
// restored them. See R-fbsd1a sprint 1.2 commentary in
// block_io_publish_amd64.s for the firmware-side failure shape
// that motivated this pattern.

//go:build tamago && arm64

package uefiboard

// Defined in block_io_publish_arm64.s.
func blockIO_reset_trampolinePC() uintptr
func blockIO_read_trampolinePC() uintptr
func blockIO_write_trampolinePC() uintptr
func blockIO_flush_trampolinePC() uintptr
