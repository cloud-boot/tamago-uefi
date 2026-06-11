// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — LoongArch64 firmware->Go callback trampolines
// for the published EFI_BLOCK_IO_PROTOCOL (Phase 3 sprint 1, multi-arch
// port — companion to block_io_publish_amd64.s).
//
// Four reverse-direction trampolines (firmware -> us, LP64 -> Go ABI0):
//
//   blockIO_reset_trampoline  -> ·blockIOResetGo(SB)        (2 args)
//   blockIO_read_trampoline   -> ·blockIOReadBlocksGo(SB)   (5 args)
//   blockIO_write_trampoline  -> ·blockIOWriteBlocksGo(SB)  (5 args)
//   blockIO_flush_trampoline  -> ·blockIOFlushBlocksGo(SB)  (1 arg)
//
// Mirrors rng_protocol_loong64.s for the ABI bridging conventions.
// On load/store arches the JAL stores the return address in R1 (RA),
// NOT on the stack — Go ABI0 reserves the SP+0..7 slot itself.
//
// LP64 ABI on entry (firmware -> us):
//
//   blockIO_reset:                          blockIO_read:
//     R4 (A0) = this                         R4 = this
//     R5 (A1) = extendedVerification         R5 = mediaID
//     ret in R4                              R6 = lba
//                                            R7 = bufferSize
//                                            R8 = buffer (A4)
//                                            ret in R4
//
//   blockIO_write:                          blockIO_flush:
//     same as read                           R4 = this
//                                            ret in R4
//
// R22 is the Go g register — DO NOT touch.
// R30 is the Go assembler scratch register — DO NOT store firmware
// values into it.
//
// R-fbsd1c (sprint 1.3, 2026-06-11) carryover: LoongArch64 LP64 FP
// callee-saved fs0..fs7 (F24..F31) save/restore is included
// defensively — Go's loong64 codegen may emit FP ops inside the Go
// callback. Same risk shape as the amd64 XMM fix.
//
// Uniform 240-byte frame across all 4 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 is the reserved
// saved-LR slot), so the ret-slot offset varies per arity:
//
//   1 arg  (Flush)        : args SP+8;          ret at SP+16
//   2 args (Reset)        : args SP+8..16;      ret at SP+24
//   5 args (Read, Write)  : args SP+8..40;      ret at SP+48
//
// Frame layout (offsets relative to post-prologue SP / R3):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg0 (this)
//   SP+16   arg1
//   SP+24   arg2
//   SP+32   arg3
//   SP+40   arg4
//   SP+48..SP+55  ret slot (5-arg form; other arities place earlier)
//   SP+56   saved R1  (RA)
//   SP+64   saved R23 (S0)
//   SP+72   saved R24 (S1)
//   SP+80   saved R25 (S2)
//   SP+88   saved R26 (S3)
//   SP+96   saved R27 (S4)
//   SP+104  saved R28 (S5)
//   SP+112  saved R29 (S6)
//   SP+120  saved R31 (S8)
//                       // R22 (S7/g) is g — DO NOT touch.
//                       // R30 is assembler-scratch — DO NOT touch.
//   SP+128  padding (16-byte alignment for FP area)
//   SP+136  padding
//   SP+144  saved F24 (FS0)
//   SP+152  saved F25 (FS1)
//   SP+160  saved F26 (FS2)
//   SP+168  saved F27 (FS3)
//   SP+176  saved F28 (FS4)
//   SP+184  saved F29 (FS5)
//   SP+192  saved F30 (FS6)
//   SP+200  saved F31 (FS7)
//   SP+208..SP+239  padding (16-byte alignment headroom)

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 carryover: mirror the amd64 LEAQ-direct pattern.
// On loong64 the equivalent is the assembler's `MOVV $sym(SB),Rn`
// pseudo, which expands to `PCADDU12I+ADDI` against the symbol's
// address — bypassing the Go ABIInternal wrapper that a funcval
// first-word deref would land on.
TEXT ·blockIO_reset_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·blockIO_reset_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·blockIO_read_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·blockIO_read_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·blockIO_write_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·blockIO_write_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·blockIO_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·blockIO_flush_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// func blockIO_reset_trampoline()
// Reset(this, extendedVerification) — 2 args, ret at SP+24.
TEXT ·blockIO_reset_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3

	MOVV	R1, 56(R3)    // RA
	MOVV	R23, 64(R3)   // S0
	MOVV	R24, 72(R3)   // S1
	MOVV	R25, 80(R3)   // S2
	MOVV	R26, 88(R3)   // S3
	MOVV	R27, 96(R3)   // S4
	MOVV	R28, 104(R3)  // S5
	MOVV	R29, 112(R3)  // S6
	MOVV	R31, 120(R3)  // S8

	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)

	MOVV	R4, 8(R3)   // this
	MOVV	R5, 16(R3)  // extendedVerification

	JAL	·blockIOResetGo(SB)

	MOVV	24(R3), R4  // ret slot for 2-arg form

	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31

	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// func blockIO_read_trampoline()
// ReadBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args, ret at SP+48.
TEXT ·blockIO_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3

	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)

	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)

	MOVV	R4, 8(R3)   // this
	MOVV	R5, 16(R3)  // mediaID
	MOVV	R6, 24(R3)  // lba
	MOVV	R7, 32(R3)  // bufferSize
	MOVV	R8, 40(R3)  // buffer

	JAL	·blockIOReadBlocksGo(SB)

	MOVV	48(R3), R4

	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31

	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// func blockIO_write_trampoline()
// WriteBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args.
TEXT ·blockIO_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3

	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)

	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)

	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)
	MOVV	R8, 40(R3)

	JAL	·blockIOWriteBlocksGo(SB)

	MOVV	48(R3), R4

	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31

	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// func blockIO_flush_trampoline()
// FlushBlocks(this) — 1 arg, ret at SP+16.
TEXT ·blockIO_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3

	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)

	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)

	MOVV	R4, 8(R3)   // this

	JAL	·blockIOFlushBlocksGo(SB)

	MOVV	16(R3), R4  // ret slot for 1-arg form

	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31

	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET
