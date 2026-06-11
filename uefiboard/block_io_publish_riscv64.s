// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — RISC-V 64 firmware->Go callback trampolines
// for the published EFI_BLOCK_IO_PROTOCOL (Phase 3 sprint 1, multi-arch
// port — companion to block_io_publish_amd64.s).
//
// Four reverse-direction trampolines (firmware -> us, LP64D -> Go ABI0):
//
//   blockIO_reset_trampoline  -> ·blockIOResetGo(SB)        (2 args)
//   blockIO_read_trampoline   -> ·blockIOReadBlocksGo(SB)   (5 args)
//   blockIO_write_trampoline  -> ·blockIOWriteBlocksGo(SB)  (5 args)
//   blockIO_flush_trampoline  -> ·blockIOFlushBlocksGo(SB)  (1 arg)
//
// Mirrors rng_protocol_riscv64.s for the ABI bridging conventions.
// On load/store arches the JAL/CALL stores the return address in RA
// (X1), NOT on the stack — Go ABI0 reserves SP+0..7 itself so the
// Go callee reads its first arg at SP+8.
//
// LP64D ABI on entry (firmware -> us):
//
//   blockIO_reset:                          blockIO_read:
//     A0 = this                              A0 = this
//     A1 = extendedVerification              A1 = mediaID
//     ret in A0                              A2 = lba
//                                            A3 = bufferSize
//                                            A4 = buffer
//                                            ret in A0
//
//   blockIO_write:                          blockIO_flush:
//     same as read                           A0 = this
//                                            ret in A0
//
// X27 (S11) is the Go g register — DO NOT touch.
//
// R-fbsd1c (sprint 1.3, 2026-06-11) carryover: RISC-V psABI FP
// callee-saved fs0..fs11 (F8, F9, F18..F27) save/restore is included
// defensively — Go's riscv64 codegen may emit FP ops inside the Go
// callback. Same risk shape as the amd64 XMM fix.
//
// Uniform 288-byte frame across all 4 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 is the reserved
// saved-LR slot), so the ret-slot offset varies per arity:
//
//   1 arg  (Flush)        : args SP+8;          ret at SP+16
//   2 args (Reset)        : args SP+8..16;      ret at SP+24
//   5 args (Read, Write)  : args SP+8..40;      ret at SP+48
//
// Frame layout (offsets relative to post-prologue SP / X2):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg0 (this)
//   SP+16   arg1
//   SP+24   arg2
//   SP+32   arg3
//   SP+40   arg4
//   SP+48..SP+55  ret slot (5-arg form; other arities place earlier)
//   SP+56   saved RA  (X1)
//   SP+64   saved S0  (X8)
//   SP+72   saved S1  (X9)
//   SP+80   saved S2  (X18)
//   SP+88   saved S3  (X19)
//   SP+96   saved S4  (X20)
//   SP+104  saved S5  (X21)
//   SP+112  saved S6  (X22)
//   SP+120  saved S7  (X23)
//   SP+128  saved S8  (X24)
//   SP+136  saved S9  (X25)
//   SP+144  saved S10 (X26)
//                       // X27 (S11) is g — DO NOT touch.
//   SP+152  padding
//   SP+160  saved FS0  (F8)
//   SP+168  saved FS1  (F9)
//   SP+176  saved FS2  (F18)
//   SP+184  saved FS3  (F19)
//   SP+192  saved FS4  (F20)
//   SP+200  saved FS5  (F21)
//   SP+208  saved FS6  (F22)
//   SP+216  saved FS7  (F23)
//   SP+224  saved FS8  (F24)
//   SP+232  saved FS9  (F25)
//   SP+240  saved FS10 (F26)
//   SP+248  saved FS11 (F27)
//   SP+256..SP+287  padding (16-byte alignment headroom)

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 carryover: mirror the amd64 LEAQ-direct pattern.
// On riscv64 the equivalent is the assembler's `MOV $sym(SB),Rn`
// pseudo, which expands to `AUIPC+ADDI` against the symbol's address
// — bypassing the Go ABIInternal wrapper that a funcval first-word
// deref would land on.
TEXT ·blockIO_reset_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·blockIO_reset_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·blockIO_read_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·blockIO_read_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·blockIO_write_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·blockIO_write_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·blockIO_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·blockIO_flush_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

// func blockIO_reset_trampoline()
// Reset(this, extendedVerification) — 2 args, ret at SP+24.
TEXT ·blockIO_reset_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2

	MOV	X1, 56(X2)    // RA
	MOV	X8, 64(X2)    // S0
	MOV	X9, 72(X2)    // S1
	MOV	X18, 80(X2)   // S2
	MOV	X19, 88(X2)   // S3
	MOV	X20, 96(X2)   // S4
	MOV	X21, 104(X2)  // S5
	MOV	X22, 112(X2)  // S6
	MOV	X23, 120(X2)  // S7
	MOV	X24, 128(X2)  // S8
	MOV	X25, 136(X2)  // S9
	MOV	X26, 144(X2)  // S10

	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)

	MOV	A0, 8(X2)   // this
	MOV	A1, 16(X2)  // extendedVerification

	CALL	·blockIOResetGo(SB)

	MOV	24(X2), A0  // ret slot for 2-arg form

	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27

	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// func blockIO_read_trampoline()
// ReadBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args, ret at SP+48.
TEXT ·blockIO_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2

	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)

	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)

	MOV	A0, 8(X2)   // this
	MOV	A1, 16(X2)  // mediaID
	MOV	A2, 24(X2)  // lba
	MOV	A3, 32(X2)  // bufferSize
	MOV	A4, 40(X2)  // buffer

	CALL	·blockIOReadBlocksGo(SB)

	MOV	48(X2), A0

	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27

	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// func blockIO_write_trampoline()
// WriteBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args, identical
// shape to ReadBlocks.
TEXT ·blockIO_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2

	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)

	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)

	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	MOV	A3, 32(X2)
	MOV	A4, 40(X2)

	CALL	·blockIOWriteBlocksGo(SB)

	MOV	48(X2), A0

	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27

	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// func blockIO_flush_trampoline()
// FlushBlocks(this) — 1 arg, ret at SP+16.
TEXT ·blockIO_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2

	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)

	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)

	MOV	A0, 8(X2)   // this

	CALL	·blockIOFlushBlocksGo(SB)

	MOV	16(X2), A0  // ret slot for 1-arg form

	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27

	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET
