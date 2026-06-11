// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — LoongArch64 firmware->Go callback
// trampolines for EFI_RNG_PROTOCOL.GetRNG + GetInfo (Phase 2,
// M8.7 — R-M8.6a).
//
// Same shape as initrd_protocol_loong64.s. On load/store arches
// the JAL instruction stores the return address in R1 (RA), NOT
// on the stack — Go ABI0 reserves the SP+0..7 slot itself.
//
// LP64 ABI on entry (firmware -> us):
//
//   GetRNG:                              GetInfo:
//     R4 (A0) = this                       R4 = this
//     R5 (A1) = alg                        R5 = listSize  (UINTN *)
//     R6 (A2) = valueLength                R6 = listPtr   (EFI_RNG_ALGORITHM *)
//     R7 (A3) = valuePtr                   ret in R4
//     ret in R4
//
// R22 is the Go g register — DO NOT touch.
// R30 is the Go assembler scratch register — DO NOT store firmware values into it.
//
// R-fbsd1c (sprint 1.3, 2026-06-11): added LoongArch64 LP64 FP
// callee-saved fs0..fs7 (F24..F31) save/restore. 8 regs × 8 B =
// 64 B of FP save area added. Defensive — Go's loong64 codegen may
// emit FP ops inside the Go callback, same risk shape as the amd64
// XMM fix shipped in Sprint 1.2. Frame for GetRNG grew 144 → 208 B
// and for GetInfo grew 128 → 192 B (still 16-byte aligned).

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 follow-up: mirror the amd64 LEAQ-direct
// pattern. On loong64 the equivalent is the assembler's
// `MOVV $sym(SB),Rn` pseudo, which expands to `PCADDU12I+ADDI`
// against the symbol's address — bypassing the Go ABIInternal
// wrapper that a funcval first-word deref would land on.
TEXT ·rngGetRNG_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·rngGetRNG_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·rngGetInfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·rngGetInfo_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// func rngGetRNG_trampoline()
//
// Frame layout (4 args + 1 ret slot, 208 bytes):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg alg
//   SP+24   arg valueLength
//   SP+32   arg valuePtr
//   SP+40   ret status
//   SP+48   saved R1 (RA)
//   SP+56   saved R23 (S0)
//   SP+64   saved R24 (S1)
//   SP+72   saved R25 (S2)
//   SP+80   saved R26 (S3)
//   SP+88   saved R27 (S4)
//   SP+96   saved R28 (S5)
//   SP+104  saved R29 (S6)
//   SP+112  saved R31 (S8)
//   SP+120  padding
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
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-208, R3 // SP -= 208

	MOVV	R1, 48(R3)    // RA
	MOVV	R23, 56(R3)   // S0
	MOVV	R24, 64(R3)   // S1
	MOVV	R25, 72(R3)   // S2
	MOVV	R26, 80(R3)   // S3
	MOVV	R27, 88(R3)   // S4
	MOVV	R28, 96(R3)   // S5
	MOVV	R29, 104(R3)  // S6
	MOVV	R31, 112(R3)  // S8

	// LoongArch64 LP64 — F24..F31 (fs0..fs7) are callee-saved.
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)

	// Marshal EFI args (R4..R7) into Go ABI0 slots at SP+8..SP+32.
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)

	JAL	·rngGetRNGGo(SB)

	// Place EFI_STATUS in A0 (R4) for the firmware caller.
	MOVV	40(R3), R4

	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31

	MOVV	48(R3), R1
	MOVV	56(R3), R23
	MOVV	64(R3), R24
	MOVV	72(R3), R25
	MOVV	80(R3), R26
	MOVV	88(R3), R27
	MOVV	96(R3), R28
	MOVV	104(R3), R29
	MOVV	112(R3), R31
	ADDV	$208, R3
	RET

// func rngGetInfo_trampoline()
//
// Frame layout (3 args + 1 ret slot, 192 bytes):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg listSize
//   SP+24   arg listPtr
//   SP+32   ret status
//   SP+40   saved R1 (RA)
//   SP+48   saved R23 (S0)
//   SP+56   saved R24 (S1)
//   SP+64   saved R25 (S2)
//   SP+72   saved R26 (S3)
//   SP+80   saved R27 (S4)
//   SP+88   saved R28 (S5)
//   SP+96   saved R29 (S6)
//   SP+104  saved R31 (S8)
//   SP+112  padding
//   SP+120  padding (16-byte alignment for FP area)
//   SP+128  saved F24 (FS0)
//   SP+136  saved F25 (FS1)
//   SP+144  saved F26 (FS2)
//   SP+152  saved F27 (FS3)
//   SP+160  saved F28 (FS4)
//   SP+168  saved F29 (FS5)
//   SP+176  saved F30 (FS6)
//   SP+184  saved F31 (FS7)
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-192, R3

	MOVV	R1, 40(R3)
	MOVV	R23, 48(R3)
	MOVV	R24, 56(R3)
	MOVV	R25, 64(R3)
	MOVV	R26, 72(R3)
	MOVV	R27, 80(R3)
	MOVV	R28, 88(R3)
	MOVV	R29, 96(R3)
	MOVV	R31, 104(R3)

	MOVD	F24, 128(R3)
	MOVD	F25, 136(R3)
	MOVD	F26, 144(R3)
	MOVD	F27, 152(R3)
	MOVD	F28, 160(R3)
	MOVD	F29, 168(R3)
	MOVD	F30, 176(R3)
	MOVD	F31, 184(R3)

	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)

	JAL	·rngGetInfoGo(SB)

	MOVV	32(R3), R4

	MOVD	128(R3), F24
	MOVD	136(R3), F25
	MOVD	144(R3), F26
	MOVD	152(R3), F27
	MOVD	160(R3), F28
	MOVD	168(R3), F29
	MOVD	176(R3), F30
	MOVD	184(R3), F31

	MOVV	40(R3), R1
	MOVV	48(R3), R23
	MOVV	56(R3), R24
	MOVV	64(R3), R25
	MOVV	72(R3), R26
	MOVV	80(R3), R27
	MOVV	88(R3), R28
	MOVV	96(R3), R29
	MOVV	104(R3), R31
	ADDV	$192, R3
	RET
