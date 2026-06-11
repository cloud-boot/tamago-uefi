// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — RISC-V 64 firmware->Go callback
// trampolines for EFI_RNG_PROTOCOL.GetRNG + GetInfo (Phase 2,
// M8.7 — R-M8.6a).
//
// Same shape as initrd_protocol_riscv64.s. On load/store arches the
// JAL/CALL instruction stores the return address in RA (X1), NOT
// on the stack, so unlike amd64 the Go ABI0 layout requires the
// caller to reserve the SP+0..7 slot itself; the callee's `.abi0`
// wrapper reads args at `caller_SP + 8 + N*8` and writes its
// result at `caller_SP + 8 + argsBytes`.
//
// LP64 ABI on entry (firmware -> us):
//
//   GetRNG:                              GetInfo:
//     A0 = this                            A0 = this
//     A1 = alg                             A1 = listSize  (UINTN *)
//     A2 = valueLength                     A2 = listPtr   (EFI_RNG_ALGORITHM *)
//     A3 = valuePtr                        ret in A0
//     ret in A0
//
// R-fbsd1c (sprint 1.3, 2026-06-11): added RISC-V psABI FP
// callee-saved fs0..fs11 (F8, F9, F18..F27) save/restore. Per the
// LP64D ABI the F-extension callee-saved set is the FS group: 12
// regs × 8 B = 96 B. Defensive — Go's riscv64 codegen may emit FP
// ops inside the Go callback, same risk shape as the amd64 XMM fix
// shipped in Sprint 1.2. Frame grew 160 → 256 B (still 16-byte
// aligned). Integer save offsets unchanged; FP area extends past.

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 follow-up: mirror the amd64 LEAQ-direct
// pattern. On riscv64 the equivalent is the assembler's
// `MOV $sym(SB),Rn` pseudo, which expands to `AUIPC+ADDI`
// against the symbol's address — bypassing the Go ABIInternal
// wrapper that a funcval first-word deref would land on.
TEXT ·rngGetRNG_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·rngGetRNG_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·rngGetInfo_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·rngGetInfo_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

// func rngGetRNG_trampoline()
//
// Frame layout (4 args + 1 ret slot, 256 bytes total):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg alg
//   SP+24   arg valueLength
//   SP+32   arg valuePtr
//   SP+40   ret status
//   SP+48   saved RA  (X1)
//   SP+56   saved S0  (X8)
//   SP+64   saved S1  (X9)
//   SP+72   saved S2  (X18)
//   SP+80   saved S3  (X19)
//   SP+88   saved S4  (X20)
//   SP+96   saved S5  (X21)
//   SP+104  saved S6  (X22)
//   SP+112  saved S7  (X23)
//   SP+120  saved S8  (X24)
//   SP+128  saved S9  (X25)
//   SP+136  saved S10 (X26)
//   SP+144  padding
//   SP+152  padding (16-byte alignment for FP area)
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
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-256, X2 // SP -= 256

	MOV	X1, 48(X2)    // RA
	MOV	X8, 56(X2)    // S0
	MOV	X9, 64(X2)    // S1
	MOV	X18, 72(X2)   // S2
	MOV	X19, 80(X2)   // S3
	MOV	X20, 88(X2)   // S4
	MOV	X21, 96(X2)   // S5
	MOV	X22, 104(X2)  // S6
	MOV	X23, 112(X2)  // S7
	MOV	X24, 120(X2)  // S8
	MOV	X25, 128(X2)  // S9
	MOV	X26, 136(X2)  // S10
	// X27 (S11) is the Go g register — DO NOT touch.

	// RISC-V psABI LP64D — fs0..fs11 are callee-saved.
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

	// Marshal EFI args (A0..A3) into Go ABI0 outgoing slots at
	// SP+8..SP+32 (skipping the SP+0 reserved slot).
	MOV	A0, 8(X2)   // this
	MOV	A1, 16(X2)  // alg
	MOV	A2, 24(X2)  // valueLength
	MOV	A3, 32(X2)  // valuePtr

	CALL	·rngGetRNGGo(SB)

	// Place EFI_STATUS in A0 for the firmware caller.
	MOV	40(X2), A0

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

	MOV	48(X2), X1
	MOV	56(X2), X8
	MOV	64(X2), X9
	MOV	72(X2), X18
	MOV	80(X2), X19
	MOV	88(X2), X20
	MOV	96(X2), X21
	MOV	104(X2), X22
	MOV	112(X2), X23
	MOV	120(X2), X24
	MOV	128(X2), X25
	MOV	136(X2), X26
	ADD	$256, X2
	RET

// func rngGetInfo_trampoline()
//
// Frame layout (3 args + 1 ret slot, 256 bytes total):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg listSize
//   SP+24   arg listPtr
//   SP+32   ret status
//   SP+40   saved RA  (X1)
//   SP+48..SP+136  saved S0..S10
//   SP+144 padding
//   SP+152 padding
//   SP+160..SP+248 saved FS0..FS11 (F8, F9, F18..F27)
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-256, X2

	MOV	X1, 40(X2)    // RA
	MOV	X8, 48(X2)    // S0
	MOV	X9, 56(X2)    // S1
	MOV	X18, 64(X2)   // S2
	MOV	X19, 72(X2)   // S3
	MOV	X20, 80(X2)   // S4
	MOV	X21, 88(X2)   // S5
	MOV	X22, 96(X2)   // S6
	MOV	X23, 104(X2)  // S7
	MOV	X24, 112(X2)  // S8
	MOV	X25, 120(X2)  // S9
	MOV	X26, 128(X2)  // S10

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

	// Marshal EFI args (A0..A2) into Go ABI0 outgoing slots at
	// SP+8..SP+24 (skipping the SP+0 reserved slot).
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)

	CALL	·rngGetInfoGo(SB)

	MOV	32(X2), A0

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

	MOV	40(X2), X1
	MOV	48(X2), X8
	MOV	56(X2), X9
	MOV	64(X2), X18
	MOV	72(X2), X19
	MOV	80(X2), X20
	MOV	88(X2), X21
	MOV	96(X2), X22
	MOV	104(X2), X23
	MOV	112(X2), X24
	MOV	120(X2), X25
	MOV	128(X2), X26
	ADD	$256, X2
	RET
