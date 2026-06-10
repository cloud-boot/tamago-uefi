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

#include "textflag.h"

// func rngGetRNG_trampoline()
//
// Frame layout (4 args + 1 ret slot, 144 bytes):
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
//   SP+128  padding
//   SP+136  padding (16-byte alignment)
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-144, R3 // SP -= 144

	MOVV	R1, 48(R3)    // RA
	MOVV	R23, 56(R3)   // S0
	MOVV	R24, 64(R3)   // S1
	MOVV	R25, 72(R3)   // S2
	MOVV	R26, 80(R3)   // S3
	MOVV	R27, 88(R3)   // S4
	MOVV	R28, 96(R3)   // S5
	MOVV	R29, 104(R3)  // S6
	MOVV	R31, 112(R3)  // S8

	// Marshal EFI args (R4..R7) into Go ABI0 slots at SP+8..SP+32.
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)

	JAL	·rngGetRNGGo(SB)

	// Place EFI_STATUS in A0 (R4) for the firmware caller.
	MOVV	40(R3), R4

	MOVV	48(R3), R1
	MOVV	56(R3), R23
	MOVV	64(R3), R24
	MOVV	72(R3), R25
	MOVV	80(R3), R26
	MOVV	88(R3), R27
	MOVV	96(R3), R28
	MOVV	104(R3), R29
	MOVV	112(R3), R31
	ADDV	$144, R3
	RET

// func rngGetInfo_trampoline()
//
// Frame layout (3 args + 1 ret slot, 128 bytes):
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
//   SP+120  padding (16-byte alignment)
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-128, R3

	MOVV	R1, 40(R3)
	MOVV	R23, 48(R3)
	MOVV	R24, 56(R3)
	MOVV	R25, 64(R3)
	MOVV	R26, 72(R3)
	MOVV	R27, 80(R3)
	MOVV	R28, 88(R3)
	MOVV	R29, 96(R3)
	MOVV	R31, 104(R3)

	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)

	JAL	·rngGetInfoGo(SB)

	MOVV	32(R3), R4

	MOVV	40(R3), R1
	MOVV	48(R3), R23
	MOVV	56(R3), R24
	MOVV	64(R3), R25
	MOVV	72(R3), R26
	MOVV	80(R3), R27
	MOVV	88(R3), R28
	MOVV	96(R3), R29
	MOVV	104(R3), R31
	ADDV	$128, R3
	RET
