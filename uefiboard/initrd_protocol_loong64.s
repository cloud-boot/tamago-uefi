// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — LoongArch64 firmware->Go callback
// trampoline for EFI_LOAD_FILE2_PROTOCOL.LoadFile (Phase 2, M8.2
// follow-up).
//
// REVERSE direction from eficall_loong64.s: firmware (Linux
// EFI-stub) calls into this thunk via LoongArch LP64, and we
// marshal into Go ABI0 and call ·loadFileGo.
//
// LP64 ABI on entry (firmware -> us):
//   R4..R11 (A0..A7): args (this, filePath, bp, sizeP, bufP, ...)
//   R4 (A0): return EFI_STATUS
//   callee-saved: R22 (S9 / Go g register — DO NOT touch),
//                 R23..R31 (S0..S8) + R1 (RA) + R3 (SP).
//   R30 is the Go assembler scratch register; we avoid storing
//   firmware values into it.
//
// Frame layout (top-down, post-ADDV):
//   SP+0    arg this
//   SP+8    arg filePath
//   SP+16   arg bp
//   SP+24   arg sizeP
//   SP+32   arg bufP
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
//   SP+120  padding (16-byte alignment)
// Total: 128 bytes.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-128, R3 // SP -= 128

	// Save firmware-side callee-saved regs. R22 is Go's g — leave
	// it. R30 is the Go assembler scratch — also leave.
	MOVV	R1, 48(R3)    // RA
	MOVV	R23, 56(R3)   // S0
	MOVV	R24, 64(R3)   // S1
	MOVV	R25, 72(R3)   // S2
	MOVV	R26, 80(R3)   // S3
	MOVV	R27, 88(R3)   // S4
	MOVV	R28, 96(R3)   // S5
	MOVV	R29, 104(R3)  // S6
	MOVV	R31, 112(R3)  // S8

	// Marshal EFI args (R4..R8 == A0..A4) into Go ABI0 slots.
	MOVV	R4, 0(R3)   // this
	MOVV	R5, 8(R3)   // filePath
	MOVV	R6, 16(R3)  // bp
	MOVV	R7, 24(R3)  // sizeP
	MOVV	R8, 32(R3)  // bufP

	// Call Go-side handler.
	JAL	·loadFileGo(SB)

	// Place EFI_STATUS in A0 for the firmware caller.
	MOVV	40(R3), R4

	// Restore.
	MOVV	48(R3), R1
	MOVV	56(R3), R23
	MOVV	64(R3), R24
	MOVV	72(R3), R25
	MOVV	80(R3), R26
	MOVV	88(R3), R27
	MOVV	96(R3), R28
	MOVV	104(R3), R29
	MOVV	112(R3), R31
	ADDV	$128, R3
	RET
