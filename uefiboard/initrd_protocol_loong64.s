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
// Frame layout (top-down, post-ADDV).
//
// R-M8.4a fix (2026-06-10): on load/store arches (loong64
// included) the JAL instruction stores the return address in R1
// (RA), NOT on the stack — so unlike amd64 the Go ABI0 layout
// requires the caller to reserve the SP+0..7 slot itself; the
// `loadFileGo.abi0` wrapper reads args at `caller_SP + 8 + N*8`
// and writes its result at `caller_SP + 48`. Same off-by-one bug
// hit on arm64 (live trace 2026-06-10 confirmed
// EFI_INVALID_PARAMETER from a NULL sizeP that was actually our
// bufP value); applying the same fix here pre-emptively so the
// other arches do not repeat the diagnosis cycle.
//
//   SP+0    reserved (Go ABI0 saved-LR slot — load/store arches
//           must reserve this; JAL does not push to memory)
//   SP+8    arg this
//   SP+16   arg filePath
//   SP+24   arg bp
//   SP+32   arg sizeP
//   SP+40   arg bufP
//   SP+48   ret status
//   SP+56   saved R1 (RA)
//   SP+64   saved R23 (S0)
//   SP+72   saved R24 (S1)
//   SP+80   saved R25 (S2)
//   SP+88   saved R26 (S3)
//   SP+96   saved R27 (S4)
//   SP+104  saved R28 (S5)
//   SP+112  saved R29 (S6)
//   SP+120  saved R31 (S8)
// Total: 128 bytes.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-128, R3 // SP -= 128

	// Save firmware-side callee-saved regs. R22 is Go's g — leave
	// it. R30 is the Go assembler scratch — also leave.
	MOVV	R1, 56(R3)    // RA
	MOVV	R23, 64(R3)   // S0
	MOVV	R24, 72(R3)   // S1
	MOVV	R25, 80(R3)   // S2
	MOVV	R26, 88(R3)   // S3
	MOVV	R27, 96(R3)   // S4
	MOVV	R28, 104(R3)  // S5
	MOVV	R29, 112(R3)  // S6
	MOVV	R31, 120(R3)  // S8

	// Marshal EFI args (R4..R8 == A0..A4) into Go ABI0 slots at
	// SP+8..SP+40 (skipping the SP+0 reserved slot — see the
	// frame layout comment above).
	MOVV	R4, 8(R3)   // this
	MOVV	R5, 16(R3)  // filePath
	MOVV	R6, 24(R3)  // bp
	MOVV	R7, 32(R3)  // sizeP
	MOVV	R8, 40(R3)  // bufP

	// Call Go-side handler.
	JAL	·loadFileGo(SB)

	// Place EFI_STATUS in A0 for the firmware caller.
	MOVV	48(R3), R4

	// Restore.
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$128, R3
	RET
