// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — aarch64 firmware->Go callback trampoline
// for EFI_LOAD_FILE2_PROTOCOL.LoadFile (Phase 2, M8.2 follow-up).
//
// This is the REVERSE direction from eficall_arm64.s: the firmware
// (the Linux EFI-stub on the kernel side) calls into this thunk
// via the AAPCS64 calling convention, and the thunk in turn calls
// into Go-side loadFileGo using Go ABI0.
//
// AAPCS64 ABI on entry (firmware -> us):
//   X0 = this      (EFI_LOAD_FILE2_PROTOCOL *)
//   X1 = filePath  (EFI_DEVICE_PATH_PROTOCOL *)
//   X2 = bootPolicy (BOOLEAN, UINT8 widened to UINTN)
//   X3 = bufferSize (UINTN *)
//   X4 = buffer     (VOID *)
//   ret in X0 (EFI_STATUS)
//   callee-saved: X19..X28, X29 (FP), X30 (LR), D8..D15
//   (X28 is the Go g register, X27 the assembler scratch — we MUST
//   leave g intact across our save/restore window so Go-side code
//   we call sees the right g.)
//
// Strategy:
//   1. Stash X29 (FP) + X30 (LR) + the seven AAPCS64-callee-saved
//      integer regs Go's compiled functions might touch — X19..X25.
//      (X26..X28 the Go runtime also flags callee-saved on its own
//      compiled output, so they survive the BL automatically; we
//      still re-save X29/X30 explicitly because the BL re-binds
//      X30 and Go's stack walker expects a well-formed frame at
//      (FP, LR).)
//   2. Set up a Go-ABI0 outgoing frame holding the 5 args at
//      0(SP)..32(SP) and reserve a return slot at 40(SP).
//   3. CALL ·loadFileGo(SB).
//   4. Load the EFI_STATUS from 40(SP) into X0.
//   5. Restore the saved regs + LR, return.
//
// Frame layout (top-down, post-SUB):
//   SP+0   arg this
//   SP+8   arg filePath
//   SP+16  arg bp
//   SP+24  arg sizeP
//   SP+32  arg bufP
//   SP+40  ret status
//   SP+48  saved X29 (FP)
//   SP+56  saved X30 (LR)
//   SP+64  saved X19
//   SP+72  saved X20
//   SP+80  saved X21
//   SP+88  saved X22
//   SP+96  saved X23
//   SP+104 saved X24
//   SP+112 saved X25
//   SP+120 padding (16-byte alignment)
// Total: 128 bytes.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	// Reserve frame.
	SUB	$128, RSP

	// Save FP + LR + the callee-saved general-purpose registers
	// our Go-side callee might step on.
	MOVD	R29, 48(RSP)
	MOVD	R30, 56(RSP)
	MOVD	R19, 64(RSP)
	MOVD	R20, 72(RSP)
	MOVD	R21, 80(RSP)
	MOVD	R22, 88(RSP)
	MOVD	R23, 96(RSP)
	MOVD	R24, 104(RSP)
	MOVD	R25, 112(RSP)

	// Marshal the EFI args into Go-ABI0 positions on our outgoing
	// frame. AAPCS64 already put them in X0..X4; just spill.
	MOVD	R0, 0(RSP)   // this
	MOVD	R1, 8(RSP)   // filePath
	MOVD	R2, 16(RSP)  // bp
	MOVD	R3, 24(RSP)  // sizeP
	MOVD	R4, 32(RSP)  // bufP

	// Enter Go-side handler. NOSPLIT so no stack-grow check.
	BL	·loadFileGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	40(RSP), R0

	// Restore.
	MOVD	48(RSP), R29
	MOVD	56(RSP), R30
	MOVD	64(RSP), R19
	MOVD	72(RSP), R20
	MOVD	80(RSP), R21
	MOVD	88(RSP), R22
	MOVD	96(RSP), R23
	MOVD	104(RSP), R24
	MOVD	112(RSP), R25
	ADD	$128, RSP
	RET
