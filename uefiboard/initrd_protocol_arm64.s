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
// Frame layout (top-down, post-SUB).
//
// R-M8.4a fix (2026-06-10): Go ABI0 on arm64 reserves the first 8
// bytes of the callee's incoming frame (caller's SP-at-BL + 0..7)
// as the "saved LR slot" placeholder — even though the arm64 BL
// stores LR in X30 (no push), the compiler-generated `.abi0`
// wrapper of every Go-compiled function reads its incoming args at
// `caller_SP_at_BL + 8 + N*8` and writes its result at
// `caller_SP_at_BL + 8 + argsBytes`. Cross-checked against the
// `loadFileGo.abi0` disassembly from the 2026-06-10 R-M8.4a debug
// build (offsets 72/80/88/96/104 after its own 64-byte
// frame-allocation = caller_SP + 8/16/24/32/40 for the 5 args,
// caller_SP + 48 for the result). The previous layout put args at
// SP+0..SP+32 and read the result from SP+40, which was off-by-one
// slot in every position — `loadFileGo` saw `this = filePath`,
// `fp = bootPolicy`, `bp = &bufferSize`, `sizeP = NULL`, and
// returned EFI_INVALID_PARAMETER (sizeP == 0) on every callback.
// Manifest as `EFI stub: ERROR: Failed to load initrd!` while the
// trampoline IS reached.
//
//   SP+0    reserved (Go ABI0 saved-LR slot, written by callee)
//   SP+8    arg this
//   SP+16   arg filePath
//   SP+24   arg bp
//   SP+32   arg sizeP
//   SP+40   arg bufP
//   SP+48   ret status
//   SP+56   saved X29 (FP)
//   SP+64   saved X30 (LR)
//   SP+72   saved X19
//   SP+80   saved X20
//   SP+88   saved X21
//   SP+96   saved X22
//   SP+104  saved X23
//   SP+112  saved X24
//   SP+120  saved X25
// Total: 128 bytes (still 16-byte aligned).

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	// Reserve frame.
	SUB	$128, RSP

	// Save FP + LR + the callee-saved general-purpose registers
	// our Go-side callee might step on.
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)

	// Marshal the EFI args into Go-ABI0 positions on our outgoing
	// frame. AAPCS64 already put them in X0..X4; spill at +8..+40
	// (skipping the +0 saved-LR-slot reservation; see frame layout
	// comment above).
	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // filePath
	MOVD	R2, 24(RSP)  // bp
	MOVD	R3, 32(RSP)  // sizeP
	MOVD	R4, 40(RSP)  // bufP

	// Enter Go-side handler. NOSPLIT so no stack-grow check.
	BL	·loadFileGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	48(RSP), R0

	// Restore.
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$128, RSP
	RET
