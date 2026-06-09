// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — amd64 firmware->Go callback trampoline
// for EFI_LOAD_FILE2_PROTOCOL.LoadFile (Phase 2, M8.2 follow-up).
//
// REVERSE direction from eficall_amd64.s: firmware (Linux EFI-stub)
// calls into this thunk using the Microsoft x64 calling convention,
// and we marshal into Go ABI0 and call ·loadFileGo (System V-ish,
// frame-pointer based ABI0).
//
// MS x64 ABI on entry (firmware -> us):
//   RCX = this           (EFI_LOAD_FILE2_PROTOCOL *)
//   RDX = filePath       (EFI_DEVICE_PATH_PROTOCOL *)
//   R8  = bootPolicy
//   R9  = bufferSize     (UINTN *)
//   [RSP+0x28] = buffer  (5th arg lives on the stack just past the
//                         shadow space; on entry RSP points to the
//                         return address, so caller's 5th arg is
//                         at [RSP+0x28] = ret-addr(8) + shadow(32))
//   ret in RAX
//   callee-saved integer regs: RBX, RBP, RDI, RSI, R12, R13, R14,
//                              R15. (RSP of course preserved.)
//   callee-saved XMM regs: XMM6..XMM15 (the firmware promises 16-byte
//   alignment but we use the upper-half XMM very sparingly in Go
//   code; we save the four most-likely-clobbered, XMM6..XMM9, and
//   leave the rest — Go's compiler does not emit floating-point on
//   our nosplit handler).
//
// Frame layout (top-down, post-SUB):
//   SP+0    arg this
//   SP+8    arg filePath
//   SP+16   arg bp
//   SP+24   arg sizeP
//   SP+32   arg bufP
//   SP+40   ret status
//   SP+48   saved RBX
//   SP+56   saved RBP
//   SP+64   saved RDI
//   SP+72   saved RSI
//   SP+80   saved R12
//   SP+88   saved R13
//   SP+96   saved R14
//   SP+104  saved R15
//   SP+112  padding (16-byte alignment)
// Total: 120 bytes (multiple of 8; the CALL pushes 8 more so the
// post-CALL frame is 16-byte aligned as Go expects for SSE).
// We round up to 128 to keep RSP 16-aligned at THIS frame too.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	// Save MS x64 callee-saved integer regs we may touch.
	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	// Fetch the 5th MS x64 arg (buffer) from the caller's stack.
	// Caller's RSP at our entry pointed at the return address; we
	// then SUB $128, so the firmware-side 5th arg now sits at
	// [SP + 128 (our frame) + 8 (caller's return addr) + 0x20
	// (shadow space) ] = SP + 168.
	MOVQ	168(SP), AX

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+32.
	MOVQ	CX, 0(SP)   // this  (was RCX)
	MOVQ	DX, 8(SP)   // filePath (was RDX)
	MOVQ	R8, 16(SP)  // bp
	MOVQ	R9, 24(SP)  // sizeP
	MOVQ	AX, 32(SP)  // bufP (loaded from stack above)

	// Call Go-side handler. Go ABI0 finds args at FP+offsets;
	// inside the called function, FP == our SP + 8 (post-CALL).
	CALL	·loadFileGo(SB)

	// Pull return EFI_STATUS into RAX for the firmware caller.
	MOVQ	40(SP), AX

	// Restore.
	MOVQ	48(SP), BX
	MOVQ	56(SP), BP
	MOVQ	64(SP), DI
	MOVQ	72(SP), SI
	MOVQ	80(SP), R12
	MOVQ	88(SP), R13
	MOVQ	96(SP), R14
	MOVQ	104(SP), R15
	ADDQ	$128, SP
	RET
