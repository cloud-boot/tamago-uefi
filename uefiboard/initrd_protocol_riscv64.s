// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — RISC-V 64 firmware->Go callback
// trampoline for EFI_LOAD_FILE2_PROTOCOL.LoadFile (Phase 2, M8.2
// follow-up).
//
// REVERSE direction from eficall_riscv64.s: firmware (Linux
// EFI-stub) calls into this thunk via LP64, and we marshal into
// Go ABI0 and call ·loadFileGo.
//
// LP64 ABI on entry (firmware -> us):
//   A0 = this
//   A1 = filePath
//   A2 = bootPolicy
//   A3 = bufferSize (UINTN *)
//   A4 = buffer
//   ret in A0
//   callee-saved: S0..S11 + RA (X1) + SP. X27 (S11) is the Go g
//   register and X31 (T6) is the assembler scratch. As in eficall,
//   we DO NOT touch g; we stash RA in S0.
//
// Frame layout (top-down, post-ADDI).
//
// R-M8.4a fix (2026-06-10): on load/store arches the JAL / BL /
// CALL instruction stores the return address in a register (RA on
// riscv64), NOT on the stack — so unlike amd64 the Go ABI0 layout
// requires the caller to reserve the SP+0..7 slot itself; the
// `loadFileGo.abi0` wrapper reads args at `caller_SP + 8 + N*8`
// and writes its result at `caller_SP + 48`. Same off-by-one bug
// hit on arm64 (live trace 2026-06-10 confirmed
// EFI_INVALID_PARAMETER from a NULL sizeP that was actually our
// bufP value); applying the same fix here pre-emptively so the
// other arches do not repeat the diagnosis cycle.
//
//   SP+0    reserved (Go ABI0 saved-LR slot — load/store arches
//           must reserve this; CALL does not push to memory)
//   SP+8    arg this
//   SP+16   arg filePath
//   SP+24   arg bp
//   SP+32   arg sizeP
//   SP+40   arg bufP
//   SP+48   ret status
//   SP+56   saved RA  (X1)
//   SP+64   saved S0  (X8)   — also Go's FP-equivalent under LP64
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
//   SP+152  padding (16-byte alignment)
// Total: 160 bytes.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-160, X2 // SP -= 160

	// Save firmware-side callee-saved regs we may touch. RA must
	// be preserved across our BL.
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
	// X27 (S11) is the Go g register — DO NOT touch.

	// Marshal EFI args (A0..A4) into Go ABI0 outgoing slots at
	// SP+8..SP+40 (skipping the SP+0 reserved slot — see the
	// frame layout comment above).
	MOV	A0, 8(X2)   // this
	MOV	A1, 16(X2)  // filePath
	MOV	A2, 24(X2)  // bp
	MOV	A3, 32(X2)  // sizeP
	MOV	A4, 40(X2)  // bufP

	// Call Go-side handler.
	CALL	·loadFileGo(SB)

	// Place EFI_STATUS in A0 for the firmware caller.
	MOV	48(X2), A0

	// Restore.
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
	ADD	$160, X2
	RET
