// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — amd64 firmware->Go callback trampolines
// for EFI_RNG_PROTOCOL.GetRNG + GetInfo (Phase 2, M8.7 — R-M8.6a).
//
// Same shape as initrd_protocol_amd64.s (LoadFile2 trampoline);
// see that file's frame-layout commentary for the MS x64 + Go ABI0
// conventions. On amd64 the CALL instruction itself pushes the
// 8-byte return address before the callee runs, so the
// `<callee>.abi0` wrapper sees its incoming args at
// `caller_SP_at_CALL + 0..N*8 - 1` — we do NOT reserve a +0 slot.
//
// MS x64 on entry (firmware -> us):
//
//   GetRNG:                              GetInfo:
//     RCX = this                          RCX = this
//     RDX = alg                           RDX = listSize  (UINTN *)
//     R8  = valueLength                   R8  = listPtr   (EFI_RNG_ALGORITHM *)
//     R9  = valuePtr                      ret in RAX
//     ret in RAX
//
// Frame layout for GetRNG (4 args, 1 ret):
//   SP+0    arg this
//   SP+8    arg alg
//   SP+16   arg valueLength
//   SP+24   arg valuePtr
//   SP+32   ret status
//   SP+40   saved RBX
//   SP+48   saved RBP
//   SP+56   saved RDI
//   SP+64   saved RSI
//   SP+72   saved R12
//   SP+80   saved R13
//   SP+88   saved R14
//   SP+96   saved R15
//   SP+104  padding
//   SP+112  padding
//   SP+120  padding (16-byte alignment)
// Total: 128 bytes.
//
// Frame layout for GetInfo (3 args, 1 ret): mirror of above,
// args at SP+0..16, result at SP+24.

#include "textflag.h"

// func rngGetRNG_trampoline()
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 40(SP)
	MOVQ	BP, 48(SP)
	MOVQ	DI, 56(SP)
	MOVQ	SI, 64(SP)
	MOVQ	R12, 72(SP)
	MOVQ	R13, 80(SP)
	MOVQ	R14, 88(SP)
	MOVQ	R15, 96(SP)

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+24.
	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // alg
	MOVQ	R8, 16(SP)  // valueLength
	MOVQ	R9, 24(SP)  // valuePtr

	CALL	·rngGetRNGGo(SB)

	// Pull return EFI_STATUS into RAX for the firmware caller.
	MOVQ	32(SP), AX

	MOVQ	40(SP), BX
	MOVQ	48(SP), BP
	MOVQ	56(SP), DI
	MOVQ	64(SP), SI
	MOVQ	72(SP), R12
	MOVQ	80(SP), R13
	MOVQ	88(SP), R14
	MOVQ	96(SP), R15
	ADDQ	$128, SP
	RET

// func rngGetInfo_trampoline()
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 32(SP)
	MOVQ	BP, 40(SP)
	MOVQ	DI, 48(SP)
	MOVQ	SI, 56(SP)
	MOVQ	R12, 64(SP)
	MOVQ	R13, 72(SP)
	MOVQ	R14, 80(SP)
	MOVQ	R15, 88(SP)

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+16.
	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // listSize
	MOVQ	R8, 16(SP)  // listPtr

	CALL	·rngGetInfoGo(SB)

	// Pull return EFI_STATUS into RAX for the firmware caller.
	MOVQ	24(SP), AX

	MOVQ	32(SP), BX
	MOVQ	40(SP), BP
	MOVQ	48(SP), DI
	MOVQ	56(SP), SI
	MOVQ	64(SP), R12
	MOVQ	72(SP), R13
	MOVQ	80(SP), R14
	MOVQ	88(SP), R15
	ADDQ	$128, SP
	RET
