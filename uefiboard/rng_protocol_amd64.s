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
// R-fbsd1a (sprint 1.2, 2026-06-11): added MS x64 callee-saved XMM
// save/restore (XMM6..XMM15) — Go's amd64 codegen can emit XMM ops
// inside the Go callback even for nominally-integer-only handlers,
// so returning to firmware with corrupted XMM6..XMM15 risks a
// delayed firmware-side #PF. SUB grew 128→304 to accommodate the
// 160 B XMM save area + 16 B alignment padding. Save offsets for the
// integer regs were also shifted to match the block_io_publish_amd64.s
// canonical layout (integer at 48-104, XMM at 112-256).
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
// Frame layout (post-SUB $304, multiple of 16):
//   SP+0..32   args (3 or 4 used, slot 32 ignored for 3-arg)
//   SP+40      ret status (4-arg shape) — for 3-arg, ret lives at SP+24
//   SP+48..104 saved RBX, RBP, RDI, RSI, R12..R15
//   SP+112..256 saved XMM6..XMM15
//   SP+272..288 padding
//
// GetRNG (4 args, 1 ret): args at SP+0..24, ret at SP+32.
// GetInfo (3 args, 1 ret): args at SP+0..16, ret at SP+24.

#include "textflag.h"

// func rngGetRNG_trampoline()
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$304, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVUPS	X6,  112(SP)
	MOVUPS	X7,  128(SP)
	MOVUPS	X8,  144(SP)
	MOVUPS	X9,  160(SP)
	MOVUPS	X10, 176(SP)
	MOVUPS	X11, 192(SP)
	MOVUPS	X12, 208(SP)
	MOVUPS	X13, 224(SP)
	MOVUPS	X14, 240(SP)
	MOVUPS	X15, 256(SP)

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+24.
	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // alg
	MOVQ	R8, 16(SP)  // valueLength
	MOVQ	R9, 24(SP)  // valuePtr

	CALL	·rngGetRNGGo(SB)

	// Pull return EFI_STATUS into RAX for the firmware caller.
	MOVQ	32(SP), AX

	MOVUPS	112(SP), X6
	MOVUPS	128(SP), X7
	MOVUPS	144(SP), X8
	MOVUPS	160(SP), X9
	MOVUPS	176(SP), X10
	MOVUPS	192(SP), X11
	MOVUPS	208(SP), X12
	MOVUPS	224(SP), X13
	MOVUPS	240(SP), X14
	MOVUPS	256(SP), X15

	MOVQ	48(SP), BX
	MOVQ	56(SP), BP
	MOVQ	64(SP), DI
	MOVQ	72(SP), SI
	MOVQ	80(SP), R12
	MOVQ	88(SP), R13
	MOVQ	96(SP), R14
	MOVQ	104(SP), R15
	ADDQ	$304, SP
	RET

// func rngGetInfo_trampoline()
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$304, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVUPS	X6,  112(SP)
	MOVUPS	X7,  128(SP)
	MOVUPS	X8,  144(SP)
	MOVUPS	X9,  160(SP)
	MOVUPS	X10, 176(SP)
	MOVUPS	X11, 192(SP)
	MOVUPS	X12, 208(SP)
	MOVUPS	X13, 224(SP)
	MOVUPS	X14, 240(SP)
	MOVUPS	X15, 256(SP)

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+16.
	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // listSize
	MOVQ	R8, 16(SP)  // listPtr

	CALL	·rngGetInfoGo(SB)

	// Pull return EFI_STATUS into RAX for the firmware caller.
	MOVQ	24(SP), AX

	MOVUPS	112(SP), X6
	MOVUPS	128(SP), X7
	MOVUPS	144(SP), X8
	MOVUPS	160(SP), X9
	MOVUPS	176(SP), X10
	MOVUPS	192(SP), X11
	MOVUPS	208(SP), X12
	MOVUPS	224(SP), X13
	MOVUPS	240(SP), X14
	MOVUPS	256(SP), X15

	MOVQ	48(SP), BX
	MOVQ	56(SP), BP
	MOVQ	64(SP), DI
	MOVQ	72(SP), SI
	MOVQ	80(SP), R12
	MOVQ	88(SP), R13
	MOVQ	96(SP), R14
	MOVQ	104(SP), R15
	ADDQ	$304, SP
	RET
