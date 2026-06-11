// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — amd64 firmware->Go callback trampolines
// for the published EFI_SIMPLE_FILE_SYSTEM_PROTOCOL +
// EFI_FILE_PROTOCOL (Phase 3 sprint 2B).
//
// Eleven reverse-direction trampolines (firmware -> us, MS x64 ABI ->
// Go ABI0), one per spec method (UEFI 2.10 §13.4-§13.5):
//
//   sfs_open_volume_trampoline  -> ·sfsOpenVolumeGo(SB)       (2 args)
//   sfs_file_open_trampoline    -> ·sfsFileOpenGo(SB)         (5 args)
//   sfs_file_close_trampoline   -> ·sfsFileCloseGo(SB)        (1 arg)
//   sfs_file_delete_trampoline  -> ·sfsFileDeleteGo(SB)       (1 arg)
//   sfs_file_read_trampoline    -> ·sfsFileReadGo(SB)         (3 args)
//   sfs_file_write_trampoline   -> ·sfsFileWriteGo(SB)        (3 args)
//   sfs_file_getpos_trampoline  -> ·sfsFileGetPositionGo(SB)  (2 args)
//   sfs_file_setpos_trampoline  -> ·sfsFileSetPositionGo(SB)  (2 args)
//   sfs_file_getinfo_trampoline -> ·sfsFileGetInfoGo(SB)      (4 args)
//   sfs_file_setinfo_trampoline -> ·sfsFileSetInfoGo(SB)      (4 args)
//   sfs_file_flush_trampoline   -> ·sfsFileFlushGo(SB)        (1 arg)
//
// Mirrors block_io_publish_amd64.s for the ABI bridging conventions
// — same frame layout, same MS x64 callee-saved register set
// (RBX, RBP, RDI, RSI, R12..R15 + XMM6..XMM15), same handling of
// 5th args past the shadow space at [SP+344] post-prologue.
//
// MS x64 ABI inbound (firmware -> us):
//   RCX  = arg0   (always `this` for our protocols)
//   RDX  = arg1
//   R8   = arg2
//   R9   = arg3
//   [RSP+0x28] = arg4 (5th arg, past return-addr(8)+shadow(32))
//   ret in RAX
//   callee-saved integer:  RBX, RBP, RDI, RSI, R12..R15
//   callee-saved XMM:      XMM6..XMM15 (10 regs * 16 bytes = 160 B)
//
// R-fbsd1a sprint 1.2 finding (block_io_publish_amd64.s docstring):
// must save full XMM6..XMM15 too. Go's autogen amd64 ABIInternal
// wrapper trails .abi0 epilogue with `XORPS X15,X15` + `MOVQ FS:0(g),R14`
// → corrupts MS x64 callee-saved regs and produces firmware-side delayed
// #PF (CR2 = sign-extended uint32 pattern). Each *_trampolinePC helper
// returns the LEAQ .abi0 entry directly to bypass the wrapper.
//
// Frame layout (post-SUB $304):
//   SP+0..32    args  (5 slots, 5th arg loaded from caller's stack for the 5-arg shape)
//   SP+40       ret status (or shifted by arg count for fewer args)
//   SP+48..104  saved integer callee-saved (BX BP DI SI R12..R15)
//   SP+112..256 saved XMM6..XMM15 (10*16 = 160 B)
//   SP+272..288 padding
//
// Go ABI0 lays args + ret contiguously at SP+0, so the return-slot
// offset varies per arity:
//   1 arg : ret at SP+8
//   2 args: ret at SP+16
//   3 args: ret at SP+24
//   4 args: ret at SP+32
//   5 args: ret at SP+40

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────

TEXT ·sfs_open_volume_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_open_volume_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_open_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_open_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_close_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_close_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_delete_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_delete_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_read_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_read_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_write_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_write_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_getpos_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_getpos_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_setpos_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_setpos_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_getinfo_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_getinfo_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_setinfo_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_setinfo_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·sfs_file_flush_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·sfs_file_flush_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_open_volume_trampoline — OpenVolume(this, *Root) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_open_volume_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	CALL	·sfsOpenVolumeGo(SB)
	MOVQ	16(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_open_trampoline — Open(this, *new, name, mode, attr) — 5 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_open_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	344(SP), AX  // 5th arg from caller's stack
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	MOVQ	AX, 32(SP)
	CALL	·sfsFileOpenGo(SB)
	MOVQ	40(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_close_trampoline — Close(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_close_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	CALL	·sfsFileCloseGo(SB)
	MOVQ	8(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_delete_trampoline — Delete(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_delete_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	CALL	·sfsFileDeleteGo(SB)
	MOVQ	8(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_read_trampoline — Read(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_read_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	CALL	·sfsFileReadGo(SB)
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_write_trampoline — Write(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_write_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	CALL	·sfsFileWriteGo(SB)
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_getpos_trampoline — GetPosition(this, *pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getpos_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	CALL	·sfsFileGetPositionGo(SB)
	MOVQ	16(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_setpos_trampoline — SetPosition(this, pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setpos_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	CALL	·sfsFileSetPositionGo(SB)
	MOVQ	16(SP), AX
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_getinfo_trampoline — GetInfo(this, *type, *size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	CALL	·sfsFileGetInfoGo(SB)
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_setinfo_trampoline — SetInfo(this, *type, size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	CALL	·sfsFileSetInfoGo(SB)
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

// ───────────────────────────────────────────────────────────────────
// sfs_file_flush_trampoline — Flush(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
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
	MOVQ	CX, 0(SP)
	CALL	·sfsFileFlushGo(SB)
	MOVQ	8(SP), AX
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
