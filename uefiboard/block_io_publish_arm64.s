// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — aarch64 firmware->Go callback trampolines
// for the published EFI_BLOCK_IO_PROTOCOL (Phase 3 sprint 1, multi-arch
// port — companion to block_io_publish_amd64.s).
//
// Four reverse-direction trampolines (firmware -> us, AAPCS64 -> Go ABI0):
//
//   blockIO_reset_trampoline  -> ·blockIOResetGo(SB)        (2 args)
//   blockIO_read_trampoline   -> ·blockIOReadBlocksGo(SB)   (5 args)
//   blockIO_write_trampoline  -> ·blockIOWriteBlocksGo(SB)  (5 args)
//   blockIO_flush_trampoline  -> ·blockIOFlushBlocksGo(SB)  (1 arg)
//
// Mirrors rng_protocol_arm64.s for the ABI bridging conventions — same
// AAPCS64 callee-saved integer set (X19..X25 + X29/X30) + callee-saved
// FP set (D8..D15, AAPCS64 §5.1.2). Unlike amd64 there's no shadow-space
// dance: AAPCS64 passes the first 8 args in X0..X7, so the 5-arg shapes
// (Read/Write) get all five args directly in registers.
//
// AAPCS64 ABI on entry (firmware -> us):
//
//   blockIO_reset:                          blockIO_read:
//     X0 = this                              X0 = this
//     X1 = extendedVerification              X1 = mediaID
//     ret in X0                              X2 = lba
//                                            X3 = bufferSize
//                                            X4 = buffer
//                                            ret in X0
//
//   blockIO_write:                          blockIO_flush:
//     same as read                           X0 = this
//                                            ret in X0
//
// R-fbsd1c (sprint 1.3, 2026-06-11) carryover: AAPCS64 D8..D15 FP
// callee-saved save/restore is included defensively — Go's arm64
// codegen can emit FP ops inside the Go callback even for nominally
// integer-only handlers, and corrupted D8..D15 on return to firmware
// risks a delayed firmware-side fault (same shape as the amd64
// XMM6..XMM15 fix shipped in Sprint 1.2).
//
// Uniform 224-byte frame across all 4 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 is the reserved
// saved-LR slot per arm64 Go ABI0), so the ret-slot offset varies
// per arity:
//
//   1 arg  (Flush)        : args SP+8;          ret at SP+16
//   2 args (Reset)        : args SP+8..16;      ret at SP+24
//   5 args (Read, Write)  : args SP+8..40;      ret at SP+48
//
// Frame layout (SP grows down; offsets relative to post-prologue SP):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg0 (this)
//   SP+16   arg1
//   SP+24   arg2
//   SP+32   arg3
//   SP+40   arg4
//   SP+48..SP+55  ret slot (5-arg form; other arities place ret
//                  earlier per the table above)
//   SP+56   saved X29 (FP)
//   SP+64   saved X30 (LR)
//   SP+72   saved X19
//   SP+80   saved X20
//   SP+88   saved X21
//   SP+96   saved X22
//   SP+104  saved X23
//   SP+112  saved X24
//   SP+120  saved X25
//   SP+128  saved D8
//   SP+136  saved D9
//   SP+144  saved D10
//   SP+152  saved D11
//   SP+160  saved D12
//   SP+168  saved D13
//   SP+176  saved D14
//   SP+184  saved D15
//   SP+192..SP+223  padding (16-byte alignment headroom)
//
// All trampolines are NOSPLIT (we entered on the firmware stack with
// no usable Go scheduler state).

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 carryover: mirror the amd64 LEAQ-direct pattern
// from block_io_publish_amd64.s. On arm64 the equivalent is the
// assembler's `MOVD $sym(SB),Rn` pseudo, which expands to `ADRP+ADD`
// against the symbol's address — bypassing the Go ABIInternal wrapper
// that a funcval first-word deref would land on (whose epilogue can
// clobber callee-saved regs AFTER our .abi0 epilogue restored them).
//
// Signature: func blockIO_<op>_trampolinePC() uintptr
TEXT ·blockIO_reset_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·blockIO_reset_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·blockIO_read_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·blockIO_read_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·blockIO_write_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·blockIO_write_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·blockIO_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·blockIO_flush_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// ───────────────────────────────────────────────────────────────────
// Macro-free per-trampoline implementations (Go arm64 assembler does
// not support macros). Each follows the standard:
//   1. SUB $224, RSP
//   2. Save callee-saved int + FP regs at fixed offsets
//   3. Marshal AAPCS64 args (X0..X4) into Go ABI0 slots at SP+8..
//   4. BL Go handler
//   5. Pull ret EFI_STATUS into X0 from the per-arity ret slot
//   6. Restore callee-saved
//   7. ADD $224, RSP; RET
// ───────────────────────────────────────────────────────────────────

// func blockIO_reset_trampoline()
// Reset(this, extendedVerification) — 2 args, ret at SP+24.
TEXT ·blockIO_reset_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP

	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)

	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // extendedVerification

	BL	·blockIOResetGo(SB)

	MOVD	24(RSP), R0  // ret slot for 2-arg form

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// func blockIO_read_trampoline()
// ReadBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args, ret at SP+48.
TEXT ·blockIO_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP

	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)

	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // mediaID
	MOVD	R2, 24(RSP)  // lba
	MOVD	R3, 32(RSP)  // bufferSize
	MOVD	R4, 40(RSP)  // buffer

	BL	·blockIOReadBlocksGo(SB)

	MOVD	48(RSP), R0  // ret slot for 5-arg form

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// func blockIO_write_trampoline()
// WriteBlocks(this, mediaID, lba, bufferSize, buffer) — 5 args, identical
// shape to ReadBlocks.
TEXT ·blockIO_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP

	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)

	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	MOVD	R3, 32(RSP)
	MOVD	R4, 40(RSP)

	BL	·blockIOWriteBlocksGo(SB)

	MOVD	48(RSP), R0

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// func blockIO_flush_trampoline()
// FlushBlocks(this) — 1 arg, ret at SP+16.
TEXT ·blockIO_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP

	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)

	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	MOVD	R0, 8(RSP)   // this

	BL	·blockIOFlushBlocksGo(SB)

	MOVD	16(RSP), R0  // ret slot for 1-arg form

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET
