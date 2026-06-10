// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — amd64 firmware->Go callback trampolines
// for the published EFI_BLOCK_IO_PROTOCOL (Phase 3 sprint 1).
//
// Four reverse-direction trampolines (firmware -> us, MS x64 ABI ->
// Go ABI0):
//
//   blockIO_reset_trampoline  -> ·blockIOResetGo(SB)        (2 args)
//   blockIO_read_trampoline   -> ·blockIOReadBlocksGo(SB)   (5 args)
//   blockIO_write_trampoline  -> ·blockIOWriteBlocksGo(SB)  (5 args)
//   blockIO_flush_trampoline  -> ·blockIOFlushBlocksGo(SB)  (1 arg)
//
// Mirrors initrd_protocol_amd64.s 1:1 for the ABI bridging conventions
// — same frame layout idea, same MS x64 callee-saved register set
// (RBX, RBP, RDI, RSI, R12..R15), same handling of the 5th arg
// living past the shadow space at [SP+168] post-prologue.
//
// MS x64 ABI inbound (firmware -> us):
//   RCX  = arg0   (always `this` for our protocols)
//   RDX  = arg1
//   R8   = arg2
//   R9   = arg3
//   [RSP+0x28] = arg4 (5th arg lives past return-addr(8)+shadow(32))
//   ret in RAX
//   callee-saved: RBX, RBP, RDI, RSI, R12..R15
//
// Frame layout (mirrors initrd_protocol_amd64.s post-SUB):
//   SP+0    arg0
//   SP+8    arg1
//   SP+16   arg2
//   SP+24   arg3
//   SP+32   arg4 (read from caller's stack)
//   SP+40   ret status
//   SP+48   saved RBX
//   SP+56   saved RBP
//   SP+64   saved RDI
//   SP+72   saved RSI
//   SP+80   saved R12
//   SP+88   saved R13
//   SP+96   saved R14
//   SP+104  saved R15
//   SP+112  padding
//   SP+128  (top of frame)
//
// Per initrd_protocol_amd64.s docstring: no +8 slot for "saved LR"
// needed on amd64 because CALL pushes the return address before
// callee runs, so the Go callee sees its first arg at +0.
//
// All trampolines are NOSPLIT (we entered on the firmware stack with
// no usable Go scheduler state).

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// blockIO_reset_trampoline — Reset(this, extendedVerification)
// ───────────────────────────────────────────────────────────────────
//
// EFI_STATUS Reset(IN EFI_BLOCK_IO_PROTOCOL *This,
//                  IN BOOLEAN                ExtendedVerification);
//
// 2-arg shape. Marshal RCX/RDX into SP+0..SP+8, call ·blockIOResetGo,
// read SP+16 (the ret slot at the 2-arg + ret-slot position) into RAX.
//
// Go ABI0 lays out args + ret as a contiguous run starting at SP+0:
//   func blockIOResetGo(this, extended uintptr) uintptr
//   in:  SP+0  this
//        SP+8  extended
//   out: SP+16 ret
TEXT ·blockIO_reset_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // extended

	CALL	·blockIOResetGo(SB)

	MOVQ	16(SP), AX  // ret slot is right after the 2 args

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

// ───────────────────────────────────────────────────────────────────
// blockIO_read_trampoline — ReadBlocks(this, mediaID, lba, bufSize, buf)
// ───────────────────────────────────────────────────────────────────
//
// EFI_STATUS ReadBlocks(IN  EFI_BLOCK_IO_PROTOCOL *This,
//                       IN  UINT32                 MediaId,
//                       IN  EFI_LBA                Lba,
//                       IN  UINTN                  BufferSize,
//                       OUT VOID                  *Buffer );
//
// 5-arg shape — identical to the loadFile trampoline. Args at
// RCX/RDX/R8/R9 + [SP+168] (post-SUB 128: caller's RSP at our entry
// pointed at return addr, then 32 bytes shadow, then the 5th arg —
// so the 5th arg lives at [caller_SP+8+32] = [SP+128+8+32] = [SP+168]).
//
// Go ABI0:
//   func blockIOReadBlocksGo(this, mediaID, lba, bufferSize, buffer uintptr) uintptr
//   in:  SP+0..32 args
//   out: SP+40    ret
TEXT ·blockIO_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVQ	168(SP), AX  // 5th arg (buffer) from caller's stack

	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // mediaID
	MOVQ	R8, 16(SP)  // lba
	MOVQ	R9, 24(SP)  // bufferSize
	MOVQ	AX, 32(SP)  // buffer

	CALL	·blockIOReadBlocksGo(SB)

	MOVQ	40(SP), AX

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

// ───────────────────────────────────────────────────────────────────
// blockIO_write_trampoline — WriteBlocks(this, mediaID, lba, bufSize, buf)
// ───────────────────────────────────────────────────────────────────
//
// EFI_STATUS WriteBlocks(IN EFI_BLOCK_IO_PROTOCOL *This,
//                        IN UINT32                 MediaId,
//                        IN EFI_LBA                Lba,
//                        IN UINTN                  BufferSize,
//                        IN VOID                  *Buffer );
//
// 5-arg shape, identical layout to ReadBlocks.
TEXT ·blockIO_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVQ	168(SP), AX

	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	MOVQ	AX, 32(SP)

	CALL	·blockIOWriteBlocksGo(SB)

	MOVQ	40(SP), AX

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

// ───────────────────────────────────────────────────────────────────
// blockIO_flush_trampoline — FlushBlocks(this)
// ───────────────────────────────────────────────────────────────────
//
// EFI_STATUS FlushBlocks(IN EFI_BLOCK_IO_PROTOCOL *This);
//
// 1-arg shape.
//   func blockIOFlushBlocksGo(this uintptr) uintptr
//   in:  SP+0   this
//   out: SP+8   ret
TEXT ·blockIO_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$128, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	MOVQ	CX, 0(SP)   // this

	CALL	·blockIOFlushBlocksGo(SB)

	MOVQ	8(SP), AX   // ret slot right after the 1 arg

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
