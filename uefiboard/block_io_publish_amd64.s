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
// (RBX, RBP, RDI, RSI, R12..R15 + XMM6..XMM15), same handling of the
// 5th arg living past the shadow space at [SP+344] post-prologue.
//
// MS x64 ABI inbound (firmware -> us):
//   RCX  = arg0   (always `this` for our protocols)
//   RDX  = arg1
//   R8   = arg2
//   R9   = arg3
//   [RSP+0x28] = arg4 (5th arg lives past return-addr(8)+shadow(32))
//   ret in RAX
//   callee-saved integer:  RBX, RBP, RDI, RSI, R12..R15
//   callee-saved XMM:      XMM6..XMM15 (10 regs * 16 bytes = 160 B)
//
// R-fbsd1a (sprint 1.2, 2026-06-11): previously we saved only the
// integer callee-saved set. Go's amd64 codegen can emit XMM ops inside
// the Go callback (e.g. byte-loop memmove inlining), so returning to
// firmware with corrupted XMM6..XMM15 produced a delayed firmware-side
// page-fault (CR2 = sign-extended uint32 pattern, the XMM fingerprint).
// Now we save/restore the full MS x64 callee-saved XMM set.
//
// Frame layout (post-SUB $304, multiple of 16):
//   SP+0    arg0
//   SP+8    arg1
//   SP+16   arg2
//   SP+24   arg3
//   SP+32   arg4 (read from caller's stack for the 5-arg shapes)
//   SP+40   ret status
//   SP+48   saved RBX
//   SP+56   saved RBP
//   SP+64   saved RDI
//   SP+72   saved RSI
//   SP+80   saved R12
//   SP+88   saved R13
//   SP+96   saved R14
//   SP+104  saved R15
//   SP+112  saved XMM6  (16 B)
//   SP+128  saved XMM7
//   SP+144  saved XMM8
//   SP+160  saved XMM9
//   SP+176  saved XMM10
//   SP+192  saved XMM11
//   SP+208  saved XMM12
//   SP+224  saved XMM13
//   SP+240  saved XMM14
//   SP+256  saved XMM15
//   SP+272  padding (16 B)
//   SP+288  padding (16 B)
//   SP+304  (top of frame)
//
// 5th-arg stack offset: previously SP+168 with SUB 128; SUB delta is
// 304-128=176, so the new offset is 168+176 = 344.
//
// Per initrd_protocol_amd64.s docstring: no +8 slot for "saved LR"
// needed on amd64 because CALL pushes the return address before
// callee runs, so the Go callee sees its first arg at +0.
//
// MOVUPS (unaligned) is used for XMM save/restore. The post-SUB SP is
// 16-byte aligned (entry RSP was 16-aligned per MS x64; CALL pushed
// 8 bytes; SUB 304 is a multiple of 16 → SP%16 = (16-8)%16 = 8 ...
// no: entry SP%16==0 by MS x64 contract at call site, CALL push makes
// SP%16==8 inside callee on entry, SUB 304 keeps SP%16==8). The XMM
// save area starts at SP+112; SP+112 mod 16 = 8, NOT 16-aligned. So
// MOVUPS is required (MOVAPS would #GP). Performance impact is
// negligible on modern CPUs that fuse unaligned 16-byte moves.
//
// All trampolines are NOSPLIT (we entered on the firmware stack with
// no usable Go scheduler state).

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1a sprint 1.2 follow-up: a Go function-value's first word
// points at the *ABIInternal* wrapper, not at our .abi0 entry. The
// autogen wrapper on amd64 ends with `XORPS X15,X15` + `MOVQ FS:0(g),
// R14` — both clobber MS x64 callee-saved regs (X15 + R14) AFTER our
// .abi0 epilogue restored them, which the C-side firmware (PartitionDxe
// driver-binding probe) sees as register corruption and #PFs.
//
// These helpers use `LEAQ ·sym(SB)` which, from asm, resolves to the
// ABI0 entry — bypassing the wrapper entirely. The Go-side reads the
// returned uintptr and installs it into the EFI_BLOCK_IO_PROTOCOL
// function-pointer slots, so the firmware lands directly in our
// .abi0 prologue.
//
// Signature: func blockIO_<op>_trampolinePC() uintptr
TEXT ·blockIO_reset_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·blockIO_reset_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·blockIO_read_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·blockIO_read_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·blockIO_write_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·blockIO_write_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

TEXT ·blockIO_flush_trampolinePC(SB),NOSPLIT,$0-8
	LEAQ	·blockIO_flush_trampoline(SB), AX
	MOVQ	AX, ret+0(FP)
	RET

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
	SUBQ	$304, SP

	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	// Save XMM6-XMM15 (MS x64 callee-saved).
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

	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // extended

	CALL	·blockIOResetGo(SB)

	MOVQ	16(SP), AX  // ret slot is right after the 2 args

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
// RCX/RDX/R8/R9 + [SP+344] (post-SUB 304: caller's RSP at our entry
// pointed at return addr, then 32 bytes shadow, then the 5th arg —
// so the 5th arg lives at [caller_SP+8+32] = [SP+304+8+32] = [SP+344]).
//
// Go ABI0:
//   func blockIOReadBlocksGo(this, mediaID, lba, bufferSize, buffer uintptr) uintptr
//   in:  SP+0..32 args
//   out: SP+40    ret
TEXT ·blockIO_read_trampoline(SB),NOSPLIT|NOFRAME,$0
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

	MOVQ	344(SP), AX  // 5th arg (buffer) from caller's stack

	MOVQ	CX, 0(SP)   // this
	MOVQ	DX, 8(SP)   // mediaID
	MOVQ	R8, 16(SP)  // lba
	MOVQ	R9, 24(SP)  // bufferSize
	MOVQ	AX, 32(SP)  // buffer

	CALL	·blockIOReadBlocksGo(SB)

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

	MOVQ	344(SP), AX

	MOVQ	CX, 0(SP)
	MOVQ	DX, 8(SP)
	MOVQ	R8, 16(SP)
	MOVQ	R9, 24(SP)
	MOVQ	AX, 32(SP)

	CALL	·blockIOWriteBlocksGo(SB)

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

	MOVQ	CX, 0(SP)   // this

	CALL	·blockIOFlushBlocksGo(SB)

	MOVQ	8(SP), AX   // ret slot right after the 1 arg

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
