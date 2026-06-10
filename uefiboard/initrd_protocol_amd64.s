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
//   callee-saved integer regs: RBX, RBP, RDI, RSI, R12, R13, R14, R15
//   callee-saved XMM regs:     XMM6..XMM15
//
// R-fbsd1a (sprint 1.2, 2026-06-11): the block-IO sibling trampoline
// only saved integer callee-saved regs; firmware code clobbered
// XMM6..XMM15 on return → delayed firmware-side #PF with CR2 in the
// sign-extended uint32 pattern that fingerprints XMM corruption. We
// now save the full MS x64 callee-saved XMM set here too, even though
// the LoadFile2 path historically didn't trigger it — defensive.
//
// R-amd64j Phase 3 (2026-06-10) — INCONCLUSIVE under the time cap.
// Phase-3 four-candidate COM1 dump (BP=168(SP), S8=R8, A=160(SP),
// C=176(SP)) of the EFI-stub-on-amd64 LoadFile2 invocation showed
// the 5th arg is NEITHER cleanly at the textbook MS x64 offset 168
// NOR consistently at R8 (SysV) NOR at 176. Values varied
// run-to-run with the asm prologue's stack disruption; bufP=
// 0x04C00000 (offset 168, run-1) actually produced a valid byte
// landing per the Go-side bufP[0]_post==0x1f check, but the kernel
// later read garbage from the kernel-stub-allocated buffer
// elsewhere → still "Initramfs unpacking failed: invalid magic".
// Phase 3 ruled out the "pure trampoline-arg mismatch" + "pure
// firmware double-buffer" theory split — the true failure mode is
// stranger and needs Phase-4 inspection (likely a low-memory
// reclaim during ExitBootServices on amd64 OVMF stomping the
// LoadFile2-target buffer before the kernel proper reads it).
// See docs/m8-r-amd64j-phase3-findings.md for the full dump
// + theory walkthrough. Reverting to spec offset (now SP+344 after
// the SUB grew 128→304 for the XMM saves) until Phase-4 closes.
//
// Frame layout (top-down, post-SUB $304):
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
// Why no +8 reservation here (unlike the arm64 / riscv64 /
// loong64 sibling files): on amd64 the CALL instruction itself
// pushes the 8-byte return address before the callee runs, so the
// `loadFileGo.abi0` wrapper sees its incoming args at
// `caller_SP_at_CALL + 0..N*8 - 1`. The CALL-pushed return address
// occupies the slot the ABI0 layout would otherwise reserve as the
// "saved LR" word. On the load/store arches (arm64 / riscv64 /
// loong64) the BL / JAL / CALL instruction stores LR in a register
// (X30 / X1 / R1) and DOES NOT push to memory, so those trampolines
// must reserve the +0 slot themselves and store args at SP+8..SP+40
// — see e.g. initrd_protocol_arm64.s where the layout starts at
// +8 and ends at +48.

#include "textflag.h"

// func loadFile_trampoline()
TEXT ·loadFile_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUBQ	$304, SP

	// Save MS x64 callee-saved integer regs we may touch.
	MOVQ	BX, 48(SP)
	MOVQ	BP, 56(SP)
	MOVQ	DI, 64(SP)
	MOVQ	SI, 72(SP)
	MOVQ	R12, 80(SP)
	MOVQ	R13, 88(SP)
	MOVQ	R14, 96(SP)
	MOVQ	R15, 104(SP)

	// Save MS x64 callee-saved XMM regs (R-fbsd1a fix).
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

	// Fetch the 5th MS x64 arg (buffer) from the caller's stack.
	// Caller's RSP at our entry pointed at the return address; we
	// then SUB $304, so the firmware-side 5th arg now sits at
	// [SP + 304 (our frame) + 8 (caller's return addr) + 0x20
	// (shadow space) ] = SP + 344.
	MOVQ	344(SP), AX

	// Marshal EFI args into Go ABI0 outgoing slots at SP+0..SP+32.
	// On amd64 the CALL-pushed return address provides the +0 slot
	// that the load/store arches must reserve manually.
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

	// Restore XMM (R-fbsd1a fix).
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

	// Restore integer.
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
