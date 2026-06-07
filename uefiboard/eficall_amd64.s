// cloud-boot UEFI board — MS x64 firmware-call thunk.
//
// UEFI services use the Microsoft x64 calling convention (RCX, RDX, R8, R9
// for the first four integer/pointer args, status returned in RAX, with a
// mandatory 32-byte "shadow space" reserved below the return address and
// 16-byte stack alignment at the call site). The Go (System V) ABI differs,
// so every firmware call goes through this thunk.
//
// Phase 2 extended the thunk to 5 register/stack args — needed for
// gBS->GetMemoryMap (5 OUT params: MemoryMapSize, MemoryMap, MapKey,
// DescriptorSize, DescriptorVersion), gBS->LoadImage (6 args), and the
// EFI_HTTP_PROTOCOL family's async-token configure/request paths. On
// MS x64 the 5th integer arg lives on the stack at [RSP+0x20] — just
// above the 32-byte shadow space. The thunk stores a5 there *before*
// the CALL so the callee can read it after pushing its own return
// address.
//
// Callees that take fewer than 5 args ignore the trailing register +
// stack slot. The previous Phase-1 4-arg call sites simply pass 0 for a4.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3, a4 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-56
	MOVQ	fn+0(FP), AX
	MOVQ	a0+8(FP), CX
	MOVQ	a1+16(FP), DX
	MOVQ	a2+24(FP), R8
	MOVQ	a3+32(FP), R9
	MOVQ	a4+40(FP), R11	// 5th arg, will land at [RSP+0x20] below

	// RBX is non-volatile under both System V and MS x64, so it safely
	// carries the Go stack pointer across the firmware call.
	MOVQ	SP, BX

	// Firmware wants a large, valid stack; switch to the top of RAM.
	MOVQ	runtime∕goos·RamStart(SB), SP
	MOVQ	runtime∕goos·RamSize(SB), R10
	ADDQ	R10, SP
	ANDQ	$~15, SP		// 16-byte alignment

	// MS x64 frame layout for a 5-arg call:
	//   [RSP+0x00..0x1F]  32-byte shadow space (caller-owned, callee
	//                     may scratch — required even though we passed
	//                     args in registers).
	//   [RSP+0x20]        5th arg.
	//   [RSP+0x28]        (16-byte alignment pad / would be 6th arg).
	// We reserve 0x30 = 48 bytes to keep RSP 16-byte aligned *after*
	// the CALL pushes its 8-byte return address (32 + 8 + 8 padding).
	SUBQ	$48, SP
	MOVQ	R11, 32(SP)		// 5th arg at [RSP+0x20]

	// fn is the address of the service's function-pointer slot (e.g.
	// ConOut+OutputString); call indirectly through it.
	CALL	(AX)
	ADDQ	$48, SP

	// firmware may have re-enabled interrupts
	CLI

	// restore Go stack, then publish the status (FP is valid again now that
	// SP is back to its entry value)
	MOVQ	BX, SP
	MOVQ	AX, status+48(FP)
	RET
