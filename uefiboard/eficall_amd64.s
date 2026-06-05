// cloud-boot UEFI board — MS x64 firmware-call thunk.
//
// UEFI services use the Microsoft x64 calling convention (RCX, RDX, R8, R9
// for the first four integer/pointer args, status returned in RAX, with a
// mandatory 32-byte "shadow space" reserved below the return address and
// 16-byte stack alignment at the call site). The Go (System V) ABI differs,
// so every firmware call goes through this thunk.
//
// We expose a fixed 4-argument form: every UEFI service this board calls so
// far (ConOut->OutputString, and later AllocatePages/GetMemoryMap/
// ExitBootServices) fits in <= 4 register args, so no stack-arg spilling is
// needed. Unused trailing args are passed as zero and ignored by callees.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-48
	MOVQ	fn+0(FP), AX
	MOVQ	a0+8(FP), CX
	MOVQ	a1+16(FP), DX
	MOVQ	a2+24(FP), R8
	MOVQ	a3+32(FP), R9

	// RBX is non-volatile under both System V and MS x64, so it safely
	// carries the Go stack pointer across the firmware call.
	MOVQ	SP, BX

	// Firmware wants a large, valid stack; switch to the top of RAM.
	MOVQ	runtime∕goos·RamStart(SB), SP
	MOVQ	runtime∕goos·RamSize(SB), R10
	ADDQ	R10, SP
	ANDQ	$~15, SP		// 16-byte alignment

	SUBQ	$32, SP			// MS x64 shadow space
	// fn is the address of the service's function-pointer slot (e.g.
	// ConOut+OutputString); call indirectly through it.
	CALL	(AX)
	ADDQ	$32, SP

	// firmware may have re-enabled interrupts
	CLI

	// restore Go stack, then publish the status (FP is valid again now that
	// SP is back to its entry value)
	MOVQ	BX, SP
	MOVQ	AX, status+40(FP)
	RET
