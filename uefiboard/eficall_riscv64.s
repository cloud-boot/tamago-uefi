// cloud-boot UEFI board — RISC-V 64 firmware-call thunk.
//
// UEFI on RISC-V follows the LP64 calling convention (RISC-V ELF psABI,
// also adopted by UEFI 2.10 §2.3.7): integer/pointer args in A0..A7,
// return value in A0, 16-byte stack alignment at the call site, no
// "shadow space" (unlike MS x64). The thunk loads the caller's args
// into LP64 positions and calls indirectly through the service's
// function-pointer slot.
//
// LP64 preserves S0..S11 across calls (and the firmware honours that),
// so we stash the Go link register (X1/RA) in S0 across the JALR.
// X27 (S11) is reserved by Go's riscv64 ABI for the g pointer — DO NOT touch.
// X31 (T6) is reserved as the Go assembler scratch register — also do not stash here.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-48
	MOV	fn+0(FP), T0
	MOV	a0+8(FP), A0
	MOV	a1+16(FP), A1
	MOV	a2+24(FP), A2
	MOV	a3+32(FP), A3

	// preserve Go's link register (X1/RA) across the firmware call in S0,
	// which is callee-saved under LP64.
	MOV	X1, S0

	// indirect call through the service slot (T0 = fn pointer; deref to
	// obtain the actual entry, then JALR through it).
	MOV	(T0), T1
	JALR	RA, (T1)

	// restore Go RA, publish the EFI_STATUS (A0 holds the LP64 return).
	MOV	S0, X1
	MOV	A0, status+40(FP)
	RET
