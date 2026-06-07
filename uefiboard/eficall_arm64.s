// cloud-boot UEFI board — AArch64 firmware-call thunk.
//
// UEFI services on AArch64 follow AAPCS64: integer/pointer args in
// X0..X7, return in X0, 16-byte stack alignment at the call site, no
// "shadow space" (unlike MS x64). The thunk loads the caller's args
// into AAPCS64 positions and calls indirectly through the service's
// function-pointer slot. We keep Go's small goroutine stack for the
// firmware call — Boot Services entry points used by this PoC
// (ConOut->OutputString) don't need much.
//
// Phase 2 M2 widened the thunk from 5 to 6 args — needed for
// EFI_PCI_IO_PROTOCOL.Mem.Read / Mem.Write, whose canonical
// signature is `(This*, Width, BarIndex, Offset, Count, Buffer*)` —
// six args. On AAPCS64 the 5th and 6th args land in X4 and X5,
// trivially.
//
// AAPCS64 preserves X19..X28 across calls; the firmware honours that,
// so we stash the Go link register (X30) in X19 across the BL.
// R28 is reserved by Go's arm64 ABI for the g pointer — DO NOT touch.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3, a4, a5 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-64
	MOVD	fn+0(FP), R8
	MOVD	a0+8(FP), R0
	MOVD	a1+16(FP), R1
	MOVD	a2+24(FP), R2
	MOVD	a3+32(FP), R3
	MOVD	a4+40(FP), R4
	MOVD	a5+48(FP), R5

	// preserve Go's LR (X30) across the firmware BL
	MOVD	R30, R19

	// indirect call through the service slot
	MOVD	(R8), R9
	BL	(R9)

	// restore LR, publish the EFI_STATUS
	MOVD	R19, R30
	MOVD	R0, status+56(FP)
	RET
