// cloud-boot UEFI board — LoongArch64 firmware-call thunk.
//
// UEFI on LoongArch follows the LoongArch ELF psABI LP64 (UEFI 2.10
// §2.3.x): integer/pointer args in R4..R11 (A0..A7), return value in
// R4 (A0), 16-byte stack alignment at the call site, no "shadow space".
// The thunk loads the caller's args into LP64 positions and calls
// indirectly through the service's function-pointer slot.
//
// Phase 2 widened the thunk to 5 args — needed for gBS->GetMemoryMap
// (5 OUT params), gBS->LoadImage (6 args), the EFI_HTTP_PROTOCOL
// async-token paths, and the EFI_DHCP4 / EFI_DNS4 protocol-family
// entry points. On LP64 the 5th arg lands in R8 (A4), trivially.
//
// LP64 preserves R22..R31 (saved registers) across calls. R22 is the
// Go g pointer and MUST NOT be touched; we stash the Go link register
// (R1) in R23, which is caller-callee-saved under LP64 and unused by
// Go's codegen elsewhere in this thunk. R30 is the Go asm scratch reg
// and we avoid it inside the call window.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3, a4 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-56
	MOVV	fn+0(FP), R12
	MOVV	a0+8(FP), R4
	MOVV	a1+16(FP), R5
	MOVV	a2+24(FP), R6
	MOVV	a3+32(FP), R7
	MOVV	a4+40(FP), R8

	// preserve Go's link register (R1/RA) in R23 (callee-saved under
	// LP64; firmware honours that, and Go's compiler does not use R23
	// for anything in this thunk).
	MOVV	R1, R23

	// indirect call through the service slot (R12 holds the address of
	// the function-pointer slot; deref it then JALR through R13).
	MOVV	(R12), R13
	JAL	(R13)

	// restore Go RA, publish the EFI_STATUS (R4/A0 holds the return).
	MOVV	R23, R1
	MOVV	R4, status+48(FP)
	RET
