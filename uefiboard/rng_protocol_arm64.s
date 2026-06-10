// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — aarch64 firmware->Go callback trampolines
// for EFI_RNG_PROTOCOL.GetRNG + GetInfo (Phase 2, M8.7 — R-M8.6a).
//
// Same shape as initrd_protocol_arm64.s (LoadFile2 trampoline);
// see that file's frame-layout commentary for the Go-ABI0 +
// AAPCS64 conventions. The two functions here service the two
// slots of EFI_RNG_PROTOCOL:
//
//   typedef struct {
//       EFI_RNG_GET_INFO  GetInfo;   // (this, *listSize, *listPtr)            -> EFI_STATUS
//       EFI_RNG_GET_RNG   GetRNG;    // (this, *alg, valueLength, *valuePtr)   -> EFI_STATUS
//   } EFI_RNG_PROTOCOL;
//
// AAPCS64 on entry (firmware -> us):
//
//   GetRNG:                              GetInfo:
//     X0 = this                            X0 = this
//     X1 = alg                             X1 = listSize  (UINTN *)
//     X2 = valueLength                     X2 = listPtr   (EFI_RNG_ALGORITHM *)
//     X3 = valuePtr                        ret in X0
//     ret in X0
//
// Frame layout for GetRNG (4 args + 1 ret slot, Go ABI0 reserves
// SP+0 as saved-LR placeholder on load/store arches):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg alg
//   SP+24   arg valueLength
//   SP+32   arg valuePtr
//   SP+40   ret status
//   SP+48   saved X29 (FP)
//   SP+56   saved X30 (LR)
//   SP+64   saved X19
//   SP+72   saved X20
//   SP+80   saved X21
//   SP+88   saved X22
//   SP+96   saved X23
//   SP+104  saved X24
//   SP+112  saved X25
//   SP+120  padding (16-byte alignment)
// Total: 128 bytes.
//
// Frame layout for GetInfo (3 args + 1 ret slot):
//
//   SP+0    reserved (Go ABI0 saved-LR slot)
//   SP+8    arg this
//   SP+16   arg listSize
//   SP+24   arg listPtr
//   SP+32   ret status
//   SP+40   saved X29 (FP)
//   SP+48   saved X30 (LR)
//   SP+56   saved X19
//   SP+64   saved X20
//   SP+72   saved X21
//   SP+80   saved X22
//   SP+88   saved X23
//   SP+96   saved X24
//   SP+104  saved X25
//   SP+112  padding
//   SP+120  padding (16-byte alignment)
// Total: 128 bytes (same allocation; we use ample headroom for both).

#include "textflag.h"

// func rngGetRNG_trampoline()
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$128, RSP

	MOVD	R29, 48(RSP)
	MOVD	R30, 56(RSP)
	MOVD	R19, 64(RSP)
	MOVD	R20, 72(RSP)
	MOVD	R21, 80(RSP)
	MOVD	R22, 88(RSP)
	MOVD	R23, 96(RSP)
	MOVD	R24, 104(RSP)
	MOVD	R25, 112(RSP)

	// Marshal EFI args (X0..X3) into Go-ABI0 outgoing slots at
	// SP+8..SP+32 (skipping the SP+0 saved-LR-slot reservation).
	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // alg
	MOVD	R2, 24(RSP)  // valueLength
	MOVD	R3, 32(RSP)  // valuePtr

	BL	·rngGetRNGGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	40(RSP), R0

	MOVD	48(RSP), R29
	MOVD	56(RSP), R30
	MOVD	64(RSP), R19
	MOVD	72(RSP), R20
	MOVD	80(RSP), R21
	MOVD	88(RSP), R22
	MOVD	96(RSP), R23
	MOVD	104(RSP), R24
	MOVD	112(RSP), R25
	ADD	$128, RSP
	RET

// func rngGetInfo_trampoline()
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$128, RSP

	MOVD	R29, 40(RSP)
	MOVD	R30, 48(RSP)
	MOVD	R19, 56(RSP)
	MOVD	R20, 64(RSP)
	MOVD	R21, 72(RSP)
	MOVD	R22, 80(RSP)
	MOVD	R23, 88(RSP)
	MOVD	R24, 96(RSP)
	MOVD	R25, 104(RSP)

	// Marshal EFI args (X0..X2) into Go-ABI0 outgoing slots at
	// SP+8..SP+24 (skipping the SP+0 saved-LR-slot reservation).
	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // listSize
	MOVD	R2, 24(RSP)  // listPtr

	BL	·rngGetInfoGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	32(RSP), R0

	MOVD	40(RSP), R29
	MOVD	48(RSP), R30
	MOVD	56(RSP), R19
	MOVD	64(RSP), R20
	MOVD	72(RSP), R21
	MOVD	80(RSP), R22
	MOVD	88(RSP), R23
	MOVD	96(RSP), R24
	MOVD	104(RSP), R25
	ADD	$128, RSP
	RET
