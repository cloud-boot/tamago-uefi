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
// R-fbsd1c (sprint 1.3, 2026-06-11): added AAPCS64 FP callee-saved
// V8..V15 lower-64-bit (D8..D15) save/restore (AAPCS64 §5.1.2). Go's
// arm64 codegen can emit FP ops inside the Go callback even for
// nominally-integer-only handlers, so returning to firmware with
// corrupted D8..D15 risks a delayed firmware-side fault (same shape
// as the amd64 XMM6..XMM15 fix shipped in Sprint 1.2). 8 × 8 B = 64 B
// of FP save area added; frame grew 128 → 192 B (still 16-byte
// aligned). The integer save offsets are unchanged; the FP area
// extends past the highest previous offset.
//
// Frame layout for GetRNG (4 args + 1 ret slot, 192 bytes total):
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
//   SP+120  padding (16-byte alignment for FP area)
//   SP+128  saved D8
//   SP+136  saved D9
//   SP+144  saved D10
//   SP+152  saved D11
//   SP+160  saved D12
//   SP+168  saved D13
//   SP+176  saved D14
//   SP+184  saved D15
// Total: 192 bytes.
//
// Frame layout for GetInfo (3 args + 1 ret slot, 192 bytes total):
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
//   SP+120  padding (16-byte alignment for FP area)
//   SP+128  saved D8
//   SP+136  saved D9
//   SP+144  saved D10
//   SP+152  saved D11
//   SP+160  saved D12
//   SP+168  saved D13
//   SP+176  saved D14
//   SP+184  saved D15
// Total: 192 bytes (same allocation; we use ample headroom for both).

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────
//
// R-fbsd1c sprint 1.3 follow-up: mirror the amd64 LEAQ-direct pattern
// from block_io_publish_amd64.s / sfs_publish_amd64.s. A Go
// function-value's first word points at the *ABIInternal* wrapper,
// not at our .abi0 entry, and the autogen wrapper may end with FP /
// g-register clobbers AFTER our .abi0 epilogue restored them — which
// the firmware-side caller observes as register corruption.
//
// On arm64 the LEAQ-equivalent is the assembler's `MOVD $sym(SB),Rn`
// pseudo, which the assembler expands to `ADRP+ADD` against the
// symbol's PLT/GOT-free address. This resolves to the ABI0 entry
// directly, bypassing the wrapper.
//
// Signature: func rng<op>_trampolinePC() uintptr
TEXT ·rngGetRNG_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·rngGetRNG_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·rngGetInfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·rngGetInfo_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// func rngGetRNG_trampoline()
TEXT ·rngGetRNG_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$192, RSP

	MOVD	R29, 48(RSP)
	MOVD	R30, 56(RSP)
	MOVD	R19, 64(RSP)
	MOVD	R20, 72(RSP)
	MOVD	R21, 80(RSP)
	MOVD	R22, 88(RSP)
	MOVD	R23, 96(RSP)
	MOVD	R24, 104(RSP)
	MOVD	R25, 112(RSP)

	// AAPCS64 §5.1.2 — D8..D15 (lower 64 bits of V8..V15) are
	// callee-saved. FMOVD stores the 64-bit form.
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	// Marshal EFI args (X0..X3) into Go-ABI0 outgoing slots at
	// SP+8..SP+32 (skipping the SP+0 saved-LR-slot reservation).
	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // alg
	MOVD	R2, 24(RSP)  // valueLength
	MOVD	R3, 32(RSP)  // valuePtr

	BL	·rngGetRNGGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	40(RSP), R0

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	48(RSP), R29
	MOVD	56(RSP), R30
	MOVD	64(RSP), R19
	MOVD	72(RSP), R20
	MOVD	80(RSP), R21
	MOVD	88(RSP), R22
	MOVD	96(RSP), R23
	MOVD	104(RSP), R24
	MOVD	112(RSP), R25
	ADD	$192, RSP
	RET

// func rngGetInfo_trampoline()
TEXT ·rngGetInfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$192, RSP

	MOVD	R29, 40(RSP)
	MOVD	R30, 48(RSP)
	MOVD	R19, 56(RSP)
	MOVD	R20, 64(RSP)
	MOVD	R21, 72(RSP)
	MOVD	R22, 80(RSP)
	MOVD	R23, 88(RSP)
	MOVD	R24, 96(RSP)
	MOVD	R25, 104(RSP)

	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)

	// Marshal EFI args (X0..X2) into Go-ABI0 outgoing slots at
	// SP+8..SP+24 (skipping the SP+0 saved-LR-slot reservation).
	MOVD	R0, 8(RSP)   // this
	MOVD	R1, 16(RSP)  // listSize
	MOVD	R2, 24(RSP)  // listPtr

	BL	·rngGetInfoGo(SB)

	// Pull return EFI_STATUS into X0 for the firmware caller.
	MOVD	32(RSP), R0

	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15

	MOVD	40(RSP), R29
	MOVD	48(RSP), R30
	MOVD	56(RSP), R19
	MOVD	64(RSP), R20
	MOVD	72(RSP), R21
	MOVD	80(RSP), R22
	MOVD	88(RSP), R23
	MOVD	96(RSP), R24
	MOVD	104(RSP), R25
	ADD	$192, RSP
	RET
