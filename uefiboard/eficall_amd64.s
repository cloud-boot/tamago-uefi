// cloud-boot UEFI board — MS x64 firmware-call thunk.
//
// UEFI services use the Microsoft x64 calling convention (RCX, RDX, R8, R9
// for the first four integer/pointer args, status returned in RAX, with a
// mandatory 32-byte "shadow space" reserved below the return address and
// 16-byte stack alignment at the call site). The Go (System V) ABI differs,
// so every firmware call goes through this thunk.
//
// Phase 2 M2 widened the thunk from 5 to 6 args — needed for
// EFI_PCI_IO_PROTOCOL.Mem.Read / Mem.Write, whose canonical signature
// is `(This*, Width, BarIndex, Offset, Count, Buffer*)` — six args.
// On MS x64 the 5th and 6th integer args live on the stack at
// [RSP+0x20] and [RSP+0x28], just above the 32-byte shadow space.
// The thunk stores a4/a5 there *before* the CALL so the callee can
// read them after pushing its own return address.
//
// Callees that take fewer than 6 args ignore the trailing slots. The
// Phase-1 / M0 / M1 / M1.5 / M1.6 call sites pass 0 for the unused
// trailing positions.
//
// R-amd64b (2026-06-09): dropped the pre-CALL `SP = RamStart + RamSize`
// stack switch. The original switch existed to give firmware "a large,
// valid stack" — but it derived the new SP from the same broken
// `RamStart + 704 MiB` calculation cpuinit used (text + 704 MiB, which
// overflowed past the QEMU q35 `0x80000000` PCI MMIO hole when OVMF
// loaded multi-MiB images near the top of free RAM), and on top of
// that, switching to the TOP of our allocated heap mid-runtime would
// stomp on memory the goroutine has already passed through (g0 stack
// lives in the SAME region after R-amd64b's cpuinit rewrite). The
// arm64 / riscv64 / loong64 thunks have never done this and Boot
// Services calls (ConOut->OutputString, AllocatePages, LoadImage,
// StartImage, exit) fit comfortably in a Go goroutine stack. Same
// shape adopted here. See cloud-boot/docs/m6-2-edk2-upstream-investigation.md
// § 11.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3, a4, a5 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-64
	MOVQ	fn+0(FP), AX
	MOVQ	a0+8(FP), CX
	MOVQ	a1+16(FP), DX
	MOVQ	a2+24(FP), R8
	MOVQ	a3+32(FP), R9
	MOVQ	a4+40(FP), R11	// 5th arg, lands at [RSP+0x20] below
	MOVQ	a5+48(FP), R12	// 6th arg, lands at [RSP+0x28] below

	// Stay on the Go goroutine stack (mirrors arm64 / riscv64 /
	// loong64 thunks). Just reserve the MS x64 frame: 32-byte shadow
	// space + slots for the 5th/6th args, padded so SP stays 16-byte
	// aligned after the CALL's 8-byte return-address push. 48 = 32
	// (shadow) + 16 (slot4 + slot5) gives the right alignment under
	// Go's "SP is 8-mod-16 inside any function frame" convention.
	SUBQ	$48, SP
	MOVQ	R11, 32(SP)		// 5th arg at [RSP+0x20]
	MOVQ	R12, 40(SP)		// 6th arg at [RSP+0x28]

	// fn is the address of the service's function-pointer slot (e.g.
	// ConOut+OutputString); call indirectly through it.
	CALL	(AX)
	ADDQ	$48, SP

	// firmware may have re-enabled interrupts
	CLI

	// publish the EFI_STATUS (FP is valid again now that SP is back
	// to its entry value)
	MOVQ	AX, status+56(FP)
	RET
