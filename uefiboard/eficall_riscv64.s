// cloud-boot UEFI board — RISC-V 64 firmware-call thunk.
//
// UEFI on RISC-V follows the LP64 calling convention (RISC-V ELF psABI,
// also adopted by UEFI 2.10 §2.3.7): integer/pointer args in A0..A7,
// return value in A0, 16-byte stack alignment at the call site, no
// "shadow space" (unlike MS x64). The thunk loads the caller's args
// into LP64 positions and calls indirectly through the service's
// function-pointer slot.
//
// Phase 2 widened the thunk to 5 args. The immediate driver was a real
// fault: under EDK2 stable202408 on QEMU `-machine virt`, the M0 probe's
// 4-arg call to gBS->GetMemoryMap left A4 with whatever value the Go
// runtime happened to have spilled there. EDK2's CoreGetMemoryMap reads
// A4 as the `DescriptorVersion` pointer parameter and (when non-NULL)
// stores `*DescriptorVersion = EFI_MEMORY_DESCRIPTOR_VERSION`. A4 was
// non-NULL but stale, so the store faulted with
// EXCEPT_RISCV_STORE_ACCESS_PAGE_FAULT at stval ~ NULL-256. amd64 +
// arm64 + loong64 happened to leave the 5th-arg position zero so EDK2's
// NULL guard kicked in there; riscv64 didn't get that luck. Passing an
// explicit 5th arg (a valid pointer or 0) fixes it once and for all,
// and it's what gBS->LoadImage (6 args) needs at M4 anyway. See
// `cloud-boot/docs/riscv64-edk2-getmemorymap-fix.md` for the full
// analysis and the upstream-staged EDK2 patch.
//
// Phase 2 M2 further widened from 5 to 6 args — needed for
// EFI_PCI_IO_PROTOCOL.Mem.Read / Mem.Write, whose signature is
// `(This*, Width, BarIndex, Offset, Count, Buffer*)` — six args.
// On LP64 the 6th arg lands in A5, trivially. Same lesson as the 5th
// arg: callers MUST pass a defined value (0 if unused) to avoid
// faulting firmware on stale-register dereferences. This is enforced
// by the Go declaration's parameter list.
//
// LP64 preserves S0..S11 across calls (and the firmware honours that),
// so we stash the Go link register (X1/RA) in S0 across the JALR.
// X27 (S11) is reserved by Go's riscv64 ABI for the g pointer — DO NOT touch.
// X31 (T6) is reserved as the Go assembler scratch register — also do not stash here.

#include "textflag.h"

// func efiCall(fn, a0, a1, a2, a3, a4, a5 uint64) (status uint64)
TEXT ·efiCall(SB),NOSPLIT,$0-64
	MOV	fn+0(FP), T0
	MOV	a0+8(FP), A0
	MOV	a1+16(FP), A1
	MOV	a2+24(FP), A2
	MOV	a3+32(FP), A3
	MOV	a4+40(FP), A4
	MOV	a5+48(FP), A5

	// preserve Go's link register (X1/RA) across the firmware call in S0,
	// which is callee-saved under LP64.
	MOV	X1, S0

	// indirect call through the service slot (T0 = fn pointer; deref to
	// obtain the actual entry, then JALR through it).
	MOV	(T0), T1
	JALR	RA, (T1)

	// restore Go RA, publish the EFI_STATUS (A0 holds the LP64 return).
	MOV	S0, X1
	MOV	A0, status+56(FP)
	RET
