// cloud-boot UEFI board — RISC-V 64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the RISC-V LP64 calling convention: A0 = ImageHandle,
// A1 = *EFI_SYSTEM_TABLE (per UEFI 2.10 §2.3.7 "RISC-V Platforms").
// Firmware has already brought the platform up in S-mode (M-mode is
// occupied by OpenSBI), with paging and the GIC equivalent (PLIC)
// initialised, so we skip the framework's bare-metal init (which calls
// `set_mtvec` from M-mode and is incompatible here) and only capture
// the handoff state, derive RamStart from the actual loaded text VA,
// set up the stack, and enter the standard riscv64 TamaGo rt0 path.

#include "textflag.h"

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// UEFI 2.10 RISC-V handoff state: A0 = ImageHandle, A1 = SystemTable.
	// (X10 == A0, X11 == A1 in the LP64 ABI.)
	MOV	A0, ·imageHandle(SB)
	MOV	A1, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut is at offset 64 (12.4 Simple Text Output)
	MOV	64(A1), T0
	MOV	T0, ·conOut(SB)

	// RamStart = &runtime.text + 2 MiB.  Same rationale as the arm64
	// leg: UEFI image-protection on RISC-V (S-mode page tables) marks
	// the PE .reloc / .data sub-pages of the loaded image read-only,
	// so the heap arena must start *past* the whole image rather than
	// 64 KiB below it, otherwise the first scheduler write that lands
	// inside the image takes a Store Page Fault.
	MOV	$runtime·text(SB), T0
	MOV	$0x200000, T1
	ADD	T1, T0, T0
	MOV	T0, runtime∕goos·RamStart(SB)

	// SP (X2) = RamStart + RamSize - RamStackOffset (top of RAM minus
	// the reserved stack window). Mirrors framework riscv64/init.s.
	MOV	runtime∕goos·RamStart(SB), X2
	MOV	runtime∕goos·RamSize(SB), T1
	MOV	runtime∕goos·RamStackOffset(SB), T2
	ADD	T1, X2
	SUB	T2, X2

	// FPU enable: SSTATUS.FS = 0b01 (Initial). RISC-V FP/FD instructions
	// trap unless FS != 0. Go's riscv64 codegen uses F/D regs throughout;
	// if firmware left FS=Off any FP/D insn in the runtime would trap.
	// (CSR encoding 0x100 = sstatus.)
	MOV	$(1<<13), T0
	CSRRS	T0, SSTATUS, ZERO

	// enter the standard riscv64 TamaGo rt0
	JMP	_rt0_tamago_start(SB)
