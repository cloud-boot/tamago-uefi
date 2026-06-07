// cloud-boot UEFI board — RISC-V 64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the RISC-V LP64 calling convention: A0 = ImageHandle,
// A1 = *EFI_SYSTEM_TABLE (per UEFI 2.10 §2.3.7 "RISC-V Platforms").
// Firmware has already brought the platform up in S-mode (M-mode is
// occupied by OpenSBI), with paging and the GIC equivalent (PLIC)
// initialised, so we skip the framework's bare-metal init (which calls
// `set_mtvec` from M-mode and is incompatible here) and only capture
// the handoff state, allocate a writable heap chunk via
// gBS->AllocatePages (the page immediately past our image is
// frequently another firmware module's RO data, so picking
// "text + N" as heap base is unsafe — same arm64/loong64 lesson),
// set RamStart/RamSize/Bloc to that chunk, set the stack to its top,
// and enter the standard riscv64 TamaGo rt0 path.

#include "textflag.h"

// EFI_SYSTEM_TABLE field offsets (UEFI 2.10 §4.3.1).
#define EFI_ST_CONOUT          64
#define EFI_ST_BOOTSERVICES    96

// EFI_BOOT_SERVICES field offsets (UEFI 2.10 §4.2).
#define EFI_BS_ALLOCATEPAGES   40

// EFI_ALLOCATE_TYPE / EFI_MEMORY_TYPE enums.
#define EFI_ALLOCATE_ANY_PAGES  0
#define EFI_LOADER_DATA         2

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// UEFI 2.10 RISC-V handoff state: A0 = ImageHandle, A1 = SystemTable.
	// (X10 == A0, X11 == A1 in the LP64 ABI.)
	MOV	A0, ·imageHandle(SB)
	MOV	A1, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut at offset 64.
	MOV	EFI_ST_CONOUT(A1), T0
	MOV	T0, ·conOut(SB)

	// Preserve SystemTable across BL by stashing in S0 (callee-saved
	// under LP64 / RISC-V psABI).
	MOV	A1, S0

	// gBS = SystemTable->BootServices, then AllocatePages slot.
	MOV	EFI_ST_BOOTSERVICES(A1), T0
	MOV	EFI_BS_ALLOCATEPAGES(T0), T1

	// AllocatePages(AllocateAnyPages, EfiLoaderData, RamSize>>12, &heapBase).
	// LP64: A0..A3 hold args.
	MOV	$EFI_ALLOCATE_ANY_PAGES, A0
	MOV	$EFI_LOADER_DATA, A1
	MOV	runtime∕goos·RamSize(SB), A2
	SRL	$12, A2, A2
	MOV	$·heapBase(SB), A3
	// Preserve Go's return address (X1/RA) — LP64 firmware may clobber it.
	MOV	X1, S1
	JALR	X1, (T1)
	MOV	S1, X1

	// A0 = EFI_STATUS. Non-zero == failure; halt.
	BNE	A0, ZERO, allocFail

	// Wire RamStart + Bloc to the allocated base.
	MOV	·heapBase(SB), T0
	MOV	T0, runtime∕goos·RamStart(SB)
	MOV	T0, runtime∕goos·Bloc(SB)

	// SP (X2) = RamStart + RamSize - RamStackOffset.
	MOV	T0, X2
	MOV	runtime∕goos·RamSize(SB), T1
	MOV	runtime∕goos·RamStackOffset(SB), T2
	ADD	T1, X2
	SUB	T2, X2

	// FPU enable: SSTATUS.FS = 0b01 (Initial). RISC-V FP/D instructions
	// trap unless FS != 0. Go's riscv64 codegen uses F/D regs throughout;
	// if firmware left FS=Off any FP/D insn in the runtime would trap.
	// (CSR encoding 0x100 = sstatus.)
	MOV	$(1<<13), T0
	CSRRS	T0, SSTATUS, ZERO

	// enter the standard riscv64 TamaGo rt0
	JMP	_rt0_tamago_start(SB)

allocFail:
	JMP	allocFail
