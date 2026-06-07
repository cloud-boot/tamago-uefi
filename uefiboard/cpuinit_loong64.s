// cloud-boot UEFI board — LoongArch 64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the LoongArch LP64 calling convention (UEFI 2.10 §2.3.x):
// R4 (A0) = ImageHandle, R5 (A1) = *EFI_SYSTEM_TABLE. Firmware has
// already brought the platform up in PLV0 with the MMU, interrupt
// controller and stable-timer initialised, so we skip the framework's
// bare-metal init (CSR.EUEN.FPE/CSR.EENTRY/CSR.DMW writes — those are
// done by EDK2 already for the firmware's own purposes) and only
// capture the handoff state, allocate a writable heap chunk via
// gBS->AllocatePages (the page immediately past our image is
// frequently another firmware module's RO data and picking "text +
// N" is unsafe), set RamStart/RamSize/Bloc to that chunk, point the
// stack at its top, then enter the standard loong64 TamaGo rt0 path.
//
// LoongArch register summary (Go asm naming):
//   R0  = zero    R1  = RA (link)
//   R2  = TP      R3  = SP
//   R4..R11       arg/return (A0..A7)
//   R12..R20      caller-saved temporaries
//   R21..R31      callee-saved (R22 = g per Go ABI, R30 = asm tmp)

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
	// Phase-1.5 boot marker on the QEMU virt ns16550a UART (THR
	// at 0x1FE001E0). Confirms firmware actually entered our PE
	// before the AllocatePages call clobbers some of A0..A7.
	MOVV	$0x1fe001e0, R12
	MOVV	$65, R13	// 'A'
	MOVB	R13, (R12)

	// UEFI 2.10 LoongArch handoff state.
	MOVV	R4, ·imageHandle(SB)
	MOVV	R5, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut at offset 64.
	MOVV	EFI_ST_CONOUT(R5), R6
	MOVV	R6, ·conOut(SB)

	// Preserve SystemTable in R23 (callee-saved under LP64) across
	// the BL into AllocatePages.
	MOVV	R5, R23

	// gBS = SystemTable->BootServices, then AllocatePages slot.
	MOVV	EFI_ST_BOOTSERVICES(R5), R12
	MOVV	EFI_BS_ALLOCATEPAGES(R12), R13

	// AllocatePages(AllocateAnyPages, EfiLoaderData, RamSize>>12, &heapBase).
	// LP64: R4..R7 hold args. Derive Pages from linker-supplied RamSize
	// so changing the heap size only touches board_loong64.go.
	MOVV	$EFI_ALLOCATE_ANY_PAGES, R4
	MOVV	$EFI_LOADER_DATA, R5
	MOVV	runtime∕goos·RamSize(SB), R6
	SRLV	$12, R6
	MOVV	$·heapBase(SB), R7
	// stash Go RA (R1) — LP64 firmware will clobber it.
	MOVV	R1, R24
	JAL	(R13)
	MOVV	R24, R1

	// R4 = EFI_STATUS. Non-zero == failure; halt.
	BNE	R4, R0, allocFail

	// Enable the FPU: CSR.EUEN.FPE = 1 (CSR 0x2 bit 0). Empirically
	// QEMU's EDK2 LoongArch leaves FPE clear in the boot env it hands
	// to us (the floating-point disable exception fires on the first
	// fmov/fadd otherwise), so re-enable it here BEFORE control reaches
	// any Go code. csrwr lacks a mnemonic in Go's loong64 assembler,
	// so the instruction is encoded directly:
	//   csrwr R19, 0x2  =>  0x04000020 | (0x2<<10) | (1<<5) | 19  =  0x04000833.
	MOVV	$1, R19
	WORD	$0x04000833

	// Wire RamStart + Bloc to the allocated base.
	MOVV	·heapBase(SB), R6
	MOVV	R6, runtime∕goos·RamStart(SB)
	MOVV	R6, runtime∕goos·Bloc(SB)

	// SP (R3) = RamStart + RamSize - RamStackOffset.
	MOVV	R6, R3
	MOVV	runtime∕goos·RamSize(SB), R7
	MOVV	runtime∕goos·RamStackOffset(SB), R8
	ADDV	R7, R3
	SUBV	R8, R3

	// enter the standard loong64 TamaGo rt0
	JMP	_rt0_tamago_start(SB)

allocFail:
	// No fallback console at this point; spin so the failure is
	// visible (and pre-fault) rather than wandering into RO memory.
	JMP	allocFail
