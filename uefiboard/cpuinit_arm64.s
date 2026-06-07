// cloud-boot UEFI board — aarch64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the AArch64 calling convention (AAPCS64): X0 = ImageHandle,
// X1 = *EFI_SYSTEM_TABLE. Firmware has already brought the platform up
// in EL1 with the MMU + GIC initialised, so we skip the framework's
// EL3->EL1 dance (which the stock framework cpuinit performs for bare
// metal) and only capture the handoff state, allocate a writable heap
// chunk via gBS->AllocatePages (the page immediately past our image
// is frequently another firmware module's RO .text, so we MUST go
// through Boot Services to get guaranteed-writable memory — picking
// "text +/- N" is unsafe), set RamStart/RamSize/Bloc to that chunk,
// point the stack at its top, and enter the standard arm64 TamaGo
// rt0 path.

#include "textflag.h"

// EFI_SYSTEM_TABLE field offsets (UEFI 2.10 §4.3.1)
#define EFI_ST_CONOUT          64
#define EFI_ST_BOOTSERVICES    96

// EFI_BOOT_SERVICES field offsets (UEFI 2.10 §4.2)
#define EFI_BS_ALLOCATEPAGES   40

// EFI_ALLOCATE_TYPE / EFI_MEMORY_TYPE enums (UEFI 2.10 §7.2)
#define EFI_ALLOCATE_ANY_PAGES  0
#define EFI_LOADER_DATA         2

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// UEFI 2.3.4.1 handoff state
	MOVD	R0, ·imageHandle(SB)
	MOVD	R1, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut at offset 64 (12.4 SimpleTextOutput)
	MOVD	EFI_ST_CONOUT(R1), R2
	MOVD	R2, ·conOut(SB)

	// gBS = SystemTable->BootServices, then AllocatePages function ptr.
	MOVD	EFI_ST_BOOTSERVICES(R1), R10
	MOVD	EFI_BS_ALLOCATEPAGES(R10), R11

	// AllocatePages(AllocateAnyPages, EfiLoaderData, RamSize>>12, &heapBase).
	// AAPCS64: X0=Type, X1=MemoryType, X2=Pages, X3=*Memory.
	// Derive Pages from the linker-supplied RamSize so changing the heap
	// size only requires touching board_arm64.go's `ramSize`.
	MOVD	$EFI_ALLOCATE_ANY_PAGES, R0
	MOVD	$EFI_LOADER_DATA, R1
	MOVD	runtime∕goos·RamSize(SB), R2
	LSR	$12, R2, R2
	MOVD	$·heapBase(SB), R3
	BL	(R11)

	// R0 = EFI_STATUS. Non-zero == failure; halt with a marker.
	// Anything else is unsafe to continue with — Boot Services is our
	// only path to writable memory beyond the image and we have no
	// fallback console at this point.
	CBNZ	R0, allocFail

	// Wire RamStart + Bloc to the allocated base. Setting both makes
	// `osinit` skip its `firstmoduledata.end`-based bloc init and use
	// our base instead, which is the whole point: the runtime's sbrk
	// allocator starts at Bloc and grows up, so we MUST anchor it to
	// the page chunk we just allocated.
	MOVD	·heapBase(SB), R3
	MOVD	R3, runtime∕goos·RamStart(SB)
	MOVD	R3, runtime∕goos·Bloc(SB)

	// SP = RamStart + RamSize - RamStackOffset (top of the chunk,
	// minus the reserved stack window). Mirrors framework arm64/init.s.
	MOVD	R3, RSP
	MOVD	runtime∕goos·RamSize(SB), R1
	MOVD	runtime∕goos·RamStackOffset(SB), R2
	ADD	R1, RSP
	SUB	R2, RSP

	// Clear SCTLR_EL1.A (alignment check). Leave M (MMU enable) ON so the
	// firmware's identity-mapped page tables continue to cover code/data
	// and MMIO with the right memory attributes; turning the MMU off
	// downgrades MMIO writes (e.g. the PL011 UART) to a default
	// Normal-Non-cacheable type and they stop becoming visible.
	MRS	SCTLR_EL1, R3
	BIC	$1<<1, R3	// A: alignment check
	MSR	R3, SCTLR_EL1
	WORD	$0xd5033fdf	// isb sy (Go arm64 asm rejects "ISB SY" without arm64.h macros)

	// Enable FP/SIMD access at EL0/EL1 via CPACR_EL1.FPEN = 0b11. Go arm64
	// codegen uses V/D/S registers throughout; if firmware left FPEN
	// disabled, any FP/SIMD instruction in the runtime would trap.
	MRS	CPACR_EL1, R3
	ORR	$(3<<20), R3
	MSR	R3, CPACR_EL1
	WORD	$0xd5033fdf	// isb sy

	// enter the standard arm64 TamaGo rt0
	B	_rt0_tamago_start(SB)

allocFail:
	// AllocatePages returned non-zero. We have no console here (ConOut
	// would require a goroutine-grade stack we don't yet have), so just
	// park forever. A real loader would print the status to a UART that
	// it knows is available pre-MMU and reset the platform.
	B	allocFail
