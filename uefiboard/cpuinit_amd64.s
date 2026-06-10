// cloud-boot UEFI board — amd64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters here
// with the MS x64 ABI: RCX = ImageHandle, RDX = *EFI_SYSTEM_TABLE. No Go
// stack and no runtime exist yet, so the very first instructions must
// capture the handoff registers before anything clobbers them.
//
// R-amd64e H6 probe (2026-06-10): Re-introduces R-amd64b's
// AllocatePages-from-cpuinit, but this time BRACKETED by
// gBS->RaiseTPL(TPL_NOTIFY) / gBS->RestoreTPL(savedTPL). The hypothesis
// (per docs § 14.5 H6): the patched-OVMF AllocatePages crash may be a
// race with firmware-internal event-handler callbacks (timer ticks,
// virtual-address-change events) that fire during the dispatch at
// TPL_APPLICATION (the default level at StartImage entry). Raising to
// TPL_NOTIFY (16) masks every event with a TPL <= NOTIFY, including
// the timer event the firmware's idle loop uses. If H6 holds, the
// matrix flips back to all-original-PASS like R-amd64a baseline.
//
// Falls back to bare-metal RamStart heuristic if AllocatePages fails:
// the bare-metal path is what main currently ships and what H5's
// hwinit1 probe rides on top of (so even if H6 doesn't help, this
// cpuinit gives a clean state from which the H5-style hwinit1
// AllocatePages can run).
//
// Mirrors the contract of TamaGo's goos trampoline (runtime/goos.CPUInit
// → JMP cpuinit) and ends by entering the standard amd64 TamaGo rt0.

#include "textflag.h"

// EFI_SYSTEM_TABLE field offsets (UEFI 2.10 §4.3.1).
#define EFI_ST_CONOUT          64
#define EFI_ST_BOOTSERVICES    96

// EFI_BOOT_SERVICES field offsets (UEFI 2.10 §4.2 — natural layout,
// 24 bytes of EFI_TABLE_HEADER preceding the function pointers).
#define EFI_BS_RAISE_TPL       24
#define EFI_BS_RESTORE_TPL     32
#define EFI_BS_ALLOCATEPAGES   40

// EFI_ALLOCATE_TYPE / EFI_MEMORY_TYPE enums (UEFI 2.10 §7.2).
#define EFI_ALLOCATE_ANY_PAGES   0
#define EFI_BOOT_SERVICES_DATA   4

// EFI_TPL levels (UEFI 2.10 §7.1).
#define TPL_NOTIFY              16

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// firmware may leave interrupts enabled
	CLI

	// UEFI 2.3.4.1 handoff state
	MOVQ	CX, ·imageHandle(SB)
	MOVQ	DX, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut at offset 64 (12.4 Simple Text Output)
	MOVQ	EFI_ST_CONOUT(DX), AX
	MOVQ	AX, ·conOut(SB)

	// Go's amd64 codegen uses SSE; firmware does not guarantee the CR0/CR4
	// SSE bits. Reuse the framework's enabler (amd64/features.s). UEFI is
	// already in long mode with paging, so we do NOT touch page tables.
	CALL	sse_enable(SB)

	// gBS = SystemTable->BootServices.
	MOVQ	EFI_ST_BOOTSERVICES(DX), R10

	// H6 step 1: RaiseTPL(TPL_NOTIFY). 1-arg call (MS x64: RCX),
	// returns the previous TPL in RAX. The previous TPL is stashed
	// in R15 (callee-saved under MS x64) so we can restore it after
	// AllocatePages.
	MOVQ	EFI_BS_RAISE_TPL(R10), R11
	MOVQ	$TPL_NOTIFY, CX
	MOVQ	SP, R13					// stash original SP
	SUBQ	$32, SP					// MS x64 shadow space
	ANDQ	$~15, SP				// 16-byte align at CALL site
	CALL	(R11)
	MOVQ	R13, SP					// restore SP
	MOVQ	AX, R15					// stash previous TPL

	// H6 step 2: AllocatePages(AllocateAnyPages, EfiBootServicesData,
	// RamSize>>12, &heapBase). MS x64 RCX/RDX/R8/R9; 32-byte shadow;
	// 16-byte SP alignment.
	// RDX may have been clobbered by RaiseTPL — reload gBS pointer
	// from the systemTable package global.
	MOVQ	·systemTable(SB), DX
	MOVQ	EFI_ST_BOOTSERVICES(DX), R10
	MOVQ	EFI_BS_ALLOCATEPAGES(R10), R11
	MOVQ	$EFI_ALLOCATE_ANY_PAGES, CX
	MOVQ	$EFI_BOOT_SERVICES_DATA, DX
	MOVQ	runtime∕goos·RamSize(SB), R8
	SHRQ	$12, R8					// pages = RamSize >> 12
	MOVQ	$·heapBase(SB), R9
	MOVQ	SP, R13
	SUBQ	$32, SP
	ANDQ	$~15, SP
	CALL	(R11)
	MOVQ	R13, SP
	MOVQ	AX, R12					// save EFI_STATUS

	// H6 step 3: RestoreTPL(previous TPL stashed in R15). 1-arg call,
	// no return value.
	MOVQ	·systemTable(SB), DX
	MOVQ	EFI_ST_BOOTSERVICES(DX), R10
	MOVQ	EFI_BS_RESTORE_TPL(R10), R11
	MOVQ	R15, CX					// previous TPL
	MOVQ	SP, R13
	SUBQ	$32, SP
	ANDQ	$~15, SP
	CALL	(R11)
	MOVQ	R13, SP

	// AllocatePages status check.
	TESTQ	R12, R12
	JNZ	allocFallback

	// AllocatePages succeeded: anchor RamStart + Bloc to the allocated
	// base. Setting both makes osinit skip its `firstmoduledata.end`-
	// based bloc init and use our base instead.
	MOVQ	·heapBase(SB), R12
	MOVQ	R12, runtime∕goos·RamStart(SB)
	MOVQ	R12, runtime∕goos·Bloc(SB)

	// SP = heapBase + RamSize - RamStackOffset (top of the chunk
	// minus the reserved stack window). Matches arm64 / riscv64 /
	// loong64 paths.
	MOVQ	R12, SP
	MOVQ	runtime∕goos·RamSize(SB), AX
	MOVQ	runtime∕goos·RamStackOffset(SB), BX
	ADDQ	AX, SP
	SUBQ	BX, SP

	// R-amd64c SP-alignment defensive nudge.
	SUBQ	$8, SP

	JMP	runtime·rt0_amd64_tamago(SB)

allocFallback:
	// AllocatePages failed but didn't crash the firmware (the H6
	// hypothesis is that RaiseTPL prevents the crash; if it returns
	// a non-zero status instead, we silently fall back to the
	// bare-metal heuristic so the runtime still comes up and the
	// hwinit1 probe can run).
	MOVQ	$runtime·text(SB), AX
	SUBQ	$(64*1024), AX
	MOVQ	AX, runtime∕goos·RamStart(SB)
	MOVQ	runtime∕goos·RamStart(SB), SP
	MOVQ	runtime∕goos·RamSize(SB), AX
	MOVQ	runtime∕goos·RamStackOffset(SB), BX
	ADDQ	AX, SP
	SUBQ	BX, SP
	JMP	runtime·rt0_amd64_tamago(SB)
