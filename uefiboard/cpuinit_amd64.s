// cloud-boot UEFI board — amd64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters here
// with the MS x64 ABI: RCX = ImageHandle, RDX = *EFI_SYSTEM_TABLE. No Go
// stack and no runtime exist yet, so the very first instructions must
// capture the handoff registers before anything clobbers them.
//
// Mirrors the contract of TamaGo's goos trampoline (runtime/goos.CPUInit
// → JMP cpuinit) and ends by entering the standard amd64 TamaGo rt0.

#include "textflag.h"

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// firmware may leave interrupts enabled
	CLI

	// UEFI 2.3.4.1 handoff state
	MOVQ	CX, ·imageHandle(SB)
	MOVQ	DX, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut is at offset 64 (12.4 Simple Text Output)
	MOVQ	64(DX), AX
	MOVQ	AX, ·conOut(SB)

	// Go's amd64 codegen uses SSE; firmware does not guarantee the CR0/CR4
	// SSE bits. Reuse the framework's enabler (amd64/features.s). UEFI is
	// already in long mode with paging, so we do NOT touch page tables.
	CALL	sse_enable(SB)

	// RamStart = &runtime.text - 64 KiB. Deriving it from the actual loaded
	// text address (rather than the link base) keeps us tolerant to wherever
	// the firmware placed the image.
	MOVQ	$runtime·text(SB), AX
	SUBQ	$(64*1024), AX
	MOVQ	AX, runtime∕goos·RamStart(SB)

	// stack pointer = RamStart + RamSize - RamStackOffset (top of RAM minus
	// the reserved stack window)
	MOVQ	runtime∕goos·RamStart(SB), SP
	MOVQ	runtime∕goos·RamSize(SB), AX
	MOVQ	runtime∕goos·RamStackOffset(SB), BX
	ADDQ	AX, SP
	SUBQ	BX, SP

	// enter the standard amd64 TamaGo runtime bring-up
	JMP	runtime·rt0_amd64_tamago(SB)
