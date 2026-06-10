// cloud-boot UEFI board — amd64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters here
// with the MS x64 ABI: RCX = ImageHandle, RDX = *EFI_SYSTEM_TABLE. No Go
// stack and no runtime exist yet, so the very first instructions must
// capture the handoff registers before anything clobbers them.
//
// Mirrors the contract of TamaGo's goos trampoline (runtime/goos.CPUInit
// → JMP cpuinit) and ends by entering the standard amd64 TamaGo rt0.
//
// R-amd64f #2 (2026-06-10): RamStart is anchored at the page-aligned start
// of `·heapReserve(SB)` — a 128 MiB .bss reservation in board_amd64.go that
// the firmware's own LoadImage AllocatePages already covered (the linker
// rolls it into the PE32+ SizeOfImage). We do NOT call any Boot Service
// from cpuinit: every Boot Service dispatch from cpuinit on patched OVMF
// amd64 crashes (R-amd64e H5/H6 confirmed it's not AllocatePages-specific;
// see docs/m6-2-edk2-upstream-investigation.md § 15 + § 16). The reserve
// IS firmware-allocated, RW, mapped, ours — we just need to compute its
// page-aligned base and point the runtime at it.

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

	// RamStart = page_align_up(&heapReserve[0]). heapReserve is the
	// 128 MiB .bss reservation in board_amd64.go (firmware-allocated as
	// part of our PE32+ SizeOfImage); rounding up to the next 4 KiB
	// boundary guarantees clean page math even though Go's linker does
	// not promise page-aligned BSS symbol placement.
	MOVQ	$·heapReserve(SB), AX
	ADDQ	$0xFFF, AX
	ANDQ	$~0xFFF, AX
	MOVQ	AX, runtime∕goos·RamStart(SB)

	// stack pointer = RamStart + RamSize - RamStackOffset (top of RAM
	// minus the reserved stack window). RamSize == heapReserveSize
	// (128 MiB) — set in board_amd64.go; the trailing +4096 slack on
	// heapReserve absorbs the round-up so we never run past the array.
	MOVQ	runtime∕goos·RamStart(SB), SP
	MOVQ	runtime∕goos·RamSize(SB), AX
	MOVQ	runtime∕goos·RamStackOffset(SB), BX
	ADDQ	AX, SP
	SUBQ	BX, SP

	// enter the standard amd64 TamaGo runtime bring-up
	JMP	runtime·rt0_amd64_tamago(SB)
