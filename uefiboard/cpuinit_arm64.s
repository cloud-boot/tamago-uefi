// cloud-boot UEFI board — aarch64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the AArch64 calling convention (AAPCS64): X0 = ImageHandle,
// X1 = *EFI_SYSTEM_TABLE. Firmware has already brought the platform up
// in EL1 with the MMU + GIC initialised, so we skip the framework's
// EL3->EL1 dance (which the stock framework cpuinit performs for bare
// metal) and only capture the handoff state, derive RamStart from the
// actual loaded text VA, set up the stack, and enter the standard
// arm64 TamaGo rt0 path.

#include "textflag.h"

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// UEFI 2.3.4.1 handoff state
	MOVD	R0, ·imageHandle(SB)
	MOVD	R1, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut is at offset 64 (12.4 Simple Text Output)
	MOVD	64(R1), R2
	MOVD	R2, ·conOut(SB)

	// RamStart = &runtime.text + 2 MiB. The runtime's heap arena lives in
	// [RamStart, RamStart+RamSize] and only avoids the .text / .data
	// ranges via TextRegion/DataRegion — it does NOT know about the PE
	// .reloc section, which UEFI image-protection on AArch64 maps as
	// read-only. With the amd64 trick of RamStart=text-64KiB the heap
	// then partially overlaps .reloc, and the first scheduler write that
	// lands there takes an L3 permission fault. Starting RamStart past
	// the whole image (text + ~1.6 MiB image span, rounded up to 2 MiB
	// for headroom on bigger builds) keeps the heap on plain firmware
	// RAM (writable Normal-cacheable) and side-steps it entirely.
	MOVD	$runtime·text(SB), R3
	MOVD	$0x200000, R4
	ADD	R4, R3, R3
	MOVD	R3, runtime∕goos·RamStart(SB)

	// SP = RamStart + RamSize - RamStackOffset (top of RAM minus the
	// reserved stack window). Mirrors framework arm64/init.s.
	MOVD	runtime∕goos·RamStart(SB), R1
	MOVD	R1, RSP
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
