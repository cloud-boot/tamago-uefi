// cloud-boot UEFI board — amd64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters here
// with the MS x64 ABI: RCX = ImageHandle, RDX = *EFI_SYSTEM_TABLE. No Go
// stack and no runtime exist yet, so the very first instructions must
// capture the handoff registers before anything clobbers them.
//
// R-amd64b (2026-06-09): switched from the bare-metal-style
// `RamStart = &runtime.text - 64 KiB; SP = RamStart + RamSize`
// heuristic (704 MiB hard-coded in board_amd64.go) to a
// `gBS->AllocatePages(EFI_ALLOCATE_ANY_PAGES, EfiLoaderData, ...)`
// handoff — mirroring cpuinit_arm64.s / cpuinit_riscv64.s /
// cpuinit_loong64.s. Reason: the post-edk2-stable202505 image-
// protection rework places multi-MiB PE32+ images near the TOP of
// free RAM (empirically ImageBase ≈ 0x7D1A_9000 for the 4.9 MiB HTTPS
// probe on `-m 2048`), so `text + 704 MiB` overflowed past the
// `0x80000000` PCI MMIO hole, AND any smaller window still risked
// overlapping the patched OVMF's now-RO/XP firmware-allocator pages
// scattered through `[0x7E000000..0x7FFF0000]`. AllocatePages returns
// a guaranteed-RAM, RW, NX-free, page-aligned region that — by
// construction — does NOT overlap firmware code, data, or the
// loaded image. See cloud-boot/docs/m6-2-edk2-upstream-investigation.md
// § 11.
//
// R-amd64c (2026-06-10): added the `SUBQ $8, SP` JMP-rt0-prologue
// alignment nudge. cpuinit_arm64.s / cpuinit_riscv64.s / cpuinit_loong64.s
// all enter their per-arch rt0 with SP at 0-mod-16; on amd64, Go's
// rt0_amd64_tamago path expects SP at 8-mod-16 (its first non-NOSPLIT
// CALL into runtime.check executes `runtime.check`'s prologue, which
// assumes SP+8 = 16-mod-16 to satisfy MOVDQA-style aligned loads in
// later compiled code). AllocatePages returns a page-aligned base
// (0-mod-4096 ⇒ 0-mod-16), so `SP = heapBase + RamSize - 1MiB` lands
// at 0-mod-16 — exactly one nibble off what rt0 needs. The SUBQ $8
// before JMP rt0 fixes that. Result: M5 HTTP original PASSes against
// the patched OVMF; the larger images (HTTPS / OCI / EFIHANDOVER) still
// fail with the R-amd64b "RIP=Go-prologue-bytes" signature — that
// failure is image-load-address-dependent and tracked separately
// (see § 13 H1 firstmoduledata layout and H3 MTRR/PAT). See
// cloud-boot/docs/m6-2-edk2-upstream-investigation.md § 13.
//
// Mirrors the contract of TamaGo's goos trampoline (runtime/goos.CPUInit
// → JMP cpuinit) and ends by entering the standard amd64 TamaGo rt0.

#include "textflag.h"

// EFI_SYSTEM_TABLE field offsets (UEFI 2.10 §4.3.1).
#define EFI_ST_CONOUT          64
#define EFI_ST_BOOTSERVICES    96

// EFI_BOOT_SERVICES field offsets (UEFI 2.10 §4.2 — natural layout,
// 24 bytes of EFI_TABLE_HEADER preceding the function pointers).
#define EFI_BS_ALLOCATEPAGES   40

// EFI_ALLOCATE_TYPE / EFI_MEMORY_TYPE enums (UEFI 2.10 §7.2).
#define EFI_ALLOCATE_ANY_PAGES   0
#define EFI_LOADER_DATA          2
#define EFI_BOOT_SERVICES_DATA   4

// R-amd64e H4 probe (2026-06-10): the AllocatePages memory-type
// argument is EfiBootServicesData (=4), not EfiLoaderData (=2).
// Rationale: under the patched OVMF (edk2-stable202605 + the three
// M6.2 image-protection fixes), AllocatePages dispatches through
// GcdAllocateMemory → CoreUpdateMemoryAttributes, which differentiates
// by memory type when deciding whether to walk the
// EFI_LOADED_IMAGE_PROTOCOL slot of the calling image (so the new
// pages can inherit the loader image's RO/XP attributes). An
// EfiLoaderData request touches that slot; EfiBootServicesData skips
// it (kernel-data pages are never loader-image-derived). The R-amd64d
// register-dump root-cause (RIP = non-canonical Go-prologue bytes
// from an indirect call vtable dereferenced inside AllocatePages)
// implicates exactly that kind of code path. See
// cloud-boot/docs/m6-2-edk2-upstream-investigation.md § 14 (H4)
// and § 15 (R-amd64e).

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// firmware may leave interrupts enabled
	CLI

	// UEFI 2.3.4.1 handoff state
	MOVQ	CX, ·imageHandle(SB)
	MOVQ	DX, ·systemTable(SB)

	// Go's amd64 ABIInternal uses R14 = current goroutine pointer.
	// The runtime's split-stack check at every (non-NOSPLIT) function
	// prologue reads `0x10(R14)` to compare SP against the stack
	// guard. The bare-metal init.s gets away without setting R14
	// only because the CPU comes from reset with R14=0 and the boot
	// ROM identity-maps address 0x10, so the read returns a tiny
	// value that always compares-less than SP and the JBE-to-
	// morestack is never taken. UEFI firmware runs its own code
	// pre-handoff and leaves R14 holding an arbitrary firmware
	// callee-saved value; if that value puts `R14+0x10` in a
	// firmware-protected or non-canonical region, the very first
	// non-NOSPLIT Go function called from rt0_amd64_tamago
	// (`runtime.check`) faults its stack-check load. Mirror the
	// bare-metal "R14 is zero at entry" contract by zeroing it
	// explicitly. The runtime will later overwrite R14 = g0 via
	// gogo / mstart once the scheduler is up.
	XORQ	R14, R14

	// EFI_SYSTEM_TABLE.ConOut at offset 64 (UEFI 12.4 SimpleTextOutput)
	MOVQ	EFI_ST_CONOUT(DX), AX
	MOVQ	AX, ·conOut(SB)

	// Go's amd64 codegen uses SSE; firmware does not guarantee the CR0/CR4
	// SSE bits. Reuse the framework's enabler (amd64/features.s). UEFI is
	// already in long mode with paging, so we do NOT touch page tables.
	CALL	sse_enable(SB)

	// gBS = SystemTable->BootServices.
	MOVQ	EFI_ST_BOOTSERVICES(DX), R10
	// AllocatePages function pointer.
	MOVQ	EFI_BS_ALLOCATEPAGES(R10), R11

	// MS x64 ABI: AllocatePages(AllocateAnyPages, EfiBootServicesData,
	// pages, &Memory). Args in RCX, RDX, R8, R9; mandatory 32-byte
	// shadow space below the return address; 16-byte SP alignment
	// at the call site.
	//
	// We have NO usable Go stack yet (firmware-provided SP is fine
	// pre-CALL — it's the firmware's own stack and the firmware lets
	// us use it during boot services). Just reserve the shadow space.
	//
	// R-amd64e H4: BootServicesData (=4), not LoaderData (=2). See the
	// big comment block at the EFI_BOOT_SERVICES_DATA #define above.
	MOVQ	$EFI_ALLOCATE_ANY_PAGES, CX
	MOVQ	$EFI_BOOT_SERVICES_DATA, DX
	MOVQ	runtime∕goos·RamSize(SB), R8
	SHRQ	$12, R8					// RamSize >> 12 = page count
	MOVQ	$·heapBase(SB), R9
	// MS x64 ABI: 16-byte SP alignment AT THE CALL SITE (so the
	// callee sees SP = (16N - 8) at entry, i.e. RIP + a 16-aligned
	// frame). Stash original SP in R13 (callee-saved under MS x64);
	// reserve 32-byte shadow space; force-align.
	MOVQ	SP, R13
	SUBQ	$32, SP
	ANDQ	$~15, SP				// 16-byte align (loses up to 15B, harmless)
	CALL	(R11)
	MOVQ	R13, SP

	// RAX = EFI_STATUS. Non-zero == failure; halt forever (no console
	// reachable without Boot Services + a Go stack we don't yet have).
	TESTQ	AX, AX
	JNZ	allocFail

	// Anchor RamStart and Bloc to the allocated base. Setting both
	// makes osinit skip its `firstmoduledata.end`-based bloc init
	// (which would point INTO the image and away from our region)
	// and use our base instead — the runtime's sbrk allocator starts
	// at Bloc and grows up, so it MUST live inside the page chunk we
	// just allocated.
	MOVQ	·heapBase(SB), R12
	MOVQ	R12, runtime∕goos·RamStart(SB)
	MOVQ	R12, runtime∕goos·Bloc(SB)

	// Zero the entire allocated region. UEFI AllocatePages returns
	// UNDEFINED memory contents, but the TamaGo runtime's bring-up
	// implicitly depends on zeros in several places — the most
	// observable being rt0_amd64_tamago at
	// `tamago-pie/src/runtime/sys_tamago_amd64.s:120-123`, which
	// reads argc from 24(SP) and argv from 32(SP) without any
	// explicit zero-init contract. Under the bare-metal init.s the
	// region was zeroed-by-side-effect of the PML4 setup's
	// `REP STOSB`; under AllocatePages we have to do it ourselves.
	// REP STOSB on a 128 MiB region takes <10 ms on any modern CPU
	// (a single linear memset is the best case for the LSU + DRAM
	// streaming buffers), and it neutralises an entire class of
	// "uninitialised data sneaks into the runtime" bugs (istack guard
	// scratch, type-bitmap reads, the malloc bump allocator's first
	// hand-off, the persistent-arena chunks osinit takes from Bloc).
	MOVQ	R12, DI					// dst = heap base
	MOVQ	runtime∕goos·RamSize(SB), CX		// count = RamSize
	XORL	AX, AX					// fill byte = 0
	CLD
	REP;	STOSB

	// SP = RamStart + RamSize - RamStackOffset (top of the chunk,
	// minus the reserved stack window). Matches framework
	// amd64/init.s; matches cpuinit_arm64.s / cpuinit_riscv64.s /
	// cpuinit_loong64.s.
	MOVQ	R12, SP
	MOVQ	runtime∕goos·RamSize(SB), AX
	MOVQ	runtime∕goos·RamStackOffset(SB), BX
	ADDQ	AX, SP
	SUBQ	BX, SP

	// R-amd64c: nudge SP by 8 so rt0_amd64_tamago enters with SP at
	// 8-mod-16 instead of 0-mod-16. AllocatePages returns a 0-mod-4096
	// base, so heapBase + RamSize - RamStackOffset lands at 0-mod-16.
	// Rationale: in one R-amd64c probe variant (cpuinit + printChar
	// debug-trace helper carrying a 96-byte .text bump and a marker
	// CALL/RET pair right before this JMP), removing or adding the
	// SUBQ $8 toggled HTTP-original between PASS and FAIL in a way
	// that LOOKED like an SP-alignment fix. Reproducing the same
	// PASS in the STRIPPED variant (no marker calls) failed — the
	// nudge alone is insufficient. Kept here as a 1-instruction
	// no-cost defensive against the canonical Go-amd64 ABI's
	// "SP+8 = 16-mod-16 at CALL site" expectation; the real bug is
	// elsewhere (most likely in the .text-layout-sensitive crash
	// signature documented at § 13).
	SUBQ	$8, SP

	// enter the standard amd64 TamaGo runtime bring-up
	JMP	runtime·rt0_amd64_tamago(SB)

allocFail:
	// AllocatePages returned non-zero. We have no console reachable
	// from here (ConOut OutputString would require a goroutine-grade
	// stack we don't yet have), so just park forever. A real loader
	// would print the status to a serial port it knows is always
	// available pre-runtime and reset the platform.
	HLT
	JMP	-1(PC)
