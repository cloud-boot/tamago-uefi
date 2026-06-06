// cloud-boot UEFI board — LoongArch 64 firmware entry point.
//
// Set as the PE entry via `-ldflags -E cpuinit`. UEFI firmware enters
// here with the LoongArch LP64 calling convention (UEFI 2.10 §2.3.x):
// R4 (A0) = ImageHandle, R5 (A1) = *EFI_SYSTEM_TABLE. Firmware has
// already brought the platform up in PLV0 with the MMU, interrupt
// controller and stable-timer initialised, so we skip the framework's
// bare-metal init (CSR.EUEN.FPE/CSR.EENTRY/CSR.DMW writes — those are
// done by EDK2 already for the firmware's own purposes) and only
// capture the handoff state, derive RamStart from the actual loaded
// text VA, set up the stack, then enter the standard loong64 TamaGo
// rt0 path.
//
// LoongArch register summary (Go asm naming):
//   R0  = zero    R1  = RA (link)
//   R2  = TP      R3  = SP
//   R4..R11       arg/return (A0..A7)
//   R12..R20      caller-saved temporaries
//   R21..R31      callee-saved (R22 = g per Go ABI, R30 = asm tmp)
//
// Phase-1.5 note: a single debug marker writes 'A' on the QEMU virt
// ns16550a UART (THR @ 0x1FE001E0) before the runtime takes over.
// Empirically, an explicit `csrwr R19, EUEN` to re-enable the FPU here
// throws a fatal Instruction-Non-Defined exception (ESTAT.Ecode=0x0D)
// under EDK2 LoongArch — so we leave EUEN alone and trust the firmware
// to have set it up (it does; firmware uses FP itself). Same "skip
// what firmware already did" pattern as the arm64 SCTLR/CPACR dance.

#include "textflag.h"

TEXT cpuinit(SB),NOSPLIT|NOFRAME,$0
	// Phase-1.5 boot marker on the QEMU virt ns16550a UART (THR
	// at 0x1FE001E0). Confirms firmware actually entered our PE
	// before the runtime takes over the console via ConOut. Remove
	// once boot reaches the runtime print path reliably.
	MOVV	$0x1fe001e0, R12
	MOVV	$65, R13	// 'A'
	MOVB	R13, (R12)

	// UEFI 2.10 LoongArch handoff state.
	MOVV	R4, ·imageHandle(SB)
	MOVV	R5, ·systemTable(SB)

	// EFI_SYSTEM_TABLE.ConOut is at offset 64 (UEFI 12.4
	// SimpleTextOutput).
	MOVV	64(R5), R6
	MOVV	R6, ·conOut(SB)

	// RamStart = &runtime.text + 2 MiB. Same rationale as the arm64
	// and riscv64 legs: UEFI image-protection on LoongArch marks
	// the loaded PE's read-only sub-pages (.text/.rdata/.reloc)
	// read-only at the page-table level, so the heap arena must
	// start *past* the whole image rather than 64 KiB below it.
	// Otherwise the first scheduler write that lands in the image
	// takes a Store-Page or Modify-Page fault.
	MOVV	$runtime·text(SB), R6
	MOVV	$0x200000, R7
	ADDV	R7, R6, R6
	MOVV	R6, runtime∕goos·RamStart(SB)

	// SP (R3) = RamStart + RamSize - RamStackOffset (top of RAM
	// minus the reserved stack window). Mirrors framework
	// loong64/loong64.s.
	MOVV	runtime∕goos·RamStart(SB), R3
	MOVV	runtime∕goos·RamSize(SB), R7
	MOVV	runtime∕goos·RamStackOffset(SB), R8
	ADDV	R7, R3
	SUBV	R8, R3

	// enter the standard loong64 TamaGo rt0
	JMP	_rt0_tamago_start(SB)
