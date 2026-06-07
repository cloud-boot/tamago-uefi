// cloud-boot UEFI board — arm64 post-EBS interrupt mask (M2-B).
//
// `postEBSDisableInterrupts` masks the current EL's interrupt enable
// bits (DAIF.{IRQ,FIQ}) so that no interrupt fires into a firmware
// handler torn down by ExitBootServices.
//
// Reference: Arm ARM ARMv8.5 (DDI 0487F.a) §D13.2.1 — DAIF system
// register, bit layout:
//
//	DAIF.D  (bit 9)  — debug exceptions     (we leave as-is)
//	DAIF.A  (bit 8)  — SError exceptions    (we leave as-is)
//	DAIF.I  (bit 7)  — IRQ interrupts       (set to 1 = masked)
//	DAIF.F  (bit 6)  — FIQ interrupts       (set to 1 = masked)
//
// Setting DAIFSET.{I,F} sets the I and F bits of DAIF in one
// instruction (Arm ARM §C5.2.2). The mask value is 0b11 << 6 = 0xC0,
// which `MSR DAIFSet, #imm6` encodes as `imm6 = 0b1100 << 2 |
// 0b00 = 0x30`... but we use the simpler form `MSR DAIFSet, #3`
// which sets the bottom two bits of DAIFSet (= I and F).

#include "textflag.h"

TEXT ·postEBSDisableInterrupts(SB),NOSPLIT|NOFRAME,$0
	// DAIFSet, #3 → set I and F → IRQ and FIQ masked.
	WORD	$0xd50343df	// msr DAIFSet, #3
	RET
