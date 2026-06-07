// cloud-boot UEFI board — loong64 post-EBS interrupt mask (M2-B).
//
// `postEBSDisableInterrupts` clears CSR.CRMD.IE (current-mode
// interrupt enable, bit 2). The CRMD CSR is index 0x0; bit 2 is
// the interrupt-enable for the current privilege level.
//
// Reference: LoongArch Privileged Spec v1.10 §7.2.1 "CRMD" — bit 2
// (IE) gates per-mode interrupt acceptance. Linux clears it via
// `csrxchg` with mask=0b100, val=0 in arch/loongarch/include/asm/
// irqflags.h.
//
// LoongArch CSR access requires direct encoding because the Go
// loong64 assembler lacks csrxchg mnemonics. The instruction we
// want is `csrxchg rd, rj, csr` where:
//   - rd holds the value to write (we use R0 = 0 to clear IE)
//   - rj holds the bit mask (only the bits set in rj are written)
//   - csr is the CSR number (0x0 for CRMD)
//
// Encoding (LoongArch ISA Vol 2 §7.2): `0x04000000 | (csr << 10) |
// (rj << 5) | rd`. With csr=0, rj=12 (a temp holding 0b100), rd=0:
//
//   0x04000000 | (0<<10) | (12<<5) | 0 = 0x04000180

#include "textflag.h"

TEXT ·postEBSDisableInterrupts(SB),NOSPLIT|NOFRAME,$0
	// Build the mask 0b100 in R12. Then csrxchg R0, R12, CRMD.
	MOVV	$0x4, R12
	WORD	$0x04000180
	RET
