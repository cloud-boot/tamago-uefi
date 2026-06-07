// cloud-boot UEFI board — arm64 helpers.
//
// Reading CNTPCT_EL0 and CNTFRQ_EL0 directly so the board doesn't
// need to import the TamaGo framework's arm64 package (which would
// drag in its `Init` → `cpu.InitMMU()` linkname'd as Hwinit0). The
// Generic Timer registers are unconditionally available at EL1
// under UEFI without any prior init.

#include "textflag.h"

// func rdcntpct() uint64
TEXT ·rdcntpct(SB),NOSPLIT,$0-8
	MRS	CNTPCT_EL0, R0
	MOVD	R0, ret+0(FP)
	RET

// func rdcntfrq() uint64
TEXT ·rdcntfrq(SB),NOSPLIT,$0-8
	MRS	CNTFRQ_EL0, R0
	MOVD	R0, ret+0(FP)
	RET
