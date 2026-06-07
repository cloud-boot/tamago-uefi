// cloud-boot UEFI board — loong64 helpers.
//
// Reading the stable-timer counter (RDTIME.D) and CPUCFG directly
// so the board doesn't need to import the cloud-boot-local framework
// loong64 package (which would otherwise drag in its Init linkname'd
// as Hwinit0 and collide with the board's own Hwinit0).

#include "textflag.h"

// func rdStableCounter() int64
TEXT ·rdStableCounter(SB),NOSPLIT,$0-8
	RDTIMED	R0, R4
	MOVV	R4, ret+0(FP)
	RET

// func rdCPUCFG(reg uint32) uint32
TEXT ·rdCPUCFG(SB),NOSPLIT,$0-12
	MOVW	reg+0(FP), R5
	CPUCFG	R5, R4
	MOVW	R4, ret+8(FP)
	RET
