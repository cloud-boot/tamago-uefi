// cloud-boot UEFI board — riscv64 inline-asm helpers.

#include "textflag.h"

// func rdtime() uint64
//
// Reads the user-mode TIME CSR (0xC01). Available under S-mode UEFI
// because OpenSBI exposes the SBI TIME extension which wires this CSR
// up to the platform mtime register.
//
// RDTIME is the Go riscv64 assembler's spelling of the Zicntr pseudo-
// instruction `rdtime t0` = `csrrs t0, time, zero`, encoded 0xc01022f3
// (funct12=0xC01, rs1=0, funct3=010 (CSRRS), rd=5 (T0), opcode=1110011).
TEXT ·rdtime(SB),NOSPLIT|NOFRAME,$0-8
	RDTIME	T0
	MOV	T0, ret+0(FP)
	RET
