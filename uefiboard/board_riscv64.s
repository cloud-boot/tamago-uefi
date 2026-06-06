// cloud-boot UEFI board — riscv64 inline-asm helpers.

#include "textflag.h"

// func rdtime() uint64
//
// Reads the user-mode TIME CSR (0xC01). Available under S-mode UEFI
// because OpenSBI exposes the SBI TIME extension which wires this CSR
// up to the platform mtime register.
//
// Encoded as CSRRS T0, TIME, ZERO via WORD because the Go riscv64
// assembler has no `TIME` CSR mnemonic.
//   csrrs t0, time, zero  → 0xc0102_2f3
//     funct12=0xC01, rs1=0, funct3=010 (CSRRS), rd=5 (T0), opcode=1110011
TEXT ·rdtime(SB),NOSPLIT|NOFRAME,$0-8
	WORD	$0xc01022f3
	MOV	T0, ret+0(FP)
	RET
