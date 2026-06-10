// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — riscv64 stub for the R-amd64j COM1 serial
// debug helper. No-op (no x86 I/O port space on riscv64).

#include "textflag.h"

// func serialOutB(port uint16, val uint8)
TEXT ·serialOutB(SB), NOSPLIT|NOFRAME, $0-3
	RET
