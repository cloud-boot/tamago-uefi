// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — raw COM1 serial debug for the R-amd64j
// Phase-3 diagnostic (write-bypass diagnosis for EFI_LOAD_FILE2
// double-buffer / trampoline-arg-mismatch theory split).
//
// Bypasses the firmware ConOut path entirely (which crashes amd64
// firmware when called from inside the nosplit LoadFile2 callback
// — see initrd_protocol_trace_tamago.go) by writing one byte at a
// time to the 16550 UART data port 0x3f8 (COM1). QEMU routes COM1
// to the chardev attached to `-serial chardev:char0` (which is
// already piped to stdio in internal/livekernelboot/run.sh's amd64
// QEMU args), so emitted bytes show up on the run.sh capture.
//
// NOSPLIT + NOFRAME so it is safe to call from the nosplit
// loadFileGo body and from inside the asm trampoline itself.

#include "textflag.h"

// func serialOutB(port uint16, val uint8)
//
// Signature uses uint16 for the port + uint8 for the value to keep
// the Go-side wrapper trivial. Stack arg layout on amd64 (Go ABI0):
//   port+0(FP) = uint16 at SP+0 (2 bytes)
//   val+2(FP)  = uint8  at SP+2 (1 byte)
TEXT ·serialOutB(SB), NOSPLIT|NOFRAME, $0-3
	MOVW	port+0(FP), DX
	MOVB	val+2(FP), AL
	OUTB
	RET
