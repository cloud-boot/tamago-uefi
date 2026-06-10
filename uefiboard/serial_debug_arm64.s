// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — arm64 stub for the R-amd64j COM1 serial
// debug helper. There is no "port 0x3f8" on arm64; the helper is
// a silent no-op so the Go-side serial_debug.go body compiles
// uniformly across all four arches. The other three arches have
// their own debug channels (ConOut tracing — see
// initrd_protocol_trace_tamago.go) that don't crash like the
// amd64 ConOut path does.

#include "textflag.h"

// func serialOutB(port uint16, val uint8)
TEXT ·serialOutB(SB), NOSPLIT|NOFRAME, $0-3
	RET
