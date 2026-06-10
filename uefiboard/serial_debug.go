// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — Go-side helpers on top of the per-arch
// serialOutB asm symbol. Introduced 2026-06-10 for R-amd64j Phase 3:
// the amd64 ConOut path crashes when driven from inside the nosplit
// LoadFile2 callback, so we needed a wholly-firmware-bypass trace
// channel that just pokes the 16550 UART data port (0x3f8 = COM1)
// directly. QEMU routes COM1 to the chardev attached to `-serial
// chardev:char0` (see internal/livekernelboot/run.sh's amd64 case),
// so emitted bytes appear on the run.sh-captured stdout.
//
// Why these are kept after R-amd64j closes: the helpers are
// general-purpose and useful for any future nosplit-context debug
// where ConOut is unusable. They live behind an //go:build constraint
// matching all four tamago arches so the package still compiles on
// host (no asm symbol → no Go-side wrapper).
//
// IMPORTANT: every body here is //go:nosplit because the only
// (known) caller — loadFileGo and the asm trampoline — runs on the
// firmware stack with no usable Go scheduler state. The string
// indexing in DbgString uses *(*byte)(unsafe.Pointer(...)) instead
// of `s[i]` to skip any potential runtime.panicIndex bounds-check
// helper insertion under -gcflags=-N -l. See R-amd64j brief Step 2
// for the disasm-or-use-unsafe call.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"
)

// COM1 (16550 UART) data port on the PC ISA / LPC bus. Used by
// QEMU's `-serial chardev:char0` route in
// internal/livekernelboot/run.sh's amd64 case to relay UART bytes
// to stdio.
const com1DataPort uint16 = 0x3f8

// serialOutB is the per-arch asm symbol that writes one byte to
// the given x86 I/O port. amd64 emits the real `outb`; the other
// three arches stub to a no-op (no x86 I/O space).
//
//go:noescape
func serialOutB(port uint16, val uint8)

// DbgChar emits one byte to COM1 (no-op on non-amd64).
//
//go:nosplit
func DbgChar(c byte) {
	serialOutB(com1DataPort, c)
}

// DbgString emits every byte of s in order. Uses unsafe.Pointer
// arithmetic to read each byte rather than `s[i]` so the Go
// compiler emits NO bounds-check call (runtime.panicIndex) — the
// nosplit caller cannot afford to call into runtime helpers.
//
//go:nosplit
func DbgString(s string) {
	// (*[2]uintptr)(unsafe.Pointer(&s)) lays out as
	// {data, len}; we want the data pointer for raw indexing.
	hdr := (*struct {
		data unsafe.Pointer
		len  int
	})(unsafe.Pointer(&s))
	base := uintptr(hdr.data)
	n := hdr.len
	for i := 0; i < n; i++ {
		b := *(*byte)(unsafe.Pointer(base + uintptr(i)))
		DbgChar(b)
	}
}

// dbgHexDigits is the lookup table DbgHex64 indexes into. A
// package-global typed var (rather than a function-local untyped
// const) so we can take its address and walk via unsafe.Pointer
// without runtime bounds-check helpers.
var dbgHexDigits = [16]byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'}

// DbgHex64 emits v as "0x" followed by exactly 16 uppercase hex
// digits (most-significant nibble first).
//
//go:nosplit
func DbgHex64(v uint64) {
	DbgChar('0')
	DbgChar('x')
	base := uintptr(unsafe.Pointer(&dbgHexDigits[0]))
	for i := 60; i >= 0; i -= 4 {
		idx := (v >> uint(i)) & 0xF
		DbgChar(*(*byte)(unsafe.Pointer(base + uintptr(idx))))
	}
}

// DbgLine emits "<prefix><hex>\r\n" — the convention used by
// R-amd64j Phase 3 instrumentation in loadFileGo.
//
//go:nosplit
func DbgLine(prefix string, v uint64) {
	DbgString(prefix)
	DbgHex64(v)
	DbgChar('\r')
	DbgChar('\n')
}
