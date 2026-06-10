// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — nosplit-safe ConOut tracer used from inside
// the EFI_LOAD_FILE2 firmware->Go callback (Phase 2, M8.4 R-M8.4a
// debug instrumentation).
//
// Why a separate tracer rather than `println` from `loadFileGo`:
//
//   - `loadFileGo` is `//go:nosplit` (the firmware entered us on
//     its own stack with no usable Go scheduler state; we must not
//     trigger a Go stack-grow / morestack path that would call
//     runtime helpers expecting a live g).
//   - The runtime `println` builtin pulls in `runtime.printlock` /
//     `runtime.printunlock` (a real mutex acquire), `runtime.gwrite`
//     (which reads `getg()` and bumps `m.locks`), plus a per-byte
//     dispatch via the `runtime/goos.Printk` hook. Any of those can
//     touch g; under a clobbered-g hypothesis (R-M8.4a #2) the very
//     instrumentation we want to use to diagnose the bug would fault
//     before we saw a single byte.
//
// The helpers below go straight to the firmware's
// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString` via the same
// `efiCall` thunk every other firmware-call site uses — the asm thunk
// itself is `NOSPLIT $0` on all four arches and does not depend on g.
// The only Go-side allocation is a stack-resident `[2]uint16`
// scratch — both guaranteed-safe inside a nosplit body.
//
// API:
//
//   loadFileTraceString(s)     — emits `s` byte-by-byte
//   loadFileTraceHex64(v)      — emits `v` as 16 hex digits + a space
//   loadFileTraceLine(tag, ...) — convenience: tag + a list of label=hex
//                                pairs + newline
//
// The output is plain ASCII so the serial-stdio capture in
// `internal/livekernelboot/run.sh` picks it up alongside the
// kernel-side `EFI stub:` lines.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"
)

// loadFileTraceEnabled gates every byte the tracer emits. The live
// arm64 R-M8.4a debug build flips this to true; production builds
// leave it false so a production EFI does not paint serial with
// per-callback diagnostics.
//
// Exported so a probe (or a future cmd/-side toggler) can set it
// before invoking PublishInitrd. The field is read once per trace
// call and treated as an atomic boolean — single-writer at probe
// init time is enough for the M8.4 debug window.
var LoadFileTraceEnabled bool

// loadFileTraceByte emits one byte to ConOut as a NUL-terminated
// UTF-16 string. Mirrors `out` in board.go but is marked //go:nosplit
// so the Go compiler will not insert a stack-grow check at the
// prologue — we call it from inside loadFileGo which itself is
// nosplit.
//
//go:nosplit
func loadFileTraceByte(c byte) {
	if conOut == 0 {
		return
	}
	u16 := [2]uint16{uint16(c), 0}
	efiCall(conOut+efiOutputString, conOut,
		uint64(uintptr(unsafe.Pointer(&u16[0]))), 0, 0, 0, 0)
}

// loadFileTraceString emits every byte of s in order, then (on '\n')
// a '\r' to satisfy ConOut's CRLF convention (firmware terminals
// otherwise leave the next line indented).
//
//go:nosplit
func loadFileTraceString(s string) {
	for i := 0; i < len(s); i++ {
		c := s[i]
		loadFileTraceByte(c)
		if c == '\n' {
			loadFileTraceByte('\r')
		}
	}
}

// loadFileTraceHex64 emits v as exactly 16 hex digits prefixed by
// "0x", with no trailing space. Most-significant nibble first.
// Used to render pointer / size values cleanly.
//
//go:nosplit
func loadFileTraceHex64(v uint64) {
	const digits = "0123456789abcdef"
	loadFileTraceByte('0')
	loadFileTraceByte('x')
	for i := 60; i >= 0; i -= 4 {
		loadFileTraceByte(digits[(v>>uint(i))&0xF])
	}
}

// loadFileTraceLine emits a one-line probe diagnostic of the shape
//
//	"<tag> <label0>=0x<hex0> <label1>=0x<hex1> ...\n"
//
// labels and vals MUST be the same length; the first len(labels)
// entries of vals are paired one-for-one.
//
//go:nosplit
func loadFileTraceLine(tag string, labels []string, vals []uint64) {
	if !LoadFileTraceEnabled {
		return
	}
	loadFileTraceString(tag)
	n := len(labels)
	if len(vals) < n {
		n = len(vals)
	}
	for i := 0; i < n; i++ {
		loadFileTraceByte(' ')
		loadFileTraceString(labels[i])
		loadFileTraceByte('=')
		loadFileTraceHex64(vals[i])
	}
	loadFileTraceByte('\n')
}
