// cloud-boot UEFI board — arch-neutral core.
//
// Holds the runtime/goos overrides that don't depend on the CPU package
// (UEFI handoff vars, RamStart placeholder, RamSize bound, ConOut Printk,
// the firmware-call thunk's Go declaration). The arch-specific entry shim
// and ABI thunk live in cpuinit_<arch>.s / eficall_<arch>.s, and any
// arch-specific Go hooks (CPU instance, Nanotime, Hwinit1, RNG, and where
// the framework doesn't already provide it, RamStackOffset) live in
// board_<arch>.go.
//
// Build always with -tags linkcpuinit,linkramstart : both are required on
// amd64 (they exclude the framework's bare-metal cpuinit and default
// RamStart so ours win), and harmless on arm64 (whose framework package
// doesn't ship those symbols at all).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// UEFI handoff state, captured by the per-arch cpuinit shim from the
// firmware entry registers (RCX/RDX on amd64, X0/X1 on arm64, A0/A1 on
// riscv64) and the System Table. ConOut sits at offset 64 of
// EFI_SYSTEM_TABLE on every UEFI platform.
var (
	imageHandle uint64 // set in cpuinit_<arch>.s
	systemTable uint64 // set in cpuinit_<arch>.s
	conOut      uint64 // EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*, set in cpuinit_<arch>.s
)

// RamStart placeholder. The real value is written by the per-arch cpuinit
// shim (RamStart = &runtime.text - 64 KiB, so the runtime tracks wherever
// firmware loaded the image). Declared here unconditionally because
// neither framework/amd64 (when built with -tags linkramstart) nor
// framework/arm64 (no mem.go at all) provides the symbol.
//
//go:linkname ramStart runtime/goos.RamStart
var ramStart uint64

// RamSize is per-arch (see board_<arch>.go): firmware on amd64 typically
// loads the image in low RAM with plenty of room above, so 704 MiB works
// with QEMU -m 2048; on aarch64-virt firmware places the image near the
// top of installed RAM, leaving only a thin sliver above — a smaller
// bound is required there. A later milestone reconciles RamSize against
// the UEFI memory map post-World, as go-boot's amd64 path does.

// EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString lives at offset 0x08 on
// every UEFI revision/arch.
const efiOutputString = 0x08

// efiCall invokes a UEFI service through its function-pointer slot. The
// implementation lives in eficall_<arch>.s and respects the platform's
// UEFI calling convention (MS x64 on amd64, AAPCS64 on arm64, LP64 on
// riscv64). Returns EFI_STATUS in the low 64 bits.
//
//go:noescape
func efiCall(fn, a0, a1, a2, a3 uint64) (status uint64)

// printk emits one byte to the UEFI ConOut as a NUL-terminated UTF-16
// string. conOut is captured in asm at entry, so this is usable from the
// earliest runtime prints.
//
//go:linkname printk runtime/goos.Printk
func printk(c byte) {
	if conOut == 0 {
		return
	}
	out(c)
	if c == '\n' {
		out('\r')
	}
}

func out(c byte) {
	u16 := [2]uint16{uint16(c), 0}
	efiCall(conOut+efiOutputString, conOut,
		uint64(uintptr(unsafe.Pointer(&u16[0]))), 0, 0)
}
