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

// heapBase is the in/out pointer slot for EFI_BOOT_SERVICES->AllocatePages.
// The per-arch cpuinit shim passes &heapBase to AllocatePages; firmware
// writes the allocated physical-address base back into it, then cpuinit
// reads it to set goos.RamStart and goos.Bloc. Storing it as a package
// variable keeps it in our writable .data section (XP+RW under UEFI image
// protection on every platform we target), which AllocatePages requires.
//
// Initialised to 0 at link time; the value is meaningful only after the
// AllocatePages call returns success.
var heapBase uint64

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
// loong64 / riscv64). Returns EFI_STATUS in the low 64 bits.
//
// The thunk is 6-arg wide. Phase 2 M2 widened it from 5 to 6 because
// EFI_PCI_IO_PROTOCOL.Mem.Read/Write are 6-arg services:
// `(This*, Width, BarIndex, Offset, Count, Buffer*)`. The M1 widening
// from 4 to 5 was driven by a real riscv64 fault (EDK2's
// CoreGetMemoryMap dereferenced a stale A4 as a NULL-relative pointer;
// see `eficall_riscv64.s`). The M2 widening continues the same
// invariant: every position MUST hold a defined value, even if the
// callee ignores it. Callees that take fewer than 6 args ignore the
// trailing positions — caller passes 0 for unused slots.
//
//go:noescape
func efiCall(fn, a0, a1, a2, a3, a4, a5 uint64) (status uint64)

// BlkSink, when non-nil, receives a copy of every byte printk emits.
// Used by the Phase-2 M1.6 Block IO side-channel probe to mirror
// ConOut output into a virtio-blk scratch region so observers on a
// hypervisor that doesn't expose ConOut (Apple VZ via vfkit 0.6.3 —
// see R-M1'a) can recover the probe output post-halt.
//
// Default: nil = Phase-1 / M0 / M1 / M1.5 behaviour preserved bit-for-bit.
// The probe binds this in its init path; if binding fails (no
// writable virtio-blk), it leaves BlkSink == nil and we degrade
// gracefully to ConOut-only.
//
// Single-writer; the probe is single-goroutine at print time. M1.6
// does NOT add any synchronisation here — adding a lock would pull
// runtime/sync into the EFI binary's print path, which we don't want.
var BlkSink *BlkRingBuffer

// printk emits one byte to the UEFI ConOut as a NUL-terminated UTF-16
// string. conOut is captured in asm at entry, so this is usable from the
// earliest runtime prints. When BlkSink is set (M1.6 side-channel
// probe), the same byte is mirrored into the ring buffer; the BlkSink
// then auto-flushes to the bound virtio-blk via Block IO on threshold
// or sentinel.
//
//go:linkname printk runtime/goos.Printk
func printk(c byte) {
	if BlkSink != nil {
		BlkSink.BlkPrintk(c)
	}
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
		uint64(uintptr(unsafe.Pointer(&u16[0]))), 0, 0, 0, 0)
}
