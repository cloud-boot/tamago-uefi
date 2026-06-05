// cloud-boot UEFI board — amd64.
//
// This is cloud-boot's OWN GOOS=tamago runtime/goos overlay for UEFI on
// amd64. It reuses the TamaGo framework's amd64 CPU package (SSE enable,
// TSC timer, RDRAND, RamStackOffset, Hwinit0) and overrides only the
// UEFI-specific hooks: the firmware entry (cpuinit_amd64.s), RamStart
// (written by that entry), RamSize, Nanotime, Hwinit1, and Printk via the
// UEFI ConOut.
//
// Build with: -tags linkcpuinit,linkramstart  (these exclude the
// framework's bare-metal cpuinit and default RamStart so ours win).

//go:build tamago && amd64

package uefiboard

import (
	"unsafe"

	"github.com/usbarmory/tamago/amd64"
)

// UEFI handoff state, captured in cpuinit_amd64.s from the entry registers
// (RCX/RDX) and the System Table.
var (
	imageHandle uint64 // set in cpuinit_amd64.s
	systemTable uint64 // set in cpuinit_amd64.s
	conOut      uint64 // EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL*, set in cpuinit_amd64.s
)

// CPU is this board's processor instance (timer/RNG/feature state).
var CPU = &amd64.CPU{}

// RamStart placeholder. The real value is written by cpuinit_amd64.s; we
// declare the goos.RamStart symbol here because the -tags linkramstart
// build excludes the framework's default (amd64/mem.go).
//
//go:linkname ramStart runtime/goos.RamStart
var ramStart uint64

// RamSize is an initial coarse bound on usable RAM (704 MiB). A later
// milestone reconciles it against the UEFI memory map post-World.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x2c000000

// EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL.OutputString lives at offset 0x08.
const efiOutputString = 0x08

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	CPU.Init()
}

// efiCall invokes a UEFI service pointer using the MS x64 ABI
// (eficall_amd64.s).
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
