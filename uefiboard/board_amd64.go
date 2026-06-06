// cloud-boot UEFI board — amd64-specific Go hooks.
//
// Reuses the TamaGo framework's amd64 CPU package for the TSC timer,
// RDRAND (InitRNG/GetRandomData), RamStackOffset and Hwinit0. Only the
// UEFI-specific Nanotime / Hwinit1 wrappers and the board's CPU instance
// live here; everything arch-neutral is in board.go and the firmware
// entry + ABI thunk are in cpuinit_amd64.s / eficall_amd64.s.

//go:build tamago && amd64

package uefiboard

import (
	_ "unsafe"

	"github.com/usbarmory/tamago/amd64"
)

// CPU is this board's processor instance (timer/RNG/feature state).
var CPU = &amd64.CPU{}

// RamSize: 704 MiB. amd64 UEFI typically loads the image low so the
// region [text-64KiB, +RamSize) fits comfortably with QEMU -m 2048.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x2c000000

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	CPU.Init()
}
