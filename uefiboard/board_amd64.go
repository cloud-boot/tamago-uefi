// cloud-boot UEFI board — amd64-specific Go hooks.
//
// Reuses the TamaGo framework's amd64 CPU package for the TSC timer,
// RDRAND (InitRNG/GetRandomData), RamStackOffset and Hwinit0. Only the
// UEFI-specific Nanotime / Hwinit1 wrappers and the board's CPU instance
// live here; everything arch-neutral is in board.go and the firmware
// entry + ABI thunk are in cpuinit_amd64.s / eficall_amd64.s.
//
// R-amd64e H5 probe (2026-06-10): hwinit1 additionally calls the
// gBS->AllocatePages Boot Service to measure whether the same call that
// crashed the firmware when invoked from cpuinit (R-amd64b..d) also
// crashes when invoked from a fully-initialised Go context (after the
// runtime's schedinit completes). This is the "defer AllocatePages
// out of cpuinit" hypothesis from § 14.5. Three possible outcomes,
// each diagnostic:
//   - AllocatePages returns successfully → the bug is firmware-lifecycle-
//     specific (only crashes pre-schedinit); a real loader can pivot to
//     a hwinit1-allocated heap.
//   - AllocatePages returns an error → the firmware is rejecting the
//     call type/params, not crashing; we'd see the error code in the
//     log and the runtime keeps going.
//   - AllocatePages crashes the firmware (#GP again) → the bug is
//     intrinsic to the AllocatePages dispatch for our PE32+ binary,
//     independent of when we call it. H5 ruled out.

//go:build tamago && amd64

package uefiboard

import (
	"runtime"
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

// hwinit1Probe runs the R-amd64e H5 AllocatePages probe from hwinit1
// — at this point the Go runtime has completed schedinit and a real
// goroutine stack is in use, so any firmware-stack-corruption issue
// from cpuinit is out of the picture.
//
// We try a SMALL 4 KiB allocation (enough to exercise the dispatch
// without monopolising the firmware's free pages); the return path
// either prints "R-amd64e-H5: AllocatePages OK base=..." or
// "R-amd64e-H5: AllocatePages ERR ..." or crashes the firmware (#GP),
// in which case the smoke runner's grep matches CpuPageTableLib and
// reports FAIL_GP.
func hwinit1Probe() {
	const probePages = 1
	print("R-amd64e-H5: calling AllocatePages from hwinit1 ... ")
	addr, err := AllocatePages(uint32(EfiBootServicesData), probePages)
	if err != nil {
		print("ERR ")
		print(err.Error())
		print("\n")
		return
	}
	print("OK base=0x")
	printHex(addr)
	print("\n")
	// Best-effort free — if FreePages also crashes, we still got the
	// PASS signal from the AllocatePages line above.
	if err := FreePages(addr, probePages); err != nil {
		print("R-amd64e-H5: FreePages ERR ")
		print(err.Error())
		print("\n")
	} else {
		print("R-amd64e-H5: FreePages OK\n")
	}
	_ = runtime.GOOS // keep runtime import live
}

// printHex prints a uint64 as 16 lowercase hex digits via the runtime's
// goos.Printk (the same path println uses pre-os). No allocations.
func printHex(v uint64) {
	const digits = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	// print() expects a string; convert via unsafe-free slice cast is
	// not possible without the unsafe package; emit byte-by-byte.
	for i := 0; i < 16; i++ {
		print(string(buf[i : i+1]))
	}
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	CPU.Init()
	hwinit1Probe()
}
