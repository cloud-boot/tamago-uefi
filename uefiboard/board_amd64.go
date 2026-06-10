// cloud-boot UEFI board — amd64-specific Go hooks.
//
// Reuses the TamaGo framework's amd64 CPU package for the TSC timer,
// RDRAND (InitRNG/GetRandomData), RamStackOffset and Hwinit0. Only the
// UEFI-specific Nanotime / Hwinit1 wrappers and the board's CPU instance
// live here; everything arch-neutral is in board.go and the firmware
// entry + ABI thunk are in cpuinit_amd64.s / eficall_amd64.s.
//
// R-amd64f #2 (2026-06-10): the heap is now anchored on a giant .bss
// reservation (heapReserve below) rather than the bare-metal
// `text - 64 KiB` fiction or a Boot-Services AllocatePages call. See
// docs/m6-2-edk2-upstream-investigation.md § 16 for the rationale: any
// Boot Service call from cpuinit crashes patched OVMF (R-amd64e H5/H6),
// so we use a region the firmware has ALREADY allocated for us — the
// PE32+ image's own SizeOfImage span — via a Go-side .bss array. The
// linker rolls this into the PE's SizeOfImage; the firmware's LoadImage
// AllocatePages happens server-side before our entry; cpuinit only needs
// to point RamStart/SP at it.

//go:build tamago && amd64

package uefiboard

import (
	_ "unsafe"

	"github.com/usbarmory/tamago/amd64"
)

// CPU is this board's processor instance (timer/RNG/feature state).
var CPU = &amd64.CPU{}

// heapReserveSize is the .bss-backed heap reservation: 128 MiB. The
// linker emits this as zero-initialised .bss (no raw bytes in the PE
// on-disk; only SizeOfImage grows), so the file size is unchanged.
// 128 MiB matches the arm64 board's ramSize, which is sized for the
// M8.3 Linux-EFI-stub kernel-boot path (the synchronous gunzip+tar
// extract holds vmlinuz uncompressed and the gzipped layer
// simultaneously, ~75 MiB working set). Page-aligned at use site by
// cpuinit_amd64.s; the +4096 slack accommodates the round-up.
const heapReserveSize = 0x08000000 // 128 MiB

// heapReserve is the firmware-allocated, RW, mapped region that backs
// goos.RamStart/RamSize/SP. cpuinit_amd64.s references it as
// `·heapReserve(SB)`. Marked global through normal package-var rules;
// `var _ = heapReserve[0]` in the package guarantees the linker
// retains it (a pure-asm reference is not enough — the Go linker may
// otherwise dead-code-eliminate it as unused from Go).
var heapReserve [heapReserveSize + 0x1000]byte

// Keep heapReserve alive against dead-code elimination. The Go linker
// inspects Go-side references, not asm-side; without this anchor the
// 128 MiB array could be pruned because no Go code reads it.
var _ = &heapReserve[0]

// RamSize: 128 MiB. Matches heapReserveSize. Anchored at the
// page-aligned start of heapReserve by cpuinit_amd64.s, so the region
// [RamStart, RamStart+RamSize) is exactly the .bss reservation
// (firmware-allocated, mapped, RW — guaranteed valid memory).
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = heapReserveSize

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	CPU.Init()
}
