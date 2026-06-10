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

// heapReserveSize is the .bss-backed heap reservation: 256 MiB. The
// linker emits this as zero-initialised .bss (no raw bytes in the PE
// on-disk; only SizeOfImage grows), so the file size is unchanged.
// Page-aligned at use site by cpuinit_amd64.s; the +4096 slack
// accommodates the round-up.
//
// R-amd64h (2026-06-10): bumped from 128 MiB to 256 MiB. Headroom
// for the HTTPS / OCI cells, paired with the rxLoop idle-yield fix
// in ministack/stack.go (rxLoopIdleSleep). Diagnosis (pcap + Go
// runtime OOM trace):
//
//   - HTTP (port 80, ~1 s end-to-end): PASSed at 128 MiB. The
//     inline-pump path in dialTCP4Once returns on the SYN-ACK fast
//     enough that the rxLoop goroutine's per-RecvFrame allocation
//     leak (go-virtio/net's `commonNetError` string-typed sentinel
//     boxed to `error` on every poll = 16 byte mallocgc per call)
//     doesn't accumulate.
//
//   - HTTPS (port 443, ~30 s wall clock): FAILed at 128 MiB with
//     `out of memory: cannot allocate 4194304-byte block (117276672
//     in use)`. The DialTLSWithRetry path holds the inline pump in
//     dialTCP4Once for the full per-attempt timeout × 3 attempts; on
//     amd64 the runtime now does hardware-timer-driven async
//     preemption (it didn't when arm64/riscv64/loong64 were brought
//     up — those archs leave the rxLoop goroutine permanently
//     parked), so the rxLoop competes for RecvFrame calls at full
//     CPU and the boxing leak rate hits MB/s. pcap-confirmed: ZERO
//     port-443 packets reached the wire because the OOM throw fired
//     BEFORE the SYN was emitted. Bumping the heap to 256 MiB +
//     adding a 1 µs idle sleep in rxLoop drops the leak rate by
//     ~3 orders of magnitude AND raises the ceiling above the worst-
//     case 30-second dial-budget allocation footprint, so the SYN
//     fires, SYN-ACK lands, and the TLS handshake completes.
//
//   - Why arm64 / riscv64 / loong64 don't hit it at 128 MiB: their
//     tamago runtime does not yet emit async-preemption signals from
//     the EDK2 timer, so the rxLoop goroutine is never scheduled.
//     Only the inline pump runs, and it stays inside its own
//     bounded poll window. amd64's recent preemption rollout
//     unlocked the latent rxLoop leak.
//
// 256 MiB grows the on-disk PE only via SizeOfImage (.bss is zero
// on disk — SizeOfRawData unchanged); BOOTX64-HTTPS.EFI does not
// grow. EDK2 LoadImage's AllocatePages(SizeOfImage) on QEMU+EDK2
// `-m 2048` finds the 256 MiB block with ~1.7 GiB of free Boot
// Services memory to spare. The long-term fix is upstream
// go-virtio/net switching to a pre-boxed `error` sentinel; until
// that ships, the rxLoop yield + this headroom bump together close
// the gap.
const heapReserveSize = 0x10000000 // 256 MiB

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
