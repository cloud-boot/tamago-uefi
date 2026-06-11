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
//
// R-amd64j (Sprint 2E, 2026-06-11): bumped from 256 MiB to 320 MiB
// to close the FreeBSD OCI boot OOM. Sprint 2D'' confirmed the
// streaming pipeline is architecturally minimal (no transient
// bytes.Buffer; FetchBlobToBuffer streams TLS body directly into
// the LBA-aligned final publish slice). The remaining ~176 MiB
// working set is fundamental:
//
//   - 65 MiB streamed image (FreeBSD bootonly disk image, padded to
//     512-byte LBA)
//   - ~80-120 MiB cosign verifier (cert-chain DER + ASN.1 decode
//     intermediates + TLS handshake state retained across the
//     stream because Validate() can only fire at EOF)
//   - ~16 KiB TLS record buffer per Conn (negligible at this scale,
//     but real)
//   - Go runtime span/mspan/mcentral overhead (~32 MiB at this
//     working-set size)
//
// Total peak working set: ~251 MiB. At a 256 MiB heap that's 98 %
// full and the Go allocator (no-compaction free-list) cannot find a
// contiguous span for the final manifest decode, throwing OOM.
//
// Sprint 2D' bumped this to 384 MiB; sprint 2E re-tested both 320
// MiB and 384 MiB on QEMU+EDK2 stable202605 with `-m 4096`:
//
//   - 320 MiB: probe boots, streams, then OOMs at 300 MiB in-use
//     (4 MiB span request fails). The 320 MiB ceiling minus 1 MiB
//     stack window minus ~12 MiB Go runtime persistent allocs
//     leaves ~307 MiB usable heap, which barely fits the cosign
//     verifier + TLS retain + image working set. Net: 320 MiB
//     pushes the OOM point ~50 MiB later (from 251 → 300) but
//     does not eliminate it.
//
//   - 384 MiB: was previously feared to break LoadImage at the
//     stable202605 AllocatePages call. Re-measured: QEMU `-m
//     4096` gives EDK2 boot-services ~3.5 GiB free at LoadImage
//     time, and SizeOfImage = 384 MiB + ~5 MiB code/data = 389
//     MiB rounds well under that ceiling. Sprint 2D' must have
//     run with `-m 2048` (the 256 MiB baseline assumption). With
//     -m 4096 (live runner default) 384 MiB loads cleanly and
//     gives the runtime +64 MiB headroom over the worst-case
//     working set, closing the OOM.
//
// 384 MiB is NOT enough either: the rxLoop + dispatch path allocates
// per-packet (ParseTCP4's `append([]byte(nil), pkt[hdrLen:]...)` at
// line 210, plus tcp4Checksum's `make([]byte, ...)` at line 256).
// For a 65 MiB image stream the rxLoop processes ~45k TCP segments,
// each leaving ~1.5 KiB of short-lived slice allocations — total
// ~67 MiB of allocation pressure beyond the image. With Go's pacer
// at GOGC=100 the GC fires when heap doubles, so the allocator
// reaches ~364 MiB committed before GC catches up — at which point
// a 4 MiB span request OOMs because we're 20 MiB from the ceiling.
//
// Sprint 2E: bump to 512 MiB. Headroom math:
//   - 65 MiB streamed image (FreeBSD bootonly, 512-LBA padded)
//   - ~32-50 MiB GC-staged rxLoop slice allocations (peak)
//   - ~16 KiB TLS record buffer (negligible)
//   - ~32 MiB Go runtime spans/mspan/mcache/persistent allocs
//   - 1 MiB stack window + 64 KiB stackguard
//   Total transient peak: ~150 MiB. 512 - 150 = 362 MiB cushion
//   (240 %), large enough to absorb the pacer-lag in Go's GOGC=100
//   default without falling back to manual GC tuning at runtime.
//
// QEMU -m 4096 (the runner default) gives EDK2 ~3.5 GiB of boot-
// services memory free at LoadImage time; SizeOfImage = 512 MiB +
// ~5 MiB code/data = 517 MiB rounds well under that ceiling.
// stable202605 confirmed loading.
//
// Other options considered (see docs/architecture/phase3-multi-os-
// oci-boot.md § Sprint 2E):
//   B — Defer cosign verify until after stream. Not applicable here:
//       the FreeBSD probe does NOT do cosign (only kernelboot does).
//       The OOM is from per-packet rxLoop allocs, not cosign retain.
//   C — Build-tag cosign off. Not applicable (no cosign here).
//   D — Refactor ParseTCP4 / tcp4Checksum to pool slices. The Right
//       Thing but architectural — saved for Sprint 2F. Bumping the
//       heap closes 2E cheaply while the per-packet alloc churn is
//       designed away properly.
const heapReserveSize = 0x20000000 // 512 MiB (Sprint 2E)

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

// RamSize: matches heapReserveSize (Sprint 2E: 320 MiB). Anchored
// at the page-aligned start of heapReserve by cpuinit_amd64.s, so
// the region [RamStart, RamStart+RamSize) is exactly the .bss
// reservation (firmware-allocated, mapped, RW — guaranteed valid
// memory).
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
