// cloud-boot UEFI board — arm64-specific Go hooks.
//
// Self-contained on arm64 (does NOT import the TamaGo framework's arm64
// CPU package), for the same reason board_riscv64.go is self-contained:
// the framework's `arm64.Init` is linknamed to `runtime/goos.Hwinit0`
// and calls `cpu.InitMMU()`, which under UEFI on AArch64 clobbers the
// firmware's page tables (the firmware has already set up Normal/Cacheable
// RAM + Device MMIO mappings and we depend on them) and hangs bring-up.
// We supply our own `Hwinit0` linkname below; importing the framework's
// arm64 package alongside ours would cause a duplicate-linkname error.
//
// Nanotime reads CNTPCT_EL0 directly (Generic Timer "physical count" CSR)
// and rescales by CNTFRQ_EL0 (counter frequency); both are available at
// EL1 under UEFI without any timer-side initialisation.

//go:build tamago && arm64

package uefiboard

import (
	_ "unsafe"
)

// RamSize: 128 MiB. cpuinit_arm64.s passes (RamSize >> 12) as the page
// count to gBS->AllocatePages, and points goos.RamStart / goos.Bloc at
// the returned base. 128 MiB safely fits in QEMU virt -m 4096 and is
// sized for the M8.3 Linux-EFI-stub kernel-boot path: the siderolabs
// `boot/vmlinuz` arm64 image is ~53 MiB uncompressed, the gzipped
// layer is ~22 MiB compressed; holding both in the Go heap
// simultaneously during the synchronous gunzip+tar extract (see
// `extractVmlinuzFromTarGz` in phase2_oci_kernel_boot.go — chosen
// over the io.Pipe path because TamaGo+UEFI has no async preemption
// and the producer goroutine cannot be scheduled while the consumer
// blocks on Read; R-M8.3b) needs ~75 MiB of heap. 128 MiB gives a
// ~50 MiB working-margin (TLS buffers, ministack queues, the OCI
// client's manifest/index/token strings, the SHA-256 verifier's
// running state). A real loader will reconcile against the UEFI
// memory map post-World instead of hard-coding this.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x08000000

// Framework arm64 has no RamStackOffset linkname; declare it here. 1 MiB
// stack window matches the amd64 default.
//
//go:linkname ramStackOffset runtime/goos.RamStackOffset
var ramStackOffset uint64 = 0x100000

// rdcntpct reads CNTPCT_EL0 (Generic Timer Physical Count). Defined in
// board_arm64.s.
func rdcntpct() uint64

// rdcntfrq reads CNTFRQ_EL0 (Generic Timer Counter Frequency, in Hz).
// Defined in board_arm64.s.
func rdcntfrq() uint64

// hwinit0 takes the place of framework arm64.Init when this package
// is built. Empty: cpuinit_arm64.s already did the heavy lifting
// (AllocatePages → RamStart/Bloc, SP, SCTLR.A, CPACR.FPEN) before
// the runtime started. Anything we'd add here would run on a Go
// stack — fine — but there's nothing left that needs the goos hook.
//
//go:linkname hwinit0 runtime/goos.Hwinit0
func hwinit0() {}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	// No-op under UEFI: firmware installed its own exception vectors
	// and we're not yet ready to take over from them (no idle governor,
	// no interrupt routing). A real loader fills this in after
	// ExitBootServices.
}

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	freq := rdcntfrq()
	if freq == 0 {
		return 0
	}
	cnt := rdcntpct()
	// nanoseconds = cnt * 1e9 / freq. Split as (cnt / freq) * 1e9 +
	// ((cnt % freq) * 1e9) / freq to avoid uint64 overflow at high
	// counter values (cnt * 1e9 wraps for cnt > ~18.4 G ticks =
	// ~308s @ 60 MHz QEMU virt counter).
	secs := cnt / freq
	rem := cnt % freq
	return int64(secs*1_000_000_000 + (rem*1_000_000_000)/freq)
}

//go:linkname initRNG runtime/goos.InitRNG
func initRNG() {}

// Deterministic xorshift RNG. The Go runtime calls InitRNG +
// GetRandomData early (e.g. for the hashmap seed); a real loader will
// want ARMv8.5 RNDR or a virtio-rng source.
var rngState uint64 = 0x9E3779B97F4A7C15

//go:linkname getRandomData runtime/goos.GetRandomData
func getRandomData(b []byte) {
	for i := range b {
		rngState ^= rngState << 13
		rngState ^= rngState >> 7
		rngState ^= rngState << 17
		b[i] = byte(rngState)
	}
}
