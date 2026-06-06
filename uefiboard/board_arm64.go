// cloud-boot UEFI board — arm64-specific Go hooks.
//
// Uses the TamaGo framework's arm64 CPU package for the generic-timer
// based Nanotime and Hwinit0 (empty stub provided by the framework).
// Unlike amd64, the framework's arm64 package does NOT export
// RamStackOffset or an RNG, so the board provides them here. The
// firmware entry + ABI thunk live in cpuinit_arm64.s / eficall_arm64.s.

//go:build tamago && arm64

package uefiboard

import (
	_ "unsafe"

	"github.com/usbarmory/tamago/arm64"
)

// CPU is this board's processor instance (timer/MMU/exception state).
// UEFI on AArch64 already ran the platform in EL1 with the MMU + GIC up,
// so Hwinit1 only needs the (light) TamaGo-side init for things the
// runtime relies on (counter frequency for Nanotime, etc.).
var CPU = &arm64.CPU{}

// RamSize: 32 MiB. On aarch64-virt the firmware places the image near
// the top of installed RAM, leaving only a few dozen MiB above. 32 MiB
// safely fits in that sliver and is enough for a hello PoC heap. Replace
// with a UEFI memory-map reconciliation post-World for a real loader.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x02000000

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	// Skip framework arm64.CPU.Init() on UEFI: it installs an exception
	// vector table (initVectorTable writes VBAR_EL1) which would conflict
	// with the firmware's vectors that we still depend on, and it sets
	// goos.Idle to a WFI-based governor whose interrupts we haven't wired
	// up.
	//
	// Phase 1.5 note: empirically the runtime never reaches this point —
	// it hangs silently in the standard arm64 bring-up between cpuinit and
	// the schedinit/InitRNG call. See README "Status / Phase 1.5".
}

//go:linkname initRNG runtime/goos.InitRNG
func initRNG() {}

// Framework arm64 has no RamStackOffset linkname; declare it here. 1 MiB
// stack window matches the amd64 default.
//
//go:linkname ramStackOffset runtime/goos.RamStackOffset
var ramStackOffset uint64 = 0x100000

// Framework arm64 has no RNG hook. The Go runtime calls InitRNG +
// GetRandomData early (e.g. for the hashmap seed), so we provide a
// deterministic xorshift adequate for a hello-world / boot path; a real
// loader will want either ARMv8.5 RNDR or a virtio-rng source.
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
