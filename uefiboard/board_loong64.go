// cloud-boot UEFI board — loong64-specific Go hooks.
//
// Self-contained on loong64 (does NOT import the cloud-boot-local
// framework loong64 package), for the same reason board_arm64.go is:
// the framework's `loong64.Init` is linknamed `runtime/goos.Hwinit0`
// and would conflict with the board's own Hwinit0. We supply our
// own here, plus Nanotime via the stable-timer / CPUCFG path.

//go:build tamago && loong64

package uefiboard

import (
	_ "unsafe"
)

// RamSize: 128 MiB. Bumped from 64 MiB on 2026-06-10 to match
// board_arm64.go for M8.4 self-publish MODE C: the streamed Debian
// loong64 vmlinuz is 8.7 MiB raw / 8.3 MiB gzipped (zstd-compressed
// payload already), so the streaming buffer + tar walk fits well
// under 32 MiB — but we go to 128 MiB so the heap has the same
// breathing room arm64 has post-stream when LoadImage runs.
// Safely fits in QEMU virt -m 4096.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x08000000

// Framework loong64 has no RamStackOffset linkname; declare it here.
// 1 MiB stack window matches the arm64/amd64/riscv64 defaults.
//
//go:linkname ramStackOffset runtime/goos.RamStackOffset
var ramStackOffset uint64 = 0x100000

// rdStableCounter reads the LoongArch stable-timer counter via RDTIME.D
// (defined in board_loong64.s).
func rdStableCounter() int64

// rdCPUCFG returns CPUCFG[reg] (defined in board_loong64.s).
func rdCPUCFG(reg uint32) uint32

// counterFreq derives the stable-timer frequency in Hz from CPUCFG
// words 4 and 5: freq = word4 * (word5 & 0xffff) / (word5 >> 16).
// Falls back to QEMU virt's 100 MHz default when CPUCFG reports 0.
func counterFreq() int64 {
	base := int64(rdCPUCFG(4))
	if base == 0 {
		return 100_000_000
	}
	cfg5 := rdCPUCFG(5)
	mul := int64(cfg5 & 0xffff)
	div := int64((cfg5 >> 16) & 0xffff)
	if mul == 0 || div == 0 {
		return base
	}
	return base * mul / div
}

//go:linkname hwinit0 runtime/goos.Hwinit0
func hwinit0() {
	// Empty: cpuinit_loong64.s already wired RamStart/Bloc and SP
	// before the runtime entered. No further pre-osinit setup needed.
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	// No-op under UEFI: firmware already enabled the FPU, installed
	// exception vectors and brought up the stable-timer. A real
	// loader fills this in after ExitBootServices.
}

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	freq := counterFreq()
	if freq <= 0 {
		return 0
	}
	cnt := uint64(rdStableCounter())
	// nanoseconds = cnt * 1e9 / freq. Split as (cnt / freq) * 1e9 +
	// (cnt % freq) * 1e9 / freq to avoid the uint64 overflow that
	// `cnt * 1e9` would hit past ~18 G ticks.
	f := uint64(freq)
	secs := cnt / f
	rem := cnt % f
	return int64(secs*1_000_000_000 + (rem*1_000_000_000)/f)
}

//go:linkname initRNG runtime/goos.InitRNG
func initRNG() {
	rngState = uint64(rdStableCounter()) ^ 0x9E3779B97F4A7C15
}

// splitmix64 PRNG seeded by the stable-timer in initRNG. Not crypto-
// grade; a real loader will want a HW RNG or virtio-rng.
var rngState uint64

func rngNext() uint64 {
	rngState += 0x9E3779B97F4A7C15
	z := rngState
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

//go:linkname getRandomData runtime/goos.GetRandomData
func getRandomData(b []byte) {
	for i := 0; i < len(b); {
		r := rngNext()
		for j := 0; j < 8 && i < len(b); j++ {
			b[i] = byte(r)
			r >>= 8
			i++
		}
	}
}
