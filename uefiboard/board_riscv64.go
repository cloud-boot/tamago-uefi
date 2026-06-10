// cloud-boot UEFI board — riscv64-specific Go hooks.
//
// Unlike amd64 / arm64, the riscv64 leg does NOT import the TamaGo
// framework's riscv64 CPU package: that package's `irq.s` contains
// register references (X3 aka GP) that the current Go riscv64
// assembler in our patched tamago-go toolchain rejects ("illegal or
// missing addressing mode for symbol X3"). The framework code is
// also tailored for M-mode bare-metal, which doesn't apply under
// UEFI (M-mode is occupied by OpenSBI underneath); even the
// CPU.Init() helper writes MTVEC and disables M-mode interrupts and
// would trap if executed from UEFI's S-mode.
//
// We therefore implement only the minimum hooks the runtime needs:
//
//   - Hwinit0 / Hwinit1   (no-op under UEFI, see file header)
//   - Nanotime            (S-mode TIME CSR via SBI TIME extension)
//   - InitRNG / GetRandomData
//   - RamSize / RamStackOffset
//
// The firmware entry + ABI thunk live in cpuinit_riscv64.s /
// eficall_riscv64.s; the rdtime helper lives in board_riscv64.s.

//go:build tamago && riscv64

package uefiboard

import (
	_ "unsafe"
)

// RamSize: 128 MiB. Bumped from 32 MiB on 2026-06-10 to match
// board_arm64.go for M8.4 self-publish MODE C: the streamed Debian
// riscv64 vmlinux is 31 MiB raw / 10 MiB gzipped, and the buffered
// gunzip+tar pipeline in streamExtractVmlinuz needs raw + compressed
// + tar buffer simultaneously (~42 MiB peak). 32 MiB no longer fits.
// 128 MiB safely fits in QEMU virt -m 4096.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x08000000

// rdtime reads the user-mode TIME CSR (encoding 0xC01) — available
// under S-mode UEFI thanks to OpenSBI's TIME extension.
//
// Defined in board_riscv64.s.
func rdtime() uint64

// Hwinit0 trampoline. The riscv64 framework provides this as
// `riscv64.Init` linknamed to `runtime/goos.Hwinit0`, but we don't
// import that package (see file header), so we declare an empty
// stub here.
//
//go:linkname hwinit0 runtime/goos.Hwinit0
func hwinit0() {}

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	// QEMU virt's TIME CSR runs at 10 MHz (100 ns/tick). Multiplying
	// by 100 gives nanoseconds. A real loader would query the
	// platform's timebase-frequency from the device tree / ACPI.
	return int64(rdtime()) * 100
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	// No-op under UEFI: the firmware has already installed S-mode
	// exception vectors and brought up the platform; nothing for us
	// to do here for a hello-world bring-up. A real loader will
	// install its own runtime services here post-ExitBootServices.
}

//go:linkname initRNG runtime/goos.InitRNG
func initRNG() {}

// Framework riscv64 has no RamStackOffset linkname; declare it here.
// 1 MiB stack window matches the amd64/arm64 defaults.
//
//go:linkname ramStackOffset runtime/goos.RamStackOffset
var ramStackOffset uint64 = 0x100000

// Deterministic xorshift RNG. The Go runtime calls InitRNG +
// GetRandomData early (e.g. for the hashmap seed); the framework
// doesn't ship a riscv64 hook so we provide this PoC-grade source.
// A real loader will want the Zkr (Scalar Cryptography) entropy CSR
// or a virtio-rng device.
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
