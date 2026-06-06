// cloud-boot UEFI board — loong64-specific Go hooks.
//
// Uses the TamaGo framework's loong64 CPU package (staged locally in
// usbarmory/tamago/loong64/, pending upstream usbarmory/tamago#70 and
// usbarmory/tamago-go#17 — see README) for the stable-timer based
// Nanotime and the empty Hwinit0 stub. Like arm64 and riscv64, the
// framework's loong64 package does NOT export RamStackOffset or an
// RNG, so the board provides them here. The firmware entry + ABI
// thunk live in cpuinit_loong64.s / eficall_loong64.s.

//go:build tamago && loong64

package uefiboard

import (
	_ "unsafe"

	"github.com/usbarmory/tamago/loong64"
)

// CPU is this board's processor instance (stable-timer state).
//
// UEFI on LoongArch already ran the platform in PLV0 with the MMU,
// interrupt controller and stable-timer up, so Hwinit1 only needs the
// (light) TamaGo-side init for the counter frequency (so Nanotime
// returns nanoseconds rather than raw ticks).
var CPU = &loong64.CPU{}

// RamSize: 64 MiB. On loongarch64-virt the firmware places the image
// somewhere in the installed RAM region (QEMU -m 4096); 64 MiB above
// the image base safely fits the heap arena for the hello PoC. Replace
// with a UEFI memory-map reconciliation post-World for a real loader.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x04000000

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	// Skip framework loong64.CPU.Init() on UEFI: it touches CSR state
	// (Exit/Idle hooks) that is fine, but in a more complete framework
	// version it would also re-program CSR.EENTRY, CSR.ECFG and the
	// exception vector — all of which would clobber firmware's vectors
	// that we still depend on for any synchronous exception during
	// bring-up.
	//
	// We DO want the timer multiplier programmed so nanotime() returns
	// nanoseconds rather than raw stable-timer ticks; do that part
	// explicitly here.
	CPU.InitTimer()
}

// Framework loong64 has no RamStackOffset linkname; declare it here.
// 1 MiB stack window matches the amd64 / arm64 / riscv64 defaults.
//
//go:linkname ramStackOffset runtime/goos.RamStackOffset
var ramStackOffset uint64 = 0x100000

//go:linkname initRNG runtime/goos.InitRNG
func initRNG() {
	loong64.InitRNG()
}

//go:linkname getRandomData runtime/goos.GetRandomData
func getRandomData(b []byte) {
	loong64.GetRandomData(b)
}
