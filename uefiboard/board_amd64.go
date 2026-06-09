// cloud-boot UEFI board — amd64-specific Go hooks.
//
// Reuses the TamaGo framework's amd64 CPU package for the TSC timer,
// RDRAND (InitRNG/GetRandomData), RamStackOffset and Hwinit0. Only the
// UEFI-specific Nanotime / Hwinit1 wrappers and the board's CPU instance
// live here; everything arch-neutral is in board.go and the firmware
// entry + ABI thunk are in cpuinit_amd64.s / eficall_amd64.s.
//
// R-amd64b (2026-06-09): RamSize lowered from 704 MiB (`0x2c000000`,
// inherited from the bare-metal usbarmory convention) to 128 MiB
// (`0x08000000`). cpuinit_amd64.s now passes `(RamSize >> 12)` page
// count to gBS->AllocatePages(EFI_ALLOCATE_ANY_PAGES, EfiLoaderData,
// ...) and anchors goos.RamStart + goos.Bloc + SP to the returned
// base — matching the arm64 / riscv64 / loong64 cpuinit shape.
// Reason: the pre-rewrite scheme derived RamStart from
// `&runtime.text - 64 KiB`, which is fine on bare metal (where the
// boot ROM places the kernel at a predictable base with empty RAM
// above) but broken under the patched OVMF, which loads multi-MiB
// PE32+ images near the TOP of free RAM and marks adjacent regions
// RO/XP. 704 MiB above the image overflowed past the QEMU q35
// `0x80000000` PCI MMIO hole; any value that still fit risked
// landing inside one of the firmware allocator's now-protected
// pages. See cloud-boot/docs/m6-2-edk2-upstream-investigation.md
// § 11.

//go:build tamago && amd64

package uefiboard

import (
	_ "unsafe"

	"github.com/usbarmory/tamago/amd64"
)

// CPU is this board's processor instance (timer/RNG/feature state).
var CPU = &amd64.CPU{}

// RamSize: 128 MiB. cpuinit_amd64.s passes (RamSize >> 12) as the page
// count to gBS->AllocatePages, then points goos.RamStart / goos.Bloc at
// the returned base. 128 MiB safely fits in QEMU q35 -m 2048 's
// EfiLoaderData arena (which the patched OVMF sizes generously) and is
// sized to match the upper bound of cloud-boot's M6/M7/M8 amd64
// workloads: the largest is the M7 OCI streaming fetch + cosign verify
// of a multi-layer chained-EFI image, holding the manifest, the
// signing-bundle, the OCI client's interim string buffers, the TLS
// record buffers, and the in-flight blob chunks (≤ 1 MiB streamed)
// simultaneously in heap; observed peak ~30 MiB on arm64 with the same
// scenario. 128 MiB gives a comfortable ~4× margin and matches arm64 /
// riscv64 / loong64 board files for cross-arch consistency. A real
// loader will reconcile this against the UEFI memory map post-World.
//
//go:linkname ramSize runtime/goos.RamSize
var ramSize uint64 = 0x08000000

//go:linkname nanotime runtime/goos.Nanotime
func nanotime() int64 {
	return CPU.GetTime()
}

//go:linkname hwinit1 runtime/goos.Hwinit1
func hwinit1() {
	CPU.Init()
}
