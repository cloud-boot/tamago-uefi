// cloud-boot UEFI board — gBS->AllocatePages wrapper (Phase 2, M2).
//
// AllocatePages is the canonical way for a UEFI app to request
// page-aligned, device-coherent RAM the firmware tracks as
// EfiLoaderData / EfiBootServicesData. The Phase-1 cpuinit shim
// already calls it once at entry to set up the runtime heap; M2's
// virtqueue allocator calls it again for each virtqueue's
// descriptor/avail/used ring buffer (Virtio 1.1 §2.6 mandates a
// contiguous 4 KiB-aligned allocation per queue).
//
// We expose ONLY `AllocateAnyPages` (firmware picks the address) +
// `EfiBootServicesData` (released at ExitBootServices, exactly the
// lifetime our virtqueues need). M4's loader pivot will add the
// `AllocateAddress` variant for the kernel image staging.
//
// EFI_BOOT_SERVICES.AllocatePages signature (UEFI 2.10 §7.2.1):
//
//	EFI_STATUS AllocatePages(
//	    IN     EFI_ALLOCATE_TYPE       Type,
//	    IN     EFI_MEMORY_TYPE         MemoryType,
//	    IN     UINTN                   Pages,
//	    IN OUT EFI_PHYSICAL_ADDRESS   *Memory );
//
// (4 args — well within the 6-arg efiCall envelope.)
//
// Reference: edk2.git MdePkg/Include/Uefi/UefiSpec.h (the prototype)
// and MdeModulePkg/Core/Dxe/Mem/Page.c::CoreAllocatePages (the
// reference implementation).
//
// Why a separate file (not folded into memorymap_tamago.go): keeping
// memory-allocator concerns separate from memory-map enumeration makes
// the M2 virtqueue allocator's call graph obvious in `git blame`, and
// it gives the M2 work its own host-buildable seam (no `//go:build
// tamago` on the call-shape comments).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// EFI_ALLOCATE_TYPE values (UEFI 2.10 §7.2.1):
//
//	AllocateAnyPages       = 0  firmware picks the address
//	AllocateMaxAddress     = 1  caller specifies an upper bound
//	AllocateAddress        = 2  caller specifies an exact base
//
// M2 only uses AllocateAnyPages — the virtqueue's physical address is
// communicated to the device through the QueueDesc/QueueDriver/
// QueueDevice MMIO registers, so we don't care where firmware places
// it as long as it's 4 KiB-aligned (which AllocatePages guarantees per
// UEFI 2.10 §7.2.1 — every page returned is `EFI_PAGE_SIZE`-aligned).
const (
	EFIAllocateAnyPages   uint32 = 0
	EFIAllocateMaxAddress uint32 = 1
	EFIAllocateAddress    uint32 = 2
)

// efiBSAllocatePages is the function-pointer offset of AllocatePages
// in EFI_BOOT_SERVICES (UEFI 2.10 §4.2, table 4.2 — the 5th UINTN
// slot after the 24-byte EFI_TABLE_HEADER + 2 TPL services).
const efiBSAllocatePages = 40

// efiBSFreePages is the parity FreePages slot. M2 does NOT call it
// (we rely on ExitBootServices to release the EfiBootServicesData
// pages); declared here so the M4 loader can wire up explicit frees
// if needed.
const efiBSFreePages = 48

// AllocatePages allocates `count` 4 KiB pages of `memoryType`, returning
// the firmware-chosen physical base address. `memoryType` is one of
// the `EfiBootServicesData` / `EfiLoaderData` etc constants from
// memorymap.go (Virtqueue and DMA buffers want
// EfiBootServicesData — released automatically at ExitBootServices,
// no manual free required).
//
// Returns the base physical address (which on every UEFI arch we
// target — amd64 (identity), arm64-virt (identity below 1 GiB),
// loong64 (identity), riscv64 (identity) — is also a usable Go-side
// pointer while still in Boot Services).
//
// Errors are wrapped *EFIError if the firmware refuses; common
// failures are EFI_OUT_OF_RESOURCES (firmware is out of free pages)
// and EFI_INVALID_PARAMETER (we passed a malformed Type / MemoryType).
func AllocatePages(memoryType uint32, count uintptr) (uint64, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	if count == 0 {
		return 0, nil
	}
	var addr uint64
	status := efiCall(
		bs+efiBSAllocatePages,
		uint64(EFIAllocateAnyPages),
		uint64(memoryType),
		uint64(count),
		uint64(uintptr(unsafe.Pointer(&addr))),
		0,
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "AllocatePages"}
	}
	return addr, nil
}

// FreePages releases pages previously returned by AllocatePages. M2 does
// NOT call this — virtqueues live for the duration of Boot Services
// and the firmware reclaims them at ExitBootServices. M4 may wire it
// up for the kernel-image staging buffer.
//
// EFI_BOOT_SERVICES.FreePages signature (UEFI 2.10 §7.2.2):
//
//	EFI_STATUS FreePages(
//	    IN EFI_PHYSICAL_ADDRESS  Memory,
//	    IN UINTN                 Pages );
func FreePages(addr uint64, count uintptr) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	if count == 0 {
		return nil
	}
	status := efiCall(
		bs+efiBSFreePages,
		addr,
		uint64(count),
		0, 0, 0, 0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "FreePages"}
	}
	return nil
}
