// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — gBS->InstallConfigurationTable +
// gBS->AllocatePool live wrappers (Phase 2, M8.6). Host-buildable
// type surface in install_config_table.go.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// InstallConfigurationTable invokes gBS->InstallConfigurationTable(
// &guid, table). Per UEFI 2.10 §7.5:
//
//	EFI_STATUS InstallConfigurationTable(
//	    IN EFI_GUID  *Guid,
//	    IN VOID      *Table );
//
// If `table` is NULL, the firmware uninstalls any existing entry for
// the GUID (mode the M8.6 publish path does not exercise but is
// supported by the spec — see future M8.x DTB-unpublish hook).
//
// Returns an *EFIError on non-success; nil on EFI_SUCCESS.
//
// Note: gBS->InstallConfigurationTable can re-enter the firmware's
// notification mechanism for ExitBootServices / ConfigurationTable
// listeners; on EDK2 stable202408 + QEMU virt this is well-tested and
// the publish path is < 1 ms wall-clock.
func InstallConfigurationTable(guid EFI_GUID, table unsafe.Pointer) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	// Take a local copy of the GUID so we can hand a stable pointer
	// to the firmware. UEFI spec requires the EFI_GUID to remain
	// valid for the duration of the call but not beyond; the local
	// is on the Go stack which is fine for that bounded lifetime.
	g := guid
	status := efiCall(
		bs+efiBSInstallConfigurationTable,
		uint64(uintptr(unsafe.Pointer(&g))),
		uint64(uintptr(table)),
		0, 0, 0, 0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "InstallConfigurationTable"}
	}
	return nil
}

// AllocatePool invokes gBS->AllocatePool(memoryType, size, &outPtr).
// Returns the firmware-chosen pool address on success.
//
// AllocatePool differs from AllocatePages in two ways:
//   1. Size is in bytes, not 4 KiB pages — appropriate for sub-page
//      allocations like the M8.6 DTB pool (typically ~10 KiB).
//   2. The returned pointer is not page-aligned; the firmware's pool
//      allocator picks any natural alignment (usually 8 bytes on
//      LP64 UEFI).
//
// Caller frees via FreePool, or relies on ExitBootServices to release
// EfiBootServicesData pool memory automatically (the M8.6 PublishDTB
// path uses the latter — the DTB is consumed by the kernel EFI-stub
// during early init and the Boot Services lifetime covers that
// window).
func AllocatePool(memoryType uint32, size uintptr) (uint64, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	if size == 0 {
		return 0, nil
	}
	var addr uint64
	status := efiCall(
		bs+efiBSAllocatePool,
		uint64(memoryType),
		uint64(size),
		uint64(uintptr(unsafe.Pointer(&addr))),
		0, 0, 0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "AllocatePool"}
	}
	if addr == 0 {
		return 0, &EFIError{Status: efiInvalidParameter, Op: "AllocatePool: NULL"}
	}
	return addr, nil
}

// PublishDTB is the M8.6 high-level helper: allocates an
// EfiBootServicesData pool buffer of len(dtb) bytes, copies dtb into
// it, then calls gBS->InstallConfigurationTable(&EFIDTBTableGUID,
// poolPtr). After success, ProbeDTBConfigurationTable will see the
// installed entry, and Linux's EFI-stub (which scans the same table
// during early-init) will find the DTB without any further wiring.
//
// Lifetime: the pool memory is EfiBootServicesData, released
// automatically at ExitBootServices. The kernel EFI-stub copies the
// DTB into kernel-side storage during its early-init so the
// firmware-side copy doesn't need to outlive Boot Services.
//
// Returns ErrDTBEmpty for a zero-length input (caller bug; the
// firmware would reject the install or the kernel would crash
// dereferencing the published table). Otherwise returns any
// AllocatePool / InstallConfigurationTable error verbatim, wrapped
// as *EFIError.
//
// Idempotency: calling PublishDTB twice installs two separate pool
// allocations; UEFI's InstallConfigurationTable replaces an existing
// entry for the same GUID with the new pointer (per UEFI 2.10 §7.5),
// so the second call's table wins. The first allocation is then
// orphaned for the remainder of Boot Services but freed at EBS — no
// long-term leak. The M8.6 caller only invokes PublishDTB once per
// boot (before LoadImage(kernel)) so this is a non-issue in practice.
func PublishDTB(dtb []byte) error {
	if len(dtb) == 0 {
		return ErrDTBEmpty
	}
	// Allocate firmware-owned EfiBootServicesData pool memory big
	// enough for the DTB. AllocatePool returns a pointer to memory
	// the firmware tracks under that type — the Go heap is not
	// involved, so the buffer survives across any subsequent GC
	// (the GC doesn't traverse foreign pool memory).
	poolPtr, err := AllocatePool(EfiBootServicesData, uintptr(len(dtb)))
	if err != nil {
		return err
	}

	// Copy the DTB bytes into the firmware pool. Use unsafe.Slice to
	// build a Go []byte view of the firmware-owned region so we can
	// use copy() — saves rolling a per-byte loop.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(poolPtr))), len(dtb))
	copy(dst, dtb)

	// Install the configuration table entry. The firmware takes our
	// pool pointer as the VendorTable for EFIDTBTableGUID; the next
	// scanner (whether our own ProbeDTBConfigurationTable or the
	// kernel EFI-stub's efi_get_fdt) will find it.
	if ierr := InstallConfigurationTable(DTBGUIDBytes, unsafe.Pointer(uintptr(poolPtr))); ierr != nil {
		// On install failure the pool allocation is wasted but will
		// be freed at ExitBootServices — no leak. Don't try to
		// FreePool here: the spec allows the firmware to have already
		// taken a reference via the failed install, and double-free
		// is much worse than waste.
		return ierr
	}
	return nil
}
