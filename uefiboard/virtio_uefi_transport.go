// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// UEFI ↔ go-virtio transport adapter.
//
// The transport-agnostic virtio infrastructure lives in
// github.com/go-virtio/common; the spec-level virtio-net driver lives
// in github.com/go-virtio/net. This file bridges the two to UEFI by
// providing a `*UEFITransport` value that satisfies
// `common.Transport`:
//
//   - PCIConfigReader → EFI_PCI_IO_PROTOCOL.Pci.Read (M1 path; see
//     pci_io_protocol_tamago.go).
//   - BARMemoryAccessor → EFI_PCI_IO_PROTOCOL.Mem.Read/Write (M2 path;
//     see pci_mem_io.go).
//   - PageAllocator → gBS->AllocatePages(EfiBootServicesData) +
//     identity-mapped Go-side byte view (see alloc_pages.go).
//
// References:
//
//   - UEFI 2.10 §13.4   "EFI_PCI_IO_PROTOCOL" — Pci.Read / Mem.Read /
//     Mem.Write call shape.
//   - UEFI 2.10 §7.2.1  "EFI_BOOT_SERVICES.AllocatePages" — page
//     allocation.
//   - Virtio 1.1 §2.6   "Virtqueues" — alignment requirements for
//     descriptor / avail / used regions.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"

	"github.com/go-virtio/common"
)

// UEFITransport satisfies common.Transport for one virtio device
// exposed through EFI_PCI_IO_PROTOCOL. Construct with `NewUEFITransport(pciIO)`
// where `pciIO` is the protocol-interface pointer returned by
// `HandleProtocol(handle, &EFIPciIOProtocolGUID)`.
type UEFITransport struct {
	// PciIO is the EFI_PCI_IO_PROTOCOL interface pointer. Exposed so
	// diagnostic narrows can reach back into the underlying
	// firmware-side primitives (Attributes, GetLocation, …) without
	// re-deriving it.
	PciIO uint64

	// pinnedPages keeps Go references to the byte slices returned by
	// AllocatePages so the GC doesn't reclaim them. The driver retains
	// only the uintptr-form physical address, which the GC doesn't
	// trace. Live virtqueue / DMA-buffer pages must outlive the
	// driver; we keep them alive until ExitBootServices releases the
	// underlying EfiBootServicesData range.
	pinnedPages [][]byte
}

// NewUEFITransport constructs a Transport adapter for the device whose
// EFI_PCI_IO_PROTOCOL interface pointer is `pciIO`.
func NewUEFITransport(pciIO uint64) *UEFITransport {
	return &UEFITransport{PciIO: pciIO}
}

// --- PCIConfigReader ---------------------------------------------------

// ReadConfig8 routes a PCI config-space byte read through
// EFI_PCI_IO_PROTOCOL.Pci.Read.
func (t *UEFITransport) ReadConfig8(off uint8) (uint8, error) {
	return PciIOReadConfigU8(t.PciIO, uint32(off))
}

// ReadConfig16 routes a PCI config-space u16 read through Pci.Read.
func (t *UEFITransport) ReadConfig16(off uint8) (uint16, error) {
	return PciIOReadConfigU16(t.PciIO, uint32(off))
}

// ReadConfig32 routes a PCI config-space u32 read through Pci.Read.
func (t *UEFITransport) ReadConfig32(off uint8) (uint32, error) {
	return PciIOReadConfigU32(t.PciIO, uint32(off))
}

// --- BARMemoryAccessor -------------------------------------------------

// Read8 routes a BAR-window byte read through Mem.Read.
func (t *UEFITransport) Read8(bar uint8, off uint64) (uint8, error) {
	return PciIOMemRead8(t.PciIO, bar, off)
}

// Read16 routes a BAR-window u16 read through Mem.Read.
func (t *UEFITransport) Read16(bar uint8, off uint64) (uint16, error) {
	return PciIOMemRead16(t.PciIO, bar, off)
}

// Read32 routes a BAR-window u32 read through Mem.Read.
func (t *UEFITransport) Read32(bar uint8, off uint64) (uint32, error) {
	return PciIOMemRead32(t.PciIO, bar, off)
}

// Read64 routes a BAR-window u64 read through Mem.Read.
func (t *UEFITransport) Read64(bar uint8, off uint64) (uint64, error) {
	return PciIOMemRead64(t.PciIO, bar, off)
}

// Write8 routes a BAR-window byte write through Mem.Write.
func (t *UEFITransport) Write8(bar uint8, off uint64, v uint8) error {
	return PciIOMemWrite8(t.PciIO, bar, off, v)
}

// Write16 routes a BAR-window u16 write through Mem.Write.
func (t *UEFITransport) Write16(bar uint8, off uint64, v uint16) error {
	return PciIOMemWrite16(t.PciIO, bar, off, v)
}

// Write32 routes a BAR-window u32 write through Mem.Write.
func (t *UEFITransport) Write32(bar uint8, off uint64, v uint32) error {
	return PciIOMemWrite32(t.PciIO, bar, off, v)
}

// Write64 routes a BAR-window u64 write through Mem.Write.
func (t *UEFITransport) Write64(bar uint8, off uint64, v uint64) error {
	return PciIOMemWrite64(t.PciIO, bar, off, v)
}

// --- PageAllocator -----------------------------------------------------

// AllocatePages allocates `count` 4 KiB pages of EfiBootServicesData
// (released at ExitBootServices, exactly the lifetime virtqueues
// need), zeroes them, and returns the physical address + a Go-side
// byte view of the same region.
//
// On every UEFI arch we target the physical address returned is
// identity-mapped into the virtual address space during Boot Services,
// so the device's DMA read at `phys` and the driver's writes through
// `mem[]` see the same bytes. The cache-coherency guarantee firmware
// provides for EfiBootServicesData (UEFI 2.10 §2.3.x / §7.2 — "All
// memory regions reported by GetMemoryMap are required to be
// hardware-cache-coherent for boot services") makes that safe.
//
// Note: we keep a reference to `mem` in `t.pinnedPages` so the GC
// doesn't reclaim the underlying byte slice header. The actual page
// memory is owned by firmware (EfiBootServicesData), not the Go heap,
// so the byte slice is a thin Go-side view of that firmware memory;
// the slice itself just has to outlive ExitBootServices.
func (t *UEFITransport) AllocatePages(count int) (uint64, []byte, error) {
	if count <= 0 {
		return 0, nil, ErrAllocReturnedZero
	}
	phys, err := AllocatePages(EfiBootServicesData, uintptr(count))
	if err != nil {
		return 0, nil, err
	}
	if phys == 0 {
		return 0, nil, ErrAllocReturnedZero
	}
	n := uintptr(count) * EfiPageSize
	mem := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(phys))), int(n))
	// Zero the pages — AllocatePages doesn't (UEFI 2.10 §7.2.1).
	for i := range mem {
		mem[i] = 0
	}
	t.pinnedPages = append(t.pinnedPages, mem)
	return phys, mem, nil
}

// Compile-time interface conformance assertion.
var _ common.Transport = (*UEFITransport)(nil)
