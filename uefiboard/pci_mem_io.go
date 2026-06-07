// cloud-boot UEFI board — EFI_PCI_IO_PROTOCOL.Mem.Read/Write call
// thunks (Phase 2, M2).
//
// M1 brought up PciIo.Pci.Read/Write (PCI config-space accessors). M2
// adds the BAR-window accessors `Mem.Read` and `Mem.Write` (UEFI 2.10
// §13.4.2) which are how the virtio modern transport exposes its
// capability structures (COMMON_CFG, NOTIFY_CFG, ISR_CFG, DEVICE_CFG,
// PCI_CFG) at firmware-mediated BAR offsets. The pure-Go virtio-net
// driver routes EVERY MMIO access through this entry; we never poke
// a BAR directly from Go, because the BAR's host-side virtual address
// is firmware-private (it may not be identity-mapped on all arches,
// and on Apple VZ ARM64 the IOMMU adds another layer of indirection).
//
// EFI_PCI_IO_PROTOCOL.Mem.Read / Mem.Write signature (UEFI 2.10 §13.4.2):
//
//	EFI_STATUS Mem.Read(
//	    IN  EFI_PCI_IO_PROTOCOL       *This,
//	    IN  EFI_PCI_IO_PROTOCOL_WIDTH  Width,
//	    IN  UINT8                      BarIndex,
//	    IN  UINT64                     Offset,
//	    IN  UINTN                      Count,
//	    IN OUT VOID                   *Buffer );
//
// That's six args — exactly the M2-widened `efiCall` envelope. The
// previous (5-arg) thunk would have left the 6th-arg slot undefined,
// which on at least one arch (riscv64) caused EDK2 to dereference
// stale-register garbage. See `eficall_riscv64.s` for the prior
// incident analysis that drove the 4→5 widening.
//
// `EFI_PCI_IO_PROTOCOL_ACCESS` is a sub-struct holding two function
// pointers `Read` and `Write` (8 bytes each). For `Mem` the parent
// struct slot is at offset 16 of EFI_PCI_IO_PROTOCOL, so:
//
//	pciIOMemRead  = 16   (offset of Mem.Read entry)
//	pciIOMemWrite = 24   (offset of Mem.Write entry)
//
// Those constants are already defined in `pci_io_protocol.go`. We
// reuse them here for the slot address; `efiCall` does the standard
// `MOV (R8),R9; CALL R9` indirect through the slot.
//
// Reference: MdePkg/Include/Protocol/PciIo.h (edk2.git stable/202408)
// — every signature below is transcribed verbatim.
//
// Validation rationale:
//
//   - The `count` parameter MUST be exactly 1 for the scalar accessors
//     below (we want one read of the given `width`). Auto-increment is
//     a separate Width value (`FifoUint*` / `FillUint*`) we don't use
//     here.
//   - The `width` value MUST match the in-memory buffer size or
//     firmware will fault on the writeback. We use a stack-allocated
//     uint8 / uint16 / uint32 / uint64 slot of exactly the right size.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// PciIOMemRead is the raw `Mem.Read` thunk. Callers usually want one of
// the typed wrappers (PciIOMemRead8/16/32/64) below.
//
// `bar` is the BAR index (0..5) inside the device's config space.
// `offset` is the byte offset within that BAR (matches the
// `VirtioPCICap.Offset` field from the capability walker).
// `count` is the number of `width`-sized scalars to read; for the
// virtio modern transport we always pass 1.
// `buf` must point to `count * sizeof(width)` bytes of writable Go
// memory.
func PciIOMemRead(pciIO uint64, width EFIPciIOWidth, bar uint8, offset uint64, count uintptr, buf unsafe.Pointer) error {
	status := efiCall(
		pciIO+pciIOMemRead,
		pciIO,
		uint64(width),
		uint64(bar),
		offset,
		uint64(count),
		uint64(uintptr(buf)),
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "PciIO.Mem.Read"}
	}
	return nil
}

// PciIOMemWrite is the raw `Mem.Write` thunk; same shape as
// PciIOMemRead, but `buf` is the source of bytes the firmware writes
// to the BAR window.
func PciIOMemWrite(pciIO uint64, width EFIPciIOWidth, bar uint8, offset uint64, count uintptr, buf unsafe.Pointer) error {
	status := efiCall(
		pciIO+pciIOMemWrite,
		pciIO,
		uint64(width),
		uint64(bar),
		offset,
		uint64(count),
		uint64(uintptr(buf)),
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "PciIO.Mem.Write"}
	}
	return nil
}

// PciIOMemRead8 reads one byte from the BAR window. Used for fields
// like ISR-status (Virtio 1.1 §4.1.5.3) and the DeviceCfg MAC bytes
// (Virtio 1.1 §5.1.4).
func PciIOMemRead8(pciIO uint64, bar uint8, offset uint64) (uint8, error) {
	var v uint8
	if err := PciIOMemRead(pciIO, EFIPciIOWidthUint8, bar, offset, 1, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

// PciIOMemRead16 reads one little-endian uint16 from the BAR window.
// Used for fields like QueueSize, QueueMsixVector, QueueEnable,
// QueueNotifyOff, ConfigGeneration (Virtio 1.1 §4.1.5.1).
func PciIOMemRead16(pciIO uint64, bar uint8, offset uint64) (uint16, error) {
	var v uint16
	if err := PciIOMemRead(pciIO, EFIPciIOWidthUint16, bar, offset, 1, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

// PciIOMemRead32 reads one little-endian uint32 from the BAR window.
// Used for the DeviceFeature / DriverFeature select registers and the
// notification doorbell (Virtio 1.1 §4.1.5.1).
func PciIOMemRead32(pciIO uint64, bar uint8, offset uint64) (uint32, error) {
	var v uint32
	if err := PciIOMemRead(pciIO, EFIPciIOWidthUint32, bar, offset, 1, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

// PciIOMemRead64 reads one little-endian uint64 from the BAR window.
// Virtio 1.1 doesn't define 64-bit MMIO fields in the common config
// (QueueDesc/Driver/Device are two consecutive 32-bit halves per
// §4.1.5.1), but Mem.Read/Width=Uint64 is a legal accessor and
// future-proofing the API costs nothing.
func PciIOMemRead64(pciIO uint64, bar uint8, offset uint64) (uint64, error) {
	var v uint64
	if err := PciIOMemRead(pciIO, EFIPciIOWidthUint64, bar, offset, 1, unsafe.Pointer(&v)); err != nil {
		return 0, err
	}
	return v, nil
}

// PciIOMemWrite8 writes one byte to the BAR window. Used for the
// DeviceStatus field (Virtio 1.1 §2.1) during the M2 init sequence.
func PciIOMemWrite8(pciIO uint64, bar uint8, offset uint64, v uint8) error {
	val := v
	return PciIOMemWrite(pciIO, EFIPciIOWidthUint8, bar, offset, 1, unsafe.Pointer(&val))
}

// PciIOMemWrite16 writes one little-endian uint16 to the BAR window.
// Used for QueueSize, QueueSelect, DeviceFeatureSelect,
// DriverFeatureSelect, QueueEnable etc.
func PciIOMemWrite16(pciIO uint64, bar uint8, offset uint64, v uint16) error {
	val := v
	return PciIOMemWrite(pciIO, EFIPciIOWidthUint16, bar, offset, 1, unsafe.Pointer(&val))
}

// PciIOMemWrite32 writes one little-endian uint32 to the BAR window.
// Used for DriverFeature bitmap halves and the notification doorbell.
func PciIOMemWrite32(pciIO uint64, bar uint8, offset uint64, v uint32) error {
	val := v
	return PciIOMemWrite(pciIO, EFIPciIOWidthUint32, bar, offset, 1, unsafe.Pointer(&val))
}

// PciIOMemWrite64 writes one little-endian uint64 to the BAR window.
// Virtio 1.1 §4.1.5.1 defines QueueDesc / QueueDriver / QueueDevice as
// 64-bit physical addresses; firmware tolerates either two 32-bit
// halves OR a single 64-bit write at the same offset (UEFI 2.10
// §13.4.2 — the width determines the on-the-wire size, not the
// register layout). We use the 64-bit form because the virtio spec
// REQUIRES the high half to be written after the low half on a 1.0+
// device, and writing both halves in one transaction sidesteps that
// ordering constraint cleanly.
func PciIOMemWrite64(pciIO uint64, bar uint8, offset uint64, v uint64) error {
	val := v
	return PciIOMemWrite(pciIO, EFIPciIOWidthUint64, bar, offset, 1, unsafe.Pointer(&val))
}
