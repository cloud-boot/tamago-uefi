// cloud-boot UEFI board — EFI_PCI_IO_PROTOCOL call thunks (Phase 2, M1).
//
// Live wrappers for the five entry points M1 uses:
//
//   - PciIOPciRead       (Pci.Read     — config-space read)
//   - PciIOPciWrite      (Pci.Write    — config-space write, parity)
//   - PciIOGetLocation
//   - PciIOAttributes    (GET only — M1 doesn't enable bus master)
//   - PciIOGetBarAttributes
//
// The type-surface (GUID, offsets, width/attribute enums, config-space
// offsets, capability-header layout) lives in pci_io_protocol.go and is
// host-buildable.
//
// Reference: MdePkg/Include/Protocol/PciIo.h (edk2.git stable/202408)
// — all signatures below are transcribed from there.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// PciIOReadConfig issues `count` reads of `width` bytes each from PCI
// config space starting at `offset`. Buffer must be sized for
// `count * width` bytes; M1 always passes count=1 with a fixed-width
// scalar destination.
//
// EFI_PCI_IO_PROTOCOL.Pci.Read signature (UEFI 2.10 §13.4.7):
//
//	EFI_STATUS Read(
//	    IN  EFI_PCI_IO_PROTOCOL       *This,
//	    IN  EFI_PCI_IO_PROTOCOL_WIDTH  Width,
//	    IN  UINT32                     Offset,
//	    IN  UINTN                      Count,
//	    OUT VOID                      *Buffer );
//
// (5 args — exactly the M1-widened efiCall envelope.)
//
// Note on calling convention: efiCall expects to receive the
// ADDRESS of the function-pointer slot (it issues `CALL (AX)`, which
// dereferences AX and jumps). For PCI IO accessor sub-structs the
// function pointer for `Pci.Read` sits at the struct's start
// (offset 48 of pciIO), so we pass `pciIO+pciIOPciRead` directly —
// mirroring memorymap_tamago.go's `bs+efiBSGetMemoryMap` pattern.
func PciIOReadConfig(pciIO uint64, width EFIPciIOWidth, offset uint32, count uintptr, buf unsafe.Pointer) error {
	status := efiCall(
		pciIO+pciIOPciRead,
		pciIO,
		uint64(width),
		uint64(offset),
		uint64(count),
		uint64(uintptr(buf)),
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "PciIO.Pci.Read"}
	}
	return nil
}

// PciIOWriteConfig is the parity write of PciIOReadConfig. M1 does not
// call this; it is provided for M2's queue-init use.
func PciIOWriteConfig(pciIO uint64, width EFIPciIOWidth, offset uint32, count uintptr, buf unsafe.Pointer) error {
	status := efiCall(
		pciIO+pciIOPciWrite,
		pciIO,
		uint64(width),
		uint64(offset),
		uint64(count),
		uint64(uintptr(buf)),
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "PciIO.Pci.Write"}
	}
	return nil
}

// PciIOReadConfigU8 / U16 / U32 are typed convenience wrappers around
// PciIOReadConfig for the three sizes M1 actually uses. They return the
// scalar value, simplifying the probe's call sites.
func PciIOReadConfigU8(pciIO uint64, offset uint32) (uint8, error) {
	var v uint8
	err := PciIOReadConfig(pciIO, EFIPciIOWidthUint8, offset, 1, unsafe.Pointer(&v))
	return v, err
}

func PciIOReadConfigU16(pciIO uint64, offset uint32) (uint16, error) {
	var v uint16
	err := PciIOReadConfig(pciIO, EFIPciIOWidthUint16, offset, 1, unsafe.Pointer(&v))
	return v, err
}

func PciIOReadConfigU32(pciIO uint64, offset uint32) (uint32, error) {
	var v uint32
	err := PciIOReadConfig(pciIO, EFIPciIOWidthUint32, offset, 1, unsafe.Pointer(&v))
	return v, err
}

// PciIOGetLocation returns the (Segment, Bus, Device, Function) tuple
// for the controller bound to this protocol instance.
//
// EFI_PCI_IO_PROTOCOL.GetLocation signature (UEFI 2.10 §13.4.14):
//
//	EFI_STATUS GetLocation(
//	    IN  EFI_PCI_IO_PROTOCOL  *This,
//	    OUT UINTN                *SegmentNumber,
//	    OUT UINTN                *BusNumber,
//	    OUT UINTN                *DeviceNumber,
//	    OUT UINTN                *FunctionNumber );
//
// (5 args.)
func PciIOGetLocation(pciIO uint64) (PciLocation, error) {
	var seg, bus, dev, fun uint64
	status := efiCall(
		pciIO+pciIOGetLocation,
		pciIO,
		uint64(uintptr(unsafe.Pointer(&seg))),
		uint64(uintptr(unsafe.Pointer(&bus))),
		uint64(uintptr(unsafe.Pointer(&dev))),
		uint64(uintptr(unsafe.Pointer(&fun))),
	)
	if status != efiSuccess {
		return PciLocation{}, &EFIError{Status: status, Op: "PciIO.GetLocation"}
	}
	return PciLocation{Segment: seg, Bus: bus, Device: dev, Function: fun}, nil
}

// PciIOAttributesGet wraps the EFI_PCI_IO_PROTOCOL_ATTRIBUTES service
// (Get form only — Result OUT, no input attributes). The
// op_set/enable/disable variants are deferred to M2.
//
// EFI_PCI_IO_PROTOCOL.Attributes signature (UEFI 2.10 §13.4.13):
//
//	EFI_STATUS Attributes(
//	    IN  EFI_PCI_IO_PROTOCOL                       *This,
//	    IN  EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION    Operation,
//	    IN  UINT64                                     Attributes,
//	    OUT UINT64                                    *Result OPTIONAL );
//
// (4 args; we pass 0 in slot 5.)
func PciIOAttributesGet(pciIO uint64) (uint64, error) {
	var result uint64
	status := efiCall(
		pciIO+pciIOAttributes,
		pciIO,
		uint64(EFIPciIOAttributeOpGet),
		0, // Attributes (input) — unused for Get
		uint64(uintptr(unsafe.Pointer(&result))),
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "PciIO.Attributes (Get)"}
	}
	return result, nil
}

// PciIOGetBarAttributes returns the firmware's supported attribute
// bitmask + resource-descriptor list for the BAR. M1 prints the
// supported attribute mask only; the resource list is firmware-allocated
// and ignored for now (modest leak — see protocols_tamago.go for the
// same trade-off).
//
// EFI_PCI_IO_PROTOCOL.GetBarAttributes signature (UEFI 2.10 §13.4.15):
//
//	EFI_STATUS GetBarAttributes(
//	    IN  EFI_PCI_IO_PROTOCOL  *This,
//	    IN  UINT8                 BarIndex,
//	    OUT UINT64               *Supports OPTIONAL,
//	    OUT VOID                **Resources OPTIONAL );
//
// (4 args.)
func PciIOGetBarAttributes(pciIO uint64, barIndex uint8) (supports uint64, err error) {
	var supp uint64
	status := efiCall(
		pciIO+pciIOGetBarAttributes,
		pciIO,
		uint64(barIndex),
		uint64(uintptr(unsafe.Pointer(&supp))),
		0, // Resources OUT — discarded
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "PciIO.GetBarAttributes"}
	}
	return supp, nil
}
