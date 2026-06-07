// Host-side tests for pci_io_protocol.go.
//
// Two things this layer can get wrong: a GUID typo, and a function-
// pointer offset typo. Both are silent failures at runtime — the GUID
// mismatch makes LocateHandleBuffer return 0 handles ("no PCI devices"
// — looks like a missing-protocol bug, not a typo); a wrong offset
// makes efiCall jump to whatever lives at the wrong slot, almost
// certainly a fault. So this file's purpose is to make both classes
// impossible to ship.

package uefiboard

import (
	"encoding/binary"
	"testing"
)

func TestEFIPciIOProtocolGUID_RoundTrip(t *testing.T) {
	// Canonical text per MdePkg/Include/Protocol/PciIo.h (edk2.git
	// stable/202408):
	//   #define EFI_PCI_IO_PROTOCOL_GUID \
	//     { 0x4cf5b200, 0x68b8, 0x4ca5, \
	//       { 0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a } }
	const text = "4cf5b200-68b8-4ca5-9eec-b23e3f50029a"
	expect := guidFromText(t, text)
	got := EFIPciIOProtocolGUID
	if got != expect {
		t.Fatalf("EFIPciIOProtocolGUID mismatch:\n got    = %+v\n expect = %+v", got, expect)
	}
}

// TestEFIPciIOProtocolGUID_WireLayout verifies the exact 16-byte wire
// layout that LocateHandleBuffer sees when we pass &GUID. The
// firmware compares byte-for-byte; any endianness slip is a silent
// no-match.
func TestEFIPciIOProtocolGUID_WireLayout(t *testing.T) {
	g := EFIPciIOProtocolGUID
	var wire [16]byte
	binary.LittleEndian.PutUint32(wire[0:4], g.Data1)
	binary.LittleEndian.PutUint16(wire[4:6], g.Data2)
	binary.LittleEndian.PutUint16(wire[6:8], g.Data3)
	copy(wire[8:], g.Data4[:])
	// Expected bytes for {0x4cf5b200, 0x68b8, 0x4ca5,
	//                     {0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a}}
	// on the wire (little-endian mixed convention).
	expect := [16]byte{
		0x00, 0xb2, 0xf5, 0x4c, // Data1 little-endian
		0xb8, 0x68, // Data2 little-endian
		0xa5, 0x4c, // Data3 little-endian
		0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a, // Data4 raw
	}
	if wire != expect {
		t.Fatalf("EFIPciIOProtocolGUID wire layout wrong:\n got    = % x\n expect = % x", wire, expect)
	}
}

// TestPciIO_FunctionPointerOffsets pins the every-slot offset table
// against the documented PciIo.h struct layout. The offset values are
// derived: 16-slot fn-ptr table (8 bytes each, with the
// EFI_PCI_IO_PROTOCOL_ACCESS sub-structs flattened to 2 consecutive
// fn ptrs).
func TestPciIO_FunctionPointerOffsets(t *testing.T) {
	cases := []struct {
		name   string
		got    int
		expect int
	}{
		{"PollMem", pciIOPollMem, 0},
		{"PollIo", pciIOPollIo, 8},
		{"Mem.Read", pciIOMemRead, 16},
		{"Mem.Write", pciIOMemWrite, 24},
		{"Io.Read", pciIOIoRead, 32},
		{"Io.Write", pciIOIoWrite, 40},
		{"Pci.Read", pciIOPciRead, 48},
		{"Pci.Write", pciIOPciWrite, 56},
		{"CopyMem", pciIOCopyMem, 64},
		{"Map", pciIOMap, 72},
		{"Unmap", pciIOUnmap, 80},
		{"AllocateBuffer", pciIOAllocateBuffer, 88},
		{"FreeBuffer", pciIOFreeBuffer, 96},
		{"Flush", pciIOFlush, 104},
		{"GetLocation", pciIOGetLocation, 112},
		{"Attributes", pciIOAttributes, 120},
		{"GetBarAttributes", pciIOGetBarAttributes, 128},
		{"SetBarAttributes", pciIOSetBarAttributes, 136},
	}
	for _, c := range cases {
		if c.got != c.expect {
			t.Errorf("offset %s = %d, want %d", c.name, c.got, c.expect)
		}
	}
}

// TestPciIO_AttributeOpsAreContiguous pins the AttributeOperation enum
// to its spec values. Off-by-one here means PciIOAttributesGet sends
// the wrong opcode and the firmware either fails outright or returns
// junk.
func TestPciIO_AttributeOpsAreContiguous(t *testing.T) {
	cases := []struct {
		name string
		op   EFIPciIOAttributeOperation
		want uint32
	}{
		{"Get", EFIPciIOAttributeOpGet, 0},
		{"Set", EFIPciIOAttributeOpSet, 1},
		{"Enable", EFIPciIOAttributeOpEnable, 2},
		{"Disable", EFIPciIOAttributeOpDisable, 3},
		{"Supported", EFIPciIOAttributeOpSupported, 4},
	}
	for _, c := range cases {
		if uint32(c.op) != c.want {
			t.Errorf("attribute op %s = %d, want %d", c.name, uint32(c.op), c.want)
		}
	}
}

// TestPciIO_WidthValues pins the PCI IO width enum. M1 uses Uint8/16/32
// for config-space reads.
func TestPciIO_WidthValues(t *testing.T) {
	cases := []struct {
		name string
		w    EFIPciIOWidth
		want uint32
	}{
		{"Uint8", EFIPciIOWidthUint8, 0},
		{"Uint16", EFIPciIOWidthUint16, 1},
		{"Uint32", EFIPciIOWidthUint32, 2},
		{"Uint64", EFIPciIOWidthUint64, 3},
		{"FifoUint8", EFIPciIOWidthFifoUint8, 4},
	}
	for _, c := range cases {
		if uint32(c.w) != c.want {
			t.Errorf("width %s = %d, want %d", c.name, uint32(c.w), c.want)
		}
	}
}

// TestPciIO_ConfigSpaceOffsets pins the PCI config-space byte offsets
// the probe uses. These come from the PCI Local Bus Specification 3.0
// §6.2 (configuration space header — Type 0).
func TestPciIO_ConfigSpaceOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"VendorID", PCICfgVendorID, 0x00},
		{"DeviceID", PCICfgDeviceID, 0x02},
		{"Command", PCICfgCommand, 0x04},
		{"Status", PCICfgStatus, 0x06},
		{"RevisionID", PCICfgRevisionID, 0x08},
		{"ClassCode", PCICfgClassCode, 0x09},
		{"HeaderType", PCICfgHeaderType, 0x0e},
		{"BAR0", PCICfgBAR0, 0x10},
		{"SubsystemVID", PCICfgSubsystemVID, 0x2c},
		{"SubsystemID", PCICfgSubsystemID, 0x2e},
		{"CapabilitiesPtr", PCICfgCapabilitiesPtr, 0x34},
		{"InterruptLine", PCICfgInterruptLine, 0x3c},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("offset %s = 0x%02x, want 0x%02x", c.name, c.got, c.want)
		}
	}
}

// TestPciIO_StatusBits pins the few PCI Status-register bits the M1
// probe interprets (currently just CapabilityList = bit 4 = 0x0010).
func TestPciIO_StatusBits(t *testing.T) {
	if PCIStatusCapabilityList != 0x0010 {
		t.Errorf("PCIStatusCapabilityList = 0x%04x, want 0x0010", PCIStatusCapabilityList)
	}
	if PCICapIDVendorSpecific != 0x09 {
		t.Errorf("PCICapIDVendorSpecific = 0x%02x, want 0x09", PCICapIDVendorSpecific)
	}
}

// TestPciIO_AttributeBitmasks does a soft sanity-check on the
// attribute bitmask constants — the M1 probe doesn't yet use them,
// but M2 will, and a typo here is silent.
func TestPciIO_AttributeBitmasks(t *testing.T) {
	cases := []struct {
		name string
		bit  uint64
		want uint64
	}{
		{"ISA-MotherboardIO", EFIPciIOAttributeIsaMotherboardIO, 0x0001},
		{"IO", EFIPciIOAttributeIO, 0x0100},
		{"Memory", EFIPciIOAttributeMemory, 0x0200},
		{"BusMaster", EFIPciIOAttributeBusMaster, 0x0400},
		{"MemoryDisable", EFIPciIOAttributeMemoryDisable, 0x1000},
	}
	for _, c := range cases {
		if c.bit != c.want {
			t.Errorf("attribute %s = 0x%04x, want 0x%04x", c.name, c.bit, c.want)
		}
	}
}
