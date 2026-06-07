// cloud-boot UEFI board — EFI_PCI_IO_PROTOCOL type surface (Phase 2, M1).
//
// Pure type + GUID + offset surface for EFI_PCI_IO_PROTOCOL (UEFI 2.10
// §13.4). Host-buildable: no //go:build tamago directive, so the
// GUID-roundtrip + offset assertions can run under host `go test`. The
// live call thunks live in pci_io_protocol_tamago.go.
//
// Upstream reference (read before changing layouts):
//
//   - MdePkg/Include/Protocol/PciIo.h (edk2.git stable/202408)
//   - UEFI 2.10 §13.4 (EFI_PCI_IO_PROTOCOL definition)
//   - UEFI 2.10 §13.2 (PCI Root Bridge IO Protocol — referenced for
//     resource-descriptor formats used by GetBarAttributes).
//
// M1 scope: virtio-net device DISCOVERY + IDENTITY only. The protocol's
// function table has 16 slots; M1 uses Pci.Read, GetLocation,
// Attributes, GetBarAttributes. M2 wires Mem.Read/Write + Map/Unmap.
//
// Why a separate file (not folded into protocols_tamago.go): the GUID
// and the function-pointer offsets are host-testable; the call thunks
// require efiCall which only exists under //go:build tamago.

package uefiboard

// EFI_PCI_IO_PROTOCOL_GUID
//
//	4cf5b200-68b8-4ca5-9eec-b23e3f50029a
//
// Source: MdePkg/Include/Protocol/PciIo.h (edk2.git).
var EFIPciIOProtocolGUID = EFIGUID{
	Data1: 0x4cf5b200,
	Data2: 0x68b8,
	Data3: 0x4ca5,
	Data4: [8]uint8{0x9e, 0xec, 0xb2, 0x3e, 0x3f, 0x50, 0x02, 0x9a},
}

// EFI_PCI_IO_PROTOCOL function-pointer offsets.
//
// The protocol struct is laid out as:
//
//	struct _EFI_PCI_IO_PROTOCOL {
//	    EFI_PCI_IO_PROTOCOL_POLL_IO_MEM             PollMem;        // 0
//	    EFI_PCI_IO_PROTOCOL_POLL_IO_MEM             PollIo;         // 8
//	    EFI_PCI_IO_PROTOCOL_ACCESS                  Mem;            // 16  (two 8-byte fn ptrs: Read, Write)
//	    EFI_PCI_IO_PROTOCOL_ACCESS                  Io;             // 32
//	    EFI_PCI_IO_PROTOCOL_CONFIG_ACCESS           Pci;            // 48  (two 8-byte fn ptrs: Read, Write)
//	    EFI_PCI_IO_PROTOCOL_COPY_MEM                CopyMem;        // 64
//	    EFI_PCI_IO_PROTOCOL_MAP                     Map;            // 72
//	    EFI_PCI_IO_PROTOCOL_UNMAP                   Unmap;          // 80
//	    EFI_PCI_IO_PROTOCOL_ALLOCATE_BUFFER         AllocateBuffer; // 88
//	    EFI_PCI_IO_PROTOCOL_FREE_BUFFER             FreeBuffer;     // 96
//	    EFI_PCI_IO_PROTOCOL_FLUSH                   Flush;          // 104
//	    EFI_PCI_IO_PROTOCOL_GET_LOCATION            GetLocation;    // 112
//	    EFI_PCI_IO_PROTOCOL_ATTRIBUTES              Attributes;     // 120
//	    EFI_PCI_IO_PROTOCOL_GET_BAR_ATTRIBUTES      GetBarAttributes;// 128
//	    EFI_PCI_IO_PROTOCOL_SET_BAR_ATTRIBUTES      SetBarAttributes;// 136
//	    UINT64                                      RomSize;        // 144
//	    VOID                                       *RomImage;       // 152
//	};
//
// All function-pointer slots are sizeof(void*) on a 64-bit UEFI image.
// PciIoAccess is two consecutive fn ptrs (Read at +0, Write at +8), so
// the Read entry sits directly at the struct offset and the Write
// entry sits at offset + 8.
const (
	pciIOPollMem            = 0
	pciIOPollIo             = 8
	pciIOMemRead            = 16
	pciIOMemWrite           = 24
	pciIOIoRead             = 32
	pciIOIoWrite            = 40
	pciIOPciRead            = 48
	pciIOPciWrite           = 56
	pciIOCopyMem            = 64
	pciIOMap                = 72
	pciIOUnmap              = 80
	pciIOAllocateBuffer     = 88
	pciIOFreeBuffer         = 96
	pciIOFlush              = 104
	pciIOGetLocation        = 112
	pciIOAttributes         = 120
	pciIOGetBarAttributes   = 128
	pciIOSetBarAttributes   = 136
)

// EFI_PCI_IO_PROTOCOL_WIDTH (UEFI 2.10 §13.4.2). Used by the Pci/Mem/Io
// Read/Write accessors. We only need the FIFO-uint variants for M1
// (config-space reads at a fixed offset, no auto-increment).
type EFIPciIOWidth uint32

const (
	EFIPciIOWidthUint8     EFIPciIOWidth = 0
	EFIPciIOWidthUint16    EFIPciIOWidth = 1
	EFIPciIOWidthUint32    EFIPciIOWidth = 2
	EFIPciIOWidthUint64    EFIPciIOWidth = 3
	EFIPciIOWidthFifoUint8 EFIPciIOWidth = 4
	// ... 12 more values; M1 doesn't use them.
)

// EFI_PCI_IO_PROTOCOL_ATTRIBUTE_OPERATION (UEFI 2.10 §13.4.13). The M1
// probe reads attributes only; M2's queue init will use Enable.
type EFIPciIOAttributeOperation uint32

const (
	EFIPciIOAttributeOpGet EFIPciIOAttributeOperation = 0
	EFIPciIOAttributeOpSet EFIPciIOAttributeOperation = 1
	EFIPciIOAttributeOpEnable  EFIPciIOAttributeOperation = 2
	EFIPciIOAttributeOpDisable EFIPciIOAttributeOperation = 3
	EFIPciIOAttributeOpSupported EFIPciIOAttributeOperation = 4
)

// EFI_PCI_IO_ATTRIBUTE_* attribute bitmask (UEFI 2.10 §13.4.13 table).
// Only the bits M1+M2 might inspect are named; the full set is in
// PciIo.h.
const (
	EFIPciIOAttributeIsaMotherboardIO uint64 = 0x0001
	EFIPciIOAttributeIsaIO            uint64 = 0x0002
	EFIPciIOAttributeVGAPaletteIO     uint64 = 0x0004
	EFIPciIOAttributeVGAMemory        uint64 = 0x0008
	EFIPciIOAttributeVGAIO            uint64 = 0x0010
	EFIPciIOAttributeIDEPrimaryIO     uint64 = 0x0020
	EFIPciIOAttributeIDESecondaryIO   uint64 = 0x0040
	EFIPciIOAttributeMemoryWriteCombine uint64 = 0x0080
	EFIPciIOAttributeIO                  uint64 = 0x0100
	EFIPciIOAttributeMemory              uint64 = 0x0200
	EFIPciIOAttributeBusMaster           uint64 = 0x0400
	EFIPciIOAttributeMemoryCached        uint64 = 0x0800
	EFIPciIOAttributeMemoryDisable       uint64 = 0x1000
)

// EFI_PCI_IO_PROTOCOL_GET_LOCATION returns the per-instance
// (Segment, Bus, Device, Function) tuple. M1 prints these in the probe
// for diagnostics; M2 doesn't need them once the per-instance
// EFI_PCI_IO_PROTOCOL pointer is in hand.
type PciLocation struct {
	Segment  uint64 // PCI segment number
	Bus      uint64 // PCI bus number on segment
	Device   uint64 // PCI device number on bus
	Function uint64 // PCI function number on device
}

// PCI config-space layout: standard header (Type 0) — bytes 0..63 —
// followed by 192 bytes of device-specific config (64..255) when
// Status[CapList] is set. The Type 0 header offsets we use in M1:
//
//	0x00  Vendor ID (UINT16)
//	0x02  Device ID (UINT16)
//	0x04  Command   (UINT16)
//	0x06  Status    (UINT16)
//	0x08  Revision ID (UINT8) + Class Code [3]UINT8
//	0x0c  Cache Line Size, Latency Timer, Header Type, BIST
//	0x10  BAR0..BAR5 (six UINT32, ending at 0x28)
//	0x2c  Subsystem Vendor ID (UINT16)
//	0x2e  Subsystem Device ID (UINT16)
//	0x34  Capabilities Pointer (UINT8) — valid iff Status[CapList=bit4]
//	0x3c  Interrupt Line, Interrupt Pin
const (
	PCICfgVendorID         = 0x00
	PCICfgDeviceID         = 0x02
	PCICfgCommand          = 0x04
	PCICfgStatus           = 0x06
	PCICfgRevisionID       = 0x08
	PCICfgClassCode        = 0x09 // [3]UINT8: ProgIF/SubClass/BaseClass
	PCICfgHeaderType       = 0x0e
	PCICfgBAR0             = 0x10
	PCICfgSubsystemVID     = 0x2c
	PCICfgSubsystemID      = 0x2e
	PCICfgCapabilitiesPtr  = 0x34
	PCICfgInterruptLine    = 0x3c
)

// PCI_STATUS_CAPABILITY_LIST is bit 4 of the Status register
// (PCI Local Bus Specification 3.0 §6.2.3). When set, the Capabilities
// Pointer at 0x34 is valid and points at the first capability in a
// linked list within config space.
const PCIStatusCapabilityList uint16 = 0x0010

// PCI_CAP_ID_VENDOR_SPECIFIC = 0x09 (PCI Local Bus Specification 3.0
// Appendix H). All Virtio PCI capabilities use this ID.
const PCICapIDVendorSpecific uint8 = 0x09

// PCICapabilityHeader is the first two bytes of any PCI capability
// (PCI Local Bus Specification 3.0 §6.7):
//
//	0x00  CapID  (UINT8)
//	0x01  Next   (UINT8) — config-space offset of the next capability
//	              (0 = end of list).
type PCICapabilityHeader struct {
	CapID uint8
	Next  uint8
}
