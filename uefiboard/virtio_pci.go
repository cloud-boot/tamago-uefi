// cloud-boot UEFI board — Virtio PCI constants + capability walker
// (Phase 2, M1).
//
// Host-buildable: no //go:build tamago directive. The capability walker
// takes a "read u8 at offset" callback rather than driving an
// EFI_PCI_IO_PROTOCOL handle directly, so the host test can exercise
// it against a synthetic config-space buffer (see virtio_pci_test.go).
//
// References (read before changing constants):
//
//   - Virtio 1.1 spec (committee specification 01, 2019-04-11),
//     section 4.1 "Virtio Over PCI Bus":
//       * §4.1.2.1 "PCI Device Discovery" — vendor/device IDs.
//       * §4.1.4 "Virtio Structure PCI Capabilities" — cap layout.
//   - Virtio 1.1 spec §5.1 "Network Device" — virtio-net specific.
//   - OvmfPkg/VirtioNetDxe/VirtioNet.h (edk2.git) — EDK2's own walk
//     of the same capability chain. Pattern reference, not a code copy.

package uefiboard

// Virtio PCI vendor ID. All transitional and modern virtio devices
// publish PCI vendor 0x1AF4 (assigned by Red Hat to Qumranet for
// virtio). Reference: Virtio 1.1 §4.1.2.1.
const VirtioPCIVendorID uint16 = 0x1AF4

// Virtio PCI device IDs. The legacy range (0x1000..0x103F) and the
// modern (1.0+) range (0x1040..0x107F) are disjoint. Device-type T is
// encoded as `0x1040 + T` in the modern range. For T=1 (network), that
// gives 0x1041 modern + 0x1000 legacy.
//
// Reference: Virtio 1.1 §4.1.2.1 "PCI Device Discovery".
const (
	VirtioPCIDeviceIDLegacyNet uint16 = 0x1000
	VirtioPCIDeviceIDModernNet uint16 = 0x1041
)

// VirtioDeviceTypeNet is the modern device-type encoding for virtio-net
// (Virtio 1.1 §5.1 introduction). Used here for documentation only —
// the probe matches on DeviceID directly.
const VirtioDeviceTypeNet uint16 = 1

// VirtioPCIDeviceIDIsNet reports whether a PCI DeviceID identifies a
// virtio-net device (legacy 0x1000 OR modern 0x1041). The other
// legacy DIDs (0x1001 block, 0x1002 console, ...) are not net devices
// even though they share vendor 0x1AF4.
func VirtioPCIDeviceIDIsNet(deviceID uint16) bool {
	return deviceID == VirtioPCIDeviceIDLegacyNet || deviceID == VirtioPCIDeviceIDModernNet
}

// VirtioPCIDeviceIDIsModern reports whether a DeviceID is in the modern
// (1.0+) range (0x1040..0x107F). Legacy devices use the 0x1000..0x103F
// range and have a different PCI capability shape.
func VirtioPCIDeviceIDIsModern(deviceID uint16) bool {
	return deviceID >= 0x1040 && deviceID <= 0x107F
}

// VIRTIO_PCI_CAP_* constants — the cfg_type field at offset +3 of a
// virtio PCI capability (Virtio 1.1 §4.1.4):
//
//	struct virtio_pci_cap {
//	    u8 cap_vndr;     // PCI cap ID, always 0x09 (vendor-specific)
//	    u8 cap_next;     // next-pointer (PCI cap-list link)
//	    u8 cap_len;      // sizeof(struct virtio_pci_cap), >= 16
//	    u8 cfg_type;     // VIRTIO_PCI_CAP_* (one of the constants below)
//	    u8 bar;          // BAR index containing this structure
//	    u8 id;           // multiple-capability disambiguator
//	    u8 padding[2];
//	    le32 offset;     // offset within `bar`
//	    le32 length;     // length of the structure
//	};
const (
	VirtioPCICapCommonCfg     uint8 = 1 // common configuration
	VirtioPCICapNotifyCfg     uint8 = 2 // notifications
	VirtioPCICapISRCfg        uint8 = 3 // ISR access
	VirtioPCICapDeviceCfg     uint8 = 4 // device-specific config
	VirtioPCICapPCICfg        uint8 = 5 // PCI configuration access
	VirtioPCICapSharedMemCfg  uint8 = 8 // 1.1 addition: shared mem
	VirtioPCICapVendorCfg     uint8 = 9 // 1.1 addition: vendor-specific
)

// VirtioPCICapHeaderSize is the minimum cap_len. Capabilities of every
// cfg_type fit in 16 bytes for the common/notify/ISR/device/PCI-cfg
// kinds; SharedMem and VendorCfg can be larger but M1 doesn't walk
// into those bodies.
const VirtioPCICapHeaderSize = 16

// VirtioPCICap is the parsed Go view of `struct virtio_pci_cap`. Stored
// as direct fields (no pointer to a config-space view) so the host
// tests can hand-build instances.
type VirtioPCICap struct {
	// CapID is always 0x09 (vendor-specific). Stored only so the
	// walker's caller can sanity-check.
	CapID uint8

	// Next is the PCI cap-list link byte (config-space offset of the
	// next capability, or 0 to terminate). Stored for debugging.
	Next uint8

	// Len is the cap_len byte; values < 16 are spec-violating.
	Len uint8

	// CfgType is one of the VirtioPCICap* constants above. The walker
	// returns all of them and the caller filters.
	CfgType uint8

	// BAR is the PCI BAR index containing this structure (0..5).
	BAR uint8

	// ID disambiguates multiple capabilities of the same CfgType
	// (e.g. two device-cfg structures on a single transitional
	// device). The probe ignores it for M1.
	ID uint8

	// Offset is the byte offset within BAR of this structure.
	Offset uint32

	// Length is the byte length of the structure inside BAR.
	Length uint32

	// CfgSpaceOffset is the config-space offset where this capability
	// header sits (not part of the spec'd virtio_pci_cap struct — the
	// walker fills it in for diagnostic prints).
	CfgSpaceOffset uint8
}

// ReadU8At is the byte-reader callback signature for
// WalkVirtioPCICaps. The callback returns (value, error); a non-nil
// error short-circuits the walk and is returned to the caller.
type ReadU8At func(offset uint8) (uint8, error)

// ReadU32At is the 32-bit reader callback used for the cap's offset
// and length fields (Virtio 1.1 §4.1.4: both are le32 within the
// 16-byte cap body). Implementations on real hardware route through
// EFI_PCI_IO_PROTOCOL.Pci.Read width=Uint32; the test uses a synthetic
// byte buffer.
type ReadU32At func(offset uint8) (uint32, error)

// MaxVirtioCapsToWalk caps the cap-list walk so a malformed (cyclic
// or self-referential) cap chain doesn't hang the probe. The PCI spec
// allows at most 48 capabilities in the 192-byte device-specific
// config area; 64 is generous.
const MaxVirtioCapsToWalk = 64

// WalkVirtioPCICaps walks the PCI capability linked list starting at
// `firstCapOffset`, returning every entry whose CapID is 0x09
// (vendor-specific). The walk reads:
//
//	+0  CapID (UINT8)
//	+1  Next  (UINT8)         — caller's responsibility to follow
//	+2  cap_len (UINT8)
//	+3  cfg_type (UINT8)
//	+4  bar (UINT8)
//	+5  id (UINT8)
//	+6  padding (UINT8 x2)
//	+8  offset (LE UINT32)
//	+12 length (LE UINT32)
//
// Non-vendor capabilities (CapID != 0x09) are skipped — the walker
// just follows their Next pointer. A Next of 0 terminates the walk.
//
// `readU8` reads single bytes from config space; `readU32` reads 32
// bits at the given offset, little-endian (every UEFI arch we target
// is little-endian — see memorymap.go for the same assumption).
//
// On read error, returns the partial result + the error so the caller
// can still print what it managed to enumerate. On a malformed chain
// (cycle or Next pointing outside the standard cap area), returns
// ErrVirtioCapChainTooLong.
func WalkVirtioPCICaps(firstCapOffset uint8, readU8 ReadU8At, readU32 ReadU32At) ([]VirtioPCICap, error) {
	if firstCapOffset == 0 {
		// Status[CapList] was set but the pointer is 0 — empty list.
		// Spec-violating but harmless; treat as "no virtio caps".
		return nil, nil
	}
	var out []VirtioPCICap
	off := firstCapOffset
	for i := 0; i < MaxVirtioCapsToWalk; i++ {
		if off == 0 {
			return out, nil
		}
		// PCI cap-list pointers MUST land in the standard config-space
		// area (0x40..0xFF). A value < 0x40 is a malformed firmware.
		if off < 0x40 {
			return out, ErrVirtioCapChainBadPtr
		}
		capID, err := readU8(off + 0)
		if err != nil {
			return out, err
		}
		next, err := readU8(off + 1)
		if err != nil {
			return out, err
		}
		if capID != PCICapIDVendorSpecific {
			// Not a virtio capability; follow the link without
			// emitting anything.
			off = next
			continue
		}
		// Vendor-specific: read the rest of the 16-byte cap header.
		clen, err := readU8(off + 2)
		if err != nil {
			return out, err
		}
		cfgType, err := readU8(off + 3)
		if err != nil {
			return out, err
		}
		bar, err := readU8(off + 4)
		if err != nil {
			return out, err
		}
		id, err := readU8(off + 5)
		if err != nil {
			return out, err
		}
		offset32, err := readU32(off + 8)
		if err != nil {
			return out, err
		}
		length32, err := readU32(off + 12)
		if err != nil {
			return out, err
		}
		out = append(out, VirtioPCICap{
			CapID:          capID,
			Next:           next,
			Len:            clen,
			CfgType:        cfgType,
			BAR:            bar,
			ID:             id,
			Offset:         offset32,
			Length:         length32,
			CfgSpaceOffset: off,
		})
		off = next
	}
	return out, ErrVirtioCapChainTooLong
}

// VirtioPCICapsByType returns the first capability in `caps` whose
// CfgType matches, or nil. M1's probe uses this to locate the
// VIRTIO_PCI_CAP_DEVICE_CFG capability before reading the device-
// specific MAC.
func VirtioPCICapsByType(caps []VirtioPCICap, cfgType uint8) *VirtioPCICap {
	for i := range caps {
		if caps[i].CfgType == cfgType {
			return &caps[i]
		}
	}
	return nil
}

// VirtioNetCfgOffsetMAC / Status / MaxVirtqueuePairs / MTU are the
// device-specific config offsets for the virtio-net device
// (Virtio 1.1 §5.1.4 "Device configuration layout"):
//
//	struct virtio_net_config {
//	    u8 mac[6];                 // offset 0
//	    le16 status;               // offset 6
//	    le16 max_virtqueue_pairs;  // offset 8
//	    le16 mtu;                  // offset 10
//	    // ... 1.1 additions
//	};
//
// All addresses are relative to the start of the
// VIRTIO_PCI_CAP_DEVICE_CFG region's `offset` within its BAR.
const (
	VirtioNetCfgOffsetMAC                 uint32 = 0
	VirtioNetCfgOffsetStatus              uint32 = 6
	VirtioNetCfgOffsetMaxVirtqueuePairs   uint32 = 8
	VirtioNetCfgOffsetMTU                 uint32 = 10
)

// VirtioMACLen is the byte length of the virtio-net MAC field
// (Virtio 1.1 §5.1.4 — 6 bytes, IEEE 802.3 EUI-48).
const VirtioMACLen = 6

// Errors for the cap walker. Sentinel values; stable across Go
// revisions per the package's `errors.New` convention.
var (
	ErrVirtioCapChainTooLong = vpciError("uefi: virtio PCI cap-list walk exceeded MaxVirtioCapsToWalk (likely cyclic)")
	ErrVirtioCapChainBadPtr  = vpciError("uefi: virtio PCI cap-list pointer < 0x40 (outside standard config-space)")
)

// vpciError is a tiny sentinel-error type, mirroring the `errors.New`
// shape memorymap.go uses. Kept local so virtio_pci.go has no errors
// package dep (host-buildable without the stdlib pull-in cost).
type vpciError string

func (e vpciError) Error() string { return string(e) }
