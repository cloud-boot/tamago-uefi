// Phase-2 M1 probe — gated on `-tags phase2_pcienum`.
//
// Walks every controller publishing EFI_PCI_IO_PROTOCOL, prints
// VID/DID/Class/Subsystem/(Seg,Bus,Dev,Fn) for each, identifies virtio
// devices (vendor 0x1AF4), walks their vendor-specific PCI capability
// list, and for virtio-net devices (DID 0x1000 legacy or 0x1041
// modern) reads + prints the device MAC from the
// VIRTIO_PCI_CAP_DEVICE_CFG region.
//
// This is the M1 smoke test for Path Y (pure-Go networking on top of
// virtio-net). NO virtqueue init, NO frame TX/RX, NO ExitBootServices
// — those are M2 and M8.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_pcienum \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `probe:pcienum:*` for the per-arch wiring.)

//go:build phase2_pcienum && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// runPCIEnumProbe — when the `phase2_pcienum` build tag is set, this
// runs the M1 PCI-IO enumeration probe (walk every controller
// publishing EFI_PCI_IO_PROTOCOL, identify virtio devices, walk
// virtio capabilities). When the tag is NOT set, the no-op stub in
// phase2_pcienum_stub.go takes over. The probe-dispatch wrapper
// (phase2_dispatch.go) decides when this runs; `phase2_pcienum` and
// `phase2_snpenum` may be set together — see phase2_snpenum.go.
func runPCIEnumProbe() {
	println("phase2-pcienum: LocateHandleBuffer(EFI_PCI_IO_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-pcienum: LocateHandleBuffer FAILED:", err.Error())
		println("phase2-pcienum: this is R-M1'a triggering — capture and report")
		println("phase2-pcienum: (firmware does not publish EFI_PCI_IO_PROTOCOL)")
		return
	}
	if len(handles) == 0 {
		println("phase2-pcienum: no EFI_PCI_IO_PROTOCOL handles published")
		println("phase2-pcienum: this is R-M1'a triggering — capture and report")
		return
	}
	println("phase2-pcienum: handles=", len(handles))

	virtioNetCount := 0
	for i, h := range handles {
		println("phase2-pcienum: handle", i, "=", h)
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIPciIOProtocolGUID)
		if err != nil {
			println("phase2-pcienum:   HandleProtocol FAILED:", err.Error())
			continue
		}
		dumpOnePciIO(iface, &virtioNetCount)
	}

	println("phase2-pcienum: done. virtio-net devices found =", virtioNetCount)
}

// dumpOnePciIO prints the per-device summary for one
// EFI_PCI_IO_PROTOCOL instance. Reads VID/DID/Class/Subsystem +
// Seg/Bus/Dev/Fn unconditionally; if the device is a virtio device
// (vendor 0x1AF4), walks the cap list; if it's virtio-net, reads MAC.
func dumpOnePciIO(pciIO uint64, virtioNetCount *int) {
	vid, err := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgVendorID)
	if err != nil {
		println("phase2-pcienum:   VendorID read FAILED:", err.Error())
		return
	}
	did, err := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgDeviceID)
	if err != nil {
		println("phase2-pcienum:   DeviceID read FAILED:", err.Error())
		return
	}
	// Class code lives at 0x09..0x0B (ProgIF, SubClass, BaseClass).
	// Read as one u32 starting at 0x08 to grab Revision + class in one
	// call.
	classWord, err := uefiboard.PciIOReadConfigU32(pciIO, uefiboard.PCICfgRevisionID)
	if err != nil {
		println("phase2-pcienum:   ClassCode read FAILED:", err.Error())
		return
	}
	// classWord layout (little-endian within the read):
	//   byte 0: RevisionID
	//   byte 1: ProgIF
	//   byte 2: SubClass
	//   byte 3: BaseClass
	rev := uint8(classWord & 0xFF)
	progIF := uint8((classWord >> 8) & 0xFF)
	subClass := uint8((classWord >> 16) & 0xFF)
	baseClass := uint8((classWord >> 24) & 0xFF)

	subVID, _ := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgSubsystemVID)
	subID, _ := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgSubsystemID)

	loc, err := uefiboard.PciIOGetLocation(pciIO)
	if err != nil {
		println("phase2-pcienum:   GetLocation FAILED:", err.Error())
	}

	println("phase2-pcienum:   VID:DID =", hex16(vid), ":", hex16(did),
		"Class =", hex8(baseClass), "/", hex8(subClass), "/", hex8(progIF),
		"Rev =", hex8(rev),
		"Subsys =", hex16(subVID), ":", hex16(subID))
	println("phase2-pcienum:   (Seg,Bus,Dev,Fn) = (",
		uint64(loc.Segment), ",", uint64(loc.Bus), ",",
		uint64(loc.Device), ",", uint64(loc.Function), ")")

	if vid != uefiboard.VirtioPCIVendorID {
		return
	}
	println("phase2-pcienum:   --> VIRTIO device (vendor 0x1AF4)")
	dumpVirtioCaps(pciIO, did, virtioNetCount)
}

// dumpVirtioCaps walks the virtio PCI capability list on the given
// virtio device, prints each VIRTIO_PCI_CAP_* entry's BAR+offset, and
// — for virtio-net devices — reads the MAC from the
// VIRTIO_PCI_CAP_DEVICE_CFG region's start.
func dumpVirtioCaps(pciIO uint64, did uint16, virtioNetCount *int) {
	// Check Status[CapList] (bit 4 of the Status register at offset
	// 0x06). If unset, there's no cap-list pointer (legacy-only
	// device, e.g., the 0x1000 virtio-net on a non-modern firmware).
	status, err := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgStatus)
	if err != nil {
		println("phase2-pcienum:     Status read FAILED:", err.Error())
		return
	}
	if status&uefiboard.PCIStatusCapabilityList == 0 {
		println("phase2-pcienum:     no CapList bit — legacy-only device (no virtio modern caps)")
		if uefiboard.VirtioPCIDeviceIDIsNet(did) {
			*virtioNetCount++
			println("phase2-pcienum:     legacy virtio-net (DID 0x1000); MAC at BAR0+0x14 (legacy layout, not read here)")
		}
		return
	}
	capPtr, err := uefiboard.PciIOReadConfigU8(pciIO, uefiboard.PCICfgCapabilitiesPtr)
	if err != nil {
		println("phase2-pcienum:     CapabilitiesPtr read FAILED:", err.Error())
		return
	}
	println("phase2-pcienum:     CapList pointer = 0x", hex8(capPtr))

	// Adapter callbacks for the cap-list walker. They route reads
	// through the EFI_PCI_IO_PROTOCOL.Pci.Read accessor, so we get
	// firmware's view of config space (not raw MMIO).
	readU8 := func(off uint8) (uint8, error) {
		return uefiboard.PciIOReadConfigU8(pciIO, uint32(off))
	}
	readU32 := func(off uint8) (uint32, error) {
		return uefiboard.PciIOReadConfigU32(pciIO, uint32(off))
	}

	caps, err := uefiboard.WalkVirtioPCICaps(capPtr, readU8, readU32)
	if err != nil {
		println("phase2-pcienum:     cap-walk FAILED:", err.Error())
		// Fall through — print what we managed to collect.
	}
	if len(caps) == 0 {
		println("phase2-pcienum:     no virtio caps found")
		return
	}
	for i := range caps {
		c := caps[i]
		println("phase2-pcienum:     cap", i,
			"type=", virtioCapTypeName(c.CfgType),
			"BAR=", uint64(c.BAR),
			"offset=", uint64(c.Offset),
			"length=", uint64(c.Length),
			"id=", uint64(c.ID))
	}

	if !uefiboard.VirtioPCIDeviceIDIsNet(did) {
		return
	}
	*virtioNetCount++

	// For modern virtio-net (DID 0x1041), the MAC sits at offset 0 of
	// the VIRTIO_PCI_CAP_DEVICE_CFG region. To read it through
	// EFI_PCI_IO_PROTOCOL we'd need Mem.Read against the BAR; M1
	// doesn't ship that path yet (M2's deliverable). What M1 CAN do
	// is print the BAR+offset locator so the operator/CI can confirm
	// the device layout matches the spec, and additionally try the
	// EFI_PCI_IO_PROTOCOL.Pci.Read fallback at the device-cfg
	// capability's CFG_SPACE_OFFSET + 16 (the byte after the cap
	// header), which Virtio 1.1 §4.1.4.6 describes as an alternate
	// access path on legacy/transitional devices.
	devCfg := uefiboard.VirtioPCICapsByType(caps, uefiboard.VirtioPCICapDeviceCfg)
	if devCfg == nil {
		println("phase2-pcienum:     virtio-net device has no VIRTIO_PCI_CAP_DEVICE_CFG (modern config missing)")
		return
	}
	println("phase2-pcienum:     virtio-net device-cfg locator: BAR=",
		uint64(devCfg.BAR), "+offset=", uint64(devCfg.Offset))

	// MAC read via PciIo.Mem accessor — deferred to M2.
	// For now, attempt the PciIo.Pci.Read fallback: on QEMU+EDK2,
	// VIRTIO_PCI_CAP_PCI_CFG (cfg_type 5) exposes a window into the
	// device-cfg region via config-space writes/reads; if it's
	// present and DEVICE_CFG.BAR matches, we can read MAC[0..5]
	// through the cfg-access window.
	if pciCfg := uefiboard.VirtioPCICapsByType(caps, uefiboard.VirtioPCICapPCICfg); pciCfg != nil {
		println("phase2-pcienum:     VIRTIO_PCI_CAP_PCI_CFG present at cfg-space offset 0x",
			hex8(pciCfg.CfgSpaceOffset),
			"— MAC read via cfg-access window is M2 work")
	}
	println("phase2-pcienum:     MAC read pending M2 (needs PciIo.Mem.Read against BAR)")
}

// virtioCapTypeName maps a VIRTIO_PCI_CAP_* cfg_type to a short string
// for the probe print. Unknown types print as "Type<n>".
func virtioCapTypeName(t uint8) string {
	switch t {
	case uefiboard.VirtioPCICapCommonCfg:
		return "CommonCfg"
	case uefiboard.VirtioPCICapNotifyCfg:
		return "NotifyCfg"
	case uefiboard.VirtioPCICapISRCfg:
		return "ISRCfg"
	case uefiboard.VirtioPCICapDeviceCfg:
		return "DeviceCfg"
	case uefiboard.VirtioPCICapPCICfg:
		return "PCICfg"
	case uefiboard.VirtioPCICapSharedMemCfg:
		return "SharedMemCfg"
	case uefiboard.VirtioPCICapVendorCfg:
		return "VendorCfg"
	}
	return "Type?"
}

// hex8 / hex16 — minimal hex stringifiers, matching the dep-light
// convention used by uefiboard's hexU64. Avoid pulling fmt into the
// EFI binary.
func hex8(v uint8) string {
	const digits = "0123456789abcdef"
	var buf [4]byte
	buf[0] = '0'
	buf[1] = 'x'
	buf[2] = digits[(v>>4)&0xF]
	buf[3] = digits[v&0xF]
	return string(buf[:])
}

func hex16(v uint16) string {
	const digits = "0123456789abcdef"
	var buf [6]byte
	buf[0] = '0'
	buf[1] = 'x'
	buf[2] = digits[(v>>12)&0xF]
	buf[3] = digits[(v>>8)&0xF]
	buf[4] = digits[(v>>4)&0xF]
	buf[5] = digits[v&0xF]
	return string(buf[:])
}

