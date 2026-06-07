// cloud-boot UEFI board — Virtio modern transport: live config bring-up
// (Phase 2, M2).
//
// Two-layer setup that builds on the host-buildable `virtio_modern.go`:
//
//   1. `InitVirtioModernConfig(pciIO)` walks the PCI capability list
//      via PciIo.Pci.Read (the M1 path), parses the four required +
//      one optional virtio capabilities, fetches the
//      notify_off_multiplier from the extended NOTIFY_CFG cap, and
//      returns a `*VirtioModernConfig` keyed by the pciIO handle.
//
//   2. The per-COMMON_CFG-register accessors below route through
//      PciIo.Mem.Read/Write (the M2 path in `pci_mem_io.go`) against
//      (CommonCfgBAR, CommonCfgOffset + reg_offset). These are the
//      primitives the M2 init sequence (`virtio_net.go::Open`) calls.
//
// Reference: Virtio 1.1 §4.1.4 (cap layout) + §4.1.5.1 (COMMON_CFG
// register table) + §4.1.5.2 (notify cap extension). EDK2's
// OvmfPkg/VirtioPciDeviceDxe/VirtioPciDevice.c does the same walk
// pattern; we mirror its sequence (not its code).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// InitVirtioModernConfig drives the full modern-transport setup for
// one virtio device:
//
//  1. Read PCI Status and confirm bit 4 (CapabilityList) is set.
//  2. Read the CapabilitiesPtr at config offset 0x34.
//  3. Walk the cap list via `WalkVirtioPCICaps` with PciIo-backed
//     readers (the same readers `phase2_pcienum.go` uses in M1).
//  4. Pass the resulting `[]VirtioPCICap` to `ParseVirtioCaps`.
//  5. If NOTIFY_CFG was found, read the 4-byte
//     `notify_off_multiplier` from cfg-space at NotifyCfg's
//     CfgSpaceOffset + 16.
//
// Returns the populated `*VirtioModernConfig` or a wrapped error.
//
// Errors propagated:
//
//   - any *EFIError from PciIo.Pci.Read (config-space access failed).
//   - the cap-walker's `ErrVirtioCapChainTooLong` /
//     `ErrVirtioCapChainBadPtr` (malformed chain).
//   - `ErrNoCommonCfg`, `ErrNoNotifyCfg`, `ErrCommonCfgTooShort`
//     (required cap missing or malformed; M2 cannot proceed).
//   - the dedicated `ErrCapListBitUnset` (the device is legacy-only
//     and has no modern caps at all).
func InitVirtioModernConfig(pciIO uint64) (*VirtioModernConfig, error) {
	// Status[CapList] check (Virtio 1.1 §4.1.4 first sentence — modern
	// devices always set this bit).
	status, err := PciIOReadConfigU16(pciIO, PCICfgStatus)
	if err != nil {
		return nil, err
	}
	if status&PCIStatusCapabilityList == 0 {
		return nil, ErrCapListBitUnset
	}
	capPtr, err := PciIOReadConfigU8(pciIO, PCICfgCapabilitiesPtr)
	if err != nil {
		return nil, err
	}

	// Cap-list walker — same readers M1's pcienum probe uses.
	readU8 := func(off uint8) (uint8, error) {
		return PciIOReadConfigU8(pciIO, uint32(off))
	}
	readU32 := func(off uint8) (uint32, error) {
		return PciIOReadConfigU32(pciIO, uint32(off))
	}
	caps, walkErr := WalkVirtioPCICaps(capPtr, readU8, readU32)
	if walkErr != nil && len(caps) == 0 {
		// Hard fail only if we got nothing — partial chains still
		// usable (the standard COMMON_CFG/NOTIFY_CFG/DEVICE_CFG live
		// early in the list on QEMU and VZ both).
		return nil, walkErr
	}

	cfg, err := ParseVirtioCaps(caps)
	if err != nil {
		return nil, err
	}
	cfg.PciIO = pciIO

	// Read the extended notify_off_multiplier from PCI config space.
	// Locate the NotifyCfg cap's CfgSpaceOffset so we know where to
	// read +16.
	for i := range caps {
		c := &caps[i]
		if c.CfgType != VirtioPCICapNotifyCfg {
			continue
		}
		// Sanity check the cap_len: extended notify cap is 20 bytes
		// per Virtio 1.1 §4.1.4.4 (16-byte header + 4-byte multiplier).
		// Some legacy/transitional devices ship a 16-byte
		// NOTIFY_CFG with no multiplier; treat that as
		// multiplier=0 (every queue notifies at the same offset).
		if c.Len < 16+VirtioPCICapNotifyExtraSize {
			cfg.NotifyOffMultiplier = 0
			break
		}
		mult, err := PciIOReadConfigU32(pciIO, notifyOffMultiplierCfgOffset(c.CfgSpaceOffset))
		if err != nil {
			return nil, err
		}
		cfg.NotifyOffMultiplier = mult
		break
	}

	return cfg, nil
}

// ErrCapListBitUnset is returned by InitVirtioModernConfig if PCI
// Status[CapList] (bit 4) is unset, indicating a legacy-only device
// with no modern cap chain. M2 cannot drive a legacy device through
// PciIo.Mem.Read/Write because legacy uses I/O-port BAR layouts, not
// memory BARs (Virtio 1.1 §4.1.5 first sentence vs §4.2.4).
var ErrCapListBitUnset = vpciError("uefi: virtio modern: PCI Status[CapList] bit unset (legacy-only device)")

// --- COMMON_CFG register accessors ---------------------------------
//
// All COMMON_CFG accesses route through `PciIoMemRead/Write` against
// (CommonCfgBAR, CommonCfgOffset + reg_offset). The register offsets
// come from `virtio_modern.go::VirtioCfg*` constants.

// ReadDeviceFeatureSelect / WriteDeviceFeatureSelect drive the feature
// negotiation iterator. The driver writes a select value (0 or 1) and
// then reads DeviceFeature for the corresponding 32-bit half (low or
// high) of the 64-bit feature bitmap.
func (c *VirtioModernConfig) ReadDeviceFeatureSelect() (uint32, error) {
	return PciIOMemRead32(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDeviceFeatureSelect)
}
func (c *VirtioModernConfig) WriteDeviceFeatureSelect(v uint32) error {
	return PciIOMemWrite32(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDeviceFeatureSelect, v)
}
func (c *VirtioModernConfig) ReadDeviceFeature() (uint32, error) {
	return PciIOMemRead32(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDeviceFeature)
}
func (c *VirtioModernConfig) WriteDriverFeatureSelect(v uint32) error {
	return PciIOMemWrite32(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDriverFeatureSelect, v)
}
func (c *VirtioModernConfig) WriteDriverFeature(v uint32) error {
	return PciIOMemWrite32(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDriverFeature, v)
}

// DeviceFeatures64 / SetDriverFeatures64 read/write the full 64-bit
// feature bitmap in two 32-bit halves, hiding the select+read dance.
func (c *VirtioModernConfig) DeviceFeatures64() (uint64, error) {
	if err := c.WriteDeviceFeatureSelect(0); err != nil {
		return 0, err
	}
	lo, err := c.ReadDeviceFeature()
	if err != nil {
		return 0, err
	}
	if err := c.WriteDeviceFeatureSelect(1); err != nil {
		return 0, err
	}
	hi, err := c.ReadDeviceFeature()
	if err != nil {
		return 0, err
	}
	return uint64(lo) | uint64(hi)<<32, nil
}

func (c *VirtioModernConfig) SetDriverFeatures64(v uint64) error {
	if err := c.WriteDriverFeatureSelect(0); err != nil {
		return err
	}
	if err := c.WriteDriverFeature(uint32(v & 0xFFFFFFFF)); err != nil {
		return err
	}
	if err := c.WriteDriverFeatureSelect(1); err != nil {
		return err
	}
	return c.WriteDriverFeature(uint32(v >> 32))
}

// DeviceStatus / SetDeviceStatus drive the init-sequence state
// machine.
func (c *VirtioModernConfig) DeviceStatus() (uint8, error) {
	return PciIOMemRead8(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDeviceStatus)
}
func (c *VirtioModernConfig) SetDeviceStatus(v uint8) error {
	return PciIOMemWrite8(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgDeviceStatus, v)
}

// NumQueues returns the device's maximum supported queue count
// (Virtio 1.1 §4.1.5.1). For virtio-net this is at least 2 (rxq +
// txq); modern multi-queue devices return higher.
func (c *VirtioModernConfig) NumQueues() (uint16, error) {
	return PciIOMemRead16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgNumQueues)
}

// ConfigGeneration returns the device's configuration-generation
// counter (Virtio 1.1 §2.4.1). Used to detect device-cfg races; M2
// doesn't poll on the link-up bit so we never need it for live
// driving, but the M2 probe reads it once for diagnostics.
func (c *VirtioModernConfig) ConfigGeneration() (uint8, error) {
	return PciIOMemRead8(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgConfigGeneration)
}

// SelectQueue selects which virtqueue subsequent register accesses
// target (Virtio 1.1 §4.1.5.1.3). MUST be called before any
// QueueSize/QueueDesc/QueueDriver/QueueDevice/QueueEnable read or
// write.
func (c *VirtioModernConfig) SelectQueue(idx uint16) error {
	return PciIOMemWrite16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueSelect, idx)
}

// QueueSize returns the device's current size for the selected queue
// (the device's maximum capability; the driver MAY write a smaller
// power-of-two value).
func (c *VirtioModernConfig) QueueSize() (uint16, error) {
	return PciIOMemRead16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueSize)
}

// SetQueueSize writes the driver's chosen queue size. MUST be a
// power of two and <= the device's reported max.
func (c *VirtioModernConfig) SetQueueSize(v uint16) error {
	return PciIOMemWrite16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueSize, v)
}

// QueueNotifyOff returns the per-queue notification offset (Virtio
// 1.1 §4.1.4.4). The driver computes the BAR-relative notification
// address as `NotifyCfgOffset + queue_notify_off *
// NotifyOffMultiplier` and writes the queue index to it on every
// notify.
func (c *VirtioModernConfig) QueueNotifyOff() (uint16, error) {
	return PciIOMemRead16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueNotifyOff)
}

// SetQueueDesc / SetQueueDriver / SetQueueDevice publish the
// per-queue physical addresses to the device (Virtio 1.1 §4.1.5.1).
// All three are 64-bit; we write them with one PciIo.Mem.Write
// Width=Uint64 per spec — see pci_mem_io.go::PciIOMemWrite64 for the
// rationale.
func (c *VirtioModernConfig) SetQueueDesc(addr uint64) error {
	return PciIOMemWrite64(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueDesc, addr)
}
func (c *VirtioModernConfig) SetQueueDriver(addr uint64) error {
	return PciIOMemWrite64(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueDriver, addr)
}
func (c *VirtioModernConfig) SetQueueDevice(addr uint64) error {
	return PciIOMemWrite64(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueDevice, addr)
}

// SetQueueEnable writes 1 to QueueEnable (Virtio 1.1 §4.1.5.1.3) —
// the device starts servicing the queue.
func (c *VirtioModernConfig) SetQueueEnable(v uint16) error {
	return PciIOMemWrite16(c.PciIO, c.CommonCfgBAR, c.CommonCfgOffset+VirtioCfgQueueEnable, v)
}

// NotifyQueue writes the queue index to the per-queue notification
// address (Virtio 1.1 §4.1.4.4). The write is a 16-bit MMIO; the
// notify cap is the BAR window the device is listening on.
func (c *VirtioModernConfig) NotifyQueue(queueIdx uint16, queueNotifyOff uint16) error {
	addr := c.PerQueueNotifyOffset(queueNotifyOff)
	return PciIOMemWrite16(c.PciIO, c.NotifyCfgBAR, addr, queueIdx)
}

// DeviceCfgRead8 reads one byte from the device-specific config
// region with R-M1.6a bounds-check. Returns 0 + a sentinel error if
// the offset is outside the region the device published.
//
// Used by virtio-net to read MAC bytes (Virtio 1.1 §5.1.4 — 6 bytes
// at offset 0). On Apple VZ the device-cfg length is 17 bytes
// (matches at least the MAC + status + max_virtqueue_pairs + a byte
// of padding); on QEMU it's longer.
func (c *VirtioModernConfig) DeviceCfgRead8(offset uint32) (uint8, error) {
	if !c.HasDeviceCfg() {
		return 0, ErrNoDeviceCfg
	}
	if offset >= c.DeviceCfgLength {
		return 0, ErrDeviceCfgOutOfBounds
	}
	return PciIOMemRead8(c.PciIO, c.DeviceCfgBAR, c.DeviceCfgOffset+uint64(offset))
}

// ErrNoDeviceCfg / ErrDeviceCfgOutOfBounds are sentinels surfaced by
// DeviceCfgRead8 when the device doesn't ship a DEVICE_CFG cap or
// when the caller asked for a byte past the spec'd length (R-M1.6a).
var (
	ErrNoDeviceCfg          = vpciError("uefi: virtio modern: device has no VIRTIO_PCI_CAP_DEVICE_CFG")
	ErrDeviceCfgOutOfBounds = vpciError("uefi: virtio modern: device-cfg read past published length (R-M1.6a bounds-check)")
)
