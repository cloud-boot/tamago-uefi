// cloud-boot UEFI board — Virtio modern (1.0+) PCI transport
// (Phase 2, M2).
//
// Host-buildable: no //go:build tamago directive. The COMMON_CFG /
// NOTIFY_CFG / ISR_CFG / DEVICE_CFG / PCI_CFG layout constants and the
// `VirtioModernConfig` struct that pins the per-capability (BAR,
// offset, length, notify_off_multiplier) tuples are all pure-data and
// host-testable. The live register accessors that issue `PciIo.Mem.Read
// / Write` calls live in `virtio_modern_tamago.go` (gated on `//go:build
// tamago`).
//
// References (cited at every layout/register decision below):
//
//   - Virtio 1.1 (committee specification 01, 2019-04-11), section
//     4.1.4 "Virtio Structure PCI Capabilities" — the cap_type tag
//     values + the `struct virtio_pci_cap` body that
//     `virtio_pci.go::WalkVirtioPCICaps` parses.
//   - Virtio 1.1 §4.1.5 "PCI-specific Initialization And Device
//     Operation" — the COMMON_CFG / NOTIFY_CFG / ISR_CFG / DEVICE_CFG
//     register layouts.
//   - Virtio 1.1 §4.1.5.1 "Common configuration structure layout":
//     the table of offsets we encode below as `virtioCfg*` constants.
//   - Virtio 1.1 §4.1.5.2 "Notification capability": defines the
//     per-queue notification address as
//         cap.offset + queue_notify_off * notify_off_multiplier.
//   - edk2.git OvmfPkg/VirtioPciDeviceDxe/VirtioPciDevice.c — EDK2's
//     own implementation of the same layout walk. Pattern reference,
//     not a code copy.
//   - Linux drivers/virtio/virtio_pci_modern.c — the canonical
//     Go-translatable reference; we follow its struct shape.

package uefiboard

import "errors"

// COMMON_CFG register offsets (Virtio 1.1 §4.1.5.1, table 4.1.5.1.1):
//
//	0x00  le32  device_feature_select
//	0x04  le32  device_feature        (read)
//	0x08  le32  driver_feature_select
//	0x0c  le32  driver_feature        (write)
//	0x10  le16  msix_config
//	0x12  le16  num_queues            (read)
//	0x14  u8    device_status
//	0x15  u8    config_generation     (read)
//	0x16  le16  queue_select
//	0x18  le16  queue_size
//	0x1a  le16  queue_msix_vector
//	0x1c  le16  queue_enable
//	0x1e  le16  queue_notify_off      (read)
//	0x20  le64  queue_desc
//	0x28  le64  queue_driver
//	0x30  le64  queue_device
//
// Total 56 bytes. `virtio_pci_test.go`'s ModernNet fixture uses
// `length=56` for the CommonCfg cap, matching this layout exactly.
const (
	VirtioCfgDeviceFeatureSelect uint64 = 0x00
	VirtioCfgDeviceFeature       uint64 = 0x04
	VirtioCfgDriverFeatureSelect uint64 = 0x08
	VirtioCfgDriverFeature       uint64 = 0x0c
	VirtioCfgMsixConfig          uint64 = 0x10
	VirtioCfgNumQueues           uint64 = 0x12
	VirtioCfgDeviceStatus        uint64 = 0x14
	VirtioCfgConfigGeneration    uint64 = 0x15
	VirtioCfgQueueSelect         uint64 = 0x16
	VirtioCfgQueueSize           uint64 = 0x18
	VirtioCfgQueueMsixVector     uint64 = 0x1a
	VirtioCfgQueueEnable         uint64 = 0x1c
	VirtioCfgQueueNotifyOff      uint64 = 0x1e
	VirtioCfgQueueDesc           uint64 = 0x20
	VirtioCfgQueueDriver         uint64 = 0x28
	VirtioCfgQueueDevice         uint64 = 0x30
)

// VirtioCfgCommonCfgSize is the minimum byte-length of a valid
// VIRTIO_PCI_CAP_COMMON_CFG region. QEMU+EDK2 reports `length=56`
// (= 0x38) on the modern virtio-net device; Apple VZ may report more
// (it does on the DEVICE_CFG cap per R-M1.6a, but the COMMON_CFG cap
// is fixed-size per the spec).
const VirtioCfgCommonCfgSize uint32 = 0x38

// DeviceStatus bits (Virtio 1.1 §2.1). The M2 init sequence is:
//
//	1. Write 0 to DeviceStatus (full reset).
//	2. Set ACKNOWLEDGE.
//	3. Set DRIVER.
//	4. Read DeviceFeature, mask down, write DriverFeature.
//	5. Set FEATURES_OK, re-read DeviceStatus, confirm FEATURES_OK.
//	6. Set up rxq + txq.
//	7. Set DRIVER_OK.
//
// Failure mode: FAILED bit set (firmware/device rejected our config).
const (
	VirtioStatusAcknowledge uint8 = 0x01
	VirtioStatusDriver      uint8 = 0x02
	VirtioStatusDriverOK    uint8 = 0x04
	VirtioStatusFeaturesOK  uint8 = 0x08
	VirtioStatusNeedsReset  uint8 = 0x40
	VirtioStatusFailed      uint8 = 0x80
)

// Virtio feature bits (Virtio 1.1 §6 "Reserved Feature Bits" +
// device-specific §5.1.3 "Network Device — Feature bits"). M2 accepts
// only what it strictly needs:
//
//	VIRTIO_NET_F_MAC      (5)   device-provided MAC (Virtio 1.1 §5.1.3)
//	VIRTIO_NET_F_MTU      (3)   device-provided MTU. Informational on
//	                            QEMU+EDK2 (always offered, no semantic
//	                            change in the driver path) but
//	                            REQUIRED by Apple VZ — without it VZ
//	                            clears FEATURES_OK and the init aborts
//	                            (R-M2b, RESOLVED 2026-06-07 by live
//	                            empirical narrow). M2 doesn't read the
//	                            `mtu` field — it sticks to the
//	                            default-MTU 1518-byte rxq buffer per
//	                            VirtioNetMaxFrameSize.
//	VIRTIO_NET_F_STATUS   (16)  link-up bit (informational; required for
//	                            the device to publish virtio_net_config.status)
//	VIRTIO_F_VERSION_1    (32)  modern transport (Virtio 1.1 §6) —
//	                            non-negotiable, the entire virtio-modern
//	                            layout depends on it.
//
// Other bits are not negotiated. If the device REQUIRES one we don't
// understand (FEATURES_OK won't stick), we surface a clear error.
const (
	VirtioNetFeatureMTU    uint64 = 1 << 3  // VIRTIO_NET_F_MTU
	VirtioNetFeatureMAC    uint64 = 1 << 5  // VIRTIO_NET_F_MAC
	VirtioNetFeatureStatus uint64 = 1 << 16 // VIRTIO_NET_F_STATUS
	VirtioFeatureVersion1  uint64 = 1 << 32 // VIRTIO_F_VERSION_1
	// VirtioFeatureRingPacked is VIRTIO_F_RING_PACKED (Virtio 1.1
	// §6 — bit 34). When acknowledged, the driver MUST use the
	// packed-virtqueue layout (Virtio 1.1 §2.7) for every queue;
	// the split-virtqueue layout (§2.6) is no longer in scope. M2-A
	// is the experiment that adds packed-ring support to test
	// whether VZ's TX path unblocks under this transport.
	VirtioFeatureRingPacked uint64 = 1 << 34 // VIRTIO_F_RING_PACKED
)

// VirtioModernConfig is the parsed, pre-located handle for one virtio
// modern device. It pins the (BAR, offset, length) tuples for each
// capability so the live register accessors don't have to re-walk the
// cap list. The `pciIO` field is the EFI_PCI_IO_PROTOCOL instance
// returned by HandleProtocol — every Mem.Read/Write goes through it.
//
// `notifyOffMultiplier` is read from the NOTIFY_CFG capability's
// trailing 4-byte field (Virtio 1.1 §4.1.4.4 — the extended
// `virtio_pci_notify_cap` is 20 bytes, not 16; the 4 bytes at offset
// 16 are the multiplier). The per-queue notification address is
//
//	notifyCap.Offset + queue_notify_off * notifyOffMultiplier
//
// where `queue_notify_off` comes from COMMON_CFG.QueueNotifyOff.
type VirtioModernConfig struct {
	// PciIO is the EFI_PCI_IO_PROTOCOL handle for the device. Pinned
	// here so the per-register accessors don't have to take it as an
	// extra parameter on every call.
	PciIO uint64

	// CommonCfg is the BAR + offset of the VIRTIO_PCI_CAP_COMMON_CFG
	// region. Length is guaranteed >= 56 by the spec; we don't store
	// it in the struct since every COMMON_CFG access is at a fixed
	// offset below 56.
	CommonCfgBAR    uint8
	CommonCfgOffset uint64

	// NotifyCfg is the BAR + offset of the VIRTIO_PCI_CAP_NOTIFY_CFG
	// region. NotifyOffMultiplier is the per-device multiplier read
	// from the extended cap (Virtio 1.1 §4.1.4.4).
	NotifyCfgBAR        uint8
	NotifyCfgOffset     uint64
	NotifyCfgLength     uint32
	NotifyOffMultiplier uint32

	// ISRCfg is the BAR + offset of the VIRTIO_PCI_CAP_ISR_CFG region.
	// 1 byte at this offset, holding the interrupt-status bits the
	// device publishes for polling (Virtio 1.1 §4.1.5.3).
	ISRCfgBAR    uint8
	ISRCfgOffset uint64

	// DeviceCfg is the BAR + offset of the VIRTIO_PCI_CAP_DEVICE_CFG
	// region. Length is stored because of R-M1.6a (VZ ships
	// length=17 vs QEMU's larger value, so the MAC-read bounds-check
	// is real).
	DeviceCfgBAR    uint8
	DeviceCfgOffset uint64
	DeviceCfgLength uint32

	// PCICfg is the BAR + offset of the VIRTIO_PCI_CAP_PCI_CFG region
	// (alternate cfg-access window). Optional; on devices that don't
	// publish it, the field is zero.
	PCICfgBAR    uint8
	PCICfgOffset uint64
}

// HasNotifyCfg reports whether NOTIFY_CFG was located (length > 0).
// An init sequence MUST have it; we surface this as a clear "no
// notify cap" error early.
func (c *VirtioModernConfig) HasNotifyCfg() bool { return c.NotifyCfgLength > 0 }

// HasDeviceCfg reports whether DEVICE_CFG was located.
func (c *VirtioModernConfig) HasDeviceCfg() bool { return c.DeviceCfgLength > 0 }

// PerQueueNotifyOffset returns the BAR-relative offset that the
// virtqueue's `notify` write must hit, given the device's
// `queue_notify_off` value (read from COMMON_CFG after queue select).
// Per Virtio 1.1 §4.1.4.4:
//
//	addr = notify_cap.offset + queue_notify_off * notify_off_multiplier
//
// Returned offset is BAR-relative; the caller turns it into an MMIO
// write via PciIOMemWrite16/32 at (NotifyCfgBAR, returned offset).
func (c *VirtioModernConfig) PerQueueNotifyOffset(queueNotifyOff uint16) uint64 {
	return c.NotifyCfgOffset + uint64(queueNotifyOff)*uint64(c.NotifyOffMultiplier)
}

// ErrNoCommonCfg is returned by ParseVirtioCaps if no
// VIRTIO_PCI_CAP_COMMON_CFG capability was found — the device is
// either legacy-only (Virtio 1.0 transitional with no modern caps) or
// the cap walker hit a malformed chain. Either way, M2's init
// sequence cannot proceed.
var ErrNoCommonCfg = errors.New("uefi: virtio modern: no VIRTIO_PCI_CAP_COMMON_CFG capability found")

// ErrCommonCfgTooShort is returned by ParseVirtioCaps if the
// COMMON_CFG capability's length is below `VirtioCfgCommonCfgSize`
// (= 56 bytes). The spec mandates >= 56; anything less is firmware-
// side malformed.
var ErrCommonCfgTooShort = errors.New("uefi: virtio modern: COMMON_CFG length < 56 (firmware malformed)")

// ErrNoNotifyCfg is returned if no VIRTIO_PCI_CAP_NOTIFY_CFG
// capability is found. Notification is required for any virtqueue
// activity; absence is fatal.
var ErrNoNotifyCfg = errors.New("uefi: virtio modern: no VIRTIO_PCI_CAP_NOTIFY_CFG capability found")

// ParseVirtioCaps converts the raw capability list (output of
// WalkVirtioPCICaps) into a `VirtioModernConfig` by locating each
// required capability and pinning its BAR + offset. The
// `notifyOffMultiplier` is NOT filled here — that requires reading 4
// bytes from PCI config space at notify_cap.CfgSpaceOffset+16, which
// is a live PciIo.Pci.Read; the live wrapper does that in
// `virtio_modern_tamago.go`.
//
// Errors:
//
//   - ErrNoCommonCfg: required COMMON_CFG capability missing.
//   - ErrCommonCfgTooShort: COMMON_CFG length < 56.
//   - ErrNoNotifyCfg: required NOTIFY_CFG capability missing.
//
// Optional caps (ISRCfg, DeviceCfg, PCICfg) leave the corresponding
// fields zero if absent; callers check HasDeviceCfg() / etc before
// reading them.
func ParseVirtioCaps(caps []VirtioPCICap) (*VirtioModernConfig, error) {
	cfg := &VirtioModernConfig{}
	for i := range caps {
		c := &caps[i]
		switch c.CfgType {
		case VirtioPCICapCommonCfg:
			if c.Length < VirtioCfgCommonCfgSize {
				return nil, ErrCommonCfgTooShort
			}
			cfg.CommonCfgBAR = c.BAR
			cfg.CommonCfgOffset = uint64(c.Offset)
		case VirtioPCICapNotifyCfg:
			cfg.NotifyCfgBAR = c.BAR
			cfg.NotifyCfgOffset = uint64(c.Offset)
			cfg.NotifyCfgLength = c.Length
		case VirtioPCICapISRCfg:
			cfg.ISRCfgBAR = c.BAR
			cfg.ISRCfgOffset = uint64(c.Offset)
		case VirtioPCICapDeviceCfg:
			cfg.DeviceCfgBAR = c.BAR
			cfg.DeviceCfgOffset = uint64(c.Offset)
			cfg.DeviceCfgLength = c.Length
		case VirtioPCICapPCICfg:
			cfg.PCICfgBAR = c.BAR
			cfg.PCICfgOffset = uint64(c.Offset)
		}
	}
	if cfg.CommonCfgOffset == 0 && cfg.CommonCfgBAR == 0 {
		// No COMMON_CFG seen at all (BAR=0 + offset=0 is the unset
		// pattern; legitimate COMMON_CFG offset is always >= a few
		// bytes into the BAR window).
		hasCommon := false
		for _, c := range caps {
			if c.CfgType == VirtioPCICapCommonCfg {
				hasCommon = true
				break
			}
		}
		if !hasCommon {
			return nil, ErrNoCommonCfg
		}
	}
	if cfg.NotifyCfgLength == 0 {
		return nil, ErrNoNotifyCfg
	}
	return cfg, nil
}

// VirtioPCICapNotifyExtraSize is the byte length of the extended
// `virtio_pci_notify_cap` (Virtio 1.1 §4.1.4.4) — 4 bytes beyond the
// standard 16-byte virtio_pci_cap header, holding the
// `notify_off_multiplier`.
const VirtioPCICapNotifyExtraSize = 4

// notifyOffMultiplierCfgOffset returns the PCI config-space byte
// offset of the `notify_off_multiplier` field for a NOTIFY_CFG cap
// found at `cfgSpaceOffset`. The standard `struct virtio_pci_cap` is
// 16 bytes; the extended notify variant adds 4 more at offset +16
// (Virtio 1.1 §4.1.4.4).
func notifyOffMultiplierCfgOffset(notifyCapCfgSpaceOffset uint8) uint32 {
	return uint32(notifyCapCfgSpaceOffset) + 16
}
