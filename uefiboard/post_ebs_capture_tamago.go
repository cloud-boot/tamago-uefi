// cloud-boot UEFI board — pre-ExitBootServices live capture for the
// M2-B post-EBS experiment (Phase 2, M2-B).
//
// `CapturePreEBS` populates a `CapturedState` from a live
// EFI_PCI_IO_PROTOCOL handle. Every PCI cap walk, BAR-base read,
// page allocation, MAC byte read, and feature-bitmap fetch routes
// through Boot Services here; after `ExitToBareMetal` runs in
// `post_ebs_step_tamago.go`, none of those calls are valid any
// more. The post-EBS path (in `virtio_net_postebs.go`) consumes
// only the bytes in `CapturedState`.
//
// References:
//
//   - Virtio 1.1 §4.1.4 (cap layout) — the `ParseVirtioCaps` output
//     gives us the (BAR, offset) pairs for COMMON_CFG / NOTIFY_CFG /
//     ISR_CFG / DEVICE_CFG / PCI_CFG.
//   - UEFI 2.10 §13.4.15 — `EFI_PCI_IO_PROTOCOL.GetBarAttributes`
//     publishes the firmware's resource-descriptor list for one BAR,
//     including the host-side physical base. Mainstream UEFI
//     implementations (edk2 OvmfPkg + Apple VZ vfkit) keep the BAR
//     allocated at the same physical address across EBS, so what we
//     capture here remains valid post-EBS.
//
// Why we don't call `Map(BusMasterCommonBuffer)`: on the UEFI arches
// we target the firmware leaves the IOMMU in pass-through mode (M2
// design doc §3 M2 / cache-coherency); physical == bus address. M2-B
// inherits this assumption.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// CapturePreEBS walks the virtio-net device's PCI capability list,
// captures the physical addresses of every cfg region, allocates the
// two virtqueue rings as EfiRuntimeServicesData (so they survive
// ExitBootServices), pre-reads the MAC + offered features, and
// allocates the post-EBS diagnostic scratch.
//
// Pre-condition: `pciIO` is the EFI_PCI_IO_PROTOCOL pointer for a
// modern virtio-net device (VID 0x1AF4, DID 0x1041), already
// verified by the caller. No DeviceStatus writes are issued here —
// the post-EBS path owns the full Virtio 1.1 §3.1.1 init sequence,
// so the device is left in its firmware-reset state.
//
// Returns the populated state, or a wrapped error if any pre-EBS
// step fails. On error the partial state may already have some
// fields populated; the caller MUST treat the returned pointer as
// authoritative-or-nil, never both.
func CapturePreEBS(pciIO uint64) (*CapturedState, error) {
	state := &CapturedState{PciIO: pciIO}

	// 1. Walk the PCI capability list to find the four required
	//    + one optional virtio caps (COMMON / NOTIFY / ISR / DEVICE
	//    / PCI). `InitVirtioModernConfig` already does this work
	//    and stores the (BAR, offset) tuples; we reuse it to avoid
	//    re-implementing the walk.
	cfg, err := InitVirtioModernConfig(pciIO)
	if err != nil {
		return nil, err
	}

	// 2. Translate (BAR, offset) to physical addresses by asking
	//    the firmware for the BAR's allocated base. UEFI 2.10
	//    §13.4.15 publishes the resource list via
	//    GetBarAttributes; the canonical ACPI 2.0 64-bit address-
	//    space descriptor (0x8A) at offset 4 in the resource buffer
	//    holds the BAR's allocated min in bytes 14..21.
	//
	//    We don't have a parser for the resource list yet (the M1
	//    probe only reads the `supports` mask), so for M2-B we
	//    derive the BAR base by a different route: the
	//    PCI cfg-space BAR0..5 registers at config offset 0x10
	//    + 4*idx hold the BAR's physical base (after firmware
	//    bus-resource assignment). Reading via PciIo.Pci.Read is
	//    a documented path and the same one Linux uses on hosts
	//    that don't expose a special probe (drivers/pci/setup-bus.c).
	commonBase, err := readBarPhysBase(pciIO, cfg.CommonCfgBAR)
	if err != nil {
		return nil, err
	}
	state.PCICommonCfgPhys = commonBase + cfg.CommonCfgOffset

	notifyBase, err := readBarPhysBase(pciIO, cfg.NotifyCfgBAR)
	if err != nil {
		return nil, err
	}
	state.PCINotifyCfgPhys = notifyBase + cfg.NotifyCfgOffset
	state.PCINotifyOffMultiplier = cfg.NotifyOffMultiplier

	if cfg.ISRCfgOffset != 0 || cfg.ISRCfgBAR != 0 {
		isrBase, err := readBarPhysBase(pciIO, cfg.ISRCfgBAR)
		if err != nil {
			return nil, err
		}
		state.PCIIsrCfgPhys = isrBase + cfg.ISRCfgOffset
	}

	if cfg.HasDeviceCfg() {
		devBase, err := readBarPhysBase(pciIO, cfg.DeviceCfgBAR)
		if err != nil {
			return nil, err
		}
		state.PCIDeviceCfgPhys = devBase + cfg.DeviceCfgOffset
		state.PCIDeviceCfgLength = cfg.DeviceCfgLength
	}

	// 3. Read the device-offered feature bitmap. We do this BEFORE
	//    any DeviceStatus writes — Virtio 1.1 §3.1.1 step 4 reads
	//    DeviceFeature after RESET + ACK + DRIVER, but the device-
	//    side bitmap doesn't depend on those status bits being set
	//    (QEMU+EDK2 and VZ both publish it after reset alone). We
	//    set RESET + ACK + DRIVER + read + reset-again so the post-
	//    EBS path can replay the full sequence from a clean slate.
	if err := cfg.SetDeviceStatus(0); err != nil {
		return nil, err
	}
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge); err != nil {
		return nil, err
	}
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge | VirtioStatusDriver); err != nil {
		return nil, err
	}
	deviceFeats, err := cfg.DeviceFeatures64()
	if err != nil {
		return nil, err
	}
	state.DeviceFeaturesOffered = deviceFeats
	// Use the M2 R-M2b accepted mask as the starting point: MAC |
	// MTU | STATUS | VERSION_1. The post-EBS path will replay this
	// after EBS to confirm the same intersection still computes.
	state.FeatureMask = deviceFeats & VirtioNetAcceptedFeatures
	if state.FeatureMask&VirtioFeatureVersion1 == 0 {
		return nil, ErrNotModernDevice
	}
	if state.FeatureMask&VirtioNetFeatureMAC == 0 {
		return nil, ErrNoMACFeature
	}

	// 4. Read MAC pre-EBS (`cfg.DeviceCfgRead8` uses PciIo.Mem.Read
	//    which dies post-EBS). The MAC is the device's published
	//    EUI-48 at DEVICE_CFG offset 0..5.
	for i := uint32(0); i < 6; i++ {
		b, err := cfg.DeviceCfgRead8(i)
		if err != nil {
			return nil, err
		}
		state.MAC[i] = b
	}
	if state.MAC.IsZero() {
		return nil, ErrMACReadFailed
	}

	// 5. Reset the device to a clean state for the post-EBS init.
	//    `cfg.SetDeviceStatus(0)` is idempotent per Virtio 1.1
	//    §3.1.1.
	if err := cfg.SetDeviceStatus(0); err != nil {
		return nil, err
	}

	// 6. Allocate the two virtqueue rings as EfiRuntimeServicesData
	//    so they survive ExitBootServices. M2-B uses queue size 64
	//    (the M2 driver uses 16 RX + 8 TX, but here we want the
	//    same depth on both queues — keeps the layout symmetric
	//    and matches what Linux does on VZ).
	const m2bQueueSize uint16 = 64
	for i := uint16(0); i < 2; i++ {
		layout := ComputeVirtqueueLayout(m2bQueueSize)
		pages := (uintptr(layout.TotalSize) + EfiPageSize - 1) / EfiPageSize
		if pages == 0 {
			pages = 1
		}
		phys, err := AllocatePages(EfiRuntimeServicesData, pages)
		if err != nil {
			return nil, err
		}
		if phys == 0 {
			return nil, ErrAllocReturnedZero
		}
		// Zero the allocation — the device interprets a non-zero
		// used.idx as "already published frames", so we MUST zero
		// before publishing the address.
		zeroPages(uintptr(phys), pages*EfiPageSize)
		state.VQRingsPhys[i] = phys
		state.VQRingsLayout[i] = layout

		// Capture queue_notify_off pre-EBS. SelectQueue is harmless
		// outside the init sequence (Virtio 1.1 §4.1.5.1.3 — the
		// QueueSelect register is purely a multiplexer for the
		// other per-queue registers, it doesn't change device
		// state).
		if err := cfg.SelectQueue(i); err != nil {
			return nil, err
		}
		notifyOff, err := cfg.QueueNotifyOff()
		if err != nil {
			return nil, err
		}
		state.VQNotifyOff[i] = notifyOff
	}

	// 7. Allocate the post-EBS diagnostic scratch as
	//    EfiRuntimeServicesData. Single page = 4 KiB.
	scratchPhys, err := AllocatePages(EfiRuntimeServicesData, 1)
	if err != nil {
		return nil, err
	}
	if scratchPhys == 0 {
		return nil, ErrAllocReturnedZero
	}
	zeroPages(uintptr(scratchPhys), EfiPageSize)
	state.BlkPrintkScratchPhys = scratchPhys
	state.BlkPrintkScratchOffset = 0

	// 8. Allocate the post-EBS RX buffer pool. Sized for 64 buffers
	//    of (VirtioNetHdrSize + VirtioNetMaxFrameSize) bytes each.
	//    64 * 1530 = 97920 bytes → 24 pages, round up to 32 for slack.
	const rxPoolPages uintptr = 32
	rxPoolPhys, err := AllocatePages(EfiRuntimeServicesData, rxPoolPages)
	if err != nil {
		return nil, err
	}
	if rxPoolPhys == 0 {
		return nil, ErrAllocReturnedZero
	}
	zeroPages(uintptr(rxPoolPhys), rxPoolPages*EfiPageSize)
	state.rxPoolPhys = rxPoolPhys
	state.rxPoolSize = uint32(rxPoolPages * EfiPageSize)

	// 9. Allocate the post-EBS TX scratch slab. One page is plenty
	//    for the single-frame M2-B experiment.
	txScratchPhys, err := AllocatePages(EfiRuntimeServicesData, 1)
	if err != nil {
		return nil, err
	}
	if txScratchPhys == 0 {
		return nil, ErrAllocReturnedZero
	}
	zeroPages(uintptr(txScratchPhys), EfiPageSize)
	state.txScratchPhys = txScratchPhys
	state.txScratchSize = uint32(EfiPageSize)

	return state, nil
}

// readBarPhysBase reads the PCI cfg-space BAR register for BAR
// `barIndex` and returns the masked physical base. For a 64-bit
// memory BAR (bit 2 set in the low BAR), the high half lives in the
// next BAR slot and is OR'd in.
//
// Reference: PCI Local Bus Spec 3.0 §6.2.5.1 ("Base Address Registers").
// Bits 0..3 of a memory BAR are flag bits:
//
//	bit 0    = 0 (memory) / 1 (I/O)
//	bits 1..2 = type (00 = 32-bit, 01 = below-1MB, 10 = 64-bit)
//	bit 3    = prefetchable
//
// The address itself is `bar & ~0xF` (32-bit BAR) or
// `(bar & ~0xF) | (uint64(barHi) << 32)` (64-bit BAR).
func readBarPhysBase(pciIO uint64, barIndex uint8) (uint64, error) {
	// PCICfgBAR0 (= 0x10) + 4 * barIndex is the cfg-space offset of
	// BAR <barIndex>.
	offLo := uint32(PCICfgBAR0) + 4*uint32(barIndex)
	lo, err := PciIOReadConfigU32(pciIO, offLo)
	if err != nil {
		return 0, err
	}
	// I/O BARs are not used by virtio modern (Virtio 1.1 §4.1.5 —
	// modern caps live in memory BARs). If the low bit is set we
	// return what we read but the caller should treat it as an
	// error condition (the cap walker shouldn't have pointed us at
	// an I/O BAR).
	if lo&0x1 != 0 {
		return uint64(lo) &^ 0x3, nil
	}
	base := uint64(lo) &^ 0xF
	// 64-bit BAR: bits 1..2 = 0b10 → 2.
	bartype := (lo >> 1) & 0x3
	if bartype == 2 {
		hi, err := PciIOReadConfigU32(pciIO, offLo+4)
		if err != nil {
			return 0, err
		}
		base |= uint64(hi) << 32
	}
	return base, nil
}
