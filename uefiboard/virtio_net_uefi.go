// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// uefiboard ↔ go-virtio/net bridge: UEFI-flavoured `VirtioNet` /
// `VirtioModernConfig` / `Virtqueue` wrappers that keep cloud-boot's
// pre-migration call sites working.
//
// The underlying spec-level driver lives in github.com/go-virtio/net;
// the transport-agnostic config + virtqueue types live in
// github.com/go-virtio/common. This file glues them to the existing
// uefiboard API surface so phase2_virtionet_tx.go (a diagnostic narrow
// that reaches into `v.Cfg.PciIO` + `v.Cfg.NotifyCfgBAR` etc. by name)
// and ministack/link_tamago.go (an L2 adapter that wraps a
// `*uefiboard.VirtioNet`) compile unchanged.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"

	"github.com/go-virtio/common"
	virtionet "github.com/go-virtio/net"
)

// VirtioModernConfig wraps a `*common.ModernConfig` plus the UEFI
// `EFI_PCI_IO_PROTOCOL` interface pointer the live MMIO accessors need.
//
// All four required + one optional virtio capabilities live in the
// embedded common.ModernConfig; the `PciIO` field is the firmware-side
// handle the diagnostic narrows reach into (e.g.
// `PciIOAttributesGet(v.Cfg.PciIO)`).
type VirtioModernConfig struct {
	*common.ModernConfig

	// PciIO is the EFI_PCI_IO_PROTOCOL handle for the device.
	PciIO uint64
}

// VirtioNet wraps an initialised `*virtionet.VirtioNet` plus a
// reference to the UEFITransport so callers can reach back into the
// firmware-side primitives. The MAC + queue accessors mirror the
// pre-migration field layout.
type VirtioNet struct {
	// Cfg is the modern-transport handle (UEFI-flavoured wrapper around
	// `*common.ModernConfig`).
	Cfg *VirtioModernConfig

	// MAC is the device-published MAC address.
	MAC MAC6

	// NegotiatedFeatures records what the driver-feature handshake
	// settled on.
	NegotiatedFeatures uint64

	// vn is the underlying spec-level driver. Held so TransmitFrame /
	// ReceiveFrame forward through it.
	vn *virtionet.VirtioNet

	// transport is the UEFI transport adapter — the diagnostic narrows
	// reach into its PciIO field via `v.Cfg.PciIO`.
	transport *UEFITransport
}

// MAC6 aliases the go-virtio/net 6-byte MAC type — preserves the
// pre-migration uefiboard.MAC6 name.
type MAC6 = virtionet.MAC6

// Virtqueue aliases the go-virtio/common Virtqueue type.
type Virtqueue = common.Virtqueue

// VirtioNet feature-mask / queue-index / header-size re-exports.
const (
	VirtioNetHdrSize                  = virtionet.VirtioNetHdrSize
	VirtioNetRxQueueIdx               = virtionet.RxQueueIdx
	VirtioNetTxQueueIdx               = virtionet.TxQueueIdx
	VirtioNetMaxFrameSize             = virtionet.MaxFrameSize
)

// VirtioNetAcceptedFeatures preserves the pre-migration constant
// (MTU | MAC | STATUS | VERSION_1). Used by diagnostic prints.
const VirtioNetAcceptedFeatures = virtionet.AcceptedFeatures

// VirtioNetAcceptedFeaturesNarrow preserves the R-M2c narrow constant
// — "everything VZ offers except RING_PACKED". This is a diagnostic
// probe constant; production code MUST keep using VirtioNetAcceptedFeatures.
const VirtioNetAcceptedFeaturesNarrow uint64 = VirtioNetAcceptedFeatures |
	(1 << 0) | (1 << 1) |
	(1 << 7) | (1 << 8) |
	(1 << 11) | (1 << 12) |
	(1 << 28) | (1 << 29)

// VirtioNetFeatureMAC / MTU / Status — bit-mask re-exports.
const (
	VirtioNetFeatureMAC    = virtionet.FeatureMAC
	VirtioNetFeatureMTU    = virtionet.FeatureMTU
	VirtioNetFeatureStatus = virtionet.FeatureStatus
)

// VirtioFeatureVersion1 re-exports common.FeatureVersion1.
const VirtioFeatureVersion1 = common.FeatureVersion1

// DeviceStatus bit re-exports.
const (
	VirtioStatusAcknowledge = common.StatusAcknowledge
	VirtioStatusDriver      = common.StatusDriver
	VirtioStatusDriverOK    = common.StatusDriverOK
	VirtioStatusFeaturesOK  = common.StatusFeaturesOK
	VirtioStatusNeedsReset  = common.StatusNeedsReset
	VirtioStatusFailed      = common.StatusFailed
)

// VirtioNet sentinel-error re-exports (used by callers' error-formatting).
var (
	ErrTransmitTimeout   = virtionet.ErrTransmitTimeout
	ErrReceiveTimeout    = virtionet.ErrReceiveTimeout
	ErrInitWrongDeviceID = virtionet.ErrInitWrongDeviceID
	ErrFeaturesNotOK     = virtionet.ErrFeaturesNotOK
	ErrNotModernDevice   = virtionet.ErrNotModernDevice
	ErrNoMACFeature      = virtionet.ErrNoMACFeature
	ErrMACReadFailed     = virtionet.ErrMACReadFailed
	ErrQueueNotAvailable = virtionet.ErrQueueNotAvailable
)

// InitVirtioModernConfig is the UEFI-flavoured wrapper around
// `common.InitModernConfig`: it constructs a transport from the
// EFI_PCI_IO_PROTOCOL pointer and runs the common bring-up, then
// repackages the result so callers can still see the `PciIO` field
// they were reaching into pre-migration.
//
// Errors propagated:
//
//   - any *EFIError from PciIo.Pci.Read (config-space access failed).
//   - the cap-walker's ErrVirtioCapChainTooLong / ErrVirtioCapChainBadPtr.
//   - ErrNoCommonCfg / ErrNoNotifyCfg / ErrCommonCfgTooShort.
//   - ErrCapListBitUnset (the device is legacy-only).
func InitVirtioModernConfig(pciIO uint64) (*VirtioModernConfig, error) {
	t := NewUEFITransport(pciIO)
	mc, err := common.InitModernConfig(t)
	if err != nil {
		return nil, err
	}
	return &VirtioModernConfig{ModernConfig: mc, PciIO: pciIO}, nil
}

// OpenVirtioNet drives the full bring-up of one virtio-net device.
// Constructs a UEFITransport, calls virtionet.OpenVirtioNet, and
// repackages the result with the UEFI-flavoured Cfg wrapper.
func OpenVirtioNet(pciIO uint64) (*VirtioNet, error) {
	return OpenVirtioNetWithFeatures(pciIO, VirtioNetAcceptedFeatures)
}

// OpenVirtioNetWithFeatures is the parameterised variant.
func OpenVirtioNetWithFeatures(pciIO uint64, acceptedFeatures uint64) (*VirtioNet, error) {
	// Defensive PCI bus-master + memory enable — preserved from the
	// pre-migration code path. EFI_PCI_IO_PROTOCOL.Attributes(Enable,
	// Memory | BusMaster) asserts the BME bit so the device's DMA can
	// flow. Live narrow R-M2c established both QEMU+EDK2 and Apple VZ
	// pre-enable these bits at firmware bind time so this is observed
	// as a no-op; kept as a defensive guard for hypothetical future
	// firmware that doesn't pre-enable.
	if err := PciIOAttributesEnable(pciIO, EFIPciIOAttributeMemory|EFIPciIOAttributeBusMaster); err != nil {
		return nil, err
	}
	t := NewUEFITransport(pciIO)
	vn, err := virtionet.OpenVirtioNetWithFeatures(t, acceptedFeatures)
	if err != nil {
		return nil, err
	}
	return &VirtioNet{
		Cfg:                &VirtioModernConfig{ModernConfig: vn.Cfg, PciIO: pciIO},
		MAC:                vn.MAC,
		NegotiatedFeatures: vn.NegotiatedFeatures,
		vn:                 vn,
		transport:          t,
	}, nil
}

// TransmitFrame forwards to the underlying spec-level driver.
func (v *VirtioNet) TransmitFrame(frame []byte) error { return v.vn.TransmitFrame(frame) }

// ReceiveFrame forwards to the underlying spec-level driver.
func (v *VirtioNet) ReceiveFrame(pollIterations int) ([]byte, error) {
	return v.vn.ReceiveFrame(pollIterations)
}

// RxQueue exposes the RX virtqueue handle.
func (v *VirtioNet) RxQueue() *Virtqueue { return v.vn.RxQueue() }

// TxQueue exposes the TX virtqueue handle.
func (v *VirtioNet) TxQueue() *Virtqueue { return v.vn.TxQueue() }

// AllocDMABuffer allocates a single page-aligned chunk for use as a
// device-DMA-visible buffer (e.g. for the R-M2c diagnostic narrow's
// hand-rolled transmit path). Returns (phys, host-virtual addr, err).
//
// On every UEFI arch we target the physical address returned is also
// a usable Go-side pointer while still in Boot Services (identity-mapped).
func AllocDMABuffer(size uintptr) (phys uint64, addr uintptr, err error) {
	if size == 0 {
		return 0, 0, ErrAllocReturnedZero
	}
	pages := (size + EfiPageSize - 1) / EfiPageSize
	phys, err = AllocatePages(EfiBootServicesData, pages)
	if err != nil {
		return 0, 0, err
	}
	if phys == 0 {
		return 0, 0, ErrAllocReturnedZero
	}
	addr = uintptr(phys)
	// Zero the allocation.
	mem := unsafe.Slice((*byte)(unsafe.Pointer(addr)), int(pages*EfiPageSize))
	for i := range mem {
		mem[i] = 0
	}
	return phys, addr, nil
}
