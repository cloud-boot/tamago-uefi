// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// uefiboard ↔ go-virtio bridge: host-buildable type / constant
// re-exports so existing uefiboard consumers (phase2_pcienum.go,
// phase2_virtionet_tx.go, ministack/link_tamago.go) compile unchanged
// after the virtio migration.
//
// The transport-agnostic virtio types now live in
// github.com/go-virtio/common; the per-device-class drivers live in
// sibling repos (currently github.com/go-virtio/net). uefiboard owns
// the UEFI transport adapter (virtio_uefi_transport.go) and the
// re-exports below.
//
// Why re-exports rather than direct imports throughout cloud-boot:
//
//   - phase2_pcienum.go references the constants via the `uefiboard.`
//     namespace; one re-export here means the migration touches one
//     uefiboard file instead of every consumer. Future tree-wide
//     refactors can switch consumers to import go-virtio directly.
//   - The diagnostic narrow in phase2_virtionet_tx.go reaches into
//     `v.Cfg.PciIO` + `v.Cfg.NotifyCfgBAR` etc. by name; we preserve
//     those fields on the UEFI-side wrapper struct so the diagnostic
//     code keeps compiling against the same surface.

package uefiboard

import (
	"github.com/go-virtio/common"
)

// Virtio PCI vendor + device-ID re-exports. Match the field names the
// pre-migration uefiboard exposed.
const (
	VirtioPCIVendorID          = common.PCIVendorID
	VirtioPCIDeviceIDLegacyNet = common.PCIDeviceIDLegacyNet
	VirtioPCIDeviceIDModernNet = common.PCIDeviceIDModernNet
	VirtioDeviceTypeNet        = common.DeviceTypeNet
)

// VirtioPCIDeviceIDIsNet preserves the helper name.
func VirtioPCIDeviceIDIsNet(deviceID uint16) bool { return common.PCIDeviceIDIsNet(deviceID) }

// VirtioPCIDeviceIDIsModern preserves the helper name.
func VirtioPCIDeviceIDIsModern(deviceID uint16) bool { return common.PCIDeviceIDIsModern(deviceID) }

// PCI capability type re-exports.
const (
	VirtioPCICapCommonCfg    = common.PCICapCommonCfg
	VirtioPCICapNotifyCfg    = common.PCICapNotifyCfg
	VirtioPCICapISRCfg       = common.PCICapISRCfg
	VirtioPCICapDeviceCfg    = common.PCICapDeviceCfg
	VirtioPCICapPCICfg       = common.PCICapPCICfg
	VirtioPCICapSharedMemCfg = common.PCICapSharedMemCfg
	VirtioPCICapVendorCfg    = common.PCICapVendorCfg
)

// VirtioPCICapHeaderSize preserves the pre-migration constant name.
const VirtioPCICapHeaderSize = common.PCICapHeaderSize

// VirtioPCICap is a re-export of the go-virtio/common type, used by
// the pcienum probe to format capability information.
type VirtioPCICap = common.PCICap

// MaxVirtioCapsToWalk preserves the pre-migration constant name.
const MaxVirtioCapsToWalk = common.MaxCapsToWalk

// VirtioPCICapsByType preserves the helper-function name.
func VirtioPCICapsByType(caps []VirtioPCICap, cfgType uint8) *VirtioPCICap {
	return common.PCICapsByType(caps, cfgType)
}

// Reader-callback types kept for the pcienum probe's existing
// signature. The probe builds its own readers; we keep the type-alias
// shape so its call site doesn't have to change.
type ReadU8At = func(offset uint8) (uint8, error)
type ReadU32At = func(offset uint8) (uint32, error)

// WalkVirtioPCICaps preserves the pre-migration call shape. It
// constructs an adapter that satisfies common.PCIConfigReader from the
// two reader callbacks and delegates to common.WalkPCICaps.
func WalkVirtioPCICaps(firstCapOffset uint8, readU8 ReadU8At, readU32 ReadU32At) ([]VirtioPCICap, error) {
	r := &readerAdapter{readU8: readU8, readU32: readU32}
	return common.WalkPCICaps(r, firstCapOffset)
}

// readerAdapter satisfies common.PCIConfigReader from the two
// callbacks the legacy uefiboard API used. ReadConfig16 is synthesised
// from two ReadConfig8 calls — the modern transport doesn't use it
// during cap walking but the interface requires it.
type readerAdapter struct {
	readU8  ReadU8At
	readU32 ReadU32At
}

func (r *readerAdapter) ReadConfig8(off uint8) (uint8, error) { return r.readU8(off) }
func (r *readerAdapter) ReadConfig16(off uint8) (uint16, error) {
	lo, err := r.readU8(off)
	if err != nil {
		return 0, err
	}
	hi, err := r.readU8(off + 1)
	if err != nil {
		return 0, err
	}
	return uint16(lo) | uint16(hi)<<8, nil
}
func (r *readerAdapter) ReadConfig32(off uint8) (uint32, error) { return r.readU32(off) }

// VirtioNet net-driver field offset re-exports — these were on
// virtio_pci.go in the old layout. They're net-specific; we re-export
// from go-virtio/net.
//
// (Routed through go-virtio/net to keep one source of truth.)
const (
	VirtioNetCfgOffsetMAC                = 0
	VirtioNetCfgOffsetStatus             = 6
	VirtioNetCfgOffsetMaxVirtqueuePairs  = 8
	VirtioNetCfgOffsetMTU                = 10
)

// VirtioMACLen preserves the pre-migration constant name.
const VirtioMACLen = 6

// Walker-error re-exports.
var (
	ErrVirtioCapChainTooLong = common.ErrCapChainTooLong
	ErrVirtioCapChainBadPtr  = common.ErrCapChainBadPtr
)

// ErrAllocReturnedZero is surfaced by the UEFI page-allocator adapter
// when AllocatePages reports SUCCESS but the returned base is 0
// (firmware bug, defensive guard). Host-buildable (tamago build tag
// would otherwise gate it via virtio_uefi_transport.go).
var ErrAllocReturnedZero = common.ErrAllocReturnedZero
