// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- virtio-console open helper (Phase 2,
// M9.1).
//
// Mirrors the OpenVirtioNet shape (virtio_net_uefi.go): walk the
// EFI_PCI_IO_PROTOCOL handle space looking for a modern virtio-
// console PCI device (vendor 0x1AF4, device 0x1043), enable
// BusMaster + Memory, then hand the EFI_PCI_IO_PROTOCOL pointer to
// go-virtio/console's OpenVirtioConsole through a UEFITransport.
//
// Why a separate file (not folded into virtio_net_uefi.go): the
// virtio-console import is M9.1-only. Folding it in would pull
// go-virtio/console into the build closure of every phase2 probe
// (including M0 / M1 / M8.x which never touch virtio-console),
// inflating every EFI image by ~80 KiB. A separate file gated only
// by the M9.1 menu probe keeps the rest of the matrix clean.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	vconsole "github.com/go-virtio/console"
)

// VirtioPCIDeviceIDModernConsole pins the modern virtio-console PCI
// device ID. Mirrors the VirtioPCIDeviceIDModernNet re-export pattern
// from virtio_uefi_bridge.go.
const VirtioPCIDeviceIDModernConsole uint16 = 0x1043

// OpenVirtioConsole drives the full bring-up of one virtio-console
// device. Constructs a UEFITransport (the same adapter virtio-net
// uses), enables BusMaster + Memory on the PCI BAR, then delegates
// to go-virtio/console's OpenVirtioConsole.
//
// Returns the live *vconsole.VirtioConsole on success — the caller
// uses .Write([]byte) to emit bytes (satisfies io.Writer's contract
// modulo the unexported Read pollIterations argument, which the M9.1
// menu loop never invokes anyway).
//
// Errors propagated:
//   - any *EFIError from PciIOAttributesEnable.
//   - any go-virtio/console error from OpenVirtioConsole (notably
//     ErrInitWrongDeviceID if the caller passed a non-virtio-console
//     PCI handle, ErrNotModernDevice on legacy-only devices).
func OpenVirtioConsole(pciIO uint64) (*vconsole.VirtioConsole, error) {
	// Defensive PCI bus-master + memory enable — same pattern as
	// OpenVirtioNet. EDK2 typically pre-enables both bits at firmware
	// bind time, but the defensive call is the difference between
	// "boots reliably" and "boots iff the firmware bound the device".
	if err := PciIOAttributesEnable(pciIO, EFIPciIOAttributeMemory|EFIPciIOAttributeBusMaster); err != nil {
		return nil, err
	}
	t := NewUEFITransport(pciIO)
	return vconsole.OpenVirtioConsole(t)
}

// LocateVirtioConsolePciIO walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first device whose vendor/device ID is
// (0x1AF4, 0x1043). Returns the PCI IO protocol pointer (suitable for
// OpenVirtioConsole) or 0 if no virtio-console device is bound.
//
// Mirrors the locateVirtioNetForKernelBoot helper from
// phase2_oci_kernel_boot.go. Returning 0 (not an error) is the
// signal to the M9.1 menu probe to fall back to ConOutWriter — the
// firmware may simply not have been launched with
// `-device virtio-serial-pci -device virtconsole,...`, and that's a
// supported configuration.
func LocateVirtioConsolePciIO() uint64 {
	handles, err := LocateHandleBuffer(&EFIPciIOProtocolGUID)
	if err != nil {
		return 0
	}
	for _, h := range handles {
		iface, err := HandleProtocol(h, &EFIPciIOProtocolGUID)
		if err != nil {
			continue
		}
		vid, err := PciIOReadConfigU16(iface, PCICfgVendorID)
		if err != nil {
			continue
		}
		did, err := PciIOReadConfigU16(iface, PCICfgDeviceID)
		if err != nil {
			continue
		}
		if vid == VirtioPCIVendorID && did == VirtioPCIDeviceIDModernConsole {
			return iface
		}
	}
	return 0
}
