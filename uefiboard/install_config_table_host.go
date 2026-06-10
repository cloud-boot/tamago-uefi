// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host stubs for the M8.6
// InstallConfigurationTable + AllocatePool + PublishDTB wrappers.
// Mirrors the loadimage_host.go / load_options_host.go pattern: host
// build has no firmware to call into, so the live entry points panic
// with a clear message — except for PublishDTB's empty-buffer guard,
// which is pure Go and unit-tested on the host.

//go:build !tamago

package uefiboard

import "unsafe"

// InstallConfigurationTable host stub. Panics — there is no firmware.
func InstallConfigurationTable(guid EFI_GUID, table unsafe.Pointer) error {
	panic("uefi: InstallConfigurationTable not supported on host")
}

// AllocatePool host stub. Panics — there is no firmware.
func AllocatePool(memoryType uint32, size uintptr) (uint64, error) {
	panic("uefi: AllocatePool not supported on host")
}

// PublishDTB host stub. The empty-DTB guard fires before any
// firmware call would happen and is the only host-testable branch;
// non-empty inputs reach the AllocatePool call which panics.
func PublishDTB(dtb []byte) error {
	if len(dtb) == 0 {
		return ErrDTBEmpty
	}
	panic("uefi: PublishDTB not supported on host")
}
