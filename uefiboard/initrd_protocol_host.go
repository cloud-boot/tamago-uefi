// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for PublishInitrd /
// UnpublishInitrd (Phase 2, M8.2).
//
// Same split as load_options_host.go: the empty-input guards are
// host-testable; past them we panic because there is no firmware to
// call into. The device-path constructor + GUIDs ARE host-buildable
// (they live in initrd_protocol.go) and unit-tested.

//go:build !tamago

package uefiboard

// PublishInitrd installs a Load-File-2 protocol instance backed by
// the given initrd bytes. Host stub.
func PublishInitrd(initrd []byte) (uintptr, error) {
	if len(initrd) == 0 {
		return 0, ErrEmptyInitrd
	}
	panic("uefi: PublishInitrd not supported on host")
}

// UnpublishInitrd undoes PublishInitrd. Host stub.
func UnpublishInitrd(handle uintptr) error {
	if handle == 0 {
		return ErrInitrdNotPublished
	}
	panic("uefi: UnpublishInitrd not supported on host")
}
