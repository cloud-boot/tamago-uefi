// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stub for InheritParentDeviceHandle
// (Phase 2, M8.14). Mirrors the loadimage_host.go / load_options_host.go
// split pattern: zero-handle guard returns the typed error, past that we
// panic because there is no firmware to call.

//go:build !tamago

package uefiboard

// InheritParentDeviceHandle copies the parent image's LoadedImage
// DeviceHandle + FilePath into the child image at `childHandle`. Host
// stub — validates the zero-handle guard then panics; the live wrapper
// lives in inherit_device_handle.go.
func InheritParentDeviceHandle(childHandle uintptr) error {
	if childHandle == 0 {
		return ErrNilHandle
	}
	panic("uefi: InheritParentDeviceHandle not supported on host")
}
