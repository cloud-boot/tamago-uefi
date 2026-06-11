// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for PublishBlockIO /
// UnpublishBlockIO / ConnectController (Phase 3 sprint 1).
//
// Mirrors the initrd_protocol_host.go pattern: the empty-input
// guards run host-side so unit tests can exercise them, but anything
// past them panics because there is no firmware to call into. The
// Go-side handlers in block_io_publish_handlers.go remain
// host-buildable and are unit-tested directly.

//go:build !tamago || (!amd64 && tamago)

package uefiboard

import "errors"

// PublishBlockIO host stub.
func PublishBlockIO(image []byte) (uintptr, error) {
	if len(image) == 0 {
		return 0, ErrEmptyBlockImage
	}
	if (len(image) % int(BlockIOLogicalBlockSize)) != 0 {
		return 0, ErrBlockIOImageNotAligned
	}
	panic("uefi: PublishBlockIO not supported on host / non-amd64 tamago (sprint 1: amd64 only)")
}

// UnpublishBlockIO host stub.
func UnpublishBlockIO(handle uintptr) error {
	if handle == 0 {
		return ErrBlockIONotPublished
	}
	panic("uefi: UnpublishBlockIO not supported on host / non-amd64 tamago")
}

// ConnectController host stub.
func ConnectController(controllerHandle uintptr) error {
	if controllerHandle == 0 {
		return errors.New("uefi: ConnectController called with zero handle")
	}
	panic("uefi: ConnectController not supported on host / non-amd64 tamago")
}

// DisconnectController host stub.
func DisconnectController(controllerHandle uintptr) error {
	if controllerHandle == 0 {
		return errors.New("uefi: DisconnectController called with zero handle")
	}
	panic("uefi: DisconnectController not supported on host / non-amd64 tamago")
}
