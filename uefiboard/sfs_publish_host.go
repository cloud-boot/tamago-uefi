// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for PublishSFS / UnpublishSFS
// (Phase 3 sprint 2B).
//
// Mirrors block_io_publish_host.go: the nil-input guards run host-side
// so unit tests can exercise them, but anything past them panics
// because there is no firmware to call into. The Go-side handlers in
// sfs_publish_handlers.go remain host-buildable and are unit-tested
// directly against a fake filesystem.Filesystem fixture.

//go:build !tamago || (!amd64 && tamago)

package uefiboard

import (
	filesystem "github.com/go-filesystems/interface"
)

// PublishSFS host stub.
func PublishSFS(handle uintptr, fs filesystem.Filesystem) (uintptr, error) {
	if fs == nil {
		return 0, ErrSFSNilFilesystem
	}
	panic("uefi: PublishSFS not supported on host / non-amd64 tamago (sprint 2B: amd64 only)")
}

// UnpublishSFS host stub.
func UnpublishSFS(handle uintptr) error {
	if handle == 0 {
		return ErrSFSNotPublished
	}
	panic("uefi: UnpublishSFS not supported on host / non-amd64 tamago")
}
