// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stub for SetLoadOptions (Phase 2,
// M8.2). Same split pattern as loadimage_host.go: empty-cmdline /
// nil-handle guards run on the host (and are unit-tested in
// load_options_test.go); past the guards we panic because there is
// no firmware to call.

//go:build !tamago

package uefiboard

// SetLoadOptions installs cmdline (encoded as UTF-16 LE + NUL) into
// the LoadedImageProtocol of the image at handle. Host stub —
// validates inputs (the only host-testable branch) then panics.
func SetLoadOptions(handle uintptr, cmdline string) error {
	if handle == 0 {
		return ErrNilHandle
	}
	if cmdline == "" {
		return ErrEmptyCmdline
	}
	panic("uefi: SetLoadOptions not supported on host")
}
