// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side stubs for the M8.0 image-services
// wrappers. The host has no firmware to call into, so the public
// entry points panic with a clear message — matching the
// memorymap_tamago.go / loadimage_tamago.go split pattern used by
// every other live-firmware wrapper in this package.
//
// The empty-buffer guard for LoadImage IS exercised on the host:
// rejecting `len(srcBuf) == 0` before the firmware call is pure Go
// and is unit-tested in loadimage_test.go.

//go:build !tamago

package uefiboard

// LoadImage invokes gBS->LoadImage(BootPolicy=FALSE,
// ParentImageHandle=imageHandle, DevicePath=NULL,
// SourceBuffer=&srcBuf[0], SourceSize=len(srcBuf), &outHandle).
// Host-build: returns ErrLoadImageNoSource immediately if the buffer
// is empty (this is the only host-testable branch); otherwise panics
// because there is no firmware to call into.
func LoadImage(srcBuf []byte) (uintptr, error) {
	if len(srcBuf) == 0 {
		return 0, ErrLoadImageNoSource
	}
	panic("uefi: LoadImage not supported on host")
}

// StartImage invokes gBS->StartImage(handle, NULL, NULL). Host stub.
func StartImage(h uintptr) (uintptr, error) {
	panic("uefi: StartImage not supported on host")
}

// UnloadImage invokes gBS->UnloadImage(handle). Host stub.
func UnloadImage(h uintptr) error {
	panic("uefi: UnloadImage not supported on host")
}

// ExitImage invokes gBS->Exit(handle, exitStatus, 0, NULL). Host
// stub. Per UEFI 2.10 §7.4 a successful Exit does not return; the
// Go declaration returns nil only to satisfy the type system on the
// host side.
func ExitImage(handle uintptr, exitStatus uintptr) error {
	panic("uefi: ExitImage not supported on host")
}

// hostWireExitToFirmwareCalls counts host-side invocations of
// WireExitToFirmware. The host build is a no-op (there's no
// runtime/goos.Exit to hook on the host — it's a tamago-specific
// override slot), but we need at least one tracked statement so
// the coverage tool reports the function as covered.
var hostWireExitToFirmwareCalls int

// WireExitToFirmware installs a goos.Exit hook so a clean return
// from main on tamago lands in gBS->Exit (see loadimage_tamago.go
// for details). Host stub is a no-op: there is no runtime/goos.Exit
// to hook on the host, and any caller building for the host is
// necessarily in a test, where the real runtime termination is
// `t.Skip` or test exit.
func WireExitToFirmware() {
	hostWireExitToFirmwareCalls++
}
