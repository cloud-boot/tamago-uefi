// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — gBS->LoadImage / StartImage / UnloadImage /
// Exit live wrappers (Phase 2, M8.0).
//
// Tamago-only because each entry point calls into the firmware via
// uefiboard.efiCall (which only links on the tamago target — the
// per-arch eficall_<arch>.s files have no host build). The
// host-buildable type surface (offsets + ErrLoadImageNoSource) lives
// in loadimage.go, with panic stubs in loadimage_host.go.
//
// Reference: edk2.git stable/202408
//   - MdeModulePkg/Core/Dxe/Image/Image.c::CoreLoadImage /
//     CoreStartImage / CoreUnloadImage / CoreExit are the spec-
//     compliant reference implementations.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// LoadImage invokes gBS->LoadImage(BootPolicy=FALSE,
// ParentImageHandle=imageHandle, DevicePath=NULL,
// SourceBuffer=&srcBuf[0], SourceSize=len(srcBuf), &outHandle).
// Returns the child image handle on success.
//
// Empty-buffer rejection: short-circuited before the firmware call
// (see loadimage.go's ErrLoadImageNoSource); ensures the
// (SourceBuffer, SourceSize) pair never points at a (NULL, 0) tuple
// that the firmware would reject with EFI_INVALID_PARAMETER anyway.
func LoadImage(srcBuf []byte) (uintptr, error) {
	if len(srcBuf) == 0 {
		return 0, ErrLoadImageNoSource
	}
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	if imageHandle == 0 {
		// cpuinit didn't capture the parent ImageHandle — UEFI
		// requires a valid ParentImageHandle.
		return 0, ErrNoBootServices
	}
	var childHandle uint64
	status := efiCall(
		bs+efiBSLoadImage,
		0,                        // BootPolicy = FALSE
		imageHandle,              // ParentImageHandle
		0,                        // DevicePath = NULL
		uint64(uintptr(unsafe.Pointer(&srcBuf[0]))), // SourceBuffer
		uint64(uintptr(len(srcBuf))),                // SourceSize
		uint64(uintptr(unsafe.Pointer(&childHandle))),
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "LoadImage"}
	}
	return uintptr(childHandle), nil
}

// StartImage invokes gBS->StartImage(handle, NULL, NULL). Returns the
// raw EFI_STATUS the child image returned (or the firmware returned,
// if the child faulted). On non-EFI_SUCCESS the wrapper additionally
// returns an *EFIError so callers can switch on err != nil.
func StartImage(h uintptr) (uintptr, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSStartImage,
		uint64(h),
		0, // ExitDataSize = NULL
		0, // ExitData     = NULL
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return uintptr(status), &EFIError{Status: status, Op: "StartImage"}
	}
	return uintptr(status), nil
}

// UnloadImage invokes gBS->UnloadImage(handle).
func UnloadImage(h uintptr) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSUnloadImage,
		uint64(h),
		0,
		0,
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "UnloadImage"}
	}
	return nil
}

// ExitImage invokes gBS->Exit(handle, exitStatus, 0, NULL). On
// EFI_SUCCESS the firmware does not return to us (it tears down the
// child's resources and resumes the parent). If the firmware DOES
// return, that's a failure mode and is surfaced as an *EFIError.
//
// The (ExitDataSize, ExitData) pair is fixed at (0, NULL) for M8.0;
// per UEFI 2.10 §7.4 ExitData is only meaningful when ExitStatus is
// an error and the child wants to attach a UCS-2 diagnostic. Our
// chained payload always exits clean, so we never allocate the
// firmware-owned pool buffer that would otherwise be needed.
func ExitImage(handle uintptr, exitStatus uintptr) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSExit,
		uint64(handle),
		uint64(exitStatus),
		0, // ExitDataSize
		0, // ExitData
		0,
		0,
	)
	// Reached only if the firmware refused to tear us down (rare;
	// would mean an invalid handle).
	return &EFIError{Status: status, Op: "Exit"}
}

// WireExitToFirmware installs an Exit handler into the TamaGo runtime
// so that when the Go program calls os.Exit / a panic propagates to
// runtime.exit / `main` returns normally, the runtime calls
// gBS->Exit(imageHandle, code, 0, NULL) instead of halting on a spin
// loop.
//
// Without this, a chained payload that returns from main never
// returns to its parent's StartImage call (TamaGo's default
// `runtime.exit` halts in a `for {}` — see
// tamago-pie/src/runtime/os_tamago.go's `exit` function).
//
// This is the M8.0 mechanism that closes the chain-boot loop: the
// chained payload calls WireExitToFirmware() before printing its
// banner, and the runtime's eventual call into our Exit hook
// produces a clean StartImage return on the parent side.
//
// goos.Exit is documented as the canonical override hook for runtime
// termination (tamago-pie/src/runtime/goos/stub.go's `Exit` var).
//
//go:linkname goosExit runtime/goos.Exit
var goosExit func(code int32)

// WireExitToFirmware sets goos.Exit to a function that calls
// gBS->Exit. It captures the parent ImageHandle once at install
// time. Idempotent — calling it twice just rewrites the same hook.
func WireExitToFirmware() {
	goosExit = func(code int32) {
		// Translate the Go exit code into a UEFI status. Code 0 →
		// EFI_SUCCESS (0). Non-zero → EFI_ABORTED (0x80000015) so
		// the parent sees a recognisable non-zero status.
		var status uintptr
		if code == 0 {
			status = 0
		} else {
			status = 0x8000000000000015 // EFI_ABORTED on 64-bit UEFI
		}
		_ = ExitImage(uintptr(imageHandle), status)
		// If Exit returned (shouldn't), spin — we cannot trust the
		// runtime to clean up beyond this point.
		for {
		}
	}
}
