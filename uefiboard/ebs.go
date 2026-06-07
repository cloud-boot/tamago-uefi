// cloud-boot UEFI board — ExitBootServices wrapper (Phase 2, M0).
//
// Just the call thunk: declares the function, does the gBS lookup, and
// invokes it. NOT called from Phase 1's main flow — Phase 1 still
// spin-halts. M4 (per the phase-2 design doc) will wire this in after
// the kernel image + initrd are staged and the memory map is captured.
//
// UEFI 2.10 §7.4:
//
//	EFI_STATUS ExitBootServices(
//	    IN EFI_HANDLE  ImageHandle,
//	    IN UINTN       MapKey );
//
// On success: all Boot Services + their event handlers are torn down,
// Runtime Services remain, and the caller owns memory. On
// EFI_INVALID_PARAMETER: MapKey doesn't match the current memory-map
// snapshot — call GetMemoryMap again and retry. The retry choreography
// lives in M4's loader; this file only exposes the raw call.
//
// See edk2.git MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c::
// CoreExitBootServices for the spec-compliant reference behaviour.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// ExitBootServices invokes gBS->ExitBootServices(imageHandle, mapKey).
//
// mapKey MUST be the MapKey from the most recent GetMemoryMap call
// (UEFI 2.10 §7.4) — that's the firmware's tamper-evident token
// proving no memory has been allocated/freed since.
//
// Returns nil on EFI_SUCCESS. Returns an *EFIError wrapping
// EFI_INVALID_PARAMETER if the mapKey is stale (refresh GetMemoryMap +
// retry). Other statuses indicate firmware-side errors.
//
// CRITICAL: on success there are NO Boot Services any more. printk
// (which calls ConOut->OutputString through efiCall) WILL FAULT on the
// next call from this point on — Runtime Services only. The Phase-2
// loader is expected to print its last diagnostic *before* this call
// returns, and to jump directly to the loaded kernel after.
//
// Phase 1's main flow does NOT call this; it spin-halts after the
// banner. M0 ships this thunk so M4 has a known-compiles entry point.
func ExitBootServices(mapKey uintptr) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	if imageHandle == 0 {
		// cpuinit didn't capture the ImageHandle — UEFI mandates a
		// non-NULL handle here (it's the firmware's own handle for our
		// LOADED_IMAGE, used to revoke our Boot Services slot).
		return ErrNoBootServices
	}
	fnSlot := bs + efiBSExitBootServices
	_ = unsafe.Sizeof(mapKey) // touch unsafe so the import is used on all arches

	status := efiCall(
		fnSlot,
		imageHandle,
		uint64(mapKey),
		0,
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "ExitBootServices"}
	}
	return nil
}
