// cloud-boot UEFI board — ExitBootServices live thunk + EBS-crossing
// helpers for the M2-B post-EBS experiment (Phase 2, M2-B).
//
// `ExitToBareMetal` does the canonical "refresh MapKey + call
// gBS->ExitBootServices" choreography (UEFI 2.10 §7.4) and then
// disables CPU interrupts. After it returns, no Boot Services call
// is valid; the only firmware surface that still works is Runtime
// Services (Set/GetVariable, ResetSystem, GetTime), and we don't
// need any of those for the M2-B experiment.
//
// References:
//
//   - UEFI 2.10 §7.4 — ExitBootServices contract.
//   - edk2.git MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c — reference
//     EBS implementation.
//   - Virtio 1.1 §3.1.1 driver init — replayed post-EBS by
//     `InitVirtioNetPostEBS`.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// ExitToBareMetal drives the M2-B EBS crossing:
//
//  1. Re-read the memory map (the MapKey from any prior snapshot
//     is stale by definition — capture allocated runtime pages).
//  2. Call gBS->ExitBootServices(ImageHandle, MapKey).
//  3. On EFI_INVALID_PARAMETER, re-read the memory map ONCE and
//     retry; on a second failure return ErrEBSRetryExhausted.
//  4. On success, disable CPU interrupts (Virtio 1.1 driver init
//     prefers a polled doorbell over an interrupt-driven one
//     immediately post-EBS — interrupts may target firmware
//     handlers that are gone) and stash the captured state into
//     `PostEBSGlobal`.
//
// Returns nil on success — at which point Boot Services are GONE.
// On error, Boot Services are still alive and the caller can
// retry or surface the diagnostic to the user.
func ExitToBareMetal(captured *CapturedState) error {
	if captured == nil {
		return ErrPostEBSNoCapture
	}

	// Boot Services pointer + ImageHandle sanity check before we
	// even ask for a memory map — if these are missing, EBS would
	// fault.
	if getBootServices() == 0 {
		return ErrNoBootServices
	}
	if imageHandle == 0 {
		return ErrNoBootServices
	}

	var lastErr error
	for attempt := 0; attempt < MaxEBSRetries; attempt++ {
		// Refresh the memory map. The MapKey is opaque firmware
		// state; we must always pass the latest one to EBS.
		mm, err := GetMemoryMap()
		if err != nil {
			lastErr = err
			continue
		}
		// Now attempt EBS with the freshly-captured MapKey.
		ebsErr := ExitBootServices(mm.MapKey)
		if ebsErr == nil {
			// SUCCESS — Boot Services gone. Tear down our remaining
			// firmware-tied state.
			postEBSDisableInterrupts()
			PostEBSGlobal = captured
			return nil
		}
		lastErr = ebsErr
		// If the failure is EFI_INVALID_PARAMETER, the MapKey is
		// stale; loop refreshes it on the next attempt. Any other
		// status is a hard fail — break early.
		if eerr, ok := ebsErr.(*EFIError); ok && eerr.Status == efiInvalidParameter {
			continue
		}
		return ebsErr
	}
	if lastErr != nil {
		return lastErr
	}
	return ErrEBSRetryExhausted
}

// postEBSScratchStore writes one byte to the post-EBS diagnostic
// scratch buffer at the given offset. Both the buffer and the
// offset arithmetic are pre-validated by the caller in
// `PostEBSScratchAppend`; this is just the unsafe-pointer store.
//
//go:nosplit
func postEBSScratchStore(scratchPhys uint64, offset uint32, b byte) {
	if scratchPhys == 0 {
		return
	}
	addr := uintptr(scratchPhys) + uintptr(offset)
	*(*byte)(unsafe.Pointer(addr)) = b
}

// postEBSDisableInterrupts is a best-effort interrupt-mask sequence
// for the architecture. We don't enable any interrupt source ourselves
// post-EBS (the M2-B path is busy-polled), but the firmware's
// interrupt handlers are gone with Boot Services, so we mask the
// CPU's own interrupt enable bit defensively so a spurious legacy
// interrupt doesn't dispatch to a torn-down vector.
//
// Architecture-specific implementations live in
// `post_ebs_step_<arch>.s`. The Go-side declaration is platform-
// neutral; each .s file provides the body for its GOARCH.
//
//go:noescape
func postEBSDisableInterrupts()
