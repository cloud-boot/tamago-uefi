// cloud-boot UEFI board — ExitBootServices choreography for the M2-B
// post-EBS experiment (Phase 2, M2-B).
//
// Host-buildable: no //go:build tamago directive. The control-flow
// and per-cell state machine are pure data; the live thunk lives in
// `post_ebs_step_tamago.go`. The reason for the split is the same as
// elsewhere in this package — host tests can exercise the state
// transitions and the diagnostic surface without pulling in the
// firmware-call thunk.
//
// References:
//
//   - UEFI 2.10 §7.4 — `gBS->ExitBootServices(ImageHandle, MapKey)`:
//
//	    EFI_STATUS ExitBootServices(
//	        IN EFI_HANDLE  ImageHandle,
//	        IN UINTN       MapKey );
//
//     On success, the caller owns memory and Boot Services are gone.
//     On EFI_INVALID_PARAMETER, the MapKey is stale (firmware
//     allocated or freed pages between GetMemoryMap and EBS) — the
//     spec requires the caller to call GetMemoryMap again and retry.
//
//   - edk2.git MdeModulePkg/Core/Dxe/DxeMain/DxeMain.c::
//     CoreExitBootServices — the spec-compliant reference behaviour.
//
//   - Virtio 1.1 §3.1.1 — driver init choreography (replayed
//     post-EBS by `InitVirtioNetPostEBS`).
//
// Why one retry is enough: UEFI 2.10 §7.4 implementations are
// required to drain pending event handlers between GetMemoryMap and
// the EBS attempt; the only legitimate cause of EFI_INVALID_PARAMETER
// is a single race against the firmware's own allocator (e.g. an
// interrupt handler that allocated a page). One retry covers that;
// a sustained loop means firmware misbehaviour and we should fail
// loudly rather than spin.

package uefiboard

// PostEBSGlobal holds the captured state across the EBS boundary.
// Storing it in package scope keeps it in the runtime data segment
// (writable, identity-mapped) so the post-EBS direct-MMIO code path
// can find it without an argument hand-off. The Go scheduler is
// still alive post-EBS (TamaGo's runtime doesn't need Boot
// Services for its own bookkeeping), so package-scope writes work
// across the boundary.
//
// SET by `ExitToBareMetal`. CONSUMED by `InitVirtioNetPostEBS`,
// `TransmitFramePostEBS`, `ReceiveFramePostEBS`.
var PostEBSGlobal *CapturedState

// ErrEBSRetryExhausted is returned by `ExitToBareMetal` if every
// retry of `gBS->ExitBootServices` returned EFI_INVALID_PARAMETER.
// One retry is allowed (covers a legitimate race against the
// firmware's allocator); two consecutive failures indicate either a
// buggy firmware or a runaway interrupt handler.
var ErrEBSRetryExhausted = vpciError("uefi: M2-B: ExitBootServices kept returning EFI_INVALID_PARAMETER across retries")

// ErrPostEBSNoCapture is returned by `InitVirtioNetPostEBS` and
// friends if `PostEBSGlobal` is nil — i.e. `ExitToBareMetal` was
// never called, or `CapturePreEBS` returned an empty state.
var ErrPostEBSNoCapture = vpciError("uefi: M2-B: post-EBS path called before CapturePreEBS / ExitToBareMetal")

// MaxEBSRetries is the maximum number of `gBS->ExitBootServices`
// attempts. UEFI 2.10 §7.4 says one retry is sufficient on
// spec-compliant firmware; we allow two for paranoia, then give up
// (`ErrEBSRetryExhausted`).
const MaxEBSRetries = 2

// PostEBSScratchAppend appends one byte to the post-EBS diagnostic
// scratch buffer (pre-allocated by `CapturePreEBS` as
// EfiRuntimeServicesData, lives on across EBS). Out-of-bounds
// writes are silently dropped — we'd rather drop a diagnostic byte
// than fault post-EBS where we have no recovery path.
//
// Caller-supplied state pointer (not the package-scope
// `PostEBSGlobal`) so the host test can exercise the byte-bumping
// shape without going through the global.
//
// The function delegates the actual write to `postEBSScratchStore`
// — that's the seam where host vs tamago differ. The host build
// provides a no-op store (no unsafe.Pointer dereference) so the
// host-side tests can exercise the offset-arithmetic + bounds
// checks; the tamago build provides the real MMIO-grade write via
// `unsafe.Pointer`.
func PostEBSScratchAppend(state *CapturedState, b byte) {
	if state == nil {
		return
	}
	if state.BlkPrintkScratchPhys == 0 {
		return
	}
	if state.BlkPrintkScratchOffset >= PostEBSScratchSize {
		return
	}
	postEBSScratchStore(state.BlkPrintkScratchPhys, state.BlkPrintkScratchOffset, b)
	state.BlkPrintkScratchOffset++
}

// PostEBSScratchAppendBytes is the slice-shape parity of
// PostEBSScratchAppend. Used by the post-EBS path to log a short
// diagnostic string per init-sequence step.
func PostEBSScratchAppendBytes(state *CapturedState, b []byte) {
	for _, c := range b {
		PostEBSScratchAppend(state, c)
	}
}
