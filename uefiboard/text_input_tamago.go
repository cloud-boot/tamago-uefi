// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- live ReadKeyStroke wrapper (Phase 2, M9.2).
//
// Reads one keystroke from gST->ConIn->ReadKeyStroke in non-blocking
// mode. Used by the M9.2 menu loop to advance the selection cursor on
// arrow keys, confirm with Enter, or cancel with ESC. The loop polls
// in 100 ms ticks via `busyWait` (a spin-loop, NOT `time.Sleep` —
// `time.Sleep` blocks past its deadline under TamaGo+UEFI because
// haveSysmon=false on every arch; see uefiboard/doc.go "Things that
// BLOCK or MISBEHAVE under TamaGo+UEFI" and R-M9.2a in
// docs/tamago-uefi-phase2-oci-loader.md).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// ReadKeyNonblocking calls gST->ConIn->ReadKeyStroke exactly once.
// Returns the decoded keystroke on EFI_SUCCESS, or:
//
//   - ErrNoConIn if gST->ConIn is NULL (no SimpleTextInput protocol;
//     extremely rare on any firmware we target).
//   - ErrNoKey  if the firmware reported EFI_NOT_READY (no pending
//     input — the expected "still polling" outcome).
//   - *EFIError for any other non-success status.
//
// Does NOT block. The M9.2 menu loop is responsible for the inter-poll
// `busyWait` that throttles the busy-loop to ~10 polls/second. (Why
// not `time.Sleep`: see the package-level note in uefiboard/doc.go.)
func ReadKeyNonblocking() (Keystroke, error) {
	if systemTable == 0 {
		return Keystroke{}, ErrNoBootServices
	}
	conIn := *(*uint64)(unsafe.Pointer(uintptr(systemTable) + efiSTConIn))
	if conIn == 0 {
		return Keystroke{}, ErrNoConIn
	}
	// EFI_INPUT_KEY { UINT16 ScanCode; CHAR16 UnicodeChar; } — 4 bytes
	// on every UEFI arch. We allocate a Go local and pass &key to the
	// firmware; the call writes the two UINT16 fields in place.
	var key struct {
		ScanCode    uint16
		UnicodeChar uint16
	}
	status := efiCall(
		conIn+stiReadKeyStroke,
		conIn,
		uint64(uintptr(unsafe.Pointer(&key))),
		0, 0, 0, 0,
	)
	if status == efiNotReady {
		return Keystroke{}, ErrNoKey
	}
	if status != efiSuccess {
		return Keystroke{}, &EFIError{Status: status, Op: "ReadKeyStroke"}
	}
	return Keystroke{ScanCode: key.ScanCode, UnicodeChar: key.UnicodeChar}, nil
}

// ResetConIn calls gST->ConIn->Reset (EFI_INPUT_RESET). Drains any
// pending input the firmware queued before our menu loop started so
// stale keystrokes (e.g. a stray Enter from the EFI shell auto-boot
// chain) don't immediately dispatch the default entry. Best-effort;
// errors are non-fatal — surfaced for diagnostic prints, never
// blocking the menu.
//
// extendedVerification corresponds to the EFI_INPUT_RESET BOOLEAN
// argument. Pass false for "fast reset" — every firmware we target
// drains the input queue regardless. true is reserved for diagnostic
// scenarios that want the firmware's full self-test sequence.
func ResetConIn(extendedVerification bool) error {
	if systemTable == 0 {
		return ErrNoBootServices
	}
	conIn := *(*uint64)(unsafe.Pointer(uintptr(systemTable) + efiSTConIn))
	if conIn == 0 {
		return ErrNoConIn
	}
	var ev uint64
	if extendedVerification {
		ev = 1
	}
	status := efiCall(
		conIn+stiReset,
		conIn,
		ev,
		0, 0, 0, 0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "ConIn.Reset"}
	}
	return nil
}
