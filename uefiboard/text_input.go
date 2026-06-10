// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- EFI_SIMPLE_TEXT_INPUT_PROTOCOL wrapper
// (Phase 2, M9.2).
//
// Reads keystrokes from gST->ConIn (the firmware-managed console
// input) so the M9.2 menu loop can move the selection cursor, confirm
// with Enter, or cancel with ESC.
//
// Protocol layout (UEFI 2.10 §11.3.1):
//
//	typedef struct _EFI_SIMPLE_TEXT_INPUT_PROTOCOL {
//	    EFI_INPUT_RESET           Reset;          // 0
//	    EFI_INPUT_READ_KEY        ReadKeyStroke;  // 8
//	    EFI_EVENT                 WaitForKey;     // 16
//	} EFI_SIMPLE_TEXT_INPUT_PROTOCOL;
//
//	typedef struct {
//	    UINT16  ScanCode;
//	    CHAR16  UnicodeChar;
//	} EFI_INPUT_KEY;
//
// ScanCode values used by the M9.2 menu (UEFI 2.10 Appendix B,
// table B-1 "Scan Code Values"):
//
//	0x00  (no scan code, the keystroke is in UnicodeChar)
//	0x01  Up arrow
//	0x02  Down arrow
//	0x05  Home
//	0x06  End
//	0x17  ESC
//
// UnicodeChar values used by the M9.2 menu:
//
//	0x000D  '\r' / Enter / CR (LF = 0x000A but Enter is universally
//	        reported as CR on every UEFI implementation we've tested)
//
// The wrapper is split across two files so the host build compiles
// the types + constants + sentinel errors + offsets (this file) and
// only the firmware-call wiring needs the tamago build tag
// (text_input_tamago.go). Tests in text_input_test.go cover everything
// in this file; the live path is exercised by the M9.2 live runner.
//
// Why ConIn instead of a virtio-console RX poll: the dispatcher needs
// to receive keystrokes from BOTH a virtio-console-enabled QEMU and
// a bare-ConOut firmware (no virtio-serial-pci). UEFI's ConIn
// abstracts that — on a virtio-console-equipped firmware EDK2's
// SerialDxe binds the same protocol, and on bare ConOut firmware
// the same protocol reads the host PS/2 / USB / serial console
// driver. One Go-side surface; firmware does the routing.

package uefiboard

import "errors"

// Keystroke mirrors EFI_INPUT_KEY (UEFI 2.10 §11.3.1).
//
//	UINT16 ScanCode      // 0 = "no scan code; data is in UnicodeChar"
//	CHAR16 UnicodeChar   // we use the low byte only (ASCII subset)
//
// The protocol delivers one of:
//   - ScanCode != 0, UnicodeChar == 0: a non-printable key (arrow, ESC, ...)
//   - ScanCode == 0, UnicodeChar != 0: a printable character (Enter is CR)
//
// We carry both in case a future firmware (or a non-PC keyboard
// abstraction) reports both fields populated. The menu loop's switch
// reads them by name so the dispatch is unambiguous.
type Keystroke struct {
	ScanCode    uint16
	UnicodeChar uint16
}

// ScanCode values used by the M9.2 menu (UEFI 2.10 Appendix B).
// Exported so consumers don't have to copy magic numbers.
const (
	// ScanCodeNone is the "no scan code" sentinel; when ScanCode equals
	// this the keystroke is carried in UnicodeChar.
	ScanCodeNone uint16 = 0x00

	// ScanCodeUp is the cursor-up arrow.
	ScanCodeUp uint16 = 0x01

	// ScanCodeDown is the cursor-down arrow.
	ScanCodeDown uint16 = 0x02

	// ScanCodeHome jumps the selection to the first entry.
	ScanCodeHome uint16 = 0x05

	// ScanCodeEnd jumps the selection to the last entry.
	ScanCodeEnd uint16 = 0x06

	// ScanCodeESC cancels the menu (the loop halts without dispatching).
	ScanCodeESC uint16 = 0x17
)

// UnicodeChar values used by the M9.2 menu.
const (
	// UnicodeCharEnter is the Enter / Carriage Return key — UEFI 2.10
	// §11.3 mandates CR (0x000D) regardless of host platform.
	UnicodeCharEnter uint16 = 0x000D
)

// EFI_SIMPLE_TEXT_INPUT_PROTOCOL field-pointer slot offsets (UEFI
// 2.10 §11.3.1). Used by ReadKeyNonblocking to invoke the right
// function-pointer slot on the protocol struct that gST->ConIn
// points at.
const (
	// stiReset is the EFI_INPUT_RESET function-pointer slot.
	// Signature: EFI_STATUS Reset(*This, BOOLEAN ExtendedVerification).
	stiReset = 0

	// stiReadKeyStroke is the EFI_INPUT_READ_KEY function-pointer slot.
	// Signature: EFI_STATUS ReadKeyStroke(*This, *EFI_INPUT_KEY).
	stiReadKeyStroke = 8

	// stiWaitForKey is the EFI_EVENT field offset. M9.2 does NOT use
	// the WaitForKey event (the menu loop polls in 100 ms ticks); the
	// constant is here for future M9.x revisions that may want to
	// gBS->WaitForEvent on it.
	stiWaitForKey = 16
)

// efiSTConIn is the offset of the EFI_SIMPLE_TEXT_INPUT_PROTOCOL*
// (ConIn) field inside EFI_SYSTEM_TABLE. UEFI 2.10 §4.3.1; the full
// table layout is annotated in dtb_probe.go (search for
// "EFI_SYSTEM_TABLE field offsets"). ConIn sits at +48 on every
// 64-bit UEFI build.
const efiSTConIn = 48

// efiNotReady is the EFI_STATUS value the SimpleTextInput protocol
// returns from ReadKeyStroke when no key is pending in the input
// queue. UEFI 2.10 Appendix D — the high bit is set (it's a non-
// success status), and the bottom three bits are 6 (NOT_READY).
const efiNotReady uint64 = 0x8000000000000006

// ErrNoKey is returned by ReadKeyNonblocking when ReadKeyStroke
// reported EFI_NOT_READY (no pending input). Surfaced as a
// recognisable Go error so the M9.2 menu loop can branch with
// errors.Is rather than parsing an EFI_STATUS hex.
var ErrNoKey = errors.New("uefi: ReadKeyStroke reported EFI_NOT_READY (no pending input)")

// ErrNoConIn is returned by ReadKeyNonblocking when gST->ConIn is 0
// — either the firmware did not publish a SimpleTextInput protocol
// (extremely rare; every UEFI 2.x platform we target does), or
// cpuinit_<arch>.s captured the SystemTable but the firmware hadn't
// yet wired ConIn. Distinct from ErrNoKey so the caller can fall
// through to a non-interactive default (no keystroke == auto-boot).
var ErrNoConIn = errors.New("uefi: gST->ConIn is NULL (no SimpleTextInput protocol available)")
