// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M9.2 text_input helpers. The live
// firmware path lives in text_input_tamago.go and is exercised
// end-to-end by the M9.2 live menu runner; here we only verify the
// host-buildable bits: constants, offsets, and error shapes.

package uefiboard

import (
	"strings"
	"testing"
	"unsafe"
)

func TestScanCodes_MatchUEFISpec(t *testing.T) {
	// UEFI 2.10 Appendix B table B-1 — pin the scan-code values so a
	// careless edit can't silently break the M9.2 menu.
	cases := []struct {
		name string
		got  uint16
		want uint16
	}{
		{"ScanCodeNone", ScanCodeNone, 0x00},
		{"ScanCodeUp", ScanCodeUp, 0x01},
		{"ScanCodeDown", ScanCodeDown, 0x02},
		{"ScanCodeHome", ScanCodeHome, 0x05},
		{"ScanCodeEnd", ScanCodeEnd, 0x06},
		{"ScanCodeESC", ScanCodeESC, 0x17},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%02x, want 0x%02x", c.name, c.got, c.want)
		}
	}
}

func TestUnicodeChar_EnterIsCR(t *testing.T) {
	// UEFI 2.10 §11.3: Enter is always carriage return (0x000D) over
	// the UnicodeChar field.
	if UnicodeCharEnter != 0x000D {
		t.Errorf("UnicodeCharEnter = 0x%04x, want 0x000D", UnicodeCharEnter)
	}
}

func TestSimpleTextInputOffsets(t *testing.T) {
	// UEFI 2.10 §11.3.1 — the function-pointer slots in the protocol
	// vtable. The wrapper relies on these exact offsets when adding
	// to the protocol base before calling efiCall.
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"stiReset", stiReset, 0},
		{"stiReadKeyStroke", stiReadKeyStroke, 8},
		{"stiWaitForKey", stiWaitForKey, 16},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEfiSTConInOffset(t *testing.T) {
	// EFI_SYSTEM_TABLE layout pins ConIn at offset 48 on 64-bit UEFI
	// (UEFI 2.10 §4.3.1; see dtb_probe.go for the annotated layout).
	if efiSTConIn != 48 {
		t.Errorf("efiSTConIn = %d, want 48", efiSTConIn)
	}
}

func TestErrNoKey_Sentinel(t *testing.T) {
	if ErrNoKey == nil {
		t.Fatal("ErrNoKey is nil")
	}
	if !strings.Contains(ErrNoKey.Error(), "NOT_READY") {
		t.Errorf("ErrNoKey.Error() = %q, want it to mention NOT_READY", ErrNoKey.Error())
	}
}

func TestErrNoConIn_Sentinel(t *testing.T) {
	if ErrNoConIn == nil {
		t.Fatal("ErrNoConIn is nil")
	}
	if !strings.Contains(ErrNoConIn.Error(), "ConIn") {
		t.Errorf("ErrNoConIn.Error() = %q, want it to mention ConIn", ErrNoConIn.Error())
	}
}

func TestEfiNotReadyConstant(t *testing.T) {
	// UEFI 2.10 Appendix D — EFI_NOT_READY = high-bit-set | 6.
	if efiNotReady != 0x8000000000000006 {
		t.Errorf("efiNotReady = 0x%016x, want 0x8000000000000006", efiNotReady)
	}
}

func TestKeystrokeFieldLayout(t *testing.T) {
	// The Keystroke struct must match the on-the-wire EFI_INPUT_KEY
	// layout (two UINT16 fields, no padding) — otherwise the
	// firmware-side ReadKeyStroke writeback would clobber Go heap
	// adjacent storage. Verify by size.
	var k Keystroke
	if got, want := unsafe.Sizeof(k), uintptr(4); got != want {
		t.Errorf("sizeof(Keystroke) = %d, want %d (EFI_INPUT_KEY is two UINT16s)", got, want)
	}
}
