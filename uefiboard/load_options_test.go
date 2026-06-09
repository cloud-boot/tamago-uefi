// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.2 SetLoadOptions helper. The live
// firmware path lives in load_options_tamago.go and is exercised
// end-to-end by the kernelboot probe under QEMU+EDK2; here we only
// verify the host-buildable bits:
//
//  1. utf16LECmdline encodes ASCII correctly + NUL-terminates.
//  2. utf16LECmdline encodes non-ASCII BMP code points correctly.
//  3. utf16LECmdline surrogate-pairs supplementary-plane runes.
//  4. utf16LECmdline byte length matches LoadOptionsSize semantics.
//  5. SetLoadOptions rejects zero handle / empty cmdline early.
//  6. SetLoadOptions panics on the host once past the guards.
//  7. EFI_LOADED_IMAGE_PROTOCOL offsets match UEFI 2.10 §9.2.
//  8. EFI_LOADED_IMAGE_PROTOCOL_GUID round-trips through the
//     textual form (regression for an EFIGUID typo).

package uefiboard

import (
	"strings"
	"testing"
)

func TestUtf16LECmdline_ASCII(t *testing.T) {
	// "ab" -> 0x61 0x00 0x62 0x00 0x00 0x00 (NUL terminator)
	got := utf16LECmdline("ab")
	want := []byte{'a', 0x00, 'b', 0x00, 0x00, 0x00}
	if !bytesEqual(got, want) {
		t.Errorf("utf16LECmdline(\"ab\") = % x, want % x", got, want)
	}
}

func TestUtf16LECmdline_Empty(t *testing.T) {
	got := utf16LECmdline("")
	want := []byte{0x00, 0x00}
	if !bytesEqual(got, want) {
		t.Errorf("utf16LECmdline(\"\") = % x, want % x", got, want)
	}
}

func TestUtf16LECmdline_KernelCmdline(t *testing.T) {
	// Realistic Linux cmdline. Verify the trailing NUL and the size
	// formula (LoadOptionsSize = 2*(len(s)) + 2 for pure ASCII).
	s := "console=ttyS0 root=/dev/ram0"
	got := utf16LECmdline(s)
	if want := 2*len(s) + 2; len(got) != want {
		t.Errorf("len(utf16LECmdline(%q)) = %d, want %d", s, len(got), want)
	}
	if got[len(got)-1] != 0x00 || got[len(got)-2] != 0x00 {
		t.Errorf("utf16LECmdline(%q) missing trailing NUL", s)
	}
	for i, r := range []byte(s) {
		if got[2*i] != r || got[2*i+1] != 0x00 {
			t.Errorf("utf16LECmdline: byte pair %d = %02x %02x, want %02x 00",
				i, got[2*i], got[2*i+1], r)
		}
	}
}

func TestUtf16LECmdline_BMPNonASCII(t *testing.T) {
	// U+00E9 "é" — single BMP code unit, two bytes LE: 0xE9 0x00.
	got := utf16LECmdline("é")
	want := []byte{0xE9, 0x00, 0x00, 0x00}
	if !bytesEqual(got, want) {
		t.Errorf("utf16LECmdline(\"é\") = % x, want % x", got, want)
	}
}

func TestUtf16LECmdline_SupplementaryPlane(t *testing.T) {
	// U+1F600 GRINNING FACE -> surrogate pair 0xD83D / 0xDE00.
	// LE bytes: 3D D8 00 DE then NUL.
	got := utf16LECmdline("\U0001F600")
	want := []byte{0x3D, 0xD8, 0x00, 0xDE, 0x00, 0x00}
	if !bytesEqual(got, want) {
		t.Errorf("utf16LECmdline(\"\\U0001F600\") = % x, want % x", got, want)
	}
}

func TestSetLoadOptions_NilHandle(t *testing.T) {
	if err := SetLoadOptions(0, "anything"); err != ErrNilHandle {
		t.Errorf("SetLoadOptions(0, ...) err = %v, want ErrNilHandle", err)
	}
}

func TestSetLoadOptions_EmptyCmdline(t *testing.T) {
	if err := SetLoadOptions(0xDEADBEEF, ""); err != ErrEmptyCmdline {
		t.Errorf("SetLoadOptions(h, \"\") err = %v, want ErrEmptyCmdline", err)
	}
}

func TestSetLoadOptions_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("SetLoadOptions did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("SetLoadOptions panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("SetLoadOptions panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	SetLoadOptions(0xDEADBEEF, "console=ttyS0")
}

func TestErrEmptyCmdline_Message(t *testing.T) {
	if !strings.Contains(ErrEmptyCmdline.Error(), "cmdline") {
		t.Errorf("ErrEmptyCmdline = %q, expected to mention 'cmdline'", ErrEmptyCmdline.Error())
	}
}

func TestErrNilHandle_Message(t *testing.T) {
	if !strings.Contains(ErrNilHandle.Error(), "handle") {
		t.Errorf("ErrNilHandle = %q, expected to mention 'handle'", ErrNilHandle.Error())
	}
}

// The LoadedImage offsets are documented in UEFI 2.10 §9.2 table 9.4
// — assert them so a typo regresses here, not at LoadImage runtime.
func TestLoadedImageOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"Revision", efiLoadedImageRevision, 0},
		{"ParentHandle", efiLoadedImageParentHandle, 8},
		{"SystemTable", efiLoadedImageSystemTable, 16},
		{"DeviceHandle", efiLoadedImageDeviceHandle, 24},
		{"FilePath", efiLoadedImageFilePath, 32},
		{"Reserved", efiLoadedImageReserved, 40},
		{"LoadOptionsSize", efiLoadedImageLoadOptionsSize, 48},
		{"LoadOptions", efiLoadedImageLoadOptions, 56},
		{"ImageBase", efiLoadedImageImageBase, 64},
		{"ImageSize", efiLoadedImageImageSize, 72},
		{"ImageCodeType", efiLoadedImageImageCodeType, 80},
		{"ImageDataType", efiLoadedImageImageDataType, 84},
		{"Unload", efiLoadedImageUnload, 88},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s offset = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// EFI_LOADED_IMAGE_PROTOCOL_GUID round-trip via the helper that
// already parses textual GUIDs (uefiboard/http_protocol_test.go's
// guidFromText). Catches a hex-digit typo in the literal.
func TestLoadedImageProtocolGUID(t *testing.T) {
	want := guidFromText(t, "5b1b31a1-9562-11d2-8e3f-00a0c969723b")
	got := EFILoadedImageProtocolGUID
	if got.Data1 != want.Data1 || got.Data2 != want.Data2 || got.Data3 != want.Data3 {
		t.Errorf("EFILoadedImageProtocolGUID = %+v, want %+v", got, want)
	}
	for i := range got.Data4 {
		if got.Data4[i] != want.Data4[i] {
			t.Errorf("EFILoadedImageProtocolGUID.Data4[%d] = %02x, want %02x",
				i, got.Data4[i], want.Data4[i])
		}
	}
}

func TestAllocatePoolOffset(t *testing.T) {
	if efiBSAllocatePool != 64 {
		t.Errorf("efiBSAllocatePool = %d, want 64", efiBSAllocatePool)
	}
	if efiBSFreePool != 72 {
		t.Errorf("efiBSFreePool = %d, want 72", efiBSFreePool)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
