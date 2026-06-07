// Host-side tests for http_protocol.go.
//
// Pure type-surface checks. The two things that can go wrong with a
// hand-rolled UEFI GUID transcription are byte ordering and digit
// transpositions; we guard against both by round-tripping the
// canonical textual form (UEFI 2.10 §2.3.1 / RFC 4122 mixed-endian)
// against the struct field layout.
//
// Reference values: MdePkg/Include/Protocol/Http.h (edk2.git
// stable/202408).

package uefiboard

import (
	"encoding/binary"
	"testing"
)

// guidFromText parses the canonical textual form
//
//	XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
//
// (length 36, four hyphens) into an EFIGUID respecting the EFI/RFC-4122
// mixed-endian convention: Data1/Data2/Data3 are little-endian on the
// wire but big-endian in text; Data4 is raw bytes.
func guidFromText(t *testing.T, s string) EFIGUID {
	t.Helper()
	if len(s) != 36 {
		t.Fatalf("guidFromText: expected length 36, got %d (%q)", len(s), s)
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		t.Fatalf("guidFromText: missing/misplaced hyphens in %q", s)
	}
	d1 := parseHex32(t, s[0:8])
	d2 := uint16(parseHex32(t, s[9:13]))
	d3 := uint16(parseHex32(t, s[14:18]))
	var d4 [8]uint8
	d4[0] = uint8(parseHex32(t, s[19:21]))
	d4[1] = uint8(parseHex32(t, s[21:23]))
	for i := 0; i < 6; i++ {
		d4[2+i] = uint8(parseHex32(t, s[24+i*2:24+i*2+2]))
	}
	return EFIGUID{Data1: d1, Data2: d2, Data3: d3, Data4: d4}
}

func parseHex32(t *testing.T, s string) uint32 {
	t.Helper()
	var v uint32
	for _, c := range s {
		var nib uint32
		switch {
		case c >= '0' && c <= '9':
			nib = uint32(c - '0')
		case c >= 'a' && c <= 'f':
			nib = uint32(c-'a') + 10
		case c >= 'A' && c <= 'F':
			nib = uint32(c-'A') + 10
		default:
			t.Fatalf("parseHex32: non-hex char %q", c)
		}
		v = v<<4 | nib
	}
	return v
}

func TestEFIHTTPServiceBindingProtocolGUID(t *testing.T) {
	const text = "bdc8e6af-d9bc-4379-a72a-e0c4e75dae1c"
	want := guidFromText(t, text)
	if EFIHTTPServiceBindingProtocolGUID != want {
		t.Errorf("EFIHTTPServiceBindingProtocolGUID = %+v\nwant %+v\n(text %q)",
			EFIHTTPServiceBindingProtocolGUID, want, text)
	}
}

func TestEFIHTTPProtocolGUID(t *testing.T) {
	const text = "7a59b29b-910b-4171-8242-a85a0df25b5b"
	want := guidFromText(t, text)
	if EFIHTTPProtocolGUID != want {
		t.Errorf("EFIHTTPProtocolGUID = %+v\nwant %+v\n(text %q)",
			EFIHTTPProtocolGUID, want, text)
	}
}

// Serialise a GUID to its 16-byte EFI on-the-wire form and assert the
// well-known byte pattern from the spec. This catches any
// little/big-endian transposition in the Data1..Data3 fields that the
// struct comparison above might miss if `guidFromText` shared a bug
// with the GUID constant.
func guidToBytes(g EFIGUID) [16]byte {
	var b [16]byte
	binary.LittleEndian.PutUint32(b[0:4], g.Data1)
	binary.LittleEndian.PutUint16(b[4:6], g.Data2)
	binary.LittleEndian.PutUint16(b[6:8], g.Data3)
	copy(b[8:16], g.Data4[:])
	return b
}

func TestGUIDWireBytes(t *testing.T) {
	cases := []struct {
		name string
		g    EFIGUID
		want [16]byte
	}{
		{
			"EFIHTTPServiceBindingProtocolGUID",
			EFIHTTPServiceBindingProtocolGUID,
			// bdc8e6af-d9bc-4379-a72a-e0c4e75dae1c on-the-wire:
			// af e6 c8 bd  bc d9  79 43  a7 2a e0 c4 e7 5d ae 1c
			[16]byte{0xaf, 0xe6, 0xc8, 0xbd, 0xbc, 0xd9, 0x79, 0x43,
				0xa7, 0x2a, 0xe0, 0xc4, 0xe7, 0x5d, 0xae, 0x1c},
		},
		{
			"EFIHTTPProtocolGUID",
			EFIHTTPProtocolGUID,
			// 7a59b29b-910b-4171-8242-a85a0df25b5b on-the-wire:
			// 9b b2 59 7a  0b 91  71 41  82 42 a8 5a 0d f2 5b 5b
			[16]byte{0x9b, 0xb2, 0x59, 0x7a, 0x0b, 0x91, 0x71, 0x41,
				0x82, 0x42, 0xa8, 0x5a, 0x0d, 0xf2, 0x5b, 0x5b},
		},
	}
	for _, c := range cases {
		if got := guidToBytes(c.g); got != c.want {
			t.Errorf("%s wire bytes:\n got %#x\nwant %#x", c.name, got, c.want)
		}
	}
}

// Method/version enum ordering must match MdePkg/Include/Protocol/Http.h.
// A typo (e.g. swapping HEAD and PUT) would silently route fetches
// wrong; assert the spec values explicitly.
func TestEFIHTTPMethodOrdering(t *testing.T) {
	cases := []struct {
		got  EFIHTTPMethod
		want EFIHTTPMethod
		name string
	}{
		{EFIHTTPMethodGet, 0, "GET"},
		{EFIHTTPMethodPost, 1, "POST"},
		{EFIHTTPMethodPatch, 2, "PATCH"},
		{EFIHTTPMethodOptions, 3, "OPTIONS"},
		{EFIHTTPMethodConnect, 4, "CONNECT"},
		{EFIHTTPMethodHead, 5, "HEAD"},
		{EFIHTTPMethodPut, 6, "PUT"},
		{EFIHTTPMethodDelete, 7, "DELETE"},
		{EFIHTTPMethodTrace, 8, "TRACE"},
		{EFIHTTPMethodMax, 9, "MAX"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("EFIHTTPMethod %s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEFIHTTPVersionOrdering(t *testing.T) {
	if EFIHTTPVersion10 != 0 {
		t.Errorf("EFIHTTPVersion10 = %d, want 0", EFIHTTPVersion10)
	}
	if EFIHTTPVersion11 != 1 {
		t.Errorf("EFIHTTPVersion11 = %d, want 1", EFIHTTPVersion11)
	}
	if EFIHTTPVersionUnsupported != 2 {
		t.Errorf("EFIHTTPVersionUnsupported = %d, want 2", EFIHTTPVersionUnsupported)
	}
}
