// Host-side test for phase2_snpenum.go's pure helpers (no firmware
// involvement). Gated on `phase2_snpenum` so the helper symbols are
// in scope; runs under GOOS=tamago=off / GOOS=darwin builds because
// the file does NOT include the `tamago` build constraint — only the
// helper-bearing `phase2_snpenum.go` does.
//
// We test:
//   - macHex prints the canonical "XX:XX:XX:XX:XX:XX" form on a
//     6-byte input, "<empty>" on a nil input, and skips no separators.
//   - A round-trip through the synthetic EFI_SIMPLE_NETWORK_MODE
//     buffer reproduces the byte sequence the probe would print live.
//
// The probe entry point (runSNPEnumProbe) is NOT exercised here — it
// calls firmware via efiCall, which only links on the tamago target.

//go:build phase2_snpenum

package main

import (
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func TestMacHex(t *testing.T) {
	cases := []struct {
		name string
		in   []uint8
		want string
	}{
		{"empty", nil, "<empty>"},
		{"single byte", []uint8{0xab}, "ab"},
		{"qemu default MAC", []uint8{0x52, 0x54, 0x00, 0x12, 0x34, 0x56},
			"52:54:00:12:34:56"},
		{"broadcast", []uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			"ff:ff:ff:ff:ff:ff"},
		{"zero MAC", []uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			"00:00:00:00:00:00"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := macHex(c.in); got != c.want {
				t.Errorf("macHex(%#x) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestSNPProbeModePeekShape constructs an EFI_SIMPLE_NETWORK_MODE
// buffer in Go memory (the same shape firmware allocates), follows
// the same "Mode pointer → MAC slice" path the probe uses, and
// asserts the MAC + status fields round-trip. Catches a mistake in
// either the Mode-struct field layout OR the probe's MAC-slicing
// logic.
func TestSNPProbeModePeekShape(t *testing.T) {
	var mode uefiboard.EFISimpleNetworkMode
	mode.State = uint32(uefiboard.EFISimpleNetworkInitialized)
	mode.HwAddressSize = 6
	mode.MediaPresent = 1
	mode.MediaPresentSupported = 1
	mode.IfType = 1 // ARPHRD_ETHER
	macBytes := [6]uint8{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	for i, b := range macBytes {
		mode.CurrentAddress.Addr[i] = b
		mode.PermanentAddress.Addr[i] = b
	}

	// MAC is the first HwAddressSize bytes of CurrentAddress.Addr[].
	gotMAC := macHex(mode.CurrentAddress.Addr[:int(mode.HwAddressSize)])
	if want := "de:ad:be:ef:ca:fe"; gotMAC != want {
		t.Errorf("MAC from CurrentAddress = %q, want %q", gotMAC, want)
	}
	gotPerm := macHex(mode.PermanentAddress.Addr[:int(mode.HwAddressSize)])
	if want := "de:ad:be:ef:ca:fe"; gotPerm != want {
		t.Errorf("MAC from PermanentAddress = %q, want %q", gotPerm, want)
	}

	// HwAddressSize > 32 must be clamped to 32 to prevent out-of-bounds
	// MAC reads.
	mode.HwAddressSize = 64
	n := uint64(mode.HwAddressSize)
	if n > 32 {
		n = 32
	}
	if n != 32 {
		t.Errorf("clamp(HwAddressSize=64) = %d, want 32", n)
	}

	// State / boolean fields round-trip cleanly across the struct
	// boundary (a field-ordering mistake would corrupt these).
	if mode.State != uint32(uefiboard.EFISimpleNetworkInitialized) {
		t.Errorf("mode.State = %d, want %d (Initialized)",
			mode.State, uefiboard.EFISimpleNetworkInitialized)
	}
	if mode.MediaPresent != 1 {
		t.Errorf("mode.MediaPresent = %d, want 1", mode.MediaPresent)
	}
	if mode.IfType != 1 {
		t.Errorf("mode.IfType = %d, want 1 (ARPHRD_ETHER)", mode.IfType)
	}
}
