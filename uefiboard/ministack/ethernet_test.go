// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"net"
	"testing"
)

func TestMarshalAndParseEthernetRoundTrip(t *testing.T) {
	dst := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	src := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	payload := []byte("ministack-roundtrip")

	frame, err := MarshalEthernet(dst, src, EtherTypeIPv4, payload)
	if err != nil {
		t.Fatalf("MarshalEthernet: %v", err)
	}
	if got, want := len(frame), EthernetHeaderLen+len(payload); got != want {
		t.Fatalf("frame length: got %d, want %d", got, want)
	}

	parsed, err := ParseEthernet(frame)
	if err != nil {
		t.Fatalf("ParseEthernet: %v", err)
	}
	if !bytes.Equal(parsed.Dst, dst) {
		t.Errorf("Dst: got %v, want %v", parsed.Dst, dst)
	}
	if !bytes.Equal(parsed.Src, src) {
		t.Errorf("Src: got %v, want %v", parsed.Src, src)
	}
	if parsed.EtherType != EtherTypeIPv4 {
		t.Errorf("EtherType: got %#x, want %#x", parsed.EtherType, EtherTypeIPv4)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Errorf("Payload: got %q, want %q", parsed.Payload, payload)
	}
}

func TestMarshalEthernetRejectsBadMAC(t *testing.T) {
	dst := net.HardwareAddr{1, 2, 3} // too short
	src := net.HardwareAddr{1, 2, 3, 4, 5, 6}
	_, err := MarshalEthernet(dst, src, EtherTypeIPv4, nil)
	if err != ErrInvalidMAC {
		t.Fatalf("want ErrInvalidMAC, got %v", err)
	}
	// Bad src too.
	_, err = MarshalEthernet(src, dst, EtherTypeIPv4, nil)
	if err != ErrInvalidMAC {
		t.Fatalf("want ErrInvalidMAC, got %v", err)
	}
}

func TestMarshalEthernetRejectsOversize(t *testing.T) {
	dst := net.HardwareAddr{1, 1, 1, 1, 1, 1}
	src := net.HardwareAddr{2, 2, 2, 2, 2, 2}
	payload := make([]byte, MaxFrameLen) // header + this > MaxFrameLen
	_, err := MarshalEthernet(dst, src, EtherTypeIPv4, payload)
	if err != ErrFrameTooLong {
		t.Fatalf("want ErrFrameTooLong, got %v", err)
	}
}

func TestParseEthernetRejectsTooShort(t *testing.T) {
	_, err := ParseEthernet([]byte{1, 2, 3, 4, 5})
	if err != ErrFrameTooShort {
		t.Fatalf("want ErrFrameTooShort, got %v", err)
	}
}

func TestIsBroadcastAndZero(t *testing.T) {
	if !IsBroadcast(BroadcastMAC) {
		t.Errorf("BroadcastMAC should report broadcast")
	}
	if IsBroadcast(net.HardwareAddr{1, 2, 3, 4, 5, 6}) {
		t.Errorf("non-broadcast reported as broadcast")
	}
	if IsBroadcast(net.HardwareAddr{0xff, 0xff, 0xff}) {
		t.Errorf("short MAC reported as broadcast")
	}
	if !IsZeroMAC(net.HardwareAddr{0, 0, 0, 0, 0, 0}) {
		t.Errorf("zero MAC should report zero")
	}
	if IsZeroMAC(net.HardwareAddr{0, 0, 0, 0, 0, 1}) {
		t.Errorf("non-zero MAC reported as zero")
	}
	if IsZeroMAC(net.HardwareAddr{0, 0, 0}) {
		t.Errorf("short MAC should not report zero")
	}
}
