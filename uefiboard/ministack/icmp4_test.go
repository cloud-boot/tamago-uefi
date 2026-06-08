// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestMarshalAndParseICMPEcho(t *testing.T) {
	payload := []byte("ministack-icmp")
	const id, seq uint16 = 0xCAFE, 7

	buf := MarshalICMPEcho(ICMPTypeEchoRequest, id, seq, payload)
	if got, want := len(buf), ICMPHeaderLen+len(payload); got != want {
		t.Fatalf("length: got %d, want %d", got, want)
	}

	msg, err := ParseICMPEcho(buf)
	if err != nil {
		t.Fatalf("ParseICMPEcho: %v", err)
	}
	if msg.Type != ICMPTypeEchoRequest {
		t.Errorf("Type: got %d, want %d", msg.Type, ICMPTypeEchoRequest)
	}
	if msg.Code != 0 {
		t.Errorf("Code: got %d, want 0", msg.Code)
	}
	if msg.Identifier != id {
		t.Errorf("Identifier: got %#x, want %#x", msg.Identifier, id)
	}
	if msg.Sequence != seq {
		t.Errorf("Sequence: got %d, want %d", msg.Sequence, seq)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Errorf("Payload: got %q, want %q", msg.Payload, payload)
	}
}

func TestICMPChecksumValidatesOnReplay(t *testing.T) {
	buf := MarshalICMPEcho(ICMPTypeEchoReply, 1, 1, []byte("xyz"))
	// Re-summing the wire bytes (with checksum field included) yields 0.
	if got := InternetChecksum(buf); got != 0 {
		t.Errorf("re-checksum of wire bytes: got %#x, want 0", got)
	}
}

func TestParseICMPEchoRejectsShort(t *testing.T) {
	_, err := ParseICMPEcho([]byte{1, 2, 3})
	if err != ErrICMPTooShort {
		t.Errorf("want ErrICMPTooShort, got %v", err)
	}
}

func TestParseICMPEchoDetectsBadChecksum(t *testing.T) {
	buf := MarshalICMPEcho(ICMPTypeEchoRequest, 1, 1, []byte{0xff})
	// Corrupt a payload byte (not the checksum itself).
	buf[ICMPHeaderLen] ^= 0xff
	_, err := ParseICMPEcho(buf)
	if err != ErrICMPBadChecksum {
		t.Errorf("want ErrICMPBadChecksum, got %v", err)
	}
}

func TestBuildEchoRequestPacket(t *testing.T) {
	src := net.IPv4(10, 0, 2, 15)
	dst := net.IPv4(10, 0, 2, 2)
	payload := []byte("M3-mini")

	pkt, err := buildEchoRequestPacket(src, dst, 0x1234, 0x5678, 1, payload)
	if err != nil {
		t.Fatalf("buildEchoRequestPacket: %v", err)
	}

	// The full packet: IPv4 header + ICMP header + payload.
	wantLen := IPv4HeaderLen + ICMPHeaderLen + len(payload)
	if got := len(pkt); got != wantLen {
		t.Fatalf("packet length: got %d, want %d", got, wantLen)
	}

	h, body, err := ParseIPv4(pkt)
	if err != nil {
		t.Fatalf("ParseIPv4: %v", err)
	}
	if h.Protocol != IPProtoICMP {
		t.Errorf("Protocol: got %d, want %d", h.Protocol, IPProtoICMP)
	}
	if !h.Src.Equal(src) {
		t.Errorf("Src: got %v, want %v", h.Src, src)
	}
	if !h.Dst.Equal(dst) {
		t.Errorf("Dst: got %v, want %v", h.Dst, dst)
	}

	msg, err := ParseICMPEcho(body)
	if err != nil {
		t.Fatalf("ParseICMPEcho: %v", err)
	}
	if msg.Type != ICMPTypeEchoRequest {
		t.Errorf("ICMP Type: got %d, want %d", msg.Type, ICMPTypeEchoRequest)
	}
	if msg.Identifier != 0x5678 {
		t.Errorf("ICMP Identifier: got %#x, want %#x", msg.Identifier, 0x5678)
	}
	if msg.Sequence != 1 {
		t.Errorf("ICMP Sequence: got %d, want 1", msg.Sequence)
	}
	if !bytes.Equal(msg.Payload, payload) {
		t.Errorf("ICMP Payload: got %q, want %q", msg.Payload, payload)
	}
}

func TestBuildEchoReplyPacketShape(t *testing.T) {
	src := net.IPv4(10, 0, 2, 2)
	dst := net.IPv4(10, 0, 2, 15)
	pkt, err := buildEchoReplyPacket(src, dst, 0x9999, 0xAAAA, 42, []byte("R"))
	if err != nil {
		t.Fatal(err)
	}
	// The ICMP type byte sits at offset 20 (after the IPv4 header).
	if pkt[IPv4HeaderLen] != ICMPTypeEchoReply {
		t.Errorf("ICMP type byte: got %d, want %d", pkt[IPv4HeaderLen], ICMPTypeEchoReply)
	}
	// IPv4 id stamped.
	if got := binary.BigEndian.Uint16(pkt[4:6]); got != 0x9999 {
		t.Errorf("IP ID: got %#x, want %#x", got, 0x9999)
	}
}

func TestMatchByIdentifierAndSequence(t *testing.T) {
	// Two pings with different (id, seq); a reply with one of them
	// should match exactly one.
	const (
		idA, seqA uint16 = 0x4D53, 1
		idB, seqB uint16 = 0x4D53, 2
	)
	keyA := pingKey(idA, seqA)
	keyB := pingKey(idB, seqB)
	if keyA == keyB {
		t.Fatalf("pingKey collision for different (id,seq) pairs")
	}
	// And keys round-trip the high-low encoding.
	wantA := (uint32(idA) << 16) | uint32(seqA)
	if keyA != wantA {
		t.Errorf("pingKey encoding wrong: got %#x, want %#x", keyA, wantA)
	}
}
