// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// ICMPv4 Echo Request / Echo Reply (RFC 792) for ministack.
//
// On-wire ICMPv4 header (8 bytes) + payload:
//
//	+------+------+----------+----------+----------+
//	| Type | Code | Checksum | Ident    | Sequence |
//	| 1 B  | 1 B  | 2 B      | 2 B      | 2 B      |
//	+------+------+----------+----------+----------+
//	| payload (variable)                            |
//	+-----------------------------------------------+
//
// Type = 8 (Echo Request), 0 (Echo Reply). Code = 0 for both.
//
// The checksum is the one's-complement-of-the-one's-complement-sum of
// the full ICMP message (header + payload) with the checksum field
// treated as zero — same algorithm as the IPv4 header checksum.
// We share InternetChecksum from ipv4.go.
//
// Send/match strategy:
//   - The caller picks a random-ish identifier + sequence; the Stack
//     records (id, seq) → reply channel under its lock.
//   - When the RX dispatcher sees an Echo Reply, it looks up (id, seq)
//     and pushes the parsed reply onto the waiter's channel.
//   - PingOnce times out via the caller-supplied timeout. There is no
//     retry — M3-minimal is "did one ping work, yes or no".

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
)

// ICMPHeaderLen is the size of the fixed ICMPv4 header (type, code,
// checksum, identifier, sequence).
const ICMPHeaderLen = 8

// ICMPv4 types we care about.
const (
	ICMPTypeEchoReply   uint8 = 0
	ICMPTypeEchoRequest uint8 = 8
)

// ErrICMPTooShort indicates the buffer is shorter than the 8-byte
// ICMP header.
var ErrICMPTooShort = errors.New("ministack: ICMP message shorter than 8 bytes")

// ErrICMPBadChecksum indicates a checksum mismatch over the parsed
// ICMP message.
var ErrICMPBadChecksum = errors.New("ministack: ICMP checksum mismatch")

// ICMPEcho is the parsed view of an Echo Request or Echo Reply.
type ICMPEcho struct {
	Type       uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	Sequence   uint16
	Payload    []byte // payload after the 8-byte header (independent copy)
}

// MarshalICMPEcho builds an Echo Request or Echo Reply over the
// supplied identifier/sequence/payload. The checksum is computed over
// header+payload.
func MarshalICMPEcho(msgType uint8, id, seq uint16, payload []byte) []byte {
	buf := make([]byte, ICMPHeaderLen+len(payload))
	buf[0] = msgType
	buf[1] = 0 // code
	// Checksum field initially zero; computed below.
	binary.BigEndian.PutUint16(buf[4:6], id)
	binary.BigEndian.PutUint16(buf[6:8], seq)
	copy(buf[ICMPHeaderLen:], payload)
	cksum := InternetChecksum(buf)
	binary.BigEndian.PutUint16(buf[2:4], cksum)
	return buf
}

// ParseICMPEcho decodes an ICMPv4 Echo Request or Reply message. The
// caller is expected to have already verified the message arrived via
// IP protocol 1 (ICMP); this function validates the checksum and
// returns ErrICMPBadChecksum on mismatch. Type/code aren't restricted
// here — both 0 (reply) and 8 (request) parse fine; the dispatcher
// decides what to do with them.
func ParseICMPEcho(buf []byte) (ICMPEcho, error) {
	if len(buf) < ICMPHeaderLen {
		return ICMPEcho{}, ErrICMPTooShort
	}
	gotCksum := binary.BigEndian.Uint16(buf[2:4])
	// Validate the checksum: recompute over the message with the
	// checksum field zeroed.
	tmp := make([]byte, len(buf))
	copy(tmp, buf)
	tmp[2] = 0
	tmp[3] = 0
	if InternetChecksum(tmp) != gotCksum {
		return ICMPEcho{}, ErrICMPBadChecksum
	}
	payload := append([]byte(nil), buf[ICMPHeaderLen:]...)
	return ICMPEcho{
		Type:       buf[0],
		Code:       buf[1],
		Checksum:   gotCksum,
		Identifier: binary.BigEndian.Uint16(buf[4:6]),
		Sequence:   binary.BigEndian.Uint16(buf[6:8]),
		Payload:    payload,
	}, nil
}

// buildEchoRequestPacket assembles the full IPv4 packet for an ICMP
// Echo Request: IPv4 header (src → dst, proto=1, given id) + ICMP
// header + payload.
func buildEchoRequestPacket(src, dst net.IP, ipID uint16, icmpID, icmpSeq uint16, payload []byte) ([]byte, error) {
	icmp := MarshalICMPEcho(ICMPTypeEchoRequest, icmpID, icmpSeq, payload)
	return MarshalIPv4(src, dst, IPProtoICMP, ipID, icmp)
}
