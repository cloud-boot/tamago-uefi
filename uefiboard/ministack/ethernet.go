// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Ethernet II frame parse + build helpers for ministack.
//
// An Ethernet II frame on the wire is:
//
//	+--------+--------+----------+----------+
//	|  dst   |  src   | ethType  | payload  |
//	| 6 byte | 6 byte | 2 byte   | 46..1500 |
//	+--------+--------+----------+----------+
//
// The trailing FCS (4-byte CRC) is added/checked by the link hardware
// (virtio-net does that for us), so this file deals exclusively with
// the 14-byte L2 header + the payload bytes the upper layers care
// about. The minimum 46-byte payload pad is also left to the link
// (virtio-net does NOT enforce it; QEMU's user-mode NAT accepts short
// frames).
//
// We expose a tiny `EthernetFrame` struct (no allocations on the hot
// path: callers fill in fields directly and call `MarshalTo`), plus
// the two EtherTypes ministack actually cares about: ARP and IPv4.
// Anything else is dropped by `Stack.dispatch`.

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
)

// EtherType is the 16-bit identifier in the L2 header that tells us
// which upper-layer protocol the payload belongs to. Only the two
// EtherTypes ministack handles are defined here; if M4/M5 ever adds
// IPv6 or VLAN tagging this is where the constants land.
const (
	// EtherTypeIPv4 (0x0800) selects the IPv4 layer.
	EtherTypeIPv4 uint16 = 0x0800
	// EtherTypeARP (0x0806) selects the ARP layer.
	EtherTypeARP uint16 = 0x0806
)

// EthernetHeaderLen is the fixed 14-byte L2 header size.
const EthernetHeaderLen = 14

// MaxFrameLen is the maximum Ethernet II frame size ministack accepts.
// MTU 1500 payload + 14-byte L2 header. Frames larger than this are
// dropped at parse time (we don't implement fragmentation).
const MaxFrameLen = 1514

// ErrFrameTooShort is returned by ParseEthernet when the input buffer
// is shorter than the 14-byte L2 header.
var ErrFrameTooShort = errors.New("ministack: ethernet frame shorter than 14 bytes")

// ErrFrameTooLong is returned by MarshalEthernet when the payload
// would push the total frame size past MaxFrameLen.
var ErrFrameTooLong = errors.New("ministack: ethernet frame longer than MTU 1500 + 14B header")

// EthernetFrame is the parsed view of an L2 frame: 14-byte header
// plus the payload as a borrowed slice into the original buffer.
type EthernetFrame struct {
	Dst       net.HardwareAddr // 6 bytes
	Src       net.HardwareAddr // 6 bytes
	EtherType uint16
	Payload   []byte // borrowed; caller must copy before retaining
}

// ParseEthernet decodes the L2 header at the start of `frame` and
// returns an EthernetFrame whose Payload aliases the original buffer
// past byte 14. Returns ErrFrameTooShort if the buffer is too small.
// The MAC slices are independent copies (length 6) so the caller can
// reuse the input buffer.
func ParseEthernet(frame []byte) (EthernetFrame, error) {
	if len(frame) < EthernetHeaderLen {
		return EthernetFrame{}, ErrFrameTooShort
	}
	dst := make(net.HardwareAddr, 6)
	src := make(net.HardwareAddr, 6)
	copy(dst, frame[0:6])
	copy(src, frame[6:12])
	return EthernetFrame{
		Dst:       dst,
		Src:       src,
		EtherType: binary.BigEndian.Uint16(frame[12:14]),
		Payload:   frame[EthernetHeaderLen:],
	}, nil
}

// MarshalEthernet builds an L2 frame from the supplied header fields
// and payload. The returned slice is exactly `14 + len(payload)`
// bytes. Returns ErrFrameTooLong if that would exceed MaxFrameLen.
// `dst` and `src` are required to be 6-byte MAC addresses; shorter
// or longer inputs are rejected with ErrInvalidMAC.
func MarshalEthernet(dst, src net.HardwareAddr, etherType uint16, payload []byte) ([]byte, error) {
	if len(dst) != 6 || len(src) != 6 {
		return nil, ErrInvalidMAC
	}
	total := EthernetHeaderLen + len(payload)
	if total > MaxFrameLen {
		return nil, ErrFrameTooLong
	}
	frame := make([]byte, total)
	copy(frame[0:6], dst)
	copy(frame[6:12], src)
	binary.BigEndian.PutUint16(frame[12:14], etherType)
	copy(frame[EthernetHeaderLen:], payload)
	return frame, nil
}

// ErrInvalidMAC is returned when a passed-in MAC address is not the
// canonical 6-byte EUI-48 length.
var ErrInvalidMAC = errors.New("ministack: MAC address must be 6 bytes")

// BroadcastMAC is the L2 broadcast destination (used by ARP requests).
var BroadcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

// IsBroadcast reports whether the given MAC is the L2 broadcast
// destination ff:ff:ff:ff:ff:ff.
func IsBroadcast(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0xff {
			return false
		}
	}
	return true
}

// IsZeroMAC reports whether the given MAC is the all-zero placeholder
// (used by ARP requests where the target hardware address is unknown).
func IsZeroMAC(mac net.HardwareAddr) bool {
	if len(mac) != 6 {
		return false
	}
	for _, b := range mac {
		if b != 0 {
			return false
		}
	}
	return true
}
