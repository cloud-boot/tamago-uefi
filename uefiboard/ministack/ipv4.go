// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// IPv4 header construct + parse + checksum + minimal route table for
// ministack.
//
// We implement the bare minimum needed for ICMP echo to work against
// QEMU's user-mode NAT:
//
//   - 20-byte fixed header (no IP options).
//   - No fragmentation (DF=1, packets > MTU dropped at send).
//   - TTL set to 64, ToS=0.
//   - Header checksum (RFC 791 §3.1) — one's-complement sum of the
//     header 16-bit halves.
//   - Single-interface route table: one on-link subnet plus an
//     optional default gateway. `Route(dst)` returns the next-hop IP
//     the link layer should ARP for.
//
// IPv6 is intentionally out of scope. M4+ (DHCPv4, DNS) will reuse
// this layer unchanged.

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
)

// IPv4HeaderLen is the size of the fixed (no-options) IPv4 header.
const IPv4HeaderLen = 20

// IPv4 protocol numbers used by ministack. M4 (DHCP) will add UDP=17;
// M5 (TCP) will add TCP=6.
const (
	IPProtoICMP uint8 = 1
	IPProtoTCP  uint8 = 6
	IPProtoUDP  uint8 = 17
)

// IPv4DefaultTTL is the TTL ministack stamps on every outbound packet.
// 64 is the modern Linux default and works fine through QEMU NAT.
const IPv4DefaultTTL uint8 = 64

// IPv4MTU is the maximum IP payload ministack will emit. Frames whose
// IP payload would push the on-wire frame past MTU 1500 are rejected
// at send time with ErrIPv4PacketTooLong.
const IPv4MTU = 1500

// ErrIPv4HeaderTooShort indicates the supplied buffer is shorter than
// the 20-byte fixed IPv4 header.
var ErrIPv4HeaderTooShort = errors.New("ministack: IPv4 header shorter than 20 bytes")

// ErrIPv4NotV4 indicates the version nibble in the parsed header is
// not 4 (we don't support IPv6).
var ErrIPv4NotV4 = errors.New("ministack: IPv4 header version != 4")

// ErrIPv4BadChecksum indicates the checksum field in the parsed header
// doesn't match a recomputed checksum over the (zeroed-checksum) header.
var ErrIPv4BadChecksum = errors.New("ministack: IPv4 header checksum mismatch")

// ErrIPv4PacketTooLong indicates an attempt to send a packet whose
// IP payload would push total length past the MTU.
var ErrIPv4PacketTooLong = errors.New("ministack: IPv4 packet exceeds MTU 1500")

// ErrIPv4InvalidIP indicates a non-4-byte IPv4 address was passed.
var ErrIPv4InvalidIP = errors.New("ministack: IPv4 address must be 4 bytes")

// ErrNoRoute is returned by RouteTable.Lookup when no route matches
// (no on-link match and no default gateway configured).
var ErrNoRoute = errors.New("ministack: no route to host")

// IPv4Header is the parsed view of an IPv4 header. Field semantics
// follow RFC 791 §3.1. We don't expose the IHL field separately —
// only headers with IHL=5 (no options) are produced by Marshal, and
// Parse rejects anything else with ErrIPv4HeaderTooShort (treating
// the option bytes as missing from the buffer length).
type IPv4Header struct {
	TOS      uint8
	TotalLen uint16
	ID       uint16
	Flags    uint8 // top 3 bits of the Flags+FragOffset field
	FragOff  uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	Src      net.IP // 4 bytes (To4())
	Dst      net.IP // 4 bytes (To4())
}

// ParseIPv4 decodes the 20-byte IPv4 header at the start of `pkt` and
// returns an IPv4Header plus the payload slice (aliasing pkt[20:]).
// Returns ErrIPv4HeaderTooShort if the buffer is too small, ErrIPv4NotV4
// if the version nibble isn't 4, or ErrIPv4BadChecksum if the on-wire
// checksum doesn't match. IP options (IHL > 5) are NOT supported.
func ParseIPv4(pkt []byte) (IPv4Header, []byte, error) {
	if len(pkt) < IPv4HeaderLen {
		return IPv4Header{}, nil, ErrIPv4HeaderTooShort
	}
	versionIHL := pkt[0]
	if versionIHL>>4 != 4 {
		return IPv4Header{}, nil, ErrIPv4NotV4
	}
	ihl := int(versionIHL & 0x0F)
	if ihl < 5 {
		return IPv4Header{}, nil, ErrIPv4HeaderTooShort
	}
	if len(pkt) < ihl*4 {
		return IPv4Header{}, nil, ErrIPv4HeaderTooShort
	}
	// Validate the checksum BEFORE returning the parsed view. The
	// checksum covers the header bytes with the checksum field
	// itself treated as zero.
	gotCksum := binary.BigEndian.Uint16(pkt[10:12])
	var zeroed [IPv4HeaderLen]byte
	copy(zeroed[:], pkt[:IPv4HeaderLen])
	zeroed[10] = 0
	zeroed[11] = 0
	if InternetChecksum(zeroed[:]) != gotCksum {
		return IPv4Header{}, nil, ErrIPv4BadChecksum
	}

	flagsFrag := binary.BigEndian.Uint16(pkt[6:8])
	h := IPv4Header{
		TOS:      pkt[1],
		TotalLen: binary.BigEndian.Uint16(pkt[2:4]),
		ID:       binary.BigEndian.Uint16(pkt[4:6]),
		Flags:    uint8(flagsFrag >> 13),
		FragOff:  flagsFrag & 0x1FFF,
		TTL:      pkt[8],
		Protocol: pkt[9],
		Checksum: gotCksum,
		Src:      net.IP(append([]byte(nil), pkt[12:16]...)),
		Dst:      net.IP(append([]byte(nil), pkt[16:20]...)),
	}
	// Skip past the (always-5-word) header to return the payload.
	// We don't accept options, so payload starts at byte 20.
	return h, pkt[IPv4HeaderLen:], nil
}

// MarshalIPv4 builds a full IPv4 packet (header + payload). `id` is
// the IP identification value (caller-supplied; ministack increments
// a counter per send). Returns ErrIPv4PacketTooLong if the total
// length would exceed MTU 1500. Sets TTL=64, ToS=0, DF=1 (no
// fragmentation), FragOff=0. Computes and writes the header checksum.
func MarshalIPv4(src, dst net.IP, protocol uint8, id uint16, payload []byte) ([]byte, error) {
	s4 := src.To4()
	d4 := dst.To4()
	if s4 == nil || d4 == nil {
		return nil, ErrIPv4InvalidIP
	}
	total := IPv4HeaderLen + len(payload)
	if total > IPv4MTU {
		return nil, ErrIPv4PacketTooLong
	}
	pkt := make([]byte, total)
	pkt[0] = (4 << 4) | 5 // version=4, IHL=5
	pkt[1] = 0            // ToS=0
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	// DF=1 (don't fragment), MF=0, FragOff=0 → flags+frag = 0x4000.
	binary.BigEndian.PutUint16(pkt[6:8], 0x4000)
	pkt[8] = IPv4DefaultTTL
	pkt[9] = protocol
	// Checksum field initially zero; we compute and overwrite below.
	copy(pkt[12:16], s4)
	copy(pkt[16:20], d4)
	copy(pkt[IPv4HeaderLen:], payload)
	cksum := InternetChecksum(pkt[:IPv4HeaderLen])
	binary.BigEndian.PutUint16(pkt[10:12], cksum)
	return pkt, nil
}

// InternetChecksum computes the 16-bit one's-complement-of-the-one's-
// complement-sum of `data` (RFC 1071). Used for both the IPv4 header
// checksum and the ICMPv4 checksum. Operates on an odd-length input
// by treating the final byte as the high half of a final 16-bit word.
func InternetChecksum(data []byte) uint16 {
	var sum uint32
	i := 0
	for ; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if i < len(data) {
		// Odd byte — treat as high half of a 16-bit word, low half zero.
		sum += uint32(data[i]) << 8
	}
	// Fold the carry bits into the low 16.
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

// RouteTable is a tiny single-interface route table. Two routes are
// supported:
//
//   - On-link: an IPv4 subnet (Local + Mask). Destinations matching
//     this subnet are sent directly (next-hop = destination).
//   - Default gateway: any non-on-link destination uses Gateway as
//     the next-hop.
//
// Both routes are optional. Lookup returns ErrNoRoute if neither
// applies. The table is intentionally not thread-safe — callers wrap
// it in the Stack's lock.
type RouteTable struct {
	// Local is the source address ministack uses for outbound
	// packets. set via Stack.SetIPv4Address.
	Local net.IP
	// Mask is the on-link subnet mask matching Local.
	Mask net.IPMask
	// Gateway is the default-route next-hop (zero IP = no gateway).
	Gateway net.IP
}

// SetLocal records the local address + subnet mask on the table.
// `addr` and `mask` are 4-byte IPv4 / IPMask values.
func (r *RouteTable) SetLocal(addr net.IP, mask net.IPMask) error {
	a4 := addr.To4()
	if a4 == nil {
		return ErrIPv4InvalidIP
	}
	if len(mask) != 4 {
		return ErrIPv4InvalidIP
	}
	r.Local = a4
	r.Mask = append(net.IPMask(nil), mask...)
	return nil
}

// SetGateway records the default-route next-hop. Pass nil/zero IP to
// clear (no default route).
func (r *RouteTable) SetGateway(gw net.IP) error {
	if gw == nil {
		r.Gateway = nil
		return nil
	}
	g4 := gw.To4()
	if g4 == nil {
		return ErrIPv4InvalidIP
	}
	r.Gateway = g4
	return nil
}

// Lookup returns the next-hop IP for `dst`: dst itself if it's on the
// local subnet, the gateway otherwise. Returns ErrNoRoute if neither
// applies (no local set, or off-link with no gateway).
func (r *RouteTable) Lookup(dst net.IP) (net.IP, error) {
	d4 := dst.To4()
	if d4 == nil {
		return nil, ErrIPv4InvalidIP
	}
	if r.Local != nil && r.Mask != nil {
		if subnetContains(r.Local, r.Mask, d4) {
			return d4, nil
		}
	}
	if r.Gateway != nil {
		return r.Gateway, nil
	}
	return nil, ErrNoRoute
}

// subnetContains returns true when `target` is in the subnet defined
// by `local & mask`.
func subnetContains(local net.IP, mask net.IPMask, target net.IP) bool {
	if len(local) != 4 || len(mask) != 4 || len(target) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if (local[i] & mask[i]) != (target[i] & mask[i]) {
			return false
		}
	}
	return true
}
