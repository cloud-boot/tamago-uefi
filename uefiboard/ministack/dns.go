// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// DNS A-record resolver (RFC 1035) for ministack.
//
// On-wire DNS message (12-byte header + question + answer sections):
//
//	+--+--+--+--+--+--+--+--+--+--+--+--+
//	|  ID   | QR/Opcode | QD | AN | NS | AR |
//	+--+--+--+--+--+--+--+--+--+--+--+--+
//	| ... QUESTION ... ANSWER ... |
//	+----+----+----+----+----+----+
//
// Wire format quirks (relevant to A-record lookup):
//
//   - QNAME is a sequence of length-prefixed labels terminated by a
//     zero byte. `example.com` → "\x07example\x03com\x00".
//   - QTYPE A = 1; QCLASS IN = 1.
//   - Answers may use message compression (RFC 1035 §4.1.4): a label
//     starting with byte 0xC0..0xFF is a 14-bit back-pointer into the
//     same message. We follow back-pointers when reading; we never
//     emit compressed labels ourselves.
//   - We accept only A records (TYPE=1) in the ANSWER section; CNAME
//     chains aren't traversed (QEMU SLIRP forwards to the host resolver
//     which returns a direct A record for the names M5 cares about).
//
// Demux:
//
//   - The resolver opens a fresh ephemeral UDP/IPv4 source port via
//     OpenUDP4, sends the query, and ReadFrom-blocks for a reply with
//     a matching transaction ID.
//   - Mismatched IDs are silently consumed; the ReadFrom timer enforces
//     the overall deadline.

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"time"
)

// DNS protocol constants.
const (
	dnsHeaderLen     = 12
	dnsTypeA         uint16 = 1
	dnsTypeCNAME     uint16 = 5
	dnsClassIN       uint16 = 1
	dnsFlagResponse  uint16 = 0x8000
	dnsFlagRD        uint16 = 0x0100 // recursion desired
	dnsRcodeMask     uint16 = 0x000F
	dnsMaxLabelLen   = 63
	dnsMaxNameLen    = 255
	dnsClientPortLow uint16 = 49152
)

// DNS-resolver errors.
var (
	ErrDNSTimeout       = errors.New("ministack: DNS query timed out")
	ErrDNSBadFormat     = errors.New("ministack: DNS message malformed")
	ErrDNSEmptyAnswer   = errors.New("ministack: DNS reply contained no A record")
	ErrDNSRcode         = errors.New("ministack: DNS server returned an error rcode")
	ErrDNSNameTooLong   = errors.New("ministack: DNS name longer than 255 bytes")
	ErrDNSLabelTooLong  = errors.New("ministack: DNS label longer than 63 bytes")
	ErrDNSCompressLoop  = errors.New("ministack: DNS compression-pointer loop detected")
	ErrDNSInvalidServer = errors.New("ministack: DNS server address must be IPv4")
)

// dnsQueryRoot is the seed value mixed into the per-call transaction
// ID. Deterministic so tests can pin the on-wire bytes.
const dnsQueryRoot uint16 = 0x4D53 // "MS"

// dnsIDFromMAC produces a 16-bit transaction ID by mixing the MAC,
// a seed, and a per-call salt (e.g. low bits of the local port). For
// boot-time DNS we don't need cryptographic randomness; we just need
// distinct IDs across concurrent queries (the M5 client only ever
// fires one at a time, but the salt keeps successive queries from a
// retry burst distinguishable).
func dnsIDFromMAC(mac net.HardwareAddr, seed, salt uint16) uint16 {
	if len(mac) < 6 {
		return seed ^ salt
	}
	macHi := binary.BigEndian.Uint16(mac[0:2])
	macLo := binary.BigEndian.Uint16(mac[4:6])
	return seed ^ salt ^ macHi ^ macLo
}

// encodeDNSName writes `name` into a buffer in DNS wire form. Returns
// ErrDNSNameTooLong if total length (including length bytes + trailing
// zero) exceeds 255, or ErrDNSLabelTooLong if any single label exceeds
// 63 bytes.
func encodeDNSName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	labels := strings.Split(name, ".")
	total := 1 // trailing zero
	for _, l := range labels {
		if len(l) > dnsMaxLabelLen {
			return nil, ErrDNSLabelTooLong
		}
		total += 1 + len(l)
	}
	if total > dnsMaxNameLen {
		return nil, ErrDNSNameTooLong
	}
	out := make([]byte, 0, total)
	for _, l := range labels {
		out = append(out, byte(len(l)))
		out = append(out, l...)
	}
	out = append(out, 0)
	return out, nil
}

// buildDNSQuery serialises an A-record query for `name` with transaction
// ID `id`. The query is a single QD entry with QTYPE=A, QCLASS=IN.
// Sets the RD (recursion desired) flag — QEMU SLIRP's DNS forwarder
// requires it.
func buildDNSQuery(id uint16, name string) ([]byte, error) {
	qname, err := encodeDNSName(name)
	if err != nil {
		return nil, err
	}
	total := dnsHeaderLen + len(qname) + 4 // QTYPE + QCLASS
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], dnsFlagRD)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QDCOUNT
	// AN/NS/AR all zero on a query.
	copy(buf[dnsHeaderLen:], qname)
	off := dnsHeaderLen + len(qname)
	binary.BigEndian.PutUint16(buf[off:off+2], dnsTypeA)
	binary.BigEndian.PutUint16(buf[off+2:off+4], dnsClassIN)
	return buf, nil
}

// parseDNSName decodes a wire-format name starting at offset `start` in
// `pkt`. Follows compression pointers (RFC 1035 §4.1.4). Returns the
// decoded name (dotted, no trailing dot) and the offset of the first
// byte AFTER the encoded name in the original packet (which may
// precede or coincide with a pointer target). Caps pointer chain length
// to avoid loops.
func parseDNSName(pkt []byte, start int) (string, int, error) {
	if start >= len(pkt) {
		return "", 0, ErrDNSBadFormat
	}
	var labels []string
	off := start
	postPointer := -1
	chain := 0
	for {
		if off >= len(pkt) {
			return "", 0, ErrDNSBadFormat
		}
		b := pkt[off]
		if b == 0 {
			off++
			break
		}
		if b&0xC0 == 0xC0 {
			// Compression pointer — 14-bit absolute offset.
			if off+1 >= len(pkt) {
				return "", 0, ErrDNSBadFormat
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:off+2]) & 0x3FFF)
			if postPointer == -1 {
				postPointer = off + 2
			}
			chain++
			if chain > 16 {
				return "", 0, ErrDNSCompressLoop
			}
			off = ptr
			continue
		}
		if int(b)+off+1 > len(pkt) {
			return "", 0, ErrDNSBadFormat
		}
		labels = append(labels, string(pkt[off+1:off+1+int(b)]))
		off += 1 + int(b)
	}
	end := off
	if postPointer != -1 {
		end = postPointer
	}
	return strings.Join(labels, "."), end, nil
}

// parseDNSAnswerForA scans the supplied DNS reply for the first A
// record in the ANSWER section. Returns the IPv4 address or
// ErrDNSEmptyAnswer if none present.
//
// We don't traverse CNAME chains; if the reply contains "name → CNAME
// → A", we accept the inline A record (QEMU SLIRP's DNS forwarder
// typically returns both for short names; if it ever doesn't, the
// caller is welcome to add a second resolve step).
func parseDNSAnswerForA(pkt []byte, wantID uint16) (net.IP, error) {
	if len(pkt) < dnsHeaderLen {
		return nil, ErrDNSBadFormat
	}
	gotID := binary.BigEndian.Uint16(pkt[0:2])
	if gotID != wantID {
		return nil, ErrDNSBadFormat
	}
	flags := binary.BigEndian.Uint16(pkt[2:4])
	if flags&dnsFlagResponse == 0 {
		return nil, ErrDNSBadFormat
	}
	if rcode := flags & dnsRcodeMask; rcode != 0 {
		return nil, ErrDNSRcode
	}
	qdcount := binary.BigEndian.Uint16(pkt[4:6])
	ancount := binary.BigEndian.Uint16(pkt[6:8])
	off := dnsHeaderLen
	// Skip the QUESTION section.
	for i := uint16(0); i < qdcount; i++ {
		_, next, err := parseDNSName(pkt, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+4 > len(pkt) {
			return nil, ErrDNSBadFormat
		}
		off += 4 // QTYPE + QCLASS
	}
	// Walk the ANSWER section for the first A record.
	for i := uint16(0); i < ancount; i++ {
		_, next, err := parseDNSName(pkt, off)
		if err != nil {
			return nil, err
		}
		off = next
		if off+10 > len(pkt) {
			return nil, ErrDNSBadFormat
		}
		rtype := binary.BigEndian.Uint16(pkt[off : off+2])
		rclass := binary.BigEndian.Uint16(pkt[off+2 : off+4])
		// off+4..off+8 is TTL (32 bits) — we ignore.
		rdlen := binary.BigEndian.Uint16(pkt[off+8 : off+10])
		off += 10
		if off+int(rdlen) > len(pkt) {
			return nil, ErrDNSBadFormat
		}
		if rtype == dnsTypeA && rclass == dnsClassIN && rdlen == 4 {
			ip := append(net.IP(nil), pkt[off:off+4]...)
			return ip, nil
		}
		off += int(rdlen)
	}
	return nil, ErrDNSEmptyAnswer
}

// ResolveA resolves `name` to an IPv4 address by querying the supplied
// DNS server. Opens a fresh ephemeral UDP/IPv4 socket, sends an
// A-record query, and waits up to `timeout` for the reply.
//
// Returns ErrIPv4InvalidIP if `dnsServer` is non-IPv4,
// ErrDNSTimeout if no matching reply arrives,
// ErrDNSEmptyAnswer if the reply doesn't contain an A record.
func (s *Stack) ResolveA(name string, dnsServer net.IP, timeout time.Duration) (net.IP, error) {
	d4 := dnsServer.To4()
	if d4 == nil {
		return nil, ErrDNSInvalidServer
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStackClosed
	}
	mac := s.link.MAC()
	s.mu.Unlock()

	// Allocate an ephemeral UDP port. We scan for an unused one in the
	// 49152..65535 range; reusing the TCP rover is fine since the maps
	// are separate.
	var conn *UDP4Conn
	var localPort uint16
	for i := uint16(0); i < 1024; i++ {
		candidate := dnsClientPortLow + i
		c, err := s.OpenUDP4(candidate)
		if err == nil {
			conn = c
			localPort = candidate
			break
		}
		if err != ErrUDP4PortInUse {
			return nil, err
		}
	}
	if conn == nil {
		return nil, ErrUDP4PortInUse
	}
	defer conn.Close()

	id := dnsIDFromMAC(mac, dnsQueryRoot, localPort)
	query, err := buildDNSQuery(id, name)
	if err != nil {
		return nil, err
	}
	dst := &net.UDPAddr{IP: d4, Port: 53}
	if err := conn.WriteTo(query, dst); err != nil {
		return nil, err
	}

	deadline := time.Now().Add(timeout)
	buf := make([]byte, 1500)
	checker := newDeadlineChecker(timeout)
	for !checker.expired() {
		checker.tick()
		conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFrom(buf)
		if err == ErrUDP4ReadTimeout {
			return nil, ErrDNSTimeout
		}
		if err != nil {
			return nil, err
		}
		ip, perr := parseDNSAnswerForA(buf[:n], id)
		if perr == ErrDNSBadFormat {
			// Could be a reply with the wrong ID, or stray traffic.
			// Drop and keep waiting.
			continue
		}
		if perr != nil {
			return nil, perr
		}
		return ip, nil
	}
	return nil, ErrDNSTimeout
}
