// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// UDP/IPv4 (RFC 768) for ministack.
//
// On-wire UDP header (8 bytes) + payload:
//
//	+--------+--------+----------+----------+
//	| SrcPort| DstPort| Length   | Checksum |
//	| 2 B    | 2 B    | 2 B      | 2 B      |
//	+--------+--------+----------+----------+
//	| payload (variable, up to MTU - IP - UDP)
//	+-----------------------------------------------+
//
// `Length` covers the UDP header + payload (so min 8, max
// IPv4MTU - IPv4HeaderLen). The checksum covers the IPv4 pseudo-header
// (src, dst, zero, protocol, UDP length), the UDP header (with the
// checksum field treated as zero), and the payload — padded to an even
// number of bytes by treating any trailing odd byte as the high half of
// a final 16-bit word.
//
// On RX a UDP checksum of 0x0000 means "checksum disabled" (RFC 768).
// QEMU's user-mode NAT typically sets a real checksum on outbound
// frames but accepts zero on inbound; we accept both.
//
// Demux:
//
//   - The Stack owns a map[uint16]*UDP4Conn keyed by local port. M4
//     (DHCPv4) only ever opens one Conn (port 68) so a simple
//     local-port map is sufficient. M5 (DNS) opens an ephemeral
//     client port (>= 49152); the same map serves.
//   - Inbound UDP arrives via Stack.handleUDP4 → finds the Conn for the
//     dst-port → enqueues the (src, payload) datagram on a buffered
//     channel.
//   - The channel has capacity 16 — enough for the small bursts the
//     DHCP / DNS exchanges produce. Overflow drops oldest received
//     datagrams (DHCP retries solve transient loss anyway).

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// UDP4HeaderLen is the size of the fixed UDP/IPv4 header.
const UDP4HeaderLen = 8

// UDP4MaxPayload is the largest UDP payload ministack will TX, after
// subtracting the IPv4 + UDP headers from MTU 1500.
const UDP4MaxPayload = IPv4MTU - IPv4HeaderLen - UDP4HeaderLen

// udp4QueueDepth is the per-Conn RX buffer depth. 16 datagrams is more
// than enough for DHCP DORA + DNS lookups; overflow drops oldest.
const udp4QueueDepth = 16

// ErrUDP4HeaderTooShort indicates the supplied buffer is shorter than
// the 8-byte UDP header.
var ErrUDP4HeaderTooShort = errors.New("ministack: UDP header shorter than 8 bytes")

// ErrUDP4BadLength indicates the on-wire Length field is < 8 or exceeds
// the supplied buffer.
var ErrUDP4BadLength = errors.New("ministack: UDP Length field out of range")

// ErrUDP4BadChecksum indicates a UDP checksum mismatch (where checksum
// was non-zero on the wire — zero means disabled per RFC 768).
var ErrUDP4BadChecksum = errors.New("ministack: UDP checksum mismatch")

// ErrUDP4PayloadTooLong indicates an attempt to TX more than
// UDP4MaxPayload bytes in a single datagram.
var ErrUDP4PayloadTooLong = errors.New("ministack: UDP payload exceeds MTU - headers")

// ErrUDP4PortInUse is returned by OpenUDP4 when the requested local
// port is already bound by another Conn on the same Stack.
var ErrUDP4PortInUse = errors.New("ministack: UDP local port already in use")

// ErrUDP4ConnClosed is returned by any UDP4Conn method called after Close.
var ErrUDP4ConnClosed = errors.New("ministack: UDP connection closed")

// ErrUDP4ReadTimeout is returned by ReadFrom when the read deadline
// elapses before a datagram arrives.
var ErrUDP4ReadTimeout = errors.New("ministack: UDP read timed out")

// ErrUDP4InvalidAddr is returned by WriteTo when the destination Addr
// is not a *net.UDPAddr or carries a non-IPv4 IP.
var ErrUDP4InvalidAddr = errors.New("ministack: UDP destination address must be *net.UDPAddr with an IPv4")

// UDP4Header is the parsed view of a UDP header.
type UDP4Header struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

// ParseUDP4 decodes the 8-byte UDP header at the start of `pkt` and
// returns the header plus the payload slice (aliasing pkt[8:Length]).
// Verifies the on-wire checksum against the pseudo-header (RFC 768);
// `src` and `dst` are the IPv4 source / destination from the outer IP
// header, required for the pseudo-header. A wire checksum of 0 means
// "checksum disabled" and is accepted without validation.
func ParseUDP4(src, dst net.IP, pkt []byte) (UDP4Header, []byte, error) {
	if len(pkt) < UDP4HeaderLen {
		return UDP4Header{}, nil, ErrUDP4HeaderTooShort
	}
	h := UDP4Header{
		SrcPort:  binary.BigEndian.Uint16(pkt[0:2]),
		DstPort:  binary.BigEndian.Uint16(pkt[2:4]),
		Length:   binary.BigEndian.Uint16(pkt[4:6]),
		Checksum: binary.BigEndian.Uint16(pkt[6:8]),
	}
	if int(h.Length) < UDP4HeaderLen || int(h.Length) > len(pkt) {
		return UDP4Header{}, nil, ErrUDP4BadLength
	}
	payload := pkt[UDP4HeaderLen:h.Length]
	if h.Checksum != 0 {
		// Validate. Build a buffer with the checksum field zeroed
		// and recompute.
		tmp := make([]byte, h.Length)
		copy(tmp, pkt[:h.Length])
		tmp[6] = 0
		tmp[7] = 0
		got := udp4Checksum(src, dst, tmp)
		if got != h.Checksum {
			return UDP4Header{}, nil, ErrUDP4BadChecksum
		}
	}
	out := append([]byte(nil), payload...)
	return h, out, nil
}

// MarshalUDP4 builds a full UDP/IPv4 datagram (header + payload) and
// stamps the pseudo-header checksum. The returned slice is exactly
// `8 + len(payload)` bytes. Returns ErrUDP4PayloadTooLong if the total
// would exceed UDP4MaxPayload.
func MarshalUDP4(src, dst net.IP, srcPort, dstPort uint16, payload []byte) ([]byte, error) {
	if len(payload) > UDP4MaxPayload {
		return nil, ErrUDP4PayloadTooLong
	}
	total := UDP4HeaderLen + len(payload)
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(total))
	// Checksum field initially zero; computed below.
	copy(buf[UDP4HeaderLen:], payload)
	cksum := udp4Checksum(src, dst, buf)
	// Per RFC 768, a computed checksum of 0 is transmitted as all-ones.
	if cksum == 0 {
		cksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(buf[6:8], cksum)
	return buf, nil
}

// udp4Checksum computes the UDP/IPv4 checksum over the pseudo-header
// (src, dst, zero, protocol=UDP, UDP-length) + the supplied UDP bytes.
// `udp` must have the checksum field zeroed for an initial compute;
// re-summing the wire bytes yields 0 when the supplied checksum is
// correct.
func udp4Checksum(src, dst net.IP, udp []byte) uint16 {
	s4 := src.To4()
	d4 := dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	var pseudo [12]byte
	copy(pseudo[0:4], s4)
	copy(pseudo[4:8], d4)
	pseudo[8] = 0
	pseudo[9] = IPProtoUDP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(udp)))
	// Compose: pseudo-header followed by UDP bytes. We sum across the
	// concatenation via a single buffer (small allocation; called
	// infrequently — UDP is a low-rate path on this stack).
	buf := make([]byte, 0, len(pseudo)+len(udp))
	buf = append(buf, pseudo[:]...)
	buf = append(buf, udp...)
	return InternetChecksum(buf)
}

// udp4Datagram is the value type queued from the RX dispatcher to a
// blocked ReadFrom. `Src` carries the remote IP + port; `Payload` is
// an independent copy of the UDP payload bytes.
type udp4Datagram struct {
	Src     net.UDPAddr
	Payload []byte
}

// UDP4Conn is a bound UDP4 endpoint. Obtained from Stack.OpenUDP4.
// Safe for concurrent ReadFrom / WriteTo; each call serialises
// internally as needed.
type UDP4Conn struct {
	stack     *Stack
	localPort uint16
	queue     chan udp4Datagram

	mu           sync.Mutex
	closed       bool
	readDeadline time.Time // zero = no deadline
}

// LocalPort returns the bound local port.
func (c *UDP4Conn) LocalPort() uint16 {
	return c.localPort
}

// SetReadDeadline records an absolute wall-clock deadline after which a
// blocked ReadFrom returns ErrUDP4ReadTimeout. Passing the zero time
// clears the deadline. Subsequent ReadFrom calls observe the new
// deadline immediately (any in-flight blocked Read sees the old one
// until it wakes).
func (c *UDP4Conn) SetReadDeadline(t time.Time) {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
}

// ReadFrom blocks (subject to the deadline) until one UDP datagram
// arrives or the deadline elapses. Returns the number of bytes copied
// into `buf` (truncated to len(buf) without error if the payload is
// larger), the source UDPAddr, and any error.
func (c *UDP4Conn) ReadFrom(buf []byte) (int, net.Addr, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, nil, ErrUDP4ConnClosed
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	var (
		timerC <-chan time.Time
		timer  *time.Timer
	)
	if !deadline.IsZero() {
		d := time.Until(deadline)
		if d <= 0 {
			return 0, nil, ErrUDP4ReadTimeout
		}
		timer = time.NewTimer(d)
		timerC = timer.C
		defer timer.Stop()
	}

	select {
	case dg, ok := <-c.queue:
		if !ok {
			return 0, nil, ErrUDP4ConnClosed
		}
		n := copy(buf, dg.Payload)
		src := dg.Src
		return n, &src, nil
	case <-timerC:
		return 0, nil, ErrUDP4ReadTimeout
	}
}

// WriteTo sends `payload` as a single UDP datagram to `dst`. `dst` must
// be a *net.UDPAddr with an IPv4 address. The destination IPv4
// 255.255.255.255 is a limited broadcast — the stack sends it via the
// L2 broadcast MAC without consulting ARP (required for DHCP).
func (c *UDP4Conn) WriteTo(payload []byte, dst net.Addr) error {
	udst, ok := dst.(*net.UDPAddr)
	if !ok {
		return ErrUDP4InvalidAddr
	}
	d4 := udst.IP.To4()
	if d4 == nil {
		return ErrUDP4InvalidAddr
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ErrUDP4ConnClosed
	}
	c.mu.Unlock()
	return c.stack.sendUDP4(c.localPort, uint16(udst.Port), d4, payload)
}

// Close releases the bound local port and unblocks any pending
// ReadFrom. Idempotent.
func (c *UDP4Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.mu.Unlock()
	c.stack.releaseUDP4(c.localPort)
	// Closing the queue lets any blocked ReadFrom return promptly.
	close(c.queue)
	return nil
}

// deliver is called by the Stack's RX dispatcher to enqueue an
// incoming datagram. Drops the oldest queued datagram on overflow so
// the dispatcher never blocks.
func (c *UDP4Conn) deliver(dg udp4Datagram) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.mu.Unlock()
	select {
	case c.queue <- dg:
	default:
		// Buffer full. Drop oldest to make room.
		select {
		case <-c.queue:
		default:
		}
		select {
		case c.queue <- dg:
		default:
		}
	}
}
