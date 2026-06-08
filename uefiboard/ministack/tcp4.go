// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// TCP/IPv4 (RFC 793 subset) client-side implementation for ministack.
//
// Scope of this M5 implementation:
//
//   - Client-side only: SYN → SYN-ACK → ACK → data → FIN → ACK → FIN
//     → ACK. No passive listen, no accept. Enough for short HTTP/1.1
//     GETs against a known endpoint.
//   - Header parse + build (sequence, acknowledgment, flags, window,
//     checksum with the IPv4 pseudo-header).
//   - Per-connection TCB carrying snd.nxt / snd.una / rcv.nxt /
//     snd.wnd / rcv.wnd plus a small reassembly buffer keyed on seq.
//   - State machine: CLOSED → SYN_SENT → ESTABLISHED → FIN_WAIT_1 →
//     FIN_WAIT_2 → TIME_WAIT → CLOSED. The peer-initiated half is
//     ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED.
//   - Send path segments payloads at the MSS boundary (1460 for an
//     MTU-1500 IPv4 link, minus options we never include). One-shot
//     retransmit on a 1-second timeout per outstanding segment; after
//     three attempts the call surfaces ErrTCP4Timeout.
//   - Fixed receive window (32 KiB) — no slow start, no congestion
//     control. Sufficient for the boot-time HTTP GETs M5/M7 perform.
//   - Out-of-order segments are queued in a small fixed array; we
//     deliver in-order bytes to the application as their predecessors
//     fill the gap. Segments past the window are dropped (the peer
//     will retransmit).
//
// Wire layout (RFC 793 §3.1, 20-byte fixed header + payload):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|          Source Port          |       Destination Port        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                        Sequence Number                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Acknowledgment Number                      |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|  Data |          |U|A|P|R|S|F|                                |
//	| Offset|  Reserved|R|C|S|S|Y|I|         Window                 |
//	|       |          |G|K|H|T|N|N|                                |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|           Checksum            |         Urgent Pointer        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Options                    |    Padding    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                             data                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// Demux:
//
//   - The Stack owns a map[uint16]*TCP4Conn keyed by local port (only
//     one TCB per local port — fine for the client side, where each
//     DialTCP4 picks a fresh ephemeral port). Inbound segments are
//     dispatched to the Conn matching the destination port; the Conn
//     verifies the (remoteIP, remotePort) tuple before delivering.
//   - Segments with no matching Conn are dropped silently (M5 doesn't
//     emit RST for unsolicited segments — production stacks do; the
//     boot-time client doesn't need that fidelity).

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// TCP4HeaderLen is the size of the fixed (no-options) TCP header.
const TCP4HeaderLen = 20

// TCP4DefaultMSS is the maximum segment size ministack will TX. With a
// 1500-byte MTU and a 20-byte IPv4 + 20-byte TCP header, 1460 bytes of
// payload fit. We don't negotiate MSS via TCP options — the peer's MSS
// announcement is also ignored. Both sides default to the standard
// 536-1460 range; QEMU SLIRP accepts anything.
const TCP4DefaultMSS = 1460

// TCP4DefaultWindow is the receive window ministack advertises. 32 KiB
// is enough for the short HTTP GETs M5/M7 perform without ever stalling
// the sender.
const TCP4DefaultWindow uint16 = 32 * 1024

// TCP4SegmentRetransmitTimeout is the per-segment retransmit timer. A
// segment is retransmitted up to TCP4MaxRetransmits times before the
// call surfaces ErrTCP4Timeout.
const TCP4SegmentRetransmitTimeout = 1 * time.Second

// TCP4MaxRetransmits is the maximum number of retransmits per segment
// before declaring the connection dead.
const TCP4MaxRetransmits = 3

// TCP4ReassemblyDepth bounds the out-of-order reassembly queue. Eight
// queued segments is enough for the small bursts QEMU SLIRP produces.
const TCP4ReassemblyDepth = 8

// TCP flag bits (RFC 793 §3.1).
const (
	TCPFlagFIN uint8 = 0x01
	TCPFlagSYN uint8 = 0x02
	TCPFlagRST uint8 = 0x04
	TCPFlagPSH uint8 = 0x08
	TCPFlagACK uint8 = 0x10
	TCPFlagURG uint8 = 0x20
)

// TCP connection states (RFC 793 §3.2).
type tcp4State uint8

const (
	tcpClosed tcp4State = iota
	tcpSynSent
	tcpEstablished
	tcpFinWait1
	tcpFinWait2
	tcpCloseWait
	tcpClosing
	tcpLastAck
	tcpTimeWait
)

func (s tcp4State) String() string {
	switch s {
	case tcpClosed:
		return "CLOSED"
	case tcpSynSent:
		return "SYN_SENT"
	case tcpEstablished:
		return "ESTABLISHED"
	case tcpFinWait1:
		return "FIN_WAIT_1"
	case tcpFinWait2:
		return "FIN_WAIT_2"
	case tcpCloseWait:
		return "CLOSE_WAIT"
	case tcpClosing:
		return "CLOSING"
	case tcpLastAck:
		return "LAST_ACK"
	case tcpTimeWait:
		return "TIME_WAIT"
	default:
		return "UNKNOWN"
	}
}

// Errors surfaced by the TCP4 layer.
var (
	ErrTCP4HeaderTooShort = errors.New("ministack: TCP header shorter than 20 bytes")
	ErrTCP4BadChecksum    = errors.New("ministack: TCP checksum mismatch")
	ErrTCP4PortInUse      = errors.New("ministack: TCP local port already in use")
	ErrTCP4ConnClosed     = errors.New("ministack: TCP connection closed")
	ErrTCP4Timeout        = errors.New("ministack: TCP operation timed out")
	ErrTCP4ConnRefused    = errors.New("ministack: TCP connection refused (RST)")
	ErrTCP4InvalidAddr    = errors.New("ministack: TCP destination must be IPv4")
	ErrTCP4NotConnected   = errors.New("ministack: TCP connection not established")
)

// TCP4Header is the parsed view of a TCP header (fixed fields only;
// we never emit or parse TCP options on this stack).
type TCP4Header struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8 // in 32-bit words; 5 = no options
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

// ParseTCP4 decodes the TCP header at the start of `pkt` and returns
// the header, the payload slice (an independent copy), and any error.
// `src` and `dst` are the IPv4 source / destination from the outer IP
// header, required to validate the pseudo-header checksum.
func ParseTCP4(src, dst net.IP, pkt []byte) (TCP4Header, []byte, error) {
	if len(pkt) < TCP4HeaderLen {
		return TCP4Header{}, nil, ErrTCP4HeaderTooShort
	}
	dataOff := pkt[12] >> 4
	hdrLen := int(dataOff) * 4
	if hdrLen < TCP4HeaderLen || hdrLen > len(pkt) {
		return TCP4Header{}, nil, ErrTCP4HeaderTooShort
	}
	h := TCP4Header{
		SrcPort:    binary.BigEndian.Uint16(pkt[0:2]),
		DstPort:    binary.BigEndian.Uint16(pkt[2:4]),
		Seq:        binary.BigEndian.Uint32(pkt[4:8]),
		Ack:        binary.BigEndian.Uint32(pkt[8:12]),
		DataOffset: dataOff,
		Flags:      pkt[13],
		Window:     binary.BigEndian.Uint16(pkt[14:16]),
		Checksum:   binary.BigEndian.Uint16(pkt[16:18]),
		Urgent:     binary.BigEndian.Uint16(pkt[18:20]),
	}
	// Validate checksum (re-sum with the checksum field zeroed).
	tmp := make([]byte, len(pkt))
	copy(tmp, pkt)
	tmp[16] = 0
	tmp[17] = 0
	got := tcp4Checksum(src, dst, tmp)
	if got != h.Checksum {
		return TCP4Header{}, nil, ErrTCP4BadChecksum
	}
	payload := append([]byte(nil), pkt[hdrLen:]...)
	return h, payload, nil
}

// MarshalTCP4 builds a complete TCP segment (20-byte header + payload)
// and stamps the pseudo-header checksum. The returned slice is exactly
// `20 + len(payload)` bytes.
func MarshalTCP4(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, window uint16, payload []byte) ([]byte, error) {
	total := TCP4HeaderLen + len(payload)
	buf := make([]byte, total)
	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)
	buf[12] = 5 << 4 // data offset = 5 32-bit words (no options)
	buf[13] = flags
	binary.BigEndian.PutUint16(buf[14:16], window)
	// Checksum field initially zero; computed below.
	binary.BigEndian.PutUint16(buf[18:20], 0) // urgent pointer
	copy(buf[TCP4HeaderLen:], payload)
	cksum := tcp4Checksum(src, dst, buf)
	if cksum == 0 {
		// RFC 793 allows zero on the wire; ministack normalises to
		// 0xFFFF to match the UDP convention (helps debuggers spot a
		// real zero vs a forgotten compute).
		cksum = 0xFFFF
	}
	binary.BigEndian.PutUint16(buf[16:18], cksum)
	return buf, nil
}

// tcp4Checksum computes the TCP/IPv4 checksum over the pseudo-header
// (src, dst, zero, protocol=TCP, TCP-length) + the supplied TCP bytes.
// `tcp` must have the checksum field zeroed for an initial compute.
func tcp4Checksum(src, dst net.IP, tcp []byte) uint16 {
	s4 := src.To4()
	d4 := dst.To4()
	if s4 == nil || d4 == nil {
		return 0
	}
	var pseudo [12]byte
	copy(pseudo[0:4], s4)
	copy(pseudo[4:8], d4)
	pseudo[8] = 0
	pseudo[9] = IPProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	buf := make([]byte, 0, len(pseudo)+len(tcp))
	buf = append(buf, pseudo[:]...)
	buf = append(buf, tcp...)
	return InternetChecksum(buf)
}

// tcp4ReassemblyEntry holds an out-of-order segment we couldn't deliver
// immediately. `seq` is the absolute sequence number of the first byte.
type tcp4ReassemblyEntry struct {
	seq     uint32
	payload []byte
	fin     bool // peer FIN'd at the end of this segment
}

// TCP4Conn is a client TCP/IPv4 connection. Obtained from
// Stack.DialTCP4. The same Conn is the net.Conn returned by AsNetConn —
// see the wrapper at the bottom of this file. Safe for concurrent
// Read/Write/Close; each call serialises internally where needed.
type TCP4Conn struct {
	stack *Stack

	localIP   net.IP
	localPort uint16
	remoteIP  net.IP
	remotePort uint16

	mu          sync.Mutex
	state       tcp4State
	sndUna      uint32 // unacknowledged send-sequence number
	sndNxt      uint32 // next sequence number to send
	sndWnd      uint16 // peer's advertised receive window
	rcvNxt      uint32 // next sequence number we expect
	rcvWnd      uint16 // our advertised receive window
	rxQueue     []byte // bytes ready for the application to read
	reassembly  []tcp4ReassemblyEntry
	peerFinSeen bool
	closed      bool

	readDeadline  time.Time
	writeDeadline time.Time
}

// LocalAddr returns the local endpoint as a *net.TCPAddr.
func (c *TCP4Conn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), c.localIP...), Port: int(c.localPort)}
}

// RemoteAddr returns the peer endpoint as a *net.TCPAddr.
func (c *TCP4Conn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), c.remoteIP...), Port: int(c.remotePort)}
}

// SetDeadline applies the supplied wall-clock deadline to both Read and
// Write. Zero clears both.
func (c *TCP4Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// SetReadDeadline applies a wall-clock deadline to subsequent Read
// calls. Zero clears the deadline.
func (c *TCP4Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	c.readDeadline = t
	c.mu.Unlock()
	return nil
}

// SetWriteDeadline applies a wall-clock deadline to subsequent Write
// calls. Zero clears the deadline.
func (c *TCP4Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// sendSegment emits a single TCP segment with the supplied flags,
// sequence, and payload. The Conn's mutex must be held. The segment is
// wrapped in IPv4 + Ethernet and shipped via the Stack's send-frame
// path (which handles ARP for the next-hop).
func (c *TCP4Conn) sendSegment(flags uint8, seq, ack uint32, payload []byte) error {
	seg, err := MarshalTCP4(c.localIP, c.remoteIP, c.localPort, c.remotePort, seq, ack, flags, c.rcvWnd, payload)
	if err != nil {
		return err
	}
	ipPkt, err := MarshalIPv4(c.localIP, c.remoteIP, IPProtoTCP, c.stack.nextIPID(), seg)
	if err != nil {
		return err
	}
	return c.stack.sendIPv4Frame(c.remoteIP, ipPkt)
}

// deliverSegment is called by the Stack's RX dispatcher with a parsed
// TCP header + payload that matches our 4-tuple. Drives the state
// machine: SYN-ACK handshake, data delivery (in-order + reassembly),
// FIN handling, and ACK generation.
func (c *TCP4Conn) deliverSegment(h TCP4Header, payload []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}

	// RST collapses the connection unconditionally.
	if h.Flags&TCPFlagRST != 0 {
		c.state = tcpClosed
		c.closed = true
		return
	}

	// Update peer window from every segment we accept.
	c.sndWnd = h.Window

	switch c.state {
	case tcpSynSent:
		// Expect SYN-ACK matching our SYN. RFC 793 §3.4: ack must
		// equal our snd.nxt (i.e. acknowledge the SYN's own sequence).
		if h.Flags&TCPFlagSYN == 0 || h.Flags&TCPFlagACK == 0 {
			return
		}
		if h.Ack != c.sndNxt {
			return
		}
		c.rcvNxt = h.Seq + 1
		c.sndUna = h.Ack
		c.state = tcpEstablished
		// ACK the SYN-ACK (no payload).
		_ = c.sendSegment(TCPFlagACK, c.sndNxt, c.rcvNxt, nil)

	case tcpEstablished, tcpFinWait1, tcpFinWait2, tcpCloseWait:
		if h.Flags&TCPFlagACK == 0 {
			return
		}
		// Advance snd.una on ACK that covers more of our send stream.
		if seqGT(h.Ack, c.sndUna) {
			c.sndUna = h.Ack
		}

		// Accept payload only if it lands on our current rcv.nxt or
		// fills a reassembly gap.
		if len(payload) > 0 || h.Flags&TCPFlagFIN != 0 {
			c.acceptSegmentLocked(h.Seq, payload, h.Flags&TCPFlagFIN != 0)
		}

		// State transitions driven by ACK of our FIN.
		if c.state == tcpFinWait1 && h.Ack == c.sndNxt {
			c.state = tcpFinWait2
		}
		if c.peerFinSeen {
			switch c.state {
			case tcpEstablished:
				c.state = tcpCloseWait
			case tcpFinWait1:
				if h.Ack == c.sndNxt {
					c.state = tcpTimeWait
				} else {
					c.state = tcpClosing
				}
			case tcpFinWait2:
				c.state = tcpTimeWait
			}
		}

	case tcpLastAck:
		// We previously sent FIN in CLOSE_WAIT; ACK of that FIN closes
		// the connection. ack must equal snd.nxt.
		if h.Flags&TCPFlagACK != 0 && h.Ack == c.sndNxt {
			c.state = tcpClosed
		}

	case tcpClosing:
		if h.Flags&TCPFlagACK != 0 && h.Ack == c.sndNxt {
			c.state = tcpTimeWait
		}

	case tcpTimeWait, tcpClosed:
		// Drop late segments silently. A production stack would emit
		// ACKs to absorb retransmits; M5 doesn't need that fidelity.
		return
	}
}

// acceptSegmentLocked integrates `payload` (and the optional peer-FIN)
// into the receive stream. Must be called with c.mu held. In-order
// segments append to rxQueue; out-of-order segments park in the
// reassembly table. Each acceptance emits an ACK so the peer can
// advance its send window.
func (c *TCP4Conn) acceptSegmentLocked(seq uint32, payload []byte, finFlag bool) {
	// Case 1: segment aligns with our expected receive sequence.
	if seq == c.rcvNxt {
		c.rxQueue = append(c.rxQueue, payload...)
		c.rcvNxt += uint32(len(payload))
		if finFlag {
			c.peerFinSeen = true
			c.rcvNxt++
		}
		// Drain the reassembly buffer for any newly-contiguous
		// segments.
		c.drainReassemblyLocked()
		_ = c.sendSegment(TCPFlagACK, c.sndNxt, c.rcvNxt, nil)
		return
	}
	// Case 2: segment is ahead — park in the reassembly buffer if room.
	if seqGT(seq, c.rcvNxt) && len(c.reassembly) < TCP4ReassemblyDepth {
		c.reassembly = append(c.reassembly, tcp4ReassemblyEntry{
			seq:     seq,
			payload: append([]byte(nil), payload...),
			fin:     finFlag,
		})
		_ = c.sendSegment(TCPFlagACK, c.sndNxt, c.rcvNxt, nil)
		return
	}
	// Case 3: pure duplicate or behind our window — ACK anyway so the
	// peer stops retransmitting.
	_ = c.sendSegment(TCPFlagACK, c.sndNxt, c.rcvNxt, nil)
}

// drainReassemblyLocked promotes any reassembly entries that have
// become contiguous with rcv.nxt. Called with c.mu held.
func (c *TCP4Conn) drainReassemblyLocked() {
	// Iterate until no progress can be made.
	for {
		matched := -1
		for i, e := range c.reassembly {
			if e.seq == c.rcvNxt {
				matched = i
				break
			}
		}
		if matched == -1 {
			return
		}
		e := c.reassembly[matched]
		c.rxQueue = append(c.rxQueue, e.payload...)
		c.rcvNxt += uint32(len(e.payload))
		if e.fin {
			c.peerFinSeen = true
			c.rcvNxt++
		}
		// Remove the merged entry.
		c.reassembly = append(c.reassembly[:matched], c.reassembly[matched+1:]...)
	}
}

// Read returns up to len(buf) bytes from the receive stream. Blocks
// (subject to the read deadline) until at least one byte is available
// or the peer's FIN drains. After FIN with an empty queue, returns 0,
// io.EOF — except we don't import io here; the caller (HTTP client) is
// happy to treat any 0-byte / closed return as EOF.
func (c *TCP4Conn) Read(buf []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, ErrTCP4ConnClosed
	}
	deadline := c.readDeadline
	c.mu.Unlock()

	timeout := c.computeTimeout(deadline)
	checker := newDeadlineChecker(timeout)
	for !checker.expired() {
		checker.tick()
		c.mu.Lock()
		if len(c.rxQueue) > 0 {
			n := copy(buf, c.rxQueue)
			c.rxQueue = c.rxQueue[n:]
			c.mu.Unlock()
			return n, nil
		}
		// FIN seen and no queued data — signal EOF.
		if c.peerFinSeen {
			c.mu.Unlock()
			return 0, errTCP4PeerClosed
		}
		if c.closed {
			c.mu.Unlock()
			return 0, ErrTCP4ConnClosed
		}
		c.mu.Unlock()
		// Pump the RX path inline — same pattern as UDP/ARP/ICMP.
		rx, rxErr := c.stack.link.RecvFrame()
		if rxErr != nil {
			continue
		}
		_ = c.stack.dispatch(rx)
	}
	return 0, ErrTCP4Timeout
}

// errTCP4PeerClosed is the marker we return when the peer cleanly
// closed the connection and our receive queue has drained.
var errTCP4PeerClosed = errors.New("ministack: TCP peer closed")

// Write enqueues `p` for transmission. Segments are emitted at MSS
// boundaries; each segment is retransmitted up to TCP4MaxRetransmits
// times on ACK timeout. Returns the number of bytes written or
// ErrTCP4Timeout if a retransmit budget expires.
func (c *TCP4Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed || (c.state != tcpEstablished && c.state != tcpCloseWait) {
		c.mu.Unlock()
		return 0, ErrTCP4ConnClosed
	}
	deadline := c.writeDeadline
	c.mu.Unlock()

	written := 0
	for written < len(p) {
		end := written + TCP4DefaultMSS
		if end > len(p) {
			end = len(p)
		}
		segment := p[written:end]
		if err := c.sendAndAwaitAck(segment, deadline); err != nil {
			return written, err
		}
		written = end
	}
	return written, nil
}

// sendAndAwaitAck ships a single segment then drives the inline RX
// pump until snd.una passes snd.nxt. On timeout it retransmits up to
// TCP4MaxRetransmits times.
func (c *TCP4Conn) sendAndAwaitAck(segment []byte, deadline time.Time) error {
	c.mu.Lock()
	seq := c.sndNxt
	c.sndNxt += uint32(len(segment))
	wantAck := c.sndNxt
	ack := c.rcvNxt
	c.mu.Unlock()

	flags := TCPFlagACK | TCPFlagPSH
	if err := c.sendSegmentExt(flags, seq, ack, segment); err != nil {
		return err
	}

	totalBudget := c.computeTimeout(deadline)
	if totalBudget <= 0 || totalBudget > TCP4SegmentRetransmitTimeout*time.Duration(TCP4MaxRetransmits+1) {
		totalBudget = TCP4SegmentRetransmitTimeout * time.Duration(TCP4MaxRetransmits+1)
	}
	retransmits := 0
	perAttempt := newDeadlineChecker(TCP4SegmentRetransmitTimeout)
	overall := newDeadlineChecker(totalBudget)
	for !overall.expired() {
		overall.tick()
		c.mu.Lock()
		if c.closed {
			c.mu.Unlock()
			return ErrTCP4ConnClosed
		}
		if !seqLT(c.sndUna, wantAck) {
			c.mu.Unlock()
			return nil
		}
		c.mu.Unlock()
		if perAttempt.expired() {
			retransmits++
			if retransmits > TCP4MaxRetransmits {
				return ErrTCP4Timeout
			}
			// Retransmit the same segment.
			if err := c.sendSegmentExt(flags, seq, ack, segment); err != nil {
				return err
			}
			perAttempt = newDeadlineChecker(TCP4SegmentRetransmitTimeout)
		}
		perAttempt.tick()
		rx, rxErr := c.stack.link.RecvFrame()
		if rxErr != nil {
			continue
		}
		_ = c.stack.dispatch(rx)
	}
	return ErrTCP4Timeout
}

// sendSegmentExt is the lock-free wrapper around sendSegment used by
// the write path (which already serialised at the Conn boundary).
func (c *TCP4Conn) sendSegmentExt(flags uint8, seq, ack uint32, payload []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendSegment(flags, seq, ack, payload)
}

// Close performs the active-close handshake: emits FIN, waits for the
// peer's FIN-ACK + FIN, then enters TIME_WAIT and tears down. After
// Close returns the Conn is no longer usable; further Read/Write calls
// return ErrTCP4ConnClosed.
func (c *TCP4Conn) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	switch c.state {
	case tcpEstablished:
		// Send FIN. Sequence consumes one byte in the send stream.
		seq := c.sndNxt
		ack := c.rcvNxt
		c.sndNxt++
		c.state = tcpFinWait1
		c.mu.Unlock()
		_ = c.sendSegmentExt(TCPFlagFIN|TCPFlagACK, seq, ack, nil)
	case tcpCloseWait:
		// Peer already FIN'd us; emit our FIN and enter LAST_ACK.
		seq := c.sndNxt
		ack := c.rcvNxt
		c.sndNxt++
		c.state = tcpLastAck
		c.mu.Unlock()
		_ = c.sendSegmentExt(TCPFlagFIN|TCPFlagACK, seq, ack, nil)
	default:
		c.mu.Unlock()
	}

	// Pump the RX path until the FIN handshake completes or we time
	// out (short bounded wait — boot-time HTTP clients don't linger).
	checker := newDeadlineChecker(2 * time.Second)
	for !checker.expired() {
		checker.tick()
		c.mu.Lock()
		st := c.state
		c.mu.Unlock()
		if st == tcpClosed || st == tcpTimeWait {
			break
		}
		rx, rxErr := c.stack.link.RecvFrame()
		if rxErr != nil {
			continue
		}
		_ = c.stack.dispatch(rx)
	}

	c.mu.Lock()
	c.closed = true
	c.state = tcpClosed
	c.mu.Unlock()
	c.stack.releaseTCP4(c.localPort)
	return nil
}

// computeTimeout converts an absolute deadline to a duration suitable
// for the deadline checker. Zero deadline (unset) defaults to 30 s.
// Negative residual maps to 1 ns so the checker can fire its tamago
// iter-cap.
func (c *TCP4Conn) computeTimeout(deadline time.Time) time.Duration {
	if deadline.IsZero() {
		return 30 * time.Second
	}
	d := time.Until(deadline)
	if d <= 0 {
		d = 1
	}
	return d
}

// seqLT reports whether a < b in mod-2^32 sequence-number space.
// Standard RFC 793 sequence comparison.
func seqLT(a, b uint32) bool {
	return int32(a-b) < 0
}

// seqGT reports whether a > b in mod-2^32 sequence-number space.
func seqGT(a, b uint32) bool {
	return int32(a-b) > 0
}

// tcp4InitialSeq derives a deterministic initial sequence number from
// the MAC + local port. Deterministic so tests can pin packet bytes;
// the boot-time client doesn't need cryptographic randomness (boot
// runs are one-shot, and QEMU SLIRP doesn't care).
func tcp4InitialSeq(mac net.HardwareAddr, localPort uint16) uint32 {
	if len(mac) < 6 {
		return uint32(localPort) ^ 0xCAFEBABE
	}
	hi := binary.BigEndian.Uint32(mac[0:4])
	lo := binary.BigEndian.Uint16(mac[4:6])
	return hi ^ (uint32(lo) << 16) ^ uint32(localPort)
}

// DialTCP4 opens a TCP connection from a fresh ephemeral local port to
// `dst`:`port`. Returns the established Conn or any of:
//   - ErrIPv4InvalidIP (non-IPv4 destination)
//   - ErrTCP4ConnRefused (peer RST'd our SYN)
//   - ErrTCP4Timeout (no SYN-ACK within timeout)
//   - ErrNoRoute (off-link with no default gateway)
//
// The Conn's local IP is the Stack's configured local address; if none
// has been set DialTCP4 returns an error rather than dialing from
// 0.0.0.0 (TCP doesn't survive a source-IP change like DHCP DISCOVER
// does, so we require a real local address).
func (s *Stack) DialTCP4(dst net.IP, port uint16, timeout time.Duration) (*TCP4Conn, error) {
	d4 := dst.To4()
	if d4 == nil {
		return nil, ErrTCP4InvalidAddr
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, ErrStackClosed
	}
	if s.route.Local == nil {
		s.mu.Unlock()
		return nil, errors.New("ministack: no local IPv4 address set")
	}
	localIP := append(net.IP(nil), s.route.Local...)
	mac := s.link.MAC()
	s.mu.Unlock()

	localPort, err := s.allocTCP4Port()
	if err != nil {
		return nil, err
	}
	iss := tcp4InitialSeq(mac, localPort)
	conn := &TCP4Conn{
		stack:      s,
		localIP:    localIP,
		localPort:  localPort,
		remoteIP:   append(net.IP(nil), d4...),
		remotePort: port,
		state:      tcpSynSent,
		sndUna:     iss,
		sndNxt:     iss + 1, // SYN consumes a sequence number
		rcvWnd:     TCP4DefaultWindow,
	}
	s.registerTCP4(conn)

	// Send the SYN.
	if err := conn.sendSegmentExt(TCPFlagSYN, iss, 0, nil); err != nil {
		s.releaseTCP4(localPort)
		return nil, err
	}

	// Wait for SYN-ACK via inline RX pump.
	checker := newDeadlineChecker(timeout)
	for !checker.expired() {
		checker.tick()
		conn.mu.Lock()
		st := conn.state
		closed := conn.closed
		conn.mu.Unlock()
		if st == tcpEstablished {
			return conn, nil
		}
		if closed {
			s.releaseTCP4(localPort)
			return nil, ErrTCP4ConnRefused
		}
		rx, rxErr := s.link.RecvFrame()
		if rxErr != nil {
			continue
		}
		_ = s.dispatch(rx)
	}
	s.releaseTCP4(localPort)
	return nil, ErrTCP4Timeout
}

// allocTCP4Port returns a fresh ephemeral local port (>= 49152). Walks
// the demux table to avoid collisions. Falls through after a bounded
// scan; in the M5 client model only one TCB lives at any time so a
// real collision is impossible.
func (s *Stack) allocTCP4Port() (uint16, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrStackClosed
	}
	// Start at 49152 (IANA ephemeral lower bound). Probe up to 1024
	// candidates; if all are taken the caller's design is broken.
	for i := uint16(0); i < 1024; i++ {
		p := uint16(49152) + (s.tcp4PortRover+i)%(uint16(16383)-1)
		if _, exists := s.tcp4Conns[p]; !exists {
			s.tcp4PortRover = (s.tcp4PortRover + i + 1) % 16383
			return p, nil
		}
	}
	return 0, ErrTCP4PortInUse
}

// registerTCP4 installs `conn` in the per-stack demux map. Must be
// called exactly once per Dial.
func (s *Stack) registerTCP4(conn *TCP4Conn) {
	s.mu.Lock()
	if s.tcp4Conns == nil {
		s.tcp4Conns = make(map[uint16]*TCP4Conn)
	}
	s.tcp4Conns[conn.localPort] = conn
	s.mu.Unlock()
}

// releaseTCP4 removes the Conn for `localPort` from the demux table.
// Called by TCP4Conn.Close.
func (s *Stack) releaseTCP4(localPort uint16) {
	s.mu.Lock()
	delete(s.tcp4Conns, localPort)
	s.mu.Unlock()
}

// handleTCP4 is the TCP arm of the IPv4 dispatcher. Parses the TCP
// header, finds the matching Conn (if any) by destination port, and
// delegates to the Conn's deliverSegment. Segments with no matching
// Conn are dropped silently (M5 client does not act as a server).
//
// `body` may include trailing Ethernet padding (the link emits frames
// padded to the 60-byte minimum); we trim to the IP TotalLen so the
// TCP checksum doesn't pick up those trailing zero bytes.
func (s *Stack) handleTCP4(h IPv4Header, body []byte) error {
	tcpLen := int(h.TotalLen) - IPv4HeaderLen
	if tcpLen < 0 {
		return nil
	}
	if tcpLen > len(body) {
		// Truncated frame — drop. ParseTCP4 would surface this too,
		// but bailing early avoids the slice panic in the cap below.
		return nil
	}
	body = body[:tcpLen]
	th, payload, err := ParseTCP4(h.Src, h.Dst, body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	conn, ok := s.tcp4Conns[th.DstPort]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	// Match the (remoteIP, remotePort) tuple. We only support one TCB
	// per local port, but defensively verify the peer matches.
	if !conn.remoteIP.Equal(h.Src) || conn.remotePort != th.SrcPort {
		return nil
	}
	conn.deliverSegment(th, payload)
	return nil
}
