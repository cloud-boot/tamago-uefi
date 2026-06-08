// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// ARP (RFC 826) request/reply for IPv4 over Ethernet, plus a tiny
// cache.
//
// On-wire ARP packet (Ethernet + IPv4 variant, 28 bytes):
//
//	+-----+-----+-----+-----+-----+-----+--------+--------+
//	| HTYPE | PTYPE | HLN | PLN | OPER  | SHA(6) | SPA(4) |
//	| 2 B   | 2 B   | 1 B | 1 B | 2 B   |        |        |
//	+-------+-------+-----+-----+-------+--------+--------+
//	| THA(6) | TPA(4) |
//	+--------+--------+
//
// HTYPE = 1 (Ethernet), PTYPE = 0x0800 (IPv4), HLN = 6, PLN = 4.
// OPER  = 1 (request), 2 (reply).
//
// ARP cache semantics:
//   - In-memory map[uint32 (IPv4 big-endian)] → (MAC, lastSeen).
//   - Entries never expire in M3-minimal. Cache size is bounded only
//     by the number of unique IPs we talk to (single-gateway ping is
//     2 entries: us + gateway).
//   - Cache is shared with the Stack's mutex; the Stack owns the lock.
//
// Resolve(ip) flow:
//   1. Take the lock, look up the entry. Cached → return immediately.
//   2. Drop the lock, send broadcast ARP request.
//   3. Wait up to 1 second on the entry's notification channel for
//      the RX dispatcher to fill it in. Timeout → ErrARPTimeout.
//
// Incoming ARP frames are dispatched here from stack.dispatch:
//   - Request for our IP → unicast Reply.
//   - Reply (or "gratuitous" request) → cache update + notify any
//     waiter on this IP.

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"time"
)

// ARPPacketLen is the on-wire ARP-over-Ethernet-for-IPv4 size.
const ARPPacketLen = 28

// ARP hardware / protocol type constants.
const (
	arpHTYPEEthernet uint16 = 1
	arpPTYPEIPv4     uint16 = 0x0800
	arpHLNEthernet   uint8  = 6
	arpPLNIPv4       uint8  = 4
)

// ARP operation codes.
const (
	ARPOpRequest uint16 = 1
	ARPOpReply   uint16 = 2
)

// ARPDefaultTimeout is the per-Resolve wait window. 1 second is more
// than enough for QEMU NAT (which answers in microseconds) and short
// enough that probe failures surface quickly.
const ARPDefaultTimeout = 1 * time.Second

// ErrARPTimeout is returned by Resolve when no ARP Reply arrives
// within the timeout.
var ErrARPTimeout = errors.New("ministack: ARP resolve timed out")

// ErrARPInvalidPacket is returned by parseARP when the input buffer
// is malformed (too short or unsupported HTYPE/PTYPE/HLN/PLN).
var ErrARPInvalidPacket = errors.New("ministack: ARP packet malformed or unsupported (htype/ptype/hln/pln)")

// arpEntry holds one ARP cache row. `waiter` is closed when the entry
// transitions from unresolved to resolved, waking any goroutine
// blocked in Resolve.
type arpEntry struct {
	mac      net.HardwareAddr
	lastSeen time.Time
	resolved bool
	waiter   chan struct{} // closed when resolved becomes true
}

// arpTable is the cache, keyed on big-endian 4-byte IPv4 packed into
// a uint32. NOT thread-safe on its own — the enclosing Stack's mutex
// guards it.
type arpTable struct {
	entries map[uint32]*arpEntry
}

// newARPTable returns an empty cache.
func newARPTable() *arpTable {
	return &arpTable{entries: make(map[uint32]*arpEntry)}
}

// ipKey packs a 4-byte IPv4 into uint32 (big-endian) for use as a map
// key. Panics if the IP is not a 4-byte slice — callers should
// validate via .To4() first.
func ipKey(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

// getLocked returns the entry for `ip` if present (with the table
// lock held by the caller). Returns nil if absent.
func (t *arpTable) getLocked(ip net.IP) *arpEntry {
	return t.entries[ipKey(ip)]
}

// ensureLocked returns the existing entry for `ip` or creates an
// unresolved one with a fresh waiter channel.
func (t *arpTable) ensureLocked(ip net.IP) *arpEntry {
	k := ipKey(ip)
	if e, ok := t.entries[k]; ok {
		return e
	}
	e := &arpEntry{waiter: make(chan struct{})}
	t.entries[k] = e
	return e
}

// updateLocked records `mac` for `ip` and, if the entry was previously
// unresolved, closes the waiter channel to wake blocked Resolve calls.
// If the entry was already resolved with a different MAC, the MAC is
// overwritten (handles MAC changes — DHCP lease renewals etc.).
func (t *arpTable) updateLocked(ip net.IP, mac net.HardwareAddr, now time.Time) {
	e := t.ensureLocked(ip)
	e.mac = append(net.HardwareAddr(nil), mac...)
	e.lastSeen = now
	if !e.resolved {
		e.resolved = true
		close(e.waiter)
	}
}

// buildARPPacket marshals a 28-byte ARP-over-Ethernet-for-IPv4 packet.
// `op` is ARPOpRequest or ARPOpReply. For a request, `tha` (target
// hardware address) is the zero MAC; for a reply, it's the requester's
// MAC.
func buildARPPacket(op uint16, sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP) ([]byte, error) {
	if len(sha) != 6 || len(tha) != 6 {
		return nil, ErrInvalidMAC
	}
	spa4 := spa.To4()
	tpa4 := tpa.To4()
	if spa4 == nil || tpa4 == nil {
		return nil, ErrIPv4InvalidIP
	}
	buf := make([]byte, ARPPacketLen)
	binary.BigEndian.PutUint16(buf[0:2], arpHTYPEEthernet)
	binary.BigEndian.PutUint16(buf[2:4], arpPTYPEIPv4)
	buf[4] = arpHLNEthernet
	buf[5] = arpPLNIPv4
	binary.BigEndian.PutUint16(buf[6:8], op)
	copy(buf[8:14], sha)
	copy(buf[14:18], spa4)
	copy(buf[18:24], tha)
	copy(buf[24:28], tpa4)
	return buf, nil
}

// parseARP decodes a 28-byte ARP packet. Returns op, sha, spa, tha,
// tpa. Validates the HTYPE/PTYPE/HLN/PLN fields are Ethernet+IPv4 (the
// only combo we handle).
func parseARP(buf []byte) (op uint16, sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP, err error) {
	if len(buf) < ARPPacketLen {
		err = ErrARPInvalidPacket
		return
	}
	if binary.BigEndian.Uint16(buf[0:2]) != arpHTYPEEthernet {
		err = ErrARPInvalidPacket
		return
	}
	if binary.BigEndian.Uint16(buf[2:4]) != arpPTYPEIPv4 {
		err = ErrARPInvalidPacket
		return
	}
	if buf[4] != arpHLNEthernet || buf[5] != arpPLNIPv4 {
		err = ErrARPInvalidPacket
		return
	}
	op = binary.BigEndian.Uint16(buf[6:8])
	sha = append(net.HardwareAddr(nil), buf[8:14]...)
	spa = net.IP(append([]byte(nil), buf[14:18]...))
	tha = append(net.HardwareAddr(nil), buf[18:24]...)
	tpa = net.IP(append([]byte(nil), buf[24:28]...))
	return
}

// resolveTimeoutForTests is the per-Resolve timeout; tests override
// it to avoid 1-second waits when probing the error path.
var resolveTimeoutForTests = ARPDefaultTimeout

// resolveARP implements the Resolve flow for the Stack: cache lookup,
// fall through to broadcast request + bounded wait. The Stack passes
// its own mutex (mu) and the helpers it owns (link, route, mac).
//
// Split out as a function so the Stack tests can drive it with a stub
// link transport.
func resolveARP(
	mu *sync.Mutex,
	table *arpTable,
	link Link,
	srcMAC net.HardwareAddr,
	srcIP net.IP,
	target net.IP,
	timeout time.Duration,
) (net.HardwareAddr, error) {
	t4 := target.To4()
	if t4 == nil {
		return nil, ErrIPv4InvalidIP
	}

	// Fast path: cache hit.
	mu.Lock()
	if e := table.getLocked(t4); e != nil && e.resolved {
		mac := append(net.HardwareAddr(nil), e.mac...)
		mu.Unlock()
		return mac, nil
	}
	// Create (or get) the pending entry and grab its waiter channel.
	e := table.ensureLocked(t4)
	ch := e.waiter
	mu.Unlock()

	// Send broadcast ARP Request.
	pkt, err := buildARPPacket(
		ARPOpRequest,
		srcMAC, srcIP,
		net.HardwareAddr{0, 0, 0, 0, 0, 0}, t4,
	)
	if err != nil {
		return nil, err
	}
	frame, err := MarshalEthernet(BroadcastMAC, srcMAC, EtherTypeARP, pkt)
	if err != nil {
		return nil, err
	}
	if err := link.SendFrame(frame); err != nil {
		return nil, err
	}

	// Wait for the RX dispatcher to fill the entry.
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
		mu.Lock()
		e := table.getLocked(t4)
		mu.Unlock()
		if e == nil || !e.resolved {
			return nil, ErrARPTimeout
		}
		return append(net.HardwareAddr(nil), e.mac...), nil
	case <-timer.C:
		return nil, ErrARPTimeout
	}
}

// handleARPFrame is called by the Stack's RX dispatcher for every
// incoming Ethernet frame whose EtherType is 0x0806. It:
//
//   - parses the ARP packet,
//   - learns the (sender IP, sender MAC) pair (always),
//   - if the packet is a Request for our IP, builds a unicast Reply
//     and asks the link to send it,
//   - if the packet is a Reply, the cache update above is sufficient
//     (any blocked Resolve wakes via the entry's waiter chan).
//
// Errors are returned to the caller for logging; they do not stop the
// dispatch loop.
func handleARPFrame(
	mu *sync.Mutex,
	table *arpTable,
	link Link,
	ourMAC net.HardwareAddr,
	ourIP net.IP,
	payload []byte,
) error {
	op, sha, spa, _, tpa, err := parseARP(payload)
	if err != nil {
		return err
	}

	// Always learn the (sender IP, sender MAC) pair — this populates
	// the cache for the common case where we send a Request and the
	// reply happens to also be a learning opportunity for the gateway.
	mu.Lock()
	table.updateLocked(spa, sha, time.Now())
	mu.Unlock()

	// If this is a Request for our IP, respond with a Reply.
	if op == ARPOpRequest && ourIP != nil && tpa.Equal(ourIP) {
		reply, err := buildARPPacket(ARPOpReply, ourMAC, ourIP, sha, spa)
		if err != nil {
			return err
		}
		frame, err := MarshalEthernet(sha, ourMAC, EtherTypeARP, reply)
		if err != nil {
			return err
		}
		return link.SendFrame(frame)
	}
	return nil
}
