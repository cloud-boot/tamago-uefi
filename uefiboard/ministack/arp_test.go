// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"
)

// stubLink is a synthetic in-memory link for ministack tests. It
// captures TX frames in `sent` and returns RX frames from `recv` in
// order. Goroutine-safe.
type stubLink struct {
	mu      sync.Mutex
	mac     net.HardwareAddr
	sent    [][]byte
	recv    chan []byte
	sendErr error
}

func newStubLink(mac net.HardwareAddr) *stubLink {
	return &stubLink{
		mac:  append(net.HardwareAddr(nil), mac...),
		recv: make(chan []byte, 64),
	}
}

func (l *stubLink) SendFrame(frame []byte) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sendErr != nil {
		return l.sendErr
	}
	l.sent = append(l.sent, append([]byte(nil), frame...))
	return nil
}

func (l *stubLink) RecvFrame() ([]byte, error) {
	select {
	case f := <-l.recv:
		return f, nil
	case <-time.After(20 * time.Millisecond):
		return nil, errStubRecvTimeout
	}
}

func (l *stubLink) MAC() net.HardwareAddr {
	return append(net.HardwareAddr(nil), l.mac...)
}

func (l *stubLink) snapshotSent() [][]byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([][]byte, len(l.sent))
	for i, f := range l.sent {
		out[i] = append([]byte(nil), f...)
	}
	return out
}

func (l *stubLink) inject(frame []byte) {
	l.recv <- frame
}

var errStubRecvTimeout = stubError("stub: recv timeout")

type stubError string

func (e stubError) Error() string { return string(e) }

func TestBuildAndParseARPRequest(t *testing.T) {
	sha := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	tha := net.HardwareAddr{0, 0, 0, 0, 0, 0}
	spa := net.IPv4(10, 0, 2, 15)
	tpa := net.IPv4(10, 0, 2, 2)

	pkt, err := buildARPPacket(ARPOpRequest, sha, spa, tha, tpa)
	if err != nil {
		t.Fatalf("buildARPPacket: %v", err)
	}
	if len(pkt) != ARPPacketLen {
		t.Fatalf("ARP packet length: got %d, want %d", len(pkt), ARPPacketLen)
	}
	op, gotSHA, gotSPA, gotTHA, gotTPA, err := parseARP(pkt)
	if err != nil {
		t.Fatalf("parseARP: %v", err)
	}
	if op != ARPOpRequest {
		t.Errorf("OP: got %d, want %d", op, ARPOpRequest)
	}
	if !bytes.Equal(gotSHA, sha) {
		t.Errorf("SHA mismatch: got %v, want %v", gotSHA, sha)
	}
	if !gotSPA.Equal(spa) {
		t.Errorf("SPA mismatch: got %v, want %v", gotSPA, spa)
	}
	if !bytes.Equal(gotTHA, tha) {
		t.Errorf("THA mismatch: got %v, want %v", gotTHA, tha)
	}
	if !gotTPA.Equal(tpa) {
		t.Errorf("TPA mismatch: got %v, want %v", gotTPA, tpa)
	}
}

func TestParseARPRejectsShort(t *testing.T) {
	_, _, _, _, _, err := parseARP(make([]byte, 10))
	if err != ErrARPInvalidPacket {
		t.Errorf("want ErrARPInvalidPacket, got %v", err)
	}
}

func TestParseARPRejectsBadTypes(t *testing.T) {
	pkt := make([]byte, ARPPacketLen)
	// Bad HTYPE.
	pkt[1] = 2
	_, _, _, _, _, err := parseARP(pkt)
	if err != ErrARPInvalidPacket {
		t.Errorf("bad HTYPE: want ErrARPInvalidPacket, got %v", err)
	}
	// Good HTYPE, bad PTYPE.
	for i := range pkt {
		pkt[i] = 0
	}
	pkt[0], pkt[1] = 0, 1 // HTYPE = 1
	pkt[2], pkt[3] = 0x12, 0x34
	_, _, _, _, _, err = parseARP(pkt)
	if err != ErrARPInvalidPacket {
		t.Errorf("bad PTYPE: want ErrARPInvalidPacket, got %v", err)
	}
	// Good HTYPE+PTYPE, bad HLN/PLN.
	for i := range pkt {
		pkt[i] = 0
	}
	pkt[0], pkt[1] = 0, 1
	pkt[2], pkt[3] = 0x08, 0x00
	pkt[4], pkt[5] = 5, 4
	_, _, _, _, _, err = parseARP(pkt)
	if err != ErrARPInvalidPacket {
		t.Errorf("bad HLN: want ErrARPInvalidPacket, got %v", err)
	}
}

func TestARPTableInsertAndLookup(t *testing.T) {
	tbl := newARPTable()
	ip := net.IPv4(10, 0, 2, 2).To4()
	mac := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}

	if got := tbl.getLocked(ip); got != nil {
		t.Errorf("initial getLocked: want nil, got %v", got)
	}
	tbl.updateLocked(ip, mac, time.Now())
	e := tbl.getLocked(ip)
	if e == nil {
		t.Fatal("getLocked after update: want non-nil")
	}
	if !e.resolved {
		t.Errorf("entry should be resolved")
	}
	if !bytes.Equal(e.mac, mac) {
		t.Errorf("mac mismatch: got %v, want %v", e.mac, mac)
	}
}

func TestARPResolveCacheHit(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	tbl := newARPTable()
	var mu sync.Mutex
	target := net.IPv4(10, 0, 2, 2).To4()
	targetMAC := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	tbl.updateLocked(target, targetMAC, time.Now())

	got, err := resolveARP(&mu, tbl, link, net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IPv4(10, 0, 2, 15), target, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("resolveARP cache hit: %v", err)
	}
	if !bytes.Equal(got, targetMAC) {
		t.Errorf("MAC: got %v, want %v", got, targetMAC)
	}
	// No frame should have been sent for a cache hit.
	if n := len(link.snapshotSent()); n != 0 {
		t.Errorf("sent frames on cache hit: %d, want 0", n)
	}
}

func TestARPResolveTimeout(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	tbl := newARPTable()
	var mu sync.Mutex
	target := net.IPv4(10, 0, 2, 200).To4()
	_, err := resolveARP(&mu, tbl, link, net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IPv4(10, 0, 2, 15), target, 30*time.Millisecond)
	if err != ErrARPTimeout {
		t.Fatalf("want ErrARPTimeout, got %v", err)
	}
	// And one broadcast Request should have been sent.
	sent := link.snapshotSent()
	if len(sent) != 1 {
		t.Fatalf("sent frames: got %d, want 1", len(sent))
	}
	eth, err := ParseEthernet(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if !IsBroadcast(eth.Dst) {
		t.Errorf("ARP Request not broadcast: %v", eth.Dst)
	}
	if eth.EtherType != EtherTypeARP {
		t.Errorf("EtherType: got %#x, want %#x", eth.EtherType, EtherTypeARP)
	}
}

func TestARPResolveRejectsBadIP(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	var mu sync.Mutex
	_, err := resolveARP(&mu, newARPTable(), link, net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.IPv4(10, 0, 2, 15), net.ParseIP("::1"), 10*time.Millisecond)
	if err != ErrIPv4InvalidIP {
		t.Errorf("want ErrIPv4InvalidIP, got %v", err)
	}
}

func TestHandleARPFrameRespondsToRequest(t *testing.T) {
	link := newStubLink(net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	tbl := newARPTable()
	var mu sync.Mutex
	ourMAC := link.MAC()
	ourIP := net.IPv4(10, 0, 2, 15).To4()

	requesterMAC := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	requesterIP := net.IPv4(10, 0, 2, 2)

	// Build an incoming ARP Request "who has ourIP, tell requester".
	req, err := buildARPPacket(
		ARPOpRequest,
		requesterMAC, requesterIP,
		net.HardwareAddr{0, 0, 0, 0, 0, 0}, ourIP,
	)
	if err != nil {
		t.Fatal(err)
	}

	if err := handleARPFrame(&mu, tbl, link, ourMAC, ourIP, req); err != nil {
		t.Fatalf("handleARPFrame: %v", err)
	}

	// We should have sent a unicast Reply addressed back to requester.
	sent := link.snapshotSent()
	if len(sent) != 1 {
		t.Fatalf("sent frames: got %d, want 1", len(sent))
	}
	eth, err := ParseEthernet(sent[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(eth.Dst, requesterMAC) {
		t.Errorf("reply dst: got %v, want %v", eth.Dst, requesterMAC)
	}
	op, _, _, _, _, _ := parseARP(eth.Payload)
	if op != ARPOpReply {
		t.Errorf("reply op: got %d, want %d", op, ARPOpReply)
	}

	// And the cache learnt the requester.
	mu.Lock()
	e := tbl.getLocked(requesterIP.To4())
	mu.Unlock()
	if e == nil || !e.resolved || !bytes.Equal(e.mac, requesterMAC) {
		t.Errorf("requester not cached: %+v", e)
	}
}

func TestHandleARPFrameIgnoresOthersTarget(t *testing.T) {
	link := newStubLink(net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	tbl := newARPTable()
	var mu sync.Mutex
	ourIP := net.IPv4(10, 0, 2, 15).To4()

	otherTarget := net.IPv4(10, 0, 2, 99).To4()
	req, _ := buildARPPacket(
		ARPOpRequest,
		net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		net.IPv4(10, 0, 2, 2),
		net.HardwareAddr{0, 0, 0, 0, 0, 0},
		otherTarget,
	)
	if err := handleARPFrame(&mu, tbl, link, link.MAC(), ourIP, req); err != nil {
		t.Fatal(err)
	}
	// No reply because we're not the target.
	if n := len(link.snapshotSent()); n != 0 {
		t.Errorf("reply sent for foreign target: %d frames", n)
	}
	// But the sender is still learnt.
	mu.Lock()
	e := tbl.getLocked(net.IPv4(10, 0, 2, 2).To4())
	mu.Unlock()
	if e == nil || !e.resolved {
		t.Errorf("sender should have been learnt: %+v", e)
	}
}

func TestHandleARPFrameRejectsBad(t *testing.T) {
	link := newStubLink(net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	tbl := newARPTable()
	var mu sync.Mutex
	err := handleARPFrame(&mu, tbl, link, link.MAC(), net.IPv4(10, 0, 2, 15).To4(), []byte{1, 2, 3})
	if err != ErrARPInvalidPacket {
		t.Errorf("want ErrARPInvalidPacket, got %v", err)
	}
}

func TestARPResolveRaceWithIncomingReply(t *testing.T) {
	link := newStubLink(net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56})
	tbl := newARPTable()
	var mu sync.Mutex
	target := net.IPv4(10, 0, 2, 2).To4()
	targetMAC := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}

	// Kick off Resolve in a goroutine; race the reply in.
	done := make(chan struct {
		mac net.HardwareAddr
		err error
	}, 1)
	go func() {
		mac, err := resolveARP(&mu, tbl, link, net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}, net.IPv4(10, 0, 2, 15), target, 200*time.Millisecond)
		done <- struct {
			mac net.HardwareAddr
			err error
		}{mac, err}
	}()

	// Give Resolve a moment to send its broadcast.
	time.Sleep(10 * time.Millisecond)
	// Inject a Reply into the cache (mimicking RX dispatch).
	mu.Lock()
	tbl.updateLocked(target, targetMAC, time.Now())
	mu.Unlock()

	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("resolveARP race: %v", r.err)
		}
		if !bytes.Equal(r.mac, targetMAC) {
			t.Errorf("MAC: got %v, want %v", r.mac, targetMAC)
		}
	case <-time.After(time.Second):
		t.Fatal("resolveARP did not return after reply injected")
	}
}
