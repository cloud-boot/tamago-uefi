// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

// ----- Wire format round-trip ----------------------------------

func TestEncodeDNSName(t *testing.T) {
	cases := []struct {
		in   string
		want []byte
	}{
		{"", []byte{0}},
		{"example.com", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"example.com.", []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}},
		{"a", []byte{1, 'a', 0}},
	}
	for _, c := range cases {
		got, err := encodeDNSName(c.in)
		if err != nil {
			t.Errorf("encodeDNSName(%q): %v", c.in, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("encodeDNSName(%q): got %v, want %v", c.in, got, c.want)
		}
	}
}

func TestEncodeDNSNameRejectsLongLabel(t *testing.T) {
	long := make([]byte, 64) // 64 chars > max 63
	for i := range long {
		long[i] = 'a'
	}
	_, err := encodeDNSName(string(long))
	if err != ErrDNSLabelTooLong {
		t.Errorf("want ErrDNSLabelTooLong, got %v", err)
	}
}

func TestEncodeDNSNameRejectsLongName(t *testing.T) {
	// Many short labels that sum to > 255 bytes.
	var sb []byte
	for i := 0; i < 100; i++ {
		if i > 0 {
			sb = append(sb, '.')
		}
		sb = append(sb, "abcde"...)
	}
	_, err := encodeDNSName(string(sb))
	if err != ErrDNSNameTooLong {
		t.Errorf("want ErrDNSNameTooLong, got %v", err)
	}
}

func TestBuildDNSQuery(t *testing.T) {
	q, err := buildDNSQuery(0xCAFE, "example.com")
	if err != nil {
		t.Fatalf("buildDNSQuery: %v", err)
	}
	if binary.BigEndian.Uint16(q[0:2]) != 0xCAFE {
		t.Errorf("ID: got %#x", binary.BigEndian.Uint16(q[0:2]))
	}
	if binary.BigEndian.Uint16(q[2:4])&dnsFlagRD == 0 {
		t.Errorf("RD flag not set")
	}
	if binary.BigEndian.Uint16(q[4:6]) != 1 {
		t.Errorf("QDCOUNT: got %d, want 1", binary.BigEndian.Uint16(q[4:6]))
	}
	// Tail: QTYPE + QCLASS.
	tail := q[len(q)-4:]
	if binary.BigEndian.Uint16(tail[0:2]) != dnsTypeA {
		t.Errorf("QTYPE: got %d, want %d", binary.BigEndian.Uint16(tail[0:2]), dnsTypeA)
	}
	if binary.BigEndian.Uint16(tail[2:4]) != dnsClassIN {
		t.Errorf("QCLASS: got %d, want %d", binary.BigEndian.Uint16(tail[2:4]), dnsClassIN)
	}
}

func TestBuildDNSQueryRejectsLongLabel(t *testing.T) {
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'x'
	}
	_, err := buildDNSQuery(1, string(long))
	if err != ErrDNSLabelTooLong {
		t.Errorf("want ErrDNSLabelTooLong, got %v", err)
	}
}

func TestParseDNSNameSimple(t *testing.T) {
	pkt := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	name, next, err := parseDNSName(pkt, 0)
	if err != nil {
		t.Fatalf("parseDNSName: %v", err)
	}
	if name != "example.com" {
		t.Errorf("name: got %q, want example.com", name)
	}
	if next != len(pkt) {
		t.Errorf("next: got %d, want %d", next, len(pkt))
	}
}

func TestParseDNSNameWithPointer(t *testing.T) {
	// Build a buffer where the second name uses a pointer to the first.
	// Layout: [0..12] = header; [12..] = qname (no trailing) then later
	// an answer with a pointer.
	var pkt []byte
	pkt = make([]byte, 32)
	// At offset 12: encode "ex.com".
	target := []byte{2, 'e', 'x', 3, 'c', 'o', 'm', 0}
	copy(pkt[12:], target)
	// At offset 12+len(target)=20: a pointer back to offset 12.
	off := 12 + len(target)
	pkt[off] = 0xC0
	pkt[off+1] = 12
	name, end, err := parseDNSName(pkt, off)
	if err != nil {
		t.Fatalf("parseDNSName: %v", err)
	}
	if name != "ex.com" {
		t.Errorf("name: got %q, want ex.com", name)
	}
	if end != off+2 {
		t.Errorf("end: got %d, want %d", end, off+2)
	}
}

func TestParseDNSNameRejectsTruncated(t *testing.T) {
	// Length byte says 5, but only 2 bytes follow.
	pkt := []byte{5, 'a', 'b'}
	if _, _, err := parseDNSName(pkt, 0); err != ErrDNSBadFormat {
		t.Errorf("want ErrDNSBadFormat, got %v", err)
	}
}

func TestParseDNSNameDetectsLoopingPointer(t *testing.T) {
	// Construct a pointer that targets itself → infinite loop.
	pkt := make([]byte, 4)
	pkt[0] = 0xC0
	pkt[1] = 0
	pkt[2] = 0xC0
	pkt[3] = 2 // points to offset 2 which is also a pointer back to 0
	// Force a loop chain. Our parser caps chain at 16.
	if _, _, err := parseDNSName(pkt, 0); err != ErrDNSCompressLoop {
		t.Errorf("want ErrDNSCompressLoop, got %v", err)
	}
}

func TestParseDNSNameRejectsEmptyBuffer(t *testing.T) {
	if _, _, err := parseDNSName(nil, 0); err != ErrDNSBadFormat {
		t.Errorf("want ErrDNSBadFormat, got %v", err)
	}
}

// buildDNSAnswer constructs a synthetic A-record reply for `name` with
// the given transaction ID, suitable for fuzzing the parser.
func buildDNSAnswer(t *testing.T, id uint16, name string, answer net.IP) []byte {
	t.Helper()
	qname, err := encodeDNSName(name)
	if err != nil {
		t.Fatalf("encodeDNSName: %v", err)
	}
	// Header.
	buf := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], dnsFlagResponse|dnsFlagRD)
	binary.BigEndian.PutUint16(buf[4:6], 1) // QD
	binary.BigEndian.PutUint16(buf[6:8], 1) // AN
	// Question.
	buf = append(buf, qname...)
	buf = append(buf, 0, 1, 0, 1) // QTYPE A, QCLASS IN
	// Answer: NAME (compression pointer to offset 12), TYPE A, CLASS IN, TTL=60, RDLEN=4, RDATA=ip.
	buf = append(buf, 0xC0, 12)
	buf = append(buf, 0, 1, 0, 1)
	buf = append(buf, 0, 0, 0, 60)
	buf = append(buf, 0, 4)
	buf = append(buf, answer.To4()...)
	return buf
}

func TestParseDNSAnswerForA(t *testing.T) {
	want := net.IPv4(93, 184, 216, 34).To4()
	reply := buildDNSAnswer(t, 0xCAFE, "example.com", want)
	got, err := parseDNSAnswerForA(reply, 0xCAFE)
	if err != nil {
		t.Fatalf("parseDNSAnswerForA: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("A: got %v, want %v", got, want)
	}
}

func TestParseDNSAnswerForARejectsWrongID(t *testing.T) {
	reply := buildDNSAnswer(t, 0xCAFE, "example.com", net.IPv4(1, 2, 3, 4))
	if _, err := parseDNSAnswerForA(reply, 0xBEEF); err != ErrDNSBadFormat {
		t.Errorf("want ErrDNSBadFormat (wrong ID), got %v", err)
	}
}

func TestParseDNSAnswerForARejectsShort(t *testing.T) {
	if _, err := parseDNSAnswerForA([]byte{1, 2, 3}, 0); err != ErrDNSBadFormat {
		t.Errorf("want ErrDNSBadFormat, got %v", err)
	}
}

func TestParseDNSAnswerForARejectsNonResponse(t *testing.T) {
	q, _ := buildDNSQuery(0xCAFE, "example.com")
	if _, err := parseDNSAnswerForA(q, 0xCAFE); err != ErrDNSBadFormat {
		t.Errorf("want ErrDNSBadFormat (QR=0), got %v", err)
	}
}

func TestParseDNSAnswerForARejectsBadRcode(t *testing.T) {
	want := net.IPv4(1, 2, 3, 4)
	reply := buildDNSAnswer(t, 0xCAFE, "example.com", want)
	// Flip the rcode to NXDOMAIN (3).
	flags := binary.BigEndian.Uint16(reply[2:4])
	flags = (flags &^ dnsRcodeMask) | 3
	binary.BigEndian.PutUint16(reply[2:4], flags)
	if _, err := parseDNSAnswerForA(reply, 0xCAFE); err != ErrDNSRcode {
		t.Errorf("want ErrDNSRcode, got %v", err)
	}
}

func TestParseDNSAnswerForAEmptyAnswerSection(t *testing.T) {
	// Header with AN=0 — no answers.
	pkt := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(pkt[0:2], 0xCAFE)
	binary.BigEndian.PutUint16(pkt[2:4], dnsFlagResponse)
	binary.BigEndian.PutUint16(pkt[4:6], 0) // QD=0
	binary.BigEndian.PutUint16(pkt[6:8], 0) // AN=0
	if _, err := parseDNSAnswerForA(pkt, 0xCAFE); err != ErrDNSEmptyAnswer {
		t.Errorf("want ErrDNSEmptyAnswer, got %v", err)
	}
}

func TestParseDNSAnswerForASkipsCNAMEReturnsA(t *testing.T) {
	// Build a reply with [CNAME, A] in the answer section. Our parser
	// must skip the CNAME (TYPE=5) and return the A record.
	id := uint16(0xBEAF)
	qname, _ := encodeDNSName("alias.example")
	cnameRDATA, _ := encodeDNSName("canonical.example")
	buf := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], dnsFlagResponse)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], 2)
	// Question
	buf = append(buf, qname...)
	buf = append(buf, 0, 1, 0, 1)
	// First answer: CNAME pointing to the canonical name.
	buf = append(buf, 0xC0, 12)
	buf = append(buf, 0, 5, 0, 1) // TYPE=CNAME, CLASS=IN
	buf = append(buf, 0, 0, 0, 60)
	binary.BigEndian.PutUint16([]byte{0, 0}, uint16(len(cnameRDATA)))
	rdlen := make([]byte, 2)
	binary.BigEndian.PutUint16(rdlen, uint16(len(cnameRDATA)))
	buf = append(buf, rdlen...)
	buf = append(buf, cnameRDATA...)
	// Second answer: A record for canonical name.
	buf = append(buf, 0xC0, 12)
	buf = append(buf, 0, 1, 0, 1)
	buf = append(buf, 0, 0, 0, 60)
	buf = append(buf, 0, 4)
	buf = append(buf, 192, 168, 1, 100)
	got, err := parseDNSAnswerForA(buf, id)
	if err != nil {
		t.Fatalf("parseDNSAnswerForA: %v", err)
	}
	if !got.Equal(net.IPv4(192, 168, 1, 100)) {
		t.Errorf("A: got %v, want 192.168.1.100", got)
	}
}

func TestDNSIDFromMACDeterministic(t *testing.T) {
	mac := net.HardwareAddr{0x52, 0x54, 0, 1, 2, 3}
	a := dnsIDFromMAC(mac, 0xAAAA, 49152)
	b := dnsIDFromMAC(mac, 0xAAAA, 49152)
	if a != b {
		t.Errorf("ID not deterministic: %#x vs %#x", a, b)
	}
	c := dnsIDFromMAC(mac, 0xAAAA, 49153)
	if a == c {
		t.Errorf("ID collision across ports: %#x", a)
	}
	if got := dnsIDFromMAC(net.HardwareAddr{1, 2, 3}, 0x1234, 0xABCD); got != 0x1234^0xABCD {
		t.Errorf("short MAC fallback: got %#x", got)
	}
}

// ----- End-to-end resolver test --------------------------------

// dnsResponder is a synthetic UDP responder that returns a fixed A
// record for any query it receives, mirroring the query's transaction
// ID into the reply.
type dnsResponder struct {
	link      *stubLink
	clientMAC net.HardwareAddr
	serverMAC net.HardwareAddr
	clientIP  net.IP
	serverIP  net.IP
	answer    net.IP
	done      chan struct{}
	once      sync.Once
	delay     time.Duration
}

func newDNSResponder(link *stubLink, clientMAC net.HardwareAddr, clientIP, serverIP, answer net.IP) *dnsResponder {
	return &dnsResponder{
		link:      link,
		clientMAC: append(net.HardwareAddr(nil), clientMAC...),
		serverMAC: net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x03},
		clientIP:  append(net.IP(nil), clientIP...),
		serverIP:  append(net.IP(nil), serverIP...),
		answer:    append(net.IP(nil), answer...),
		done:      make(chan struct{}),
	}
}

func (d *dnsResponder) start() { go d.loop() }
func (d *dnsResponder) stop()  { d.once.Do(func() { close(d.done) }) }

func (d *dnsResponder) loop() {
	idx := 0
	for {
		select {
		case <-d.done:
			return
		default:
		}
		d.link.mu.Lock()
		var fresh [][]byte
		if idx < len(d.link.sent) {
			for i := idx; i < len(d.link.sent); i++ {
				fresh = append(fresh, append([]byte(nil), d.link.sent[i]...))
			}
			idx = len(d.link.sent)
		}
		d.link.mu.Unlock()
		for _, f := range fresh {
			d.maybeAnswer(f)
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func (d *dnsResponder) maybeAnswer(frame []byte) {
	eth, err := ParseEthernet(frame)
	if err != nil {
		return
	}
	switch eth.EtherType {
	case EtherTypeARP:
		op, sha, spa, _, tpa, err := parseARP(eth.Payload)
		if err != nil || op != ARPOpRequest {
			return
		}
		if !tpa.Equal(d.serverIP) {
			return
		}
		reply, _ := buildARPPacket(ARPOpReply, d.serverMAC, d.serverIP, sha, spa)
		rf, _ := MarshalEthernet(sha, d.serverMAC, EtherTypeARP, reply)
		d.link.inject(rf)
	case EtherTypeIPv4:
		ip, ipBody, err := ParseIPv4(eth.Payload)
		if err != nil || ip.Protocol != IPProtoUDP {
			return
		}
		uh, payload, err := ParseUDP4(ip.Src, ip.Dst, ipBody)
		if err != nil || uh.DstPort != 53 {
			return
		}
		if len(payload) < dnsHeaderLen {
			return
		}
		id := binary.BigEndian.Uint16(payload[0:2])
		// Parse the qname out of the query so we can echo it back.
		name, _, perr := parseDNSName(payload, dnsHeaderLen)
		if perr != nil {
			return
		}
		if d.delay > 0 {
			time.Sleep(d.delay)
		}
		reply := buildDNSAnswerWire(id, name, d.answer)
		udp, _ := MarshalUDP4(d.serverIP, d.clientIP, 53, uh.SrcPort, reply)
		ipPkt, _ := MarshalIPv4(d.serverIP, d.clientIP, IPProtoUDP, 0x4242, udp)
		rf, _ := MarshalEthernet(d.clientMAC, d.serverMAC, EtherTypeIPv4, ipPkt)
		d.link.inject(rf)
	}
}

// buildDNSAnswerWire is a non-testing helper (no *testing.T) so the
// responder goroutine can call it.
func buildDNSAnswerWire(id uint16, name string, answer net.IP) []byte {
	qname, err := encodeDNSName(name)
	if err != nil {
		return nil
	}
	buf := make([]byte, dnsHeaderLen)
	binary.BigEndian.PutUint16(buf[0:2], id)
	binary.BigEndian.PutUint16(buf[2:4], dnsFlagResponse|dnsFlagRD)
	binary.BigEndian.PutUint16(buf[4:6], 1)
	binary.BigEndian.PutUint16(buf[6:8], 1)
	buf = append(buf, qname...)
	buf = append(buf, 0, 1, 0, 1)
	buf = append(buf, 0xC0, 12)
	buf = append(buf, 0, 1, 0, 1)
	buf = append(buf, 0, 0, 0, 60)
	buf = append(buf, 0, 4)
	buf = append(buf, answer.To4()...)
	return buf
}

func TestResolveAEndToEnd(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x70}
	ourIP := net.IPv4(10, 0, 2, 15)
	dnsIP := net.IPv4(10, 0, 2, 3)
	want := net.IPv4(93, 184, 216, 34)
	mask := net.IPv4Mask(255, 255, 255, 0)

	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(200 * time.Millisecond)
	if err := s.SetIPv4Address(ourIP, mask); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefaultGateway(net.IPv4(10, 0, 2, 2)); err != nil {
		t.Fatal(err)
	}

	r := newDNSResponder(link, ourMAC, ourIP, dnsIP, want)
	r.start()
	defer r.stop()

	s.Start()
	defer s.Close()

	got, err := s.ResolveA("example.com", dnsIP, 2*time.Second)
	if err != nil {
		t.Fatalf("ResolveA: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("ResolveA: got %v, want %v", got, want)
	}
}

func TestResolveATimeoutNoServer(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x71}
	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(20 * time.Millisecond)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	s.Start()
	defer s.Close()
	_, err := s.ResolveA("example.com", net.IPv4(10, 0, 2, 3), 80*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestResolveARejectsBadServer(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_, err := s.ResolveA("example.com", net.ParseIP("::1"), 10*time.Millisecond)
	if err != ErrDNSInvalidServer {
		t.Errorf("want ErrDNSInvalidServer, got %v", err)
	}
}

func TestResolveAPostCloseRejects(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	s.Close()
	_, err := s.ResolveA("example.com", net.IPv4(1, 1, 1, 1), 10*time.Millisecond)
	if err != ErrStackClosed {
		t.Errorf("want ErrStackClosed, got %v", err)
	}
}

func TestResolveARejectsBadName(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	long := make([]byte, 64)
	for i := range long {
		long[i] = 'a'
	}
	_, err := s.ResolveA(string(long), net.IPv4(10, 0, 2, 3), 50*time.Millisecond)
	if err != ErrDNSLabelTooLong {
		t.Errorf("want ErrDNSLabelTooLong, got %v", err)
	}
}
