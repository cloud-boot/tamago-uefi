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

func TestDHCP4OptionsRoundTrip(t *testing.T) {
	in := []dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgOffer}},
		{tag: dhcp4OptServerID, value: []byte{10, 0, 2, 2}},
		{tag: dhcp4OptSubnetMask, value: []byte{255, 255, 255, 0}},
		{tag: dhcp4OptRouter, value: []byte{10, 0, 2, 2}},
		{tag: dhcp4OptDNS, value: []byte{10, 0, 2, 3, 8, 8, 8, 8}},
		{tag: dhcp4OptLeaseTime, value: []byte{0, 1, 0x51, 0x80}}, // 86400 seconds
	}
	buf := marshalDHCP4Options(in)
	if buf[len(buf)-1] != dhcp4OptEnd {
		t.Errorf("marshalled options not End-terminated, tail=%#x", buf[len(buf)-1])
	}

	out, err := parseDHCP4Options(buf)
	if err != nil {
		t.Fatalf("parseDHCP4Options: %v", err)
	}
	for _, e := range in {
		got, ok := out[e.tag]
		if !ok {
			t.Errorf("option %d missing after round-trip", e.tag)
			continue
		}
		if !bytes.Equal(got, e.value) {
			t.Errorf("option %d: got %v, want %v", e.tag, got, e.value)
		}
	}
}

func TestDHCP4ParseOptionsSkipsPadAndStopsAtEnd(t *testing.T) {
	// Manually-constructed option block: a few pad bytes, an option,
	// more pad bytes, the End option, and trailing garbage that MUST
	// NOT be parsed.
	buf := []byte{
		dhcp4OptPad, dhcp4OptPad,
		dhcp4OptMessageType, 1, dhcp4MsgAck,
		dhcp4OptPad,
		dhcp4OptEnd,
		// Trailing garbage — never reached.
		0x55, 0x66, 0x77,
	}
	out, err := parseDHCP4Options(buf)
	if err != nil {
		t.Fatalf("parseDHCP4Options: %v", err)
	}
	if v, ok := out[dhcp4OptMessageType]; !ok || !bytes.Equal(v, []byte{dhcp4MsgAck}) {
		t.Errorf("Message Type: got %v, want %v", v, []byte{dhcp4MsgAck})
	}
}

func TestDHCP4ParseOptionsTruncatedLength(t *testing.T) {
	// Tag + length byte saying "3 bytes follow" but supplying only 2.
	bad := []byte{dhcp4OptMessageType, 3, 0x01, 0x02}
	_, err := parseDHCP4Options(bad)
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (length overruns), got %v", err)
	}
	// Tag with no following length byte.
	bad2 := []byte{dhcp4OptMessageType}
	_, err = parseDHCP4Options(bad2)
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (missing length), got %v", err)
	}
}

func TestDHCP4ParseOptionsNoEnd(t *testing.T) {
	// No End marker — accept the truncation but parse what we have.
	buf := []byte{dhcp4OptMessageType, 1, dhcp4MsgOffer}
	out, err := parseDHCP4Options(buf)
	if err != nil {
		t.Fatalf("parseDHCP4Options: %v", err)
	}
	if v, ok := out[dhcp4OptMessageType]; !ok || v[0] != dhcp4MsgOffer {
		t.Errorf("Message Type: got %v, want OFFER", v)
	}
}

func TestDHCP4BuildAndParseMessage(t *testing.T) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	xid := uint32(0xDEADBEEF)
	opts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgDiscover}},
		{tag: dhcp4OptClientID, value: dhcp4ClientIDFromMAC(mac)},
	})
	msg, err := buildDHCP4Message(xid, mac, opts)
	if err != nil {
		t.Fatalf("buildDHCP4Message: %v", err)
	}

	// Header sanity checks.
	if msg[0] != dhcp4BootRequest {
		t.Errorf("op: got %d, want %d", msg[0], dhcp4BootRequest)
	}
	if msg[1] != dhcp4HTypeEthernet {
		t.Errorf("htype: got %d, want %d", msg[1], dhcp4HTypeEthernet)
	}
	if msg[2] != dhcp4HLenEthernet {
		t.Errorf("hlen: got %d, want %d", msg[2], dhcp4HLenEthernet)
	}
	if binary.BigEndian.Uint32(msg[4:8]) != xid {
		t.Errorf("xid: got %#x, want %#x", binary.BigEndian.Uint32(msg[4:8]), xid)
	}
	if binary.BigEndian.Uint16(msg[10:12]) != dhcp4FlagBroadcast {
		t.Errorf("flags: not broadcast")
	}
	if !bytes.Equal(msg[28:34], mac) {
		t.Errorf("chaddr: got %v, want %v", msg[28:34], mac)
	}
	if binary.BigEndian.Uint32(msg[236:240]) != dhcp4MagicCookie {
		t.Errorf("magic cookie: got %#x, want %#x", binary.BigEndian.Uint32(msg[236:240]), dhcp4MagicCookie)
	}

	// Now flip the op byte to BOOTREPLY and re-parse — that's what a
	// real DHCP server response would look like.
	msg[0] = dhcp4BootReply
	// Stamp a yiaddr we can verify.
	copy(msg[16:20], []byte{10, 0, 2, 15})

	gotXID, yi, parsed, err := parseDHCP4Message(msg)
	if err != nil {
		t.Fatalf("parseDHCP4Message: %v", err)
	}
	if gotXID != xid {
		t.Errorf("xid round-trip: got %#x, want %#x", gotXID, xid)
	}
	if !yi.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Errorf("yiaddr: got %v, want 10.0.2.15", yi)
	}
	if v := parsed[dhcp4OptMessageType]; len(v) != 1 || v[0] != dhcp4MsgDiscover {
		t.Errorf("option 53 round-trip: got %v", v)
	}
}

func TestDHCP4BuildMessageRejectsBadMAC(t *testing.T) {
	_, err := buildDHCP4Message(0, net.HardwareAddr{1, 2, 3}, nil)
	if err != ErrInvalidMAC {
		t.Errorf("want ErrInvalidMAC, got %v", err)
	}
}

func TestDHCP4ParseMessageRejectsShort(t *testing.T) {
	_, _, _, err := parseDHCP4Message(make([]byte, 10))
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (short), got %v", err)
	}
}

func TestDHCP4ParseMessageRejectsWrongOp(t *testing.T) {
	buf := make([]byte, dhcp4HeaderLen+4)
	buf[0] = dhcp4BootRequest // we're parsing a server reply: op must be 2
	binary.BigEndian.PutUint32(buf[236:240], dhcp4MagicCookie)
	_, _, _, err := parseDHCP4Message(buf)
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (op != 2), got %v", err)
	}
}

func TestDHCP4ParseMessageRejectsBadMagic(t *testing.T) {
	buf := make([]byte, dhcp4HeaderLen+4)
	buf[0] = dhcp4BootReply
	binary.BigEndian.PutUint32(buf[236:240], 0xDEADBEEF)
	_, _, _, err := parseDHCP4Message(buf)
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (magic), got %v", err)
	}
}

func TestDHCP4ParseMessageBadOptions(t *testing.T) {
	buf := make([]byte, dhcp4HeaderLen+4+2)
	buf[0] = dhcp4BootReply
	binary.BigEndian.PutUint32(buf[236:240], dhcp4MagicCookie)
	// One option, tag=53, claims length=10 but only 0 bytes available.
	buf[dhcp4HeaderLen+4] = dhcp4OptMessageType
	buf[dhcp4HeaderLen+4+1] = 10
	_, _, _, err := parseDHCP4Message(buf)
	if err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat (bad options), got %v", err)
	}
}

func TestDHCP4XIDDeterministic(t *testing.T) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	a := dhcp4XIDFromMAC(mac, 0xAAAAAAAA)
	b := dhcp4XIDFromMAC(mac, 0xAAAAAAAA)
	if a != b {
		t.Errorf("xid not deterministic: %#x vs %#x", a, b)
	}
	// Different MAC → different xid.
	other := net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	c := dhcp4XIDFromMAC(other, 0xAAAAAAAA)
	if a == c {
		t.Errorf("xid collision across MACs: %#x", a)
	}
	// Short MAC → returns seed.
	if got := dhcp4XIDFromMAC(net.HardwareAddr{1, 2, 3}, 0x12345678); got != 0x12345678 {
		t.Errorf("short MAC: got %#x, want seed", got)
	}
}

func TestDHCP4ClientIDFromMAC(t *testing.T) {
	mac := net.HardwareAddr{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe}
	id := dhcp4ClientIDFromMAC(mac)
	if id[0] != 0x01 {
		t.Errorf("hardware type byte: got %#x, want 0x01", id[0])
	}
	if !bytes.Equal(id[1:], mac) {
		t.Errorf("MAC bytes: got %v, want %v", id[1:], mac)
	}
}

func TestDHCP4ParseMessageTypeMissing(t *testing.T) {
	if _, err := parseDHCP4MessageType(dhcp4Options{}); err != ErrDHCP4MissingOption {
		t.Errorf("want ErrDHCP4MissingOption, got %v", err)
	}
}

func TestDHCP4ParseMessageTypeBadLength(t *testing.T) {
	opts := dhcp4Options{dhcp4OptMessageType: []byte{1, 2}}
	if _, err := parseDHCP4MessageType(opts); err != ErrDHCP4BadFormat {
		t.Errorf("want ErrDHCP4BadFormat, got %v", err)
	}
}

func TestDHCP4LeaseFromOptions(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	opts := dhcp4Options{
		dhcp4OptSubnetMask: {255, 255, 255, 0},
		dhcp4OptRouter:     {10, 0, 2, 2},
		dhcp4OptDNS:        {10, 0, 2, 3, 8, 8, 8, 8},
		dhcp4OptServerID:   {10, 0, 2, 2},
		dhcp4OptLeaseTime:  {0, 1, 0x51, 0x80}, // 86400 seconds = 24h
	}
	lease := dhcp4LeaseFromOptions(yi, opts)
	if !lease.IP.Equal(yi) {
		t.Errorf("IP: got %v, want %v", lease.IP, yi)
	}
	if !bytes.Equal(lease.Mask, net.IPv4Mask(255, 255, 255, 0)) {
		t.Errorf("Mask: got %v, want 255.255.255.0", lease.Mask)
	}
	if !lease.Gateway.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Errorf("Gateway: got %v, want 10.0.2.2", lease.Gateway)
	}
	if len(lease.DNS) != 2 {
		t.Fatalf("DNS count: got %d, want 2", len(lease.DNS))
	}
	if !lease.DNS[0].Equal(net.IPv4(10, 0, 2, 3)) || !lease.DNS[1].Equal(net.IPv4(8, 8, 8, 8)) {
		t.Errorf("DNS: got %v", lease.DNS)
	}
	if !lease.Server.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Errorf("Server: got %v, want 10.0.2.2", lease.Server)
	}
	if lease.Duration != 86400*time.Second {
		t.Errorf("Duration: got %v, want 24h", lease.Duration)
	}
}

func TestDHCP4LeaseCapsDNSAtFour(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	// 6 DNS servers — should be capped at 4.
	dns := make([]byte, 6*4)
	for i := 0; i < 6; i++ {
		dns[i*4+3] = byte(i + 1)
	}
	opts := dhcp4Options{dhcp4OptDNS: dns}
	lease := dhcp4LeaseFromOptions(yi, opts)
	if len(lease.DNS) != 4 {
		t.Errorf("DNS cap: got %d, want 4", len(lease.DNS))
	}
}

func TestDHCP4LeaseHandlesMissingOptions(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	lease := dhcp4LeaseFromOptions(yi, dhcp4Options{})
	if lease.Mask != nil {
		t.Errorf("Mask: got %v, want nil", lease.Mask)
	}
	if lease.Gateway != nil {
		t.Errorf("Gateway: got %v, want nil", lease.Gateway)
	}
	if lease.Duration != 0 {
		t.Errorf("Duration: got %v, want 0", lease.Duration)
	}
}

// dhcp4Server is a synthetic UDP responder that consumes the client's
// DISCOVER + REQUEST and shoots back OFFER + ACK. We drive it off the
// stubLink's "sent" tape; replies are injected back through the link's
// recv channel so the Stack's RX goroutine picks them up.
type dhcp4Server struct {
	link        *stubLink
	clientMAC   net.HardwareAddr
	serverMAC   net.HardwareAddr
	serverIP    net.IP
	offerIP     net.IP
	mask        []byte
	router      []byte
	dns         []byte
	lease       []byte
	suppressACK bool
	once        sync.Once
	done        chan struct{}
}

func newDHCP4Server(link *stubLink, clientMAC net.HardwareAddr) *dhcp4Server {
	return &dhcp4Server{
		link:      link,
		clientMAC: append(net.HardwareAddr(nil), clientMAC...),
		serverMAC: net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		serverIP:  net.IPv4(10, 0, 2, 2).To4(),
		offerIP:   net.IPv4(10, 0, 2, 15).To4(),
		mask:      []byte{255, 255, 255, 0},
		router:    []byte{10, 0, 2, 2},
		dns:       []byte{10, 0, 2, 3},
		lease:     []byte{0, 1, 0x51, 0x80},
		done:      make(chan struct{}),
	}
}

func (g *dhcp4Server) start() {
	go g.loop()
}

func (g *dhcp4Server) stop() {
	g.once.Do(func() { close(g.done) })
}

func (g *dhcp4Server) loop() {
	idx := 0
	for {
		select {
		case <-g.done:
			return
		default:
		}
		g.link.mu.Lock()
		var fresh [][]byte
		if idx < len(g.link.sent) {
			for i := idx; i < len(g.link.sent); i++ {
				fresh = append(fresh, append([]byte(nil), g.link.sent[i]...))
			}
			idx = len(g.link.sent)
		}
		g.link.mu.Unlock()
		for _, f := range fresh {
			g.respond(f)
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func (g *dhcp4Server) respond(frame []byte) {
	eth, err := ParseEthernet(frame)
	if err != nil || eth.EtherType != EtherTypeIPv4 {
		return
	}
	ip, ipBody, err := ParseIPv4(eth.Payload)
	if err != nil || ip.Protocol != IPProtoUDP {
		return
	}
	uh, payload, err := ParseUDP4(ip.Src, ip.Dst, ipBody)
	if err != nil || uh.DstPort != dhcp4ServerPort {
		return
	}
	xid, _, opts, err := parseDHCP4ClientMessage(payload)
	if err != nil {
		return
	}
	mtype, err := parseDHCP4MessageType(opts)
	if err != nil {
		return
	}
	switch mtype {
	case dhcp4MsgDiscover:
		g.sendReply(dhcp4MsgOffer, xid)
	case dhcp4MsgRequest:
		if g.suppressACK {
			return
		}
		g.sendReply(dhcp4MsgAck, xid)
	}
}

// parseDHCP4ClientMessage is a parser variant that accepts BOOTREQUEST
// (the client side of the conversation). Used by our test server.
func parseDHCP4ClientMessage(buf []byte) (xid uint32, yi net.IP, opts dhcp4Options, err error) {
	if len(buf) < dhcp4HeaderLen+4 {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	if buf[0] != dhcp4BootRequest {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	if binary.BigEndian.Uint32(buf[236:240]) != dhcp4MagicCookie {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	xid = binary.BigEndian.Uint32(buf[4:8])
	yi = append(net.IP(nil), buf[16:20]...)
	opts, err = parseDHCP4Options(buf[240:])
	return xid, yi, opts, err
}

func (g *dhcp4Server) sendReply(mtype uint8, xid uint32) {
	// Build a BOOTREPLY message with op=2, yiaddr=offerIP, plus the
	// canonical option set.
	opts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{mtype}},
		{tag: dhcp4OptServerID, value: append([]byte(nil), g.serverIP...)},
		{tag: dhcp4OptLeaseTime, value: append([]byte(nil), g.lease...)},
		{tag: dhcp4OptSubnetMask, value: append([]byte(nil), g.mask...)},
		{tag: dhcp4OptRouter, value: append([]byte(nil), g.router...)},
		{tag: dhcp4OptDNS, value: append([]byte(nil), g.dns...)},
	})
	msg, err := buildDHCP4Message(xid, g.clientMAC, opts)
	if err != nil {
		return
	}
	msg[0] = dhcp4BootReply
	copy(msg[16:20], g.offerIP)

	// Now wrap in UDP + IPv4 + Ethernet (server's MAC → client's MAC).
	udp, err := MarshalUDP4(g.serverIP, g.offerIP, dhcp4ServerPort, dhcp4ClientPort, msg)
	if err != nil {
		return
	}
	ipPkt, err := MarshalIPv4(g.serverIP, g.offerIP, IPProtoUDP, 0xCAFE, udp)
	if err != nil {
		return
	}
	frame, err := MarshalEthernet(g.clientMAC, g.serverMAC, EtherTypeIPv4, ipPkt)
	if err != nil {
		return
	}
	g.link.inject(frame)
}

func TestDHCP4AcquireEndToEnd(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(50 * time.Millisecond)
	srv := newDHCP4Server(link, ourMAC)
	srv.start()
	defer srv.stop()
	s.Start()
	defer s.Close()

	lease, err := s.DHCP4Acquire(2 * time.Second)
	if err != nil {
		t.Fatalf("DHCP4Acquire: %v", err)
	}
	if !lease.IP.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Errorf("IP: got %v, want 10.0.2.15", lease.IP)
	}
	if !bytes.Equal(lease.Mask, net.IPv4Mask(255, 255, 255, 0)) {
		t.Errorf("Mask: got %v, want 255.255.255.0", lease.Mask)
	}
	if !lease.Gateway.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Errorf("Gateway: got %v, want 10.0.2.2", lease.Gateway)
	}
	if !lease.Server.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Errorf("Server: got %v, want 10.0.2.2", lease.Server)
	}
	if len(lease.DNS) == 0 || !lease.DNS[0].Equal(net.IPv4(10, 0, 2, 3)) {
		t.Errorf("DNS: got %v, want [10.0.2.3,...]", lease.DNS)
	}
	if lease.Duration != 86400*time.Second {
		t.Errorf("Duration: got %v, want 24h", lease.Duration)
	}
}

func TestDHCP4AcquireTimeoutNoServer(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x57}
	link := newStubLink(ourMAC)
	s := New(link)
	s.Start()
	defer s.Close()
	_, err := s.DHCP4Acquire(80 * time.Millisecond)
	if err != ErrDHCP4Timeout {
		t.Errorf("want ErrDHCP4Timeout, got %v", err)
	}
}

func TestDHCP4AcquireTimeoutNoACK(t *testing.T) {
	// The server replies to DISCOVER (OFFER) but suppresses ACK.
	// We should get ErrDHCP4Timeout after the wall clock elapses.
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x58}
	link := newStubLink(ourMAC)
	s := New(link)
	srv := newDHCP4Server(link, ourMAC)
	srv.suppressACK = true
	srv.start()
	defer srv.stop()
	s.Start()
	defer s.Close()
	_, err := s.DHCP4Acquire(150 * time.Millisecond)
	if err != ErrDHCP4Timeout {
		t.Errorf("want ErrDHCP4Timeout, got %v", err)
	}
}

func TestDHCP4WaitForReturnsNAK(t *testing.T) {
	// Drive dhcp4WaitFor directly with a NAK message — it must
	// surface ErrDHCP4Nak. Build a NAK message inline.
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	conn, _ := s.OpenUDP4(dhcp4ClientPort)
	defer conn.Close()

	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	xid := uint32(0x1234ABCD)
	opts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgNak}},
		{tag: dhcp4OptServerID, value: []byte{10, 0, 2, 2}},
	})
	msg, _ := buildDHCP4Message(xid, mac, opts)
	msg[0] = dhcp4BootReply

	// Deliver the NAK as if it had arrived from the wire.
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: msg,
	})
	_, _, err := dhcp4WaitFor(conn, xid, dhcp4MsgAck, time.Now().Add(200*time.Millisecond))
	if err != ErrDHCP4Nak {
		t.Errorf("want ErrDHCP4Nak, got %v", err)
	}
}

func TestDHCP4WaitForIgnoresWrongXID(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	conn, _ := s.OpenUDP4(dhcp4ClientPort)
	defer conn.Close()

	// Inject an OFFER for some OTHER xid first.
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	opts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgOffer}},
	})
	other, _ := buildDHCP4Message(0xCCCCCCCC, mac, opts)
	other[0] = dhcp4BootReply
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: other,
	})

	// Now inject the actual one (our xid).
	wantXID := uint32(0x12345678)
	mine, _ := buildDHCP4Message(wantXID, mac, opts)
	mine[0] = dhcp4BootReply
	copy(mine[16:20], []byte{10, 0, 2, 15})
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: mine,
	})

	yi, _, err := dhcp4WaitFor(conn, wantXID, dhcp4MsgOffer, time.Now().Add(500*time.Millisecond))
	if err != nil {
		t.Fatalf("dhcp4WaitFor: %v", err)
	}
	if !yi.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Errorf("yiaddr: got %v, want 10.0.2.15", yi)
	}
}

func TestDHCP4WaitForIgnoresMalformedAndWrongType(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	conn, _ := s.OpenUDP4(dhcp4ClientPort)
	defer conn.Close()

	// Malformed payload (too short).
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: []byte{1, 2, 3},
	})
	// Wrong message type (an OFFER while we're waiting for ACK).
	mac := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	xid := uint32(0x4242)
	wrongTypeOpts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgOffer}},
	})
	wrongType, _ := buildDHCP4Message(xid, mac, wrongTypeOpts)
	wrongType[0] = dhcp4BootReply
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: wrongType,
	})
	// Missing message type option (option 53 absent).
	missingOpts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptServerID, value: []byte{10, 0, 2, 2}},
	})
	missing, _ := buildDHCP4Message(xid, mac, missingOpts)
	missing[0] = dhcp4BootReply
	conn.deliver(udp4Datagram{
		Src:     net.UDPAddr{IP: net.IPv4(10, 0, 2, 2), Port: int(dhcp4ServerPort)},
		Payload: missing,
	})

	// All three above should be silently consumed; we time out since
	// no ACK ever arrives.
	_, _, err := dhcp4WaitFor(conn, xid, dhcp4MsgAck, time.Now().Add(150*time.Millisecond))
	if err != ErrDHCP4Timeout {
		t.Errorf("want ErrDHCP4Timeout, got %v", err)
	}
}

func TestDHCP4AcquireMissingServerIDInOffer(t *testing.T) {
	// Server sends OFFER but omits option 54. The acquire must
	// surface ErrDHCP4MissingOption.
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x59}
	link := newStubLink(ourMAC)
	s := New(link)
	s.Start()
	defer s.Close()

	conn, err := s.OpenUDP4(dhcp4ClientPort)
	if err != nil {
		t.Fatal(err)
	}
	// We don't call DHCP4Acquire directly because it would re-Open the
	// same port. Instead, drive the internal state by hand and inject
	// an OFFER that's missing option 54.
	_ = conn.Close()

	// Simpler approach: re-purpose the synthetic server to drop
	// option 54 from its reply, then invoke acquire.
	srv := newDHCP4Server(link, ourMAC)
	// Override: send a server reply with NO option 54.
	srv.serverIP = net.IP{0, 0, 0, 0} // not used, we override sendReply below
	old := srv.sendReply
	_ = old
	// We replace sendReply by introducing a wrapper. Simpler: just
	// directly inject a hand-crafted OFFER once we observe the
	// DISCOVER on the link.
	go func() {
		idx := 0
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			link.mu.Lock()
			var fresh [][]byte
			if idx < len(link.sent) {
				for i := idx; i < len(link.sent); i++ {
					fresh = append(fresh, append([]byte(nil), link.sent[i]...))
				}
				idx = len(link.sent)
			}
			link.mu.Unlock()
			for _, f := range fresh {
				eth, _ := ParseEthernet(f)
				if eth.EtherType != EtherTypeIPv4 {
					continue
				}
				ipH, ipBody, _ := ParseIPv4(eth.Payload)
				if ipH.Protocol != IPProtoUDP {
					continue
				}
				uh, payload, _ := ParseUDP4(ipH.Src, ipH.Dst, ipBody)
				if uh.DstPort != dhcp4ServerPort {
					continue
				}
				xid, _, _, perr := parseDHCP4ClientMessage(payload)
				if perr != nil {
					continue
				}
				opts := marshalDHCP4Options([]dhcp4OptionEntry{
					{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgOffer}},
					// Deliberately omit option 54 (Server ID).
				})
				msg, _ := buildDHCP4Message(xid, ourMAC, opts)
				msg[0] = dhcp4BootReply
				copy(msg[16:20], []byte{10, 0, 2, 15})
				udp, _ := MarshalUDP4(net.IPv4(10, 0, 2, 2), net.IPv4(10, 0, 2, 15), dhcp4ServerPort, dhcp4ClientPort, msg)
				ipPkt, _ := MarshalIPv4(net.IPv4(10, 0, 2, 2), net.IPv4(10, 0, 2, 15), IPProtoUDP, 0, udp)
				frame, _ := MarshalEthernet(ourMAC, net.HardwareAddr{0xaa, 0, 0, 0, 0, 1}, EtherTypeIPv4, ipPkt)
				link.inject(frame)
			}
			time.Sleep(2 * time.Millisecond)
		}
	}()

	_, err = s.DHCP4Acquire(500 * time.Millisecond)
	if err != ErrDHCP4MissingOption {
		t.Errorf("want ErrDHCP4MissingOption, got %v", err)
	}
}

func TestDHCP4AcquireFailsOnOpenedPort(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x5a}
	link := newStubLink(ourMAC)
	s := New(link)
	// Pre-bind port 68 — acquire must fail to open it.
	c, _ := s.OpenUDP4(dhcp4ClientPort)
	defer c.Close()
	_, err := s.DHCP4Acquire(50 * time.Millisecond)
	if err != ErrUDP4PortInUse {
		t.Errorf("want ErrUDP4PortInUse, got %v", err)
	}
}

func TestDHCP4ParameterRequestList(t *testing.T) {
	prl := dhcp4ParameterRequestList()
	wantTags := []uint8{dhcp4OptSubnetMask, dhcp4OptRouter, dhcp4OptDNS, dhcp4OptLeaseTime, dhcp4OptBootfileName}
	if len(prl) != len(wantTags) {
		t.Fatalf("length: got %d, want %d", len(prl), len(wantTags))
	}
	for i, want := range wantTags {
		if prl[i] != want {
			t.Errorf("entry %d: got %d, want %d", i, prl[i], want)
		}
	}
}

// TestDHCP4LeaseExtractsBootfileName covers the M9.0 deliverable:
// DHCP option 67 (Bootfile-Name) is parsed off the ACK and surfaced on
// DHCP4Lease.BootfileName as a plain UTF-8 string. The OCI-ref shape
// is exactly what cloud-boot's M9 menu path expects to consume.
func TestDHCP4LeaseExtractsBootfileName(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	ref := "ghcr.io/myorg/bootconfig:v1.0"
	opts := dhcp4Options{
		dhcp4OptSubnetMask:   {255, 255, 255, 0},
		dhcp4OptRouter:       {10, 0, 2, 2},
		dhcp4OptBootfileName: []byte(ref),
	}
	lease := dhcp4LeaseFromOptions(yi, opts)
	if lease.BootfileName != ref {
		t.Errorf("BootfileName: got %q, want %q", lease.BootfileName, ref)
	}
}

// TestDHCP4LeaseBootfileNameTrimsTrailingNULs covers the ISC-dhcpd
// quirk where the option value is padded to the BOOTP file-field width
// with trailing NUL bytes. We must NOT include those NULs in the OCI
// ref string — oci.ParseRef would barf on them.
func TestDHCP4LeaseBootfileNameTrimsTrailingNULs(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	ref := "ghcr.io/myorg/bootconfig:v1.0"
	padded := append([]byte(ref), 0, 0, 0, 0)
	opts := dhcp4Options{dhcp4OptBootfileName: padded}
	lease := dhcp4LeaseFromOptions(yi, opts)
	if lease.BootfileName != ref {
		t.Errorf("BootfileName: got %q (len=%d), want %q (len=%d)",
			lease.BootfileName, len(lease.BootfileName), ref, len(ref))
	}
}

// TestDHCP4LeaseBootfileNameAbsent: when the server does not include
// option 67 the field is empty (cloud-boot's M9 dispatch then takes
// the "no menu, fall through" branch).
func TestDHCP4LeaseBootfileNameAbsent(t *testing.T) {
	yi := net.IPv4(10, 0, 2, 15).To4()
	lease := dhcp4LeaseFromOptions(yi, dhcp4Options{})
	if lease.BootfileName != "" {
		t.Errorf("BootfileName: got %q, want empty", lease.BootfileName)
	}
}

// TestDHCP4ParseMessageWithOption67 walks the full BOOTP/DHCP wire-
// format path: we hand-craft an ACK buffer containing option 67 with a
// sample OCI ref, run it through parseDHCP4Message + the lease
// builder, and verify BootfileName surfaces end-to-end. This is the
// host-side acceptance test for M9.0 deliverable #1.
func TestDHCP4ParseMessageWithOption67(t *testing.T) {
	mac := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	xid := uint32(0x4D39_0F00) // "M9.0\x00"
	ref := "ghcr.io/myorg/bootconfig:v1.0"
	opts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgAck}},
		{tag: dhcp4OptServerID, value: []byte{10, 0, 2, 2}},
		{tag: dhcp4OptSubnetMask, value: []byte{255, 255, 255, 0}},
		{tag: dhcp4OptRouter, value: []byte{10, 0, 2, 2}},
		{tag: dhcp4OptLeaseTime, value: []byte{0, 1, 0x51, 0x80}},
		{tag: dhcp4OptBootfileName, value: []byte(ref)},
	})
	msg, err := buildDHCP4Message(xid, mac, opts)
	if err != nil {
		t.Fatalf("buildDHCP4Message: %v", err)
	}
	msg[0] = dhcp4BootReply
	copy(msg[16:20], []byte{10, 0, 2, 15})

	gotXID, yi, parsed, err := parseDHCP4Message(msg)
	if err != nil {
		t.Fatalf("parseDHCP4Message: %v", err)
	}
	if gotXID != xid {
		t.Errorf("xid: got %#x, want %#x", gotXID, xid)
	}
	if !yi.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Errorf("yiaddr: got %v, want 10.0.2.15", yi)
	}
	mtype, mErr := parseDHCP4MessageType(parsed)
	if mErr != nil || mtype != dhcp4MsgAck {
		t.Fatalf("message type: got %d, err=%v, want ACK", mtype, mErr)
	}
	lease := dhcp4LeaseFromOptions(yi, parsed)
	if lease.BootfileName != ref {
		t.Errorf("end-to-end BootfileName: got %q, want %q", lease.BootfileName, ref)
	}
	if !lease.IP.Equal(net.IPv4(10, 0, 2, 15)) {
		t.Errorf("IP: got %v, want 10.0.2.15", lease.IP)
	}
	if !lease.Gateway.Equal(net.IPv4(10, 0, 2, 2)) {
		t.Errorf("Gateway: got %v, want 10.0.2.2", lease.Gateway)
	}
}
