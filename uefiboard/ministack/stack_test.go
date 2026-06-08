// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// gatewayResponder is a synthetic "remote host" that, when fed an
// incoming frame, optionally answers it. The Stack's RX goroutine
// pulls from `link.recv`; we drain `link.sent` and (depending on the
// configured behaviour) push reply frames back onto `link.recv`.
//
// This is a single-shot helper: it runs in a goroutine until `done`
// is closed.
type gatewayResponder struct {
	link        *stubLink
	gatewayMAC  net.HardwareAddr
	gatewayIP   net.IP
	answerICMP  bool
	answerARP   bool
	done        chan struct{}
	lastSentIdx int
}

func newGatewayResponder(link *stubLink, gwMAC net.HardwareAddr, gwIP net.IP) *gatewayResponder {
	return &gatewayResponder{
		link:       link,
		gatewayMAC: append(net.HardwareAddr(nil), gwMAC...),
		gatewayIP:  append(net.IP(nil), gwIP.To4()...),
		answerICMP: true,
		answerARP:  true,
		done:       make(chan struct{}),
	}
}

func (g *gatewayResponder) start() {
	go g.loop()
}

func (g *gatewayResponder) stop() {
	close(g.done)
}

func (g *gatewayResponder) loop() {
	for {
		select {
		case <-g.done:
			return
		default:
		}
		g.link.mu.Lock()
		// Drain new outbound frames.
		var newFrames [][]byte
		if g.lastSentIdx < len(g.link.sent) {
			for i := g.lastSentIdx; i < len(g.link.sent); i++ {
				newFrames = append(newFrames, append([]byte(nil), g.link.sent[i]...))
			}
			g.lastSentIdx = len(g.link.sent)
		}
		g.link.mu.Unlock()

		for _, f := range newFrames {
			g.maybeRespond(f)
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func (g *gatewayResponder) maybeRespond(frame []byte) {
	eth, err := ParseEthernet(frame)
	if err != nil {
		return
	}
	switch eth.EtherType {
	case EtherTypeARP:
		if !g.answerARP {
			return
		}
		op, sha, spa, _, tpa, err := parseARP(eth.Payload)
		if err != nil {
			return
		}
		if op != ARPOpRequest {
			return
		}
		if !tpa.Equal(g.gatewayIP) {
			return
		}
		// Build the ARP reply (gateway → sender).
		reply, err := buildARPPacket(ARPOpReply, g.gatewayMAC, g.gatewayIP, sha, spa)
		if err != nil {
			return
		}
		replyFrame, err := MarshalEthernet(sha, g.gatewayMAC, EtherTypeARP, reply)
		if err != nil {
			return
		}
		g.link.inject(replyFrame)

	case EtherTypeIPv4:
		if !g.answerICMP {
			return
		}
		h, body, err := ParseIPv4(eth.Payload)
		if err != nil {
			return
		}
		if h.Protocol != IPProtoICMP {
			return
		}
		msg, err := ParseICMPEcho(body)
		if err != nil {
			return
		}
		if msg.Type != ICMPTypeEchoRequest {
			return
		}
		// Build the Echo Reply.
		reply, err := buildEchoReplyPacket(g.gatewayIP, h.Src, 0xBEEF, msg.Identifier, msg.Sequence, msg.Payload)
		if err != nil {
			return
		}
		replyFrame, err := MarshalEthernet(eth.Src, g.gatewayMAC, EtherTypeIPv4, reply)
		if err != nil {
			return
		}
		g.link.inject(replyFrame)
	}
}

func TestStackPingOnceEndToEnd(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	gwMAC := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	gwIP := net.IPv4(10, 0, 2, 2)
	ourIP := net.IPv4(10, 0, 2, 15)
	mask := net.IPv4Mask(255, 255, 255, 0)

	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(200 * time.Millisecond)
	if err := s.SetIPv4Address(ourIP, mask); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefaultGateway(gwIP); err != nil {
		t.Fatal(err)
	}
	if got := s.LocalIPv4(); !got.Equal(ourIP) {
		t.Errorf("LocalIPv4: got %v, want %v", got, ourIP)
	}

	gw := newGatewayResponder(link, gwMAC, gwIP)
	gw.start()
	defer gw.stop()

	s.Start()
	defer s.Close()

	rt, err := s.PingOnce(gwIP, []byte("M3-mini"), 2*time.Second)
	if err != nil {
		t.Fatalf("PingOnce: %v", err)
	}
	if rt <= 0 {
		t.Errorf("round-trip non-positive: %v", rt)
	}
}

func TestStackPingOnceTimeoutWhenGatewaySilent(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(20 * time.Millisecond)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	s.Start()
	defer s.Close()

	_, err := s.PingOnce(net.IPv4(10, 0, 2, 2), []byte("x"), 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected ARP/ping timeout, got nil")
	}
	// Either an ARP timeout (no responder) or a ping timeout is acceptable.
	if err != ErrARPTimeout && err != ErrPingTimeout {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStackRespondsToARPRequest(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	ourIP := net.IPv4(10, 0, 2, 15)
	link := newStubLink(ourMAC)
	s := New(link)
	_ = s.SetIPv4Address(ourIP, net.IPv4Mask(255, 255, 255, 0))
	s.Start()
	defer s.Close()

	// Inject an ARP Request from a peer asking for our IP.
	peerMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	peerIP := net.IPv4(10, 0, 2, 7)
	req, _ := buildARPPacket(ARPOpRequest, peerMAC, peerIP, net.HardwareAddr{0, 0, 0, 0, 0, 0}, ourIP)
	reqFrame, _ := MarshalEthernet(BroadcastMAC, peerMAC, EtherTypeARP, req)
	link.inject(reqFrame)

	// Poll for the response (RX goroutine is async).
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sent := link.snapshotSent()
		if len(sent) > 0 {
			eth, err := ParseEthernet(sent[0])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(eth.Dst, peerMAC) {
				t.Errorf("ARP reply dst: got %v, want %v", eth.Dst, peerMAC)
			}
			op, _, _, _, _, _ := parseARP(eth.Payload)
			if op != ARPOpReply {
				t.Errorf("op: got %d, want %d", op, ARPOpReply)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no ARP reply sent within 1s")
}

func TestStackDispatchDropsUnknownEtherType(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	// 0x86DD = IPv6; we drop silently.
	frame, _ := MarshalEthernet(net.HardwareAddr{1, 1, 1, 1, 1, 1}, net.HardwareAddr{2, 2, 2, 2, 2, 2}, 0x86DD, []byte("ignored"))
	if err := s.dispatch(frame); err != nil {
		t.Errorf("dispatch should drop silently, got %v", err)
	}
}

func TestStackDispatchPropagatesEthernetError(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	if err := s.dispatch([]byte{1, 2, 3}); err != ErrFrameTooShort {
		t.Errorf("want ErrFrameTooShort, got %v", err)
	}
}

func TestStackDispatchIPv4DropsUnknownProto(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	// Build an IPv4 packet with proto=TCP. Ministack only knows ICMP
	// and UDP — TCP is dispatched-but-dropped silently in M4.
	ip, _ := MarshalIPv4(net.IPv4(10, 0, 2, 2), net.IPv4(10, 0, 2, 15), IPProtoTCP, 0, []byte("tcp"))
	frame, _ := MarshalEthernet(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{2, 2, 2, 2, 2, 2}, EtherTypeIPv4, ip)
	if err := s.dispatch(frame); err != nil {
		t.Errorf("TCP should drop silently, got %v", err)
	}
}

func TestStackDispatchIPv4PropagatesParseError(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	// Build a frame whose IPv4 portion is too short — but past the
	// Ethernet header, so ethernet parse OK; IPv4 parse fails.
	frame, _ := MarshalEthernet(net.HardwareAddr{1, 1, 1, 1, 1, 1}, net.HardwareAddr{2, 2, 2, 2, 2, 2}, EtherTypeIPv4, []byte{0x45})
	if err := s.dispatch(frame); err != ErrIPv4HeaderTooShort {
		t.Errorf("want ErrIPv4HeaderTooShort, got %v", err)
	}
}

func TestStackPingOnceRejectsBadDst(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_, err := s.PingOnce(net.ParseIP("::1"), nil, 10*time.Millisecond)
	if err != ErrIPv4InvalidIP {
		t.Errorf("want ErrIPv4InvalidIP, got %v", err)
	}
}

func TestStackPingOnceRequiresLocalAddress(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_, err := s.PingOnce(net.IPv4(1, 2, 3, 4), nil, 10*time.Millisecond)
	if err == nil {
		t.Fatal("expected error when local address is unset")
	}
}

func TestStackCloseIsIdempotent(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	s.Start()
	s.Close()
	s.Close() // second Close should not panic / block
}

func TestStackPostCloseRejects(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	s.Close()
	if err := s.SetIPv4Address(net.IPv4(1, 2, 3, 4), net.IPv4Mask(255, 255, 255, 0)); err != ErrStackClosed {
		t.Errorf("SetIPv4Address post-close: want ErrStackClosed, got %v", err)
	}
	if err := s.SetDefaultGateway(net.IPv4(1, 2, 3, 1)); err != ErrStackClosed {
		t.Errorf("SetDefaultGateway post-close: want ErrStackClosed, got %v", err)
	}
	_, err := s.PingOnce(net.IPv4(1, 2, 3, 4), nil, 10*time.Millisecond)
	if err != ErrStackClosed {
		t.Errorf("PingOnce post-close: want ErrStackClosed, got %v", err)
	}
}

func TestStackPingOnceSendFailPropagates(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	// Pre-populate ARP so we get straight to the IPv4 send.
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	s.arpCache.updateLocked(net.IPv4(10, 0, 2, 2).To4(), net.HardwareAddr{9, 9, 9, 9, 9, 9}, time.Now())
	link.sendErr = errors.New("synthetic send error")
	s.Start()
	defer s.Close()
	_, err := s.PingOnce(net.IPv4(10, 0, 2, 2), nil, 50*time.Millisecond)
	if err == nil {
		t.Fatal("expected send error to propagate")
	}
}

func TestStackHandleICMPEchoRequestRoundTrip(t *testing.T) {
	// Inject an ICMP Echo Request addressed to us; the Stack should
	// emit an Echo Reply via the link.
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	peerMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	link := newStubLink(ourMAC)
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	// Pre-populate ARP so the Echo Reply we send doesn't block on
	// resolving the peer's MAC.
	s.arpCache.updateLocked(net.IPv4(10, 0, 2, 7).To4(), peerMAC, time.Now())
	s.Start()
	defer s.Close()

	pkt, err := buildEchoRequestPacket(net.IPv4(10, 0, 2, 7), net.IPv4(10, 0, 2, 15), 1, 0x1234, 5, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	frame, _ := MarshalEthernet(ourMAC, peerMAC, EtherTypeIPv4, pkt)
	link.inject(frame)

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sent := link.snapshotSent()
		if len(sent) >= 1 {
			eth, err := ParseEthernet(sent[0])
			if err != nil {
				t.Fatal(err)
			}
			if eth.EtherType != EtherTypeIPv4 {
				t.Fatalf("response EtherType: %#x", eth.EtherType)
			}
			_, body, err := ParseIPv4(eth.Payload)
			if err != nil {
				t.Fatal(err)
			}
			m, err := ParseICMPEcho(body)
			if err != nil {
				t.Fatal(err)
			}
			if m.Type != ICMPTypeEchoReply {
				t.Errorf("ICMP type: got %d, want %d", m.Type, ICMPTypeEchoReply)
			}
			if !bytes.Equal(m.Payload, []byte("hi")) {
				t.Errorf("payload: got %q, want %q", m.Payload, "hi")
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no Echo Reply emitted within 1s")
}

func TestStackHandleICMPDropsNonEchoTypes(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	// Craft an ICMP message with an unsupported type (e.g. 3 = Dest
	// Unreachable). Our handler should drop it silently.
	icmp := MarshalICMPEcho(3, 1, 1, nil) // type=3 abuses Marshal but checksum is fine
	pkt, _ := MarshalIPv4(net.IPv4(10, 0, 2, 2), net.IPv4(10, 0, 2, 15), IPProtoICMP, 0, icmp)
	frame, _ := MarshalEthernet(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{2, 2, 2, 2, 2, 2}, EtherTypeIPv4, pkt)
	if err := s.dispatch(frame); err != nil {
		t.Errorf("non-Echo ICMP: want nil, got %v", err)
	}
}

func TestStackStartIdempotent(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	s.Start()
	s.Start() // second Start should not start a second goroutine
	s.Close()
}

func TestStackHandleICMPReplyUnknownIdentifier(t *testing.T) {
	// An Echo Reply whose (id, seq) doesn't match any pending ping
	// should be dropped silently (no panic).
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	icmp := MarshalICMPEcho(ICMPTypeEchoReply, 0xDEAD, 0xBEEF, []byte("unknown"))
	pkt, _ := MarshalIPv4(net.IPv4(10, 0, 2, 2), net.IPv4(10, 0, 2, 15), IPProtoICMP, 0, icmp)
	frame, _ := MarshalEthernet(net.HardwareAddr{1, 2, 3, 4, 5, 6}, net.HardwareAddr{2, 2, 2, 2, 2, 2}, EtherTypeIPv4, pkt)
	if err := s.dispatch(frame); err != nil {
		t.Errorf("dispatch: %v", err)
	}
}

func TestStackPingOnceWithoutRoute(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	// No gateway set; off-link destination must surface ErrNoRoute.
	s.Start()
	defer s.Close()
	_, err := s.PingOnce(net.IPv4(8, 8, 8, 8), nil, 50*time.Millisecond)
	if err != ErrNoRoute {
		t.Errorf("want ErrNoRoute, got %v", err)
	}
}
