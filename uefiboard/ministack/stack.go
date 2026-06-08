// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Top-level `*Stack` ties the link layer, ARP cache, route table and
// ICMP handler together. It owns:
//
//   - The Link (virtio-net adapter in the live build, synthetic stub
//     in tests).
//   - A single sync.Mutex guarding the ARP cache + the pending-pings
//     map. Held across short critical sections only.
//   - The RX goroutine (started by Start, stopped by Close).
//   - The IP-ID counter for outbound IPv4 packets (incremented under
//     the mutex).
//
// Layering:
//
//   - The Stack does NOT own a connection or listen abstraction; M3
//     only ships PingOnce. M4 will add UDP4 (DHCP/DNS) as a sibling
//     udp4.go file with its own send + dispatch helpers; M5 adds
//     TCP4 similarly. None of those additions require restructuring
//     this file beyond a new dispatch arm in `dispatch`.

package ministack

import (
	"errors"
	"net"
	"sync"
	"time"
)

// ErrStackClosed is returned by any method called after Close.
var ErrStackClosed = errors.New("ministack: stack closed")

// ErrPingTimeout is returned by PingOnce when no Echo Reply arrives
// within the supplied timeout.
var ErrPingTimeout = errors.New("ministack: ICMP echo timed out")

// pingWaiter is the state PingOnce parks under the Stack's mutex while
// waiting for an Echo Reply. Keyed on (identifier, sequence) so
// multiple concurrent pings can coexist (M3 only fires one, but the
// shape generalises).
type pingWaiter struct {
	ch chan ICMPEcho
}

// Stack is the ministack top-level object. Construct via New, attach
// addresses + gateway, call Start, then use PingOnce.
type Stack struct {
	link Link

	mu        sync.Mutex
	arpCache  *arpTable
	route     RouteTable
	pings         map[uint32]*pingWaiter // key = (id<<16)|seq
	udp4Conns     map[uint16]*UDP4Conn   // key = local UDP port
	tcp4Conns     map[uint16]*TCP4Conn   // key = local TCP port (M5)
	tcp4PortRover uint16                 // rotating ephemeral-port hint
	ipID          uint16                 // monotonic IPv4 identification
	started   bool
	closed    bool
	closeOnce sync.Once
	stopCh    chan struct{}
	doneCh    chan struct{}

	// arpTimeout is the per-Resolve wait window. Configurable so
	// tests can shorten it; defaults to ARPDefaultTimeout.
	arpTimeout time.Duration
}

// New returns an unstarted Stack bound to the given Link. The Stack
// reads the link MAC eagerly; the link is expected to be ready to TX
// and RX before this is called.
func New(link Link) *Stack {
	return &Stack{
		link:       link,
		arpCache:   newARPTable(),
		pings:      make(map[uint32]*pingWaiter),
		udp4Conns:  make(map[uint16]*UDP4Conn),
		tcp4Conns:  make(map[uint16]*TCP4Conn),
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
		arpTimeout: ARPDefaultTimeout,
	}
}

// SetIPv4Address records the stack's IPv4 address + subnet mask. The
// address is used as the source IP for outbound packets and as the
// target-match for incoming ARP Requests. Pass a 4-byte IP and a
// 4-byte IPMask (e.g. {255, 255, 255, 0} for a /24). Must be called
// before Start.
func (s *Stack) SetIPv4Address(addr net.IP, mask net.IPMask) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStackClosed
	}
	return s.route.SetLocal(addr, mask)
}

// SetDefaultGateway records the default-route next-hop. Pass nil to
// clear (no default route).
func (s *Stack) SetDefaultGateway(gw net.IP) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrStackClosed
	}
	return s.route.SetGateway(gw)
}

// SetARPTimeout overrides the per-Resolve wait window. Optional; used
// by tests to avoid 1-second waits.
func (s *Stack) SetARPTimeout(d time.Duration) {
	s.mu.Lock()
	s.arpTimeout = d
	s.mu.Unlock()
}

// LocalIPv4 returns the configured local address (or nil if none).
// Snapshot — safe to call concurrently with Start.
func (s *Stack) LocalIPv4() net.IP {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.route.Local == nil {
		return nil
	}
	return append(net.IP(nil), s.route.Local...)
}

// Start kicks off the RX goroutine. Idempotent — calling twice is a
// no-op. Must be called after SetIPv4Address / SetDefaultGateway so
// the dispatcher knows our addresses by the time the first frame
// arrives.
func (s *Stack) Start() {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	s.mu.Unlock()
	go s.rxLoop()
}

// Close shuts the RX goroutine down. Idempotent. Resolve/PingOnce
// calls already in flight return their respective timeout errors.
func (s *Stack) Close() {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		s.mu.Unlock()
		close(s.stopCh)
		if s.started {
			<-s.doneCh
		}
	})
}

// rxLoop is the RX goroutine body. Loops on link.RecvFrame; dispatches
// each frame by EtherType. Exits when Close is called.
func (s *Stack) rxLoop() {
	defer close(s.doneCh)
	for {
		select {
		case <-s.stopCh:
			return
		default:
		}
		frame, err := s.link.RecvFrame()
		if err != nil {
			// Most common error is the link's receive-timeout
			// (no frame in the budget window). Loop back. Other
			// transient errors are equally fine.
			//
			// NOTE: under tamago+UEFI this goroutine has been
			// observed to never get scheduled because the runtime
			// lacks hardware-timer-driven async preemption. The
			// authoritative RX path is the inline pump in
			// resolveARP / PingOnce; this loop is kept as a safety
			// net for environments where async preemption works.
			continue
		}
		_ = s.dispatch(frame)
	}
}

// dispatch parses an Ethernet frame and routes it to the correct
// upper-layer handler. Unknown EtherTypes are dropped silently
// (no log channel in M3-minimal). Returns the dispatcher error for
// the benefit of unit tests.
func (s *Stack) dispatch(frame []byte) error {
	eth, err := ParseEthernet(frame)
	if err != nil {
		return err
	}
	switch eth.EtherType {
	case EtherTypeARP:
		return s.handleARP(eth.Payload)
	case EtherTypeIPv4:
		return s.handleIPv4(eth.Payload)
	default:
		// Drop silently.
		return nil
	}
}

// handleARP is the ARP arm of dispatch. Reads our MAC + IP under the
// lock (so a concurrent SetIPv4Address doesn't race), then delegates
// to handleARPFrame in arp.go.
func (s *Stack) handleARP(payload []byte) error {
	s.mu.Lock()
	ourIP := s.route.Local
	s.mu.Unlock()
	return handleARPFrame(&s.mu, s.arpCache, s.link, s.link.MAC(), ourIP, payload)
}

// handleIPv4 is the IPv4 arm of dispatch. Parses the IPv4 header,
// branches by Protocol. For M3-minimal we only know about ICMP (1);
// any other protocol is dropped silently (UDP arrives in M4, TCP in
// M5). The "destination = us" check is intentionally loose — we
// accept broadcasts and any packet addressed to us; QEMU NAT
// sometimes ships replies with the destination set to the original
// source address (us).
func (s *Stack) handleIPv4(payload []byte) error {
	h, body, err := ParseIPv4(payload)
	if err != nil {
		return err
	}
	switch h.Protocol {
	case IPProtoICMP:
		return s.handleICMP(h, body)
	case IPProtoUDP:
		return s.handleUDP4(h, body)
	case IPProtoTCP:
		return s.handleTCP4(h, body)
	default:
		return nil
	}
}

// handleUDP4 is the UDP arm of dispatch. Parses the UDP header,
// validates the pseudo-header checksum, finds the Conn bound to the
// destination port, and enqueues the (src, payload) datagram on the
// Conn's RX channel. Datagrams to ports with no bound Conn are dropped
// silently.
func (s *Stack) handleUDP4(h IPv4Header, body []byte) error {
	uh, payload, err := ParseUDP4(h.Src, h.Dst, body)
	if err != nil {
		return err
	}
	s.mu.Lock()
	conn, ok := s.udp4Conns[uh.DstPort]
	s.mu.Unlock()
	if !ok {
		return nil
	}
	dg := udp4Datagram{
		Src: net.UDPAddr{
			IP:   append(net.IP(nil), h.Src.To4()...),
			Port: int(uh.SrcPort),
		},
		Payload: payload,
	}
	conn.deliver(dg)
	return nil
}

// OpenUDP4 binds a UDP4Conn on the given local port. Returns
// ErrUDP4PortInUse if another Conn already holds this port on this
// Stack.
func (s *Stack) OpenUDP4(localPort uint16) (*UDP4Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, ErrStackClosed
	}
	if _, exists := s.udp4Conns[localPort]; exists {
		return nil, ErrUDP4PortInUse
	}
	conn := &UDP4Conn{
		stack:     s,
		localPort: localPort,
		queue:     make(chan udp4Datagram, udp4QueueDepth),
	}
	s.udp4Conns[localPort] = conn
	return conn, nil
}

// releaseUDP4 removes the Conn for `localPort` from the demux table.
// Called by UDP4Conn.Close.
func (s *Stack) releaseUDP4(localPort uint16) {
	s.mu.Lock()
	delete(s.udp4Conns, localPort)
	s.mu.Unlock()
}

// sendUDP4 builds and ships a UDP datagram. Used by UDP4Conn.WriteTo.
// Selects the source IP from the Stack's local address; if no local
// address has been configured yet (DHCP DISCOVER case), uses 0.0.0.0.
// The destination 255.255.255.255 is sent via the L2 broadcast MAC
// without an ARP lookup.
func (s *Stack) sendUDP4(srcPort, dstPort uint16, dst net.IP, payload []byte) error {
	d4 := dst.To4()
	if d4 == nil {
		return ErrIPv4InvalidIP
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStackClosed
	}
	var src net.IP
	if s.route.Local != nil {
		src = append(net.IP(nil), s.route.Local...)
	} else {
		// DHCP DISCOVER ships with 0.0.0.0 as the source.
		src = net.IPv4(0, 0, 0, 0).To4()
	}
	srcMAC := s.link.MAC()
	s.mu.Unlock()

	udpBytes, err := MarshalUDP4(src, d4, srcPort, dstPort, payload)
	if err != nil {
		return err
	}
	ipPkt, err := MarshalIPv4(src, d4, IPProtoUDP, s.nextIPID(), udpBytes)
	if err != nil {
		return err
	}
	// Broadcast short-circuit: 255.255.255.255 → L2 ff:ff:ff:ff:ff:ff,
	// no ARP. DHCP DISCOVER + REQUEST take this path.
	if isLimitedBroadcast(d4) {
		frame, err := MarshalEthernet(BroadcastMAC, srcMAC, EtherTypeIPv4, ipPkt)
		if err != nil {
			return err
		}
		return s.link.SendFrame(frame)
	}
	return s.sendIPv4Frame(d4, ipPkt)
}

// isLimitedBroadcast reports whether ip is 255.255.255.255.
func isLimitedBroadcast(ip net.IP) bool {
	if len(ip) != 4 {
		return false
	}
	return ip[0] == 0xFF && ip[1] == 0xFF && ip[2] == 0xFF && ip[3] == 0xFF
}

// handleICMP processes an inbound ICMP message. Echo Replies are
// matched against the pending-pings map; matched waiters get the
// parsed reply on their channel. Echo Requests are answered with an
// Echo Reply (so a host pinging us, if it ever happens in QEMU NAT,
// gets a response). Other ICMP types are dropped silently.
func (s *Stack) handleICMP(h IPv4Header, body []byte) error {
	msg, err := ParseICMPEcho(body)
	if err != nil {
		return err
	}
	switch msg.Type {
	case ICMPTypeEchoReply:
		key := pingKey(msg.Identifier, msg.Sequence)
		s.mu.Lock()
		w, ok := s.pings[key]
		if ok {
			delete(s.pings, key)
		}
		s.mu.Unlock()
		if ok {
			// Non-blocking send: if the receiver already timed
			// out, the channel send must not block the RX
			// goroutine. The channel has capacity 1.
			select {
			case w.ch <- msg:
			default:
			}
		}
		return nil

	case ICMPTypeEchoRequest:
		// Mirror the payload back as an Echo Reply.
		reply, err := buildEchoReplyPacket(h.Dst, h.Src, s.nextIPID(), msg.Identifier, msg.Sequence, msg.Payload)
		if err != nil {
			return err
		}
		return s.sendIPv4Frame(h.Src, reply)
	default:
		return nil
	}
}

// pingKey packs (id, seq) into a single uint32 for use as a map key.
func pingKey(id, seq uint16) uint32 {
	return (uint32(id) << 16) | uint32(seq)
}

// nextIPID returns the next IPv4 identification value. Wraps at 16
// bits; collisions over short timescales don't matter for ICMP echo.
// Caller must NOT hold s.mu — we lock internally.
func (s *Stack) nextIPID() uint16 {
	s.mu.Lock()
	id := s.ipID
	s.ipID++
	s.mu.Unlock()
	return id
}

// sendIPv4Frame resolves the next-hop MAC (via the route table + ARP)
// and pushes the IPv4 packet onto the link as a complete L2 frame.
// `finalDst` is the IPv4 packet's ultimate destination; we use it for
// route lookup, then ARP for the resulting next-hop.
func (s *Stack) sendIPv4Frame(finalDst net.IP, ipPkt []byte) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrStackClosed
	}
	nextHop, err := s.route.Lookup(finalDst)
	srcMAC := s.link.MAC()
	srcIP := s.route.Local
	timeout := s.arpTimeout
	s.mu.Unlock()
	if err != nil {
		return err
	}
	mac, err := resolveARP(&s.mu, s.arpCache, s.link, srcMAC, srcIP, nextHop, timeout)
	if err != nil {
		return err
	}
	frame, err := MarshalEthernet(mac, srcMAC, EtherTypeIPv4, ipPkt)
	if err != nil {
		return err
	}
	return s.link.SendFrame(frame)
}

// buildEchoReplyPacket assembles the full IPv4 packet for an ICMP
// Echo Reply. Same shape as buildEchoRequestPacket except msgType=0.
func buildEchoReplyPacket(src, dst net.IP, ipID uint16, icmpID, icmpSeq uint16, payload []byte) ([]byte, error) {
	icmp := MarshalICMPEcho(ICMPTypeEchoReply, icmpID, icmpSeq, payload)
	return MarshalIPv4(src, dst, IPProtoICMP, ipID, icmp)
}

// PingOnce sends one ICMP Echo Request to `dst` with the supplied
// payload, then waits up to `timeout` for an Echo Reply. Returns the
// round-trip wall-clock on success or ErrPingTimeout if no matching
// reply arrives. (id, seq) is auto-assigned (id = a fixed magic,
// seq = the IPID counter ++ so concurrent calls don't collide).
//
// Pre-conditions: the Stack must be Started, SetIPv4Address must
// have been called (so we know our source IP), and either the
// destination is on our subnet or a default gateway is set.
func (s *Stack) PingOnce(dst net.IP, payload []byte, timeout time.Duration) (time.Duration, error) {
	dst4 := dst.To4()
	if dst4 == nil {
		return 0, ErrIPv4InvalidIP
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return 0, ErrStackClosed
	}
	if s.route.Local == nil {
		s.mu.Unlock()
		return 0, errors.New("ministack: no local IPv4 address set")
	}
	src := append(net.IP(nil), s.route.Local...)
	// Pick (id, seq). Identifier is a fixed magic ("MS" = 0x4D53)
	// so the reply matching key is stable; sequence advances per
	// call (we reuse the IP-ID counter for convenience).
	const pingIdent uint16 = 0x4D53
	seq := s.ipID
	s.ipID++
	key := pingKey(pingIdent, seq)
	w := &pingWaiter{ch: make(chan ICMPEcho, 1)}
	s.pings[key] = w
	ipID := s.ipID
	s.ipID++
	s.mu.Unlock()

	// On any early return below, drop the pending-ping registration.
	cleanup := func() {
		s.mu.Lock()
		delete(s.pings, key)
		s.mu.Unlock()
	}

	pkt, err := buildEchoRequestPacket(src, dst4, ipID, pingIdent, seq, payload)
	if err != nil {
		cleanup()
		return 0, err
	}
	start := time.Now()
	if err := s.sendIPv4Frame(dst4, pkt); err != nil {
		cleanup()
		return 0, err
	}

	// Inline RX pump (same rationale + same platform-specific
	// deadline as resolveARP).
	pingChecker := newDeadlineChecker(timeout)
	for !pingChecker.expired() {
		pingChecker.tick()
		// Fast path: reply already delivered.
		select {
		case <-w.ch:
			return time.Since(start), nil
		case <-s.stopCh:
			cleanup()
			return 0, ErrStackClosed
		default:
		}
		// Pump one frame from the link inline.
		rx, rxErr := s.link.RecvFrame()
		if rxErr != nil {
			continue
		}
		_ = s.dispatch(rx)
	}
	cleanup()
	return 0, ErrPingTimeout
}
