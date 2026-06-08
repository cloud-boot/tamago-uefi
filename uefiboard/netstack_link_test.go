// Host-side tests for the gvisor netstack LinkEndpoint adapter.
//
// Five concerns covered here:
//
//   1. The adapter satisfies `stack.LinkEndpoint` (compile-time
//      assertion + spot-checks of the trivial getters).
//   2. `WritePackets` flattens each PacketBuffer into a single
//      contiguous Ethernet frame and hands it to the underlying
//      transport in order.
//   3. `Attach` / `IsAttached` / `Capabilities` / `ARPHardwareType`
//      / `AddHeader` / `ParseHeader` behave per the gvisor contract.
//   4. `InjectInboundFrame` round-trips Ethernet → dispatcher.
//   5. `Close` / `Wait` lifecycle works on a host build (no RX
//      goroutine).
//
// No DMA, no virtio: the tests use a `fakeTransport` that just
// records each frame sent. The whole point of `frameTransport`
// being an interface is to enable this seam.
//
// Gated on `phase2_netstack_ping` so the gvisor import set
// only enters the `uefiboard` package's dep closure when the
// M3 milestone code is being exercised. Run with:
//
//	go test -tags phase2_netstack_ping ./uefiboard/...

//go:build phase2_netstack_ping

package uefiboard

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Compile-time interface satisfaction.
var _ stack.LinkEndpoint = (*VirtioNetLink)(nil)

// fakeTransport implements `frameTransport`: records every
// frame written to it and optionally fails on the Nth write.
type fakeTransport struct {
	frames  [][]byte
	failAt  int // 1-based; 0 disables. e.g. failAt=2 fails the 2nd TX.
	failErr error
}

func (f *fakeTransport) TransmitFrame(frame []byte) error {
	if f.failAt > 0 && len(f.frames)+1 == f.failAt {
		return f.failErr
	}
	cp := make([]byte, len(frame))
	copy(cp, frame)
	f.frames = append(f.frames, cp)
	return nil
}

func newTestLink(mtu uint32, mac tcpip.LinkAddress) (*VirtioNetLink, *fakeTransport) {
	ft := &fakeTransport{}
	link := newVirtioNetLink(ft, mac, mtu)
	return link, ft
}

// rememberingDispatcher records every DeliverNetworkPacket call.
type rememberingDispatcher struct {
	proto tcpip.NetworkProtocolNumber
	pkts  []*stack.PacketBuffer
	links []tcpip.NetworkProtocolNumber
	linkP []*stack.PacketBuffer
}

func (d *rememberingDispatcher) DeliverNetworkPacket(p tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	d.proto = p
	pkt.IncRef()
	d.pkts = append(d.pkts, pkt)
}
func (d *rememberingDispatcher) DeliverLinkPacket(p tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	pkt.IncRef()
	d.linkP = append(d.linkP, pkt)
	d.links = append(d.links, p)
}

func TestVirtioNetLinkBasicGetters(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, _ := newTestLink(1500, mac)

	if got := link.MTU(); got != 1500 {
		t.Errorf("MTU: got %d, want 1500", got)
	}
	if got := link.MaxHeaderLength(); got != header.EthernetMinimumSize {
		t.Errorf("MaxHeaderLength: got %d, want %d", got, header.EthernetMinimumSize)
	}
	if got := link.LinkAddress(); got != mac {
		t.Errorf("LinkAddress: got %q, want %q", got, mac)
	}
	if got := link.Capabilities(); got&stack.CapabilityResolutionRequired == 0 {
		t.Errorf("Capabilities: missing CapabilityResolutionRequired (got %x)", got)
	}
	if got := link.ARPHardwareType(); got != header.ARPHardwareEther {
		t.Errorf("ARPHardwareType: got %d, want ARPHardwareEther", got)
	}
	if link.IsAttached() {
		t.Errorf("IsAttached: true before Attach")
	}
}

func TestVirtioNetLinkSetMTU(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	link.SetMTU(9000)
	if got := link.MTU(); got != 9000 {
		t.Errorf("MTU after SetMTU: got %d, want 9000", got)
	}
}

func TestVirtioNetLinkSetLinkAddress(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	newAddr := tcpip.LinkAddress("\xaa\xbb\xcc\xdd\xee\xff")
	link.SetLinkAddress(newAddr)
	if got := link.LinkAddress(); got != newAddr {
		t.Errorf("LinkAddress: got %q, want %q", got, newAddr)
	}
}

func TestVirtioNetLinkAttachDetach(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	d := &rememberingDispatcher{}
	link.Attach(d)
	if !link.IsAttached() {
		t.Errorf("IsAttached: false after Attach")
	}
	link.Attach(nil)
	if link.IsAttached() {
		t.Errorf("IsAttached: true after Attach(nil)")
	}
}

func TestVirtioNetLinkWritePackets(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, ft := newTestLink(1500, mac)

	// Build two PacketBuffers, each containing a synthetic
	// "Ethernet + IPv4" payload. flattenPacketBuffer should
	// concatenate header + data into one frame.
	mkPkt := func(payload []byte) *stack.PacketBuffer {
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(header.EthernetMinimumSize),
			Payload:            buffer.MakeWithData(payload),
		})
		eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
		eth.Encode(&header.EthernetFields{
			SrcAddr: mac,
			DstAddr: tcpip.LinkAddress("\xff\xff\xff\xff\xff\xff"),
			Type:    header.IPv4ProtocolNumber,
		})
		return pkt
	}

	payload1 := []byte{0x45, 0x00, 0x00, 0x14} // truncated IPv4 hdr stub
	payload2 := []byte{0x45, 0x00, 0x00, 0x20, 0xde, 0xad}

	pkt1 := mkPkt(payload1)
	pkt2 := mkPkt(payload2)
	defer pkt1.DecRef()
	defer pkt2.DecRef()

	var list stack.PacketBufferList
	list.PushBack(pkt1)
	list.PushBack(pkt2)

	n, err := link.WritePackets(list)
	if err != nil {
		t.Fatalf("WritePackets: %v", err)
	}
	if n != 2 {
		t.Errorf("WritePackets: n=%d, want 2", n)
	}
	if len(ft.frames) != 2 {
		t.Fatalf("frames captured: %d, want 2", len(ft.frames))
	}
	// Frame 1 should be 14 (Ethernet) + 4 (payload1) bytes.
	if got, want := len(ft.frames[0]), header.EthernetMinimumSize+len(payload1); got != want {
		t.Errorf("frame[0] len: got %d, want %d", got, want)
	}
	// Frame 2 should be 14 + 6.
	if got, want := len(ft.frames[1]), header.EthernetMinimumSize+len(payload2); got != want {
		t.Errorf("frame[1] len: got %d, want %d", got, want)
	}
	// The Ethernet src in frame 1 should be our MAC.
	if !bytes.Equal(ft.frames[0][6:12], []byte(mac)) {
		t.Errorf("frame[0] src MAC: got %x, want %x", ft.frames[0][6:12], []byte(mac))
	}
	// Payload should follow at offset 14.
	if !bytes.Equal(ft.frames[0][header.EthernetMinimumSize:], payload1) {
		t.Errorf("frame[0] payload: got %x, want %x",
			ft.frames[0][header.EthernetMinimumSize:], payload1)
	}
}

func TestVirtioNetLinkWritePacketsTXErrorFirst(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, ft := newTestLink(1500, mac)
	ft.failAt = 1
	ft.failErr = errors.New("simulated TX failure")

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(header.EthernetMinimumSize),
		Payload:            buffer.MakeWithData([]byte{1, 2, 3}),
	})
	defer pkt.DecRef()

	var list stack.PacketBufferList
	list.PushBack(pkt)

	n, err := link.WritePackets(list)
	if err == nil {
		t.Errorf("WritePackets: expected error on first-write failure, got nil")
	}
	if n != 0 {
		t.Errorf("WritePackets: n=%d, want 0", n)
	}
}

func TestVirtioNetLinkWritePacketsTXErrorMidStream(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, ft := newTestLink(1500, mac)
	ft.failAt = 2 // fail on the 2nd write
	ft.failErr = errors.New("simulated TX failure")

	mkPkt := func() *stack.PacketBuffer {
		return stack.NewPacketBuffer(stack.PacketBufferOptions{
			ReserveHeaderBytes: int(header.EthernetMinimumSize),
			Payload:            buffer.MakeWithData([]byte{1, 2, 3, 4}),
		})
	}
	pkt1 := mkPkt()
	pkt2 := mkPkt()
	pkt3 := mkPkt()
	defer pkt1.DecRef()
	defer pkt2.DecRef()
	defer pkt3.DecRef()

	var list stack.PacketBufferList
	list.PushBack(pkt1)
	list.PushBack(pkt2)
	list.PushBack(pkt3)

	n, err := link.WritePackets(list)
	if err != nil {
		t.Errorf("WritePackets: unexpected error after first successful write: %v", err)
	}
	if n != 1 {
		t.Errorf("WritePackets: n=%d, want 1 (stopped at the mid-stream failure)", n)
	}
}

func TestVirtioNetLinkAddHeader(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, _ := newTestLink(1500, mac)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(header.EthernetMinimumSize),
		Payload:            buffer.MakeWithData([]byte{0xaa, 0xbb}),
	})
	defer pkt.DecRef()
	pkt.EgressRoute.LocalLinkAddress = mac
	pkt.EgressRoute.RemoteLinkAddress = tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x02")
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber

	link.AddHeader(pkt)
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	if got := eth.SourceAddress(); got != mac {
		t.Errorf("Ethernet src: got %q, want %q", got, mac)
	}
	if got := eth.Type(); got != header.IPv4ProtocolNumber {
		t.Errorf("Ethernet type: got %x, want IPv4", got)
	}
}

func TestVirtioNetLinkAddHeaderDefaultSrc(t *testing.T) {
	// EgressRoute.LocalLinkAddress empty → AddHeader should fall
	// back to our LinkAddress().
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, _ := newTestLink(1500, mac)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(header.EthernetMinimumSize),
		Payload:            buffer.MakeWithData([]byte{0xaa}),
	})
	defer pkt.DecRef()
	pkt.EgressRoute.RemoteLinkAddress = tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x02")
	pkt.NetworkProtocolNumber = header.IPv4ProtocolNumber

	link.AddHeader(pkt)
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	if got := eth.SourceAddress(); got != mac {
		t.Errorf("Ethernet src (default): got %q, want %q", got, mac)
	}
}

func TestVirtioNetLinkParseHeader(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, _ := newTestLink(1500, mac)
	// Construct an Ethernet frame: dst + src + ethertype + 4 bytes payload.
	frame := append([]byte{}, byte(0xff), 0xff, 0xff, 0xff, 0xff, 0xff)
	frame = append(frame, 0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f)
	frame = append(frame, 0x08, 0x00) // IPv4
	frame = append(frame, 0xaa, 0xbb, 0xcc, 0xdd)

	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()
	if !link.ParseHeader(pkt) {
		t.Fatalf("ParseHeader returned false on valid Ethernet frame")
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	if got := eth.Type(); got != header.IPv4ProtocolNumber {
		t.Errorf("Ethernet type: got %x, want IPv4", got)
	}
}

func TestVirtioNetLinkParseHeaderTooShort(t *testing.T) {
	mac := tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f")
	link, _ := newTestLink(1500, mac)
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData([]byte{1, 2, 3}),
	})
	defer pkt.DecRef()
	if link.ParseHeader(pkt) {
		t.Errorf("ParseHeader returned true on 3-byte frame")
	}
}

func TestVirtioNetLinkInjectInboundFrameNoDispatcher(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	frame := make([]byte, header.EthernetMinimumSize+4)
	if link.InjectInboundFrame(frame) {
		t.Errorf("InjectInboundFrame: returned true with no dispatcher attached")
	}
}

func TestVirtioNetLinkInjectInboundFrameTooShort(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	d := &rememberingDispatcher{}
	link.Attach(d)
	if link.InjectInboundFrame([]byte{1, 2, 3}) {
		t.Errorf("InjectInboundFrame: returned true on 3-byte input")
	}
	if len(d.pkts) != 0 {
		t.Errorf("dispatcher called %d times, want 0", len(d.pkts))
	}
}

func TestVirtioNetLinkInjectInboundFrame(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x52\x55\x0a\x00\x02\x0f"))
	d := &rememberingDispatcher{}
	link.Attach(d)

	frame := []byte{
		// dst MAC = ours
		0x52, 0x55, 0x0a, 0x00, 0x02, 0x0f,
		// src MAC = gateway
		0x52, 0x55, 0x0a, 0x00, 0x02, 0x02,
		// ethertype = IPv4
		0x08, 0x00,
		// 4 bytes of opaque payload
		0xaa, 0xbb, 0xcc, 0xdd,
	}
	if !link.InjectInboundFrame(frame) {
		t.Fatalf("InjectInboundFrame returned false")
	}
	if len(d.pkts) != 1 {
		t.Fatalf("dispatcher: %d pkts, want 1", len(d.pkts))
	}
	if d.proto != header.IPv4ProtocolNumber {
		t.Errorf("dispatcher proto: got %x, want IPv4", d.proto)
	}
	// Clean up the IncRef the dispatcher did.
	for _, pkt := range d.pkts {
		pkt.DecRef()
	}
}

func TestVirtioNetLinkCloseHostBuild(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	link.Close()
	// Wait must return promptly on host build (no goroutine).
	done := make(chan struct{})
	go func() {
		link.Wait()
		close(done)
	}()
	select {
	case <-done:
		// Wait returned.
	case <-time.After(2 * time.Second):
		t.Fatalf("Wait() did not return within 2s after Close()")
	}
}

func TestVirtioNetLinkCloseIdempotent(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	link.Close()
	// Second Close must not panic (channel double-close guard).
	link.Close()
}

func TestVirtioNetLinkSetOnCloseAction(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	called := false
	link.SetOnCloseAction(func() { called = true })
	link.Close()
	if !called {
		t.Errorf("SetOnCloseAction callback never fired")
	}
}

func TestFlattenPacketBuffer(t *testing.T) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(header.EthernetMinimumSize),
		Payload:            buffer.MakeWithData([]byte{0x01, 0x02, 0x03}),
	})
	defer pkt.DecRef()
	pkt.LinkHeader().Push(header.EthernetMinimumSize) // populate header bytes (zeroed)

	flat := flattenPacketBuffer(pkt)
	if got, want := len(flat), header.EthernetMinimumSize+3; got != want {
		t.Errorf("flat len: got %d, want %d", got, want)
	}
	if !bytes.Equal(flat[header.EthernetMinimumSize:], []byte{0x01, 0x02, 0x03}) {
		t.Errorf("flat payload: got %x", flat[header.EthernetMinimumSize:])
	}
}

func TestVirtioNetLinkHasRXGoroutineHostBuild(t *testing.T) {
	link, _ := newTestLink(1500, tcpip.LinkAddress("\x00\x00\x00\x00\x00\x01"))
	if link.hasRXGoroutine() {
		t.Errorf("hasRXGoroutine: true on host build before StartRX")
	}
}
