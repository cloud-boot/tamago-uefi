// cloud-boot UEFI board — gvisor netstack LinkEndpoint adapter
// (Phase 2, M3).
//
// Wires our pure-Go virtio-net rail (M2) into
// `gvisor.dev/gvisor/pkg/tcpip/stack.LinkEndpoint`, so a gvisor
// `stack.Stack` can sit on top and provide ARP + IPv4 + ICMP + UDP
// + TCP without us writing any of those protocols by hand.
//
// Host-buildable (no //go:build tamago directive on this core
// file — only the M3 build-tag gate; see below). The frame
// transport is abstracted via the `frameTransport` interface so
// the adapter can be unit-tested with a synthetic stub on the
// host (see netstack_link_test.go). The live wrapper that takes
// a real `*VirtioNet` + spins up an RX goroutine lives in
// `netstack_link_tamago.go` because `VirtioNet.ReceiveFrame` is a
// tamago-only path (it dereferences DMA pointers via `unsafe`).
//
// Interface shape: matches gvisor `v0.0.0-20260604230326-c7dbb92365cd`
// (the `go` branch HEAD just before the upstream-broken
// `pkg/tcpip/stack/bridge_test.go` commit on 2026-06-05). That
// interface revision is `NetworkLinkEndpoint` + `LinkWriter`
// composed into `LinkEndpoint`, including the (then-new)
// `SetMTU`, `SetLinkAddress`, `ARPHardwareType`, `AddHeader`,
// `ParseHeader`, `Close`, `SetOnCloseAction` methods.
//
// R-M3'a verdict (host + GOOS=tamago × 3/4 archs, 2026-06-08):
// gvisor compiles clean under TamaGo on amd64 / arm64 /
// riscv64 with the standard `linkcpuinit,linkramstart`
// build-tag set. loong64 fails inside `syscall/fd_tamago.go`
// (`undefined: write`) because tamago-pie does not ship
// `zsyscall_tamago_loong64.go` — a tamago loong64 overlay
// gap, NOT a gvisor problem. The M3 design accepts 3/4 arches
// PASS at this milestone; loong64 unblocks when the tamago
// overlay is completed (tracked separately as R-M3'b).
//
// Build-tag gate `phase2_netstack_ping`: this file pulls
// `gvisor.dev/gvisor` into the `uefiboard` package's dep
// closure. Without the tag, the netstack adapter is excluded
// from compilation, so the M2 `phase2_virtionet_tx` build (and
// every Phase-1 build) sees no gvisor imports — preserving the
// existing M0..M2 PASS on loong64 (and elsewhere). The M3
// probe binary sets `-tags phase2_netstack_ping`, which pulls
// these symbols in.

//go:build phase2_netstack_ping

package uefiboard

import (
	"sync"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// frameTransport is the contract VirtioNetLink needs from the
// underlying NIC. The production implementation is
// `*VirtioNet` (see netstack_link_tamago.go); tests pass a
// synthetic struct that records the frames written.
//
// Why an interface (not a direct `*VirtioNet` field): the
// host test build doesn't have a real DMA-backed VirtioNet to
// hand to the adapter, and we don't want the adapter to import
// `unsafe` or any tamago-only symbols.
type frameTransport interface {
	// TransmitFrame writes ONE complete Ethernet frame
	// (no virtio_net_hdr — the underlying TX path prepends
	// that). The frame is already byte-formatted (dst MAC +
	// src MAC + ethertype + payload).
	TransmitFrame(frame []byte) error
}

// VirtioNetLink is the gvisor `stack.LinkEndpoint` adapter
// over our virtio-net rail. One instance per NIC. The caller
// keeps it alive for the lifetime of the gvisor stack.
//
// Lifecycle:
//
//   - `NewVirtioNetLink(nic, mac, mtu)` constructs an unattached
//     endpoint.
//   - `stack.New(...)` plus `s.CreateNIC(id, ep)` calls
//     `ep.Attach(dispatcher)`, which stores the dispatcher.
//   - The RX goroutine (started by the tamago-only wrapper)
//     loops `nic.ReceiveFrame()` and calls
//     `dispatcher.DeliverNetworkPacket(...)` on each frame.
//   - `stack.RemoveNIC` (not exercised in M3) would call
//     `Attach(nil)`; the RX goroutine would then drop frames
//     until Close() releases everything.
type VirtioNetLink struct {
	mu       sync.RWMutex
	nic      frameTransport
	mac      tcpip.LinkAddress
	mtu      uint32
	dispatch stack.NetworkDispatcher
	closeFn  func()
	// rxStarted is set true by StartRX (tamago wrapper) once
	// the receive goroutine has been launched. Close() looks
	// at this to decide whether rxDone is owned by the
	// goroutine (which will close it on exit) or by Close()
	// itself (host build, no goroutine).
	rxStarted bool
	// rxStop is closed by Close() to ask the RX goroutine
	// (if any) to stop. The goroutine is owned by the
	// tamago-only wrapper which uses chan recv to observe
	// it; on host builds rxStop is closed but never observed
	// (no goroutine started).
	rxStop chan struct{}
	// rxDone is closed by the RX goroutine when it exits.
	// `Wait()` blocks on it.
	rxDone chan struct{}
}

// newVirtioNetLink is the shared constructor body. It does
// NOT start the RX goroutine — the tamago-only wrapper does
// that after construction (host tests construct via this same
// entry point and inject their own packets via
// `InjectInboundFrame`).
//
// `nic` must NOT be nil. `mtu` is typically 1500 (the standard
// Ethernet MTU); on a virtio-net device that negotiated
// VIRTIO_NET_F_MTU the value is min(advertised, 1500) — we
// don't try to read it back from the device because the M2
// driver caps at 1500 anyway.
func newVirtioNetLink(nic frameTransport, mac tcpip.LinkAddress, mtu uint32) *VirtioNetLink {
	return &VirtioNetLink{
		nic:    nic,
		mac:    mac,
		mtu:    mtu,
		rxStop: make(chan struct{}),
		rxDone: make(chan struct{}),
	}
}

// MTU returns the maximum payload size (post-Ethernet-header).
// For virtio-net under QEMU+EDK2 user-mode NAT this is 1500.
func (l *VirtioNetLink) MTU() uint32 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.mtu
}

// SetMTU updates the MTU. gvisor's IPv4 stack consults this on
// every send. We don't push the new value down to the virtio-net
// device (M3 doesn't renegotiate MTU); we just record it.
func (l *VirtioNetLink) SetMTU(mtu uint32) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mtu = mtu
}

// MaxHeaderLength returns the maximum space the stack must reserve
// at the front of an outgoing PacketBuffer for our link layer.
// For raw Ethernet that's exactly 14 bytes (6 dst + 6 src + 2
// ethertype). gvisor will push the Ethernet header into this
// reserved region via `AddHeader`.
func (l *VirtioNetLink) MaxHeaderLength() uint16 {
	return header.EthernetMinimumSize
}

// LinkAddress returns our MAC. gvisor uses this both as the
// Ethernet src for outgoing frames AND as the address we answer
// ARP requests against.
func (l *VirtioNetLink) LinkAddress() tcpip.LinkAddress {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.mac
}

// SetLinkAddress updates our MAC. M3 doesn't exercise this (the
// MAC is locked at OpenVirtioNet time and propagates straight
// through), but the interface requires it.
func (l *VirtioNetLink) SetLinkAddress(addr tcpip.LinkAddress) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.mac = addr
}

// Capabilities reports what offloads / properties we support.
//
//   - CapabilityResolutionRequired tells the stack to perform
//     ARP for IPv4 next-hops before handing frames to us (we
//     do NOT do MAC resolution in the device — gvisor's ARP
//     does, hence we register `arp.NewProtocol` alongside
//     `ipv4.NewProtocol` in the M3 probe).
//
// We don't offload TX/RX checksums (virtio-net could with
// VIRTIO_NET_F_CSUM, but M2 doesn't negotiate that bit; if we
// claimed the cap and didn't compute, every IPv4 host on the
// network would drop our packets).
func (l *VirtioNetLink) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}

// Attach stores the network dispatcher. Called once by
// `stack.CreateNIC`, then called again with `nil` when the NIC
// is removed.
func (l *VirtioNetLink) Attach(dispatcher stack.NetworkDispatcher) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.dispatch = dispatcher
}

// IsAttached reports whether a dispatcher is currently set.
func (l *VirtioNetLink) IsAttached() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dispatch != nil
}

// dispatcher returns the currently-attached dispatcher (or nil)
// under the read lock. Internal helper for the RX path.
func (l *VirtioNetLink) dispatcher() stack.NetworkDispatcher {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.dispatch
}

// WritePackets serialises each PacketBuffer in `pkts` into a
// single contiguous Ethernet frame (link header + network
// header + transport header + data) and hands it to the
// underlying NIC. Stops at the first TransmitFrame error and
// returns the count of successful writes.
//
// `pkts` is owned by us per the gvisor contract (see
// LinkWriter.WritePackets godoc); each buffer's data has been
// pre-populated by upper layers, with the Ethernet header
// already pushed by our `AddHeader` (gvisor calls AddHeader
// once per packet just before WritePackets).
func (l *VirtioNetLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		frame := flattenPacketBuffer(pkt)
		if err := l.nic.TransmitFrame(frame); err != nil {
			if n == 0 {
				return 0, &tcpip.ErrInvalidEndpointState{}
			}
			return n, nil
		}
		n++
	}
	return n, nil
}

// flattenPacketBuffer concatenates all header + data views of a
// PacketBuffer into a single new byte slice ready for the wire.
//
// We can't pass gvisor's `buffer.Buffer` directly to
// `VirtioNet.TransmitFrame` because the M2 TX path allocates one
// DMA buffer and copies bytes in via `unsafe.Slice` — it needs a
// linear `[]byte`. The copy here is the price of that boundary.
// (gvisor uses chunked buffers internally for zero-copy across
// the stack; the link layer is where they get serialised.)
func flattenPacketBuffer(pkt *stack.PacketBuffer) []byte {
	buf := pkt.ToBuffer()
	defer buf.Release()
	view := buf.Flatten()
	// Make a defensive copy: ToBuffer/Flatten can return a view
	// backed by the packet's reserved region. Releasing the buffer
	// invalidates that storage, so we duplicate before returning.
	out := make([]byte, len(view))
	copy(out, view)
	return out
}

// Wait blocks until the RX goroutine (if any) exits.
//
// On host builds (no RX goroutine ever started), `rxDone` was
// never written to; we have to close it on Close() so Wait()
// returns. The tamago wrapper closes rxDone explicitly when
// the goroutine exits.
func (l *VirtioNetLink) Wait() {
	<-l.rxDone
}

// ARPHardwareType reports our link's L2 type. Ethernet
// (ARPHRD_ETHER = 1) is the standard answer; gvisor's ARP
// uses this when constructing replies.
func (l *VirtioNetLink) ARPHardwareType() header.ARPHardwareType {
	return header.ARPHardwareEther
}

// AddHeader pushes the Ethernet header onto the front of an
// outgoing PacketBuffer. gvisor calls this once per outgoing
// packet, AFTER ARP has resolved the dst MAC.
//
// The reserved region (size MaxHeaderLength()) was allocated by
// the upper-layer endpoint; we just fill it in.
func (l *VirtioNetLink) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	fields := header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	}
	if len(fields.SrcAddr) == 0 {
		fields.SrcAddr = l.LinkAddress()
	}
	eth.Encode(&fields)
}

// ParseHeader consumes the link-layer header from an incoming
// PacketBuffer, populating LinkHeader() and stripping those
// bytes from the front of the data view. Returns true on
// success, false if the packet is shorter than an Ethernet
// header.
func (l *VirtioNetLink) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

// Close is called when the NIC is removed. We close `rxStop`
// to signal the (possibly-running) RX goroutine to exit, and
// invoke any on-close action set via `SetOnCloseAction`.
//
// On host builds the RX goroutine was never started, so we also
// close `rxDone` ourselves to unblock any Wait() callers.
func (l *VirtioNetLink) Close() {
	l.mu.Lock()
	stopped := false
	select {
	case <-l.rxStop:
		// already closed
	default:
		close(l.rxStop)
		stopped = true
	}
	fn := l.closeFn
	l.mu.Unlock()
	// If no RX goroutine was ever started (host build), close
	// rxDone here so Wait() returns. The tamago path closes it
	// from the goroutine on exit.
	if stopped && !l.hasRXGoroutine() {
		close(l.rxDone)
	}
	if fn != nil {
		fn()
	}
}

// SetOnCloseAction records a callback to run when Close() is
// invoked. gvisor uses this to e.g. detach the underlying device;
// we just store it.
func (l *VirtioNetLink) SetOnCloseAction(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closeFn = fn
}

// InjectInboundFrame is the host-test seam (no DMA, no virtio):
// the test feeds a complete Ethernet frame in via this method,
// which wraps it in a PacketBuffer and calls the dispatcher
// directly — exactly what the tamago RX goroutine does after
// stripping the virtio header.
//
// Returns true if the frame was delivered (i.e. a dispatcher
// is attached), false otherwise.
func (l *VirtioNetLink) InjectInboundFrame(frame []byte) bool {
	d := l.dispatcher()
	if d == nil {
		return false
	}
	if len(frame) < header.EthernetMinimumSize {
		return false
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()
	if !l.ParseHeader(pkt) {
		return false
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	d.DeliverNetworkPacket(eth.Type(), pkt)
	return true
}

// hasRXGoroutine reports whether the tamago wrapper started an
// RX goroutine (set by `StartRX` in netstack_link_tamago.go).
// On host builds it's always false; Close() then closes rxDone
// itself so Wait() returns.
func (l *VirtioNetLink) hasRXGoroutine() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.rxStarted
}
