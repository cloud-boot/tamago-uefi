// cloud-boot UEFI board — gvisor netstack LinkEndpoint adapter:
// live wrapper around `*VirtioNet` (Phase 2, M3).
//
// Pairs with `netstack_link.go` (the host-buildable core). This
// file owns the parts that need a real DMA-backed virtio-net
// device: the `OpenVirtioNetLink(*VirtioNet, mtu)` constructor
// and the `StartRX` goroutine that polls `ReceiveFrame()` and
// hands each frame to the gvisor dispatcher.
//
// Why split: `VirtioNet.ReceiveFrame` derefs DMA pointers via
// `unsafe.Slice` and uses tamago's allocator — neither is
// available on the host test build. Keeping the gvisor seam in
// host-buildable code lets us unit-test the adapter (see
// netstack_link_test.go); keeping the live constructor here
// keeps the host build clean.

//go:build phase2_netstack_ping && tamago && (amd64 || arm64 || riscv64)

package uefiboard

import (
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// OpenVirtioNetLink wraps an already-initialised `*VirtioNet`
// (typically returned by `OpenVirtioNet`) in a gvisor
// `LinkEndpoint`. The MTU defaults to 1500 if the caller
// passes 0; that's the value the QEMU+EDK2 user-mode NAT
// gateway answers with.
//
// The returned `*VirtioNetLink` is NOT yet attached to a
// gvisor stack — the caller plugs it into `stack.CreateNIC(id,
// link)`, then calls `link.StartRX()` to kick off the receive
// loop. Splitting Attach vs StartRX lets the caller register
// the NIC, add protocol addresses, and configure routes BEFORE
// any inbound frame can race into a half-built stack.
func OpenVirtioNetLink(vn *VirtioNet, mtu uint32) *VirtioNetLink {
	if mtu == 0 {
		mtu = VirtioNetDefaultMTU
	}
	mac := tcpip.LinkAddress(vn.MAC[:])
	return newVirtioNetLink(vn, mac, mtu)
}

// VirtioNetDefaultMTU is the Ethernet payload cap we advertise
// to gvisor. QEMU user-mode NAT's gateway answers with this MTU;
// VZ also uses 1500. We don't try to read it from the device
// because M2 doesn't negotiate VIRTIO_NET_F_MTU.
const VirtioNetDefaultMTU uint32 = 1500

// StartRX launches the RX poll goroutine. Must be called once
// after the link has been attached to a stack (via
// `stack.CreateNIC`). Idempotent — calling it twice is a no-op.
//
// The goroutine polls `vn.ReceiveFrame(pollIterations)` in a
// tight loop. Each frame is wrapped in a `*stack.PacketBuffer`,
// the Ethernet header is parsed off, and the packet is handed
// to the dispatcher's `DeliverNetworkPacket`.
//
// `pollIterations` is the per-call poll budget passed to
// `ReceiveFrame` (e.g. 1024 → ~10ms wall on QEMU). Lower
// values check `rxStop` more often; higher values reduce
// per-poll overhead. 1024 is a reasonable default for the
// M3 ping probe; the goroutine loops back into ReceiveFrame
// immediately on timeout so the effective polling is
// continuous.
func (l *VirtioNetLink) StartRX(pollIterations int) {
	l.mu.Lock()
	if l.rxStarted {
		l.mu.Unlock()
		return
	}
	l.rxStarted = true
	vn, ok := l.nic.(*VirtioNet)
	l.mu.Unlock()
	if !ok {
		// Test seam: a non-VirtioNet transport was injected.
		// Don't start a goroutine, but mark Wait() unblocked.
		close(l.rxDone)
		return
	}
	if pollIterations <= 0 {
		pollIterations = 1024
	}
	go l.rxLoop(vn, pollIterations)
}

// rxLoop is the goroutine body. Exits when rxStop is closed.
//
// On each frame:
//  1. Parse the Ethernet header (LinkHeader population).
//  2. Look up the dispatcher under the read lock.
//  3. Call `DeliverNetworkPacket(ethType, pkt)` — this is the
//     gvisor entry into the IPv4/ARP/ICMP code path.
//
// Frames whose dispatcher is nil (NIC removed mid-flight) are
// silently dropped. Receive errors other than timeout would
// be surfaced via the M2 println channel if we wanted to log
// them; for M3 we treat them as "try again next poll" because
// the timeout path is the steady state when the network is
// idle.
func (l *VirtioNetLink) rxLoop(vn *VirtioNet, pollIterations int) {
	defer close(l.rxDone)
	for {
		select {
		case <-l.rxStop:
			return
		default:
		}
		frame, err := vn.ReceiveFrame(pollIterations)
		if err != nil {
			// Most common error is ErrReceiveTimeout — no
			// frames in the budget window. Loop back and
			// poll again. Other errors are also benign at
			// this layer; surfacing them would require a
			// log channel we haven't wired.
			continue
		}
		l.deliverRX(frame)
	}
}

// deliverRX hands one captured frame to the gvisor dispatcher.
// Split out so the rxLoop body stays small and so the host
// test can exercise the wrapping logic via InjectInboundFrame.
func (l *VirtioNetLink) deliverRX(frame []byte) {
	d := l.dispatcher()
	if d == nil {
		return
	}
	if len(frame) < header.EthernetMinimumSize {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(frame),
	})
	defer pkt.DecRef()
	if !l.ParseHeader(pkt) {
		return
	}
	eth := header.Ethernet(pkt.LinkHeader().Slice())
	d.DeliverNetworkPacket(eth.Type(), pkt)
}
