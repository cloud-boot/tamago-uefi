// Phase-2 M3 probe — gated on `-tags phase2_netstack_ping`.
//
// First end-to-end test of the gvisor netstack
// (`gvisor.dev/gvisor/pkg/tcpip`) sitting on top of our pure-Go
// virtio-net rail. Locates the first modern virtio-net PCI
// device (VID 0x1AF4 / DID 0x1041), brings it up via the M2
// path, attaches it to a `stack.Stack` configured with IPv4
// + ARP + ICMP4, assigns a static address (10.0.2.15/24 — the
// QEMU NAT default), installs a default route via 10.0.2.2,
// opens an ICMPv4 raw endpoint, sends an Echo Request to the
// gateway, and waits for an Echo Reply.
//
// On QEMU+EDK2 (amd64 / arm64 / loong64 / riscv64) the NAT
// gateway answers Echo Requests with a synthesised reply in
// < 50 ms typically. The probe prints the per-attempt
// spin-count so a regression in stack init or RX delivery
// surfaces clearly.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_netstack_ping \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `netstack:efi:<arch>` for the per-arch
// wiring.) The probe pulls in `phase2_blkprintk` automatically
// via the Taskfile so the Block-IO side-channel teeing is
// available; on QEMU the ConOut log is sufficient on its own.
//
// R-M3'a verification — 2026-06-08: gvisor
// `v0.0.0-20260604230326-c7dbb92365cd` (the `go` branch HEAD
// just before the upstream-broken `bridge_test.go` commit on
// 2026-06-05) compiles clean under `GOOS=tamago` across all
// four target architectures with the standard
// `linkcpuinit,linkramstart` build-tag set. No tamago overlay
// patch was required.

//go:build phase2_netstack_ping && tamago

package main

import (
	"bytes"

	"github.com/cloud-boot/tamago-uefi/uefiboard"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/arp"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// Static IP / gateway / prefix length match QEMU's default
// user-mode (SLIRP) network layout (Qemu Networking docs:
// https://wiki.qemu.org/Documentation/Networking#User_Networking).
// We don't DHCP at M3 — that's M4's job. A static address keeps
// the probe minimal.
var (
	netstackProbeIP        = tcpip.AddrFrom4([4]byte{10, 0, 2, 15})
	netstackProbeGW        = tcpip.AddrFrom4([4]byte{10, 0, 2, 2})
	netstackProbeNetmask   = tcpip.MaskFromBytes([]byte{255, 255, 255, 0})
	netstackProbeNICID     = tcpip.NICID(1)
	netstackProbePollSpins = 1024 // per-call ReceiveFrame budget; RX goroutine loops continuously
)

// runNetstackPingProbe is the entry point the dispatcher calls
// when the `phase2_netstack_ping` build tag is set.
//
// Phases:
//
//  1. Locate the first virtio-net device handle (M1.5 PCI walk
//     reused). Skip if absent (e.g. SNP-only firmware).
//  2. `OpenVirtioNet` brings the device up (M2 init sequence).
//  3. `OpenVirtioNetLink` wraps it in a `stack.LinkEndpoint`.
//  4. Build the gvisor stack with IPv4 + ARP + ICMP4 + UDP.
//  5. Configure NIC + protocol address + default route.
//  6. Start the link's RX goroutine.
//  7. Open an ICMPv4 raw endpoint, send Echo Request, poll for
//     reply.
//  8. Print result. The probe never returns — main.go halts.
func runNetstackPingProbe() {
	println("phase2-netstack-ping: M3 — gvisor netstack over virtio-net")

	pciIO := locateVirtioNetForNetstack()
	if pciIO == 0 {
		println("phase2-netstack-ping: no modern virtio-net device found — M3 cannot run")
		return
	}

	println("phase2-netstack-ping: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-netstack-ping: OpenVirtioNet FAILED:", err.Error())
		return
	}
	println("phase2-netstack-ping: device UP. MAC =", vn.MAC.String())

	link := uefiboard.OpenVirtioNetLink(vn, 0 /* default MTU 1500 */)
	println("phase2-netstack-ping: built VirtioNetLink, MTU =", link.MTU())

	// Build the gvisor stack. Protocols enumerated:
	//
	//   - ipv4 — required for L3.
	//   - arp  — gvisor synthesises ARP req/replies on our
	//            behalf when the IPv4 layer needs to resolve
	//            a next-hop. `CapabilityResolutionRequired`
	//            on the link endpoint tells gvisor to engage
	//            the ARP module before WritePackets.
	//   - icmp.NewProtocol4 — required for `s.NewEndpoint` to
	//            be able to construct an ICMPv4 endpoint.
	//   - udp  — pulled in proactively so M4's DHCPv4 client
	//            can layer onto the same stack instance later
	//            without a rebuild.
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			arp.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			icmp.NewProtocol4,
			udp.NewProtocol,
		},
	})
	println("phase2-netstack-ping: stack.New OK")

	if tcperr := s.CreateNIC(netstackProbeNICID, link); tcperr != nil {
		println("phase2-netstack-ping: CreateNIC FAILED:", tcperr.String())
		return
	}
	println("phase2-netstack-ping: CreateNIC OK")

	// IPv4 /24 address bind. `AddressLifetimes` left at
	// zero-value = permanent (gvisor default). Properties{}
	// keeps the address public; we want ARP for it.
	addrWithPrefix := tcpip.AddressWithPrefix{
		Address:   netstackProbeIP,
		PrefixLen: 24,
	}
	addr := tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: addrWithPrefix,
	}
	if tcperr := s.AddProtocolAddress(netstackProbeNICID, addr, stack.AddressProperties{}); tcperr != nil {
		println("phase2-netstack-ping: AddProtocolAddress FAILED:", tcperr.String())
		return
	}
	println("phase2-netstack-ping: AddProtocolAddress OK (10.0.2.15/24)")

	// Default route: everything via 10.0.2.2. The destination
	// subnet is empty (0.0.0.0/0), which gvisor matches as
	// "default".
	defaultSubnet, subErr := tcpip.NewSubnet(
		tcpip.AddrFrom4([4]byte{0, 0, 0, 0}),
		netstackProbeNetmask,
	)
	if subErr != nil {
		println("phase2-netstack-ping: NewSubnet (default route) FAILED:", subErr.Error())
		return
	}
	s.SetRouteTable([]tcpip.Route{{
		Destination: defaultSubnet,
		Gateway:     netstackProbeGW,
		NIC:         netstackProbeNICID,
	}})
	println("phase2-netstack-ping: route table set (default via 10.0.2.2)")

	// Kick off the link's RX goroutine. Frames the device
	// receives now flow into the stack's dispatcher and get
	// routed up to whichever endpoint (ARP, IPv4/ICMP) is
	// interested.
	link.StartRX(netstackProbePollSpins)
	println("phase2-netstack-ping: RX goroutine started")

	// Build the ICMPv4 raw endpoint we'll write Echo Requests
	// through. `icmp.NewProtocol4`'s NewEndpoint returns a
	// connection-style endpoint that doesn't need an explicit
	// raw socket option — gvisor's ICMP endpoint constructs
	// the IPv4 + ICMP headers internally.
	var wq waiter.Queue
	ep, tcperr := s.NewEndpoint(icmp.ProtocolNumber4, ipv4.ProtocolNumber, &wq)
	if tcperr != nil {
		println("phase2-netstack-ping: NewEndpoint(ICMP4) FAILED:", tcperr.String())
		return
	}
	defer ep.Close()
	println("phase2-netstack-ping: NewEndpoint(ICMP4) OK")

	// Subscribe to read-readable events so we can block waiting
	// for the Echo Reply.
	we, ch := waiter.NewChannelEntry(waiter.ReadableEvents)
	wq.EventRegister(&we)
	defer wq.EventUnregister(&we)

	// Echo Request payload — 8 bytes of "ABCDEFGH" plus the
	// 8-byte ICMP header (type 8, code 0, checksum, id, seq).
	// gvisor's ICMP endpoint fills in the header on Write; we
	// just provide the payload.
	echoPayload := []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}

	to := tcpip.FullAddress{
		NIC:  netstackProbeNICID,
		Addr: netstackProbeGW,
	}
	wrote, tcperr := ep.Write(bytes.NewReader(echoPayload), tcpip.WriteOptions{To: &to})
	if tcperr != nil {
		println("phase2-netstack-ping: ep.Write FAILED:", tcperr.String())
		return
	}
	println("phase2-netstack-ping: ICMP Echo Request sent,", wrote, "bytes to 10.0.2.2")

	// Wait for the reply. TamaGo's bare-metal config has no
	// time.After, so we use a bounded busy-poll loop on the
	// readable channel. Each iteration either:
	//   - sees a wake on `ch` → attempt Read (success path)
	//   - falls through default → spin a small budget of
	//     cycles so the RX goroutine gets CPU
	//
	// At ~1 ms per outer iteration on QEMU (firmware-bound),
	// 5000 iterations bound the wait at roughly 5 s, well above
	// the typical < 50 ms NAT reply latency.
	const maxSpins = 5000
	var sink tcpip.SliceWriter = make([]byte, 1500)
	for spin := 0; spin < maxSpins; spin++ {
		select {
		case <-ch:
			res, tcperr := ep.Read(&sink, tcpip.ReadOptions{})
			if tcperr != nil {
				// Spurious wake-up; keep waiting.
				continue
			}
			println("phase2-netstack-ping: ICMP Echo Reply received,",
				res.Count, "bytes,", res.Total, "total in pkt,",
				"after", spin, "spin iterations")
			println("phase2-netstack-ping: ROUND-TRIP OK — probe PASS")
			return
		default:
			for j := 0; j < 1000; j++ {
				_ = j
			}
		}
	}
	println("phase2-netstack-ping: NO REPLY within", maxSpins, "spin iterations — probe FAILED")
}

// locateVirtioNetForNetstack walks the EFI_PCI_IO_PROTOCOL
// handle space looking for the first 1AF4:1041 (modern
// virtio-net). Returns 0 if none found. Borrows the M2 probe's
// pattern verbatim — kept as a separate helper here so the M3
// dispatcher can call it without pulling in the rest of the M2
// instrumentation.
func locateVirtioNetForNetstack() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-netstack-ping: LocateHandleBuffer FAILED:", err.Error())
		return 0
	}
	for _, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIPciIOProtocolGUID)
		if err != nil {
			continue
		}
		vid, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgVendorID)
		if err != nil {
			continue
		}
		did, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgDeviceID)
		if err != nil {
			continue
		}
		if vid == uefiboard.VirtioPCIVendorID && did == uefiboard.VirtioPCIDeviceIDModernNet {
			return iface
		}
	}
	return 0
}
