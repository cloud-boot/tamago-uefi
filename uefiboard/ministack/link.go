// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Link abstraction for ministack.
//
// Ministack talks to the network through a tiny `Link` interface
// rather than directly to `*uefiboard.VirtioNet`. Why:
//
//   - Tests can swap in a synthetic in-memory link without touching
//     virtio-net, DMA, or the tamago build tag.
//   - When M2.1 brings up the SNP rail (or any future rail), we add a
//     new Link implementation in a sibling file without changing the
//     Stack.
//
// The interface is minimal: send a frame, receive a frame, expose our
// own MAC. We do NOT model link-up / link-down or MTU here; ministack
// hardcodes MTU 1500 in ipv4.go, and the device is assumed up before
// the Stack is constructed (the M2 OpenVirtioNet call performs the
// init sequence).
//
// The live adapter from `*uefiboard.VirtioNet` lives in
// `link_tamago.go` (build tag `tamago`) so the host test build doesn't
// need DMA primitives.

package ministack

import "net"

// Link is the L2 transport ministack sits on top of. Implementations
// are responsible for adding/stripping any device-specific framing
// (e.g. the virtio_net_hdr prefix on the virtio-net rail). Ministack
// itself only ever sees raw Ethernet II frames.
type Link interface {
	// SendFrame submits one Ethernet II frame for transmission. The
	// implementation is allowed to block until the device acknowledges
	// the descriptor; ministack tolerates either model.
	SendFrame(frame []byte) error

	// RecvFrame blocks (or busy-polls, for the virtio-net rail) until
	// one Ethernet II frame is available, then returns it. Returning
	// any error (timeout, device fault) is handled by the RX goroutine
	// as "try again next iteration".
	RecvFrame() ([]byte, error)

	// MAC returns the 6-byte hardware address the device advertises.
	// Ministack uses this as the source MAC for every outbound frame
	// and as the "is this for me" filter on incoming ARP requests.
	MAC() net.HardwareAddr
}
