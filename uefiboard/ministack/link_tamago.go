// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Live adapter from `*uefiboard.VirtioNet` to ministack's `Link`
// interface. Gated on the `tamago` build tag so the host test build
// keeps a clean dependency surface (no DMA, no virtio-net device).
//
// Per-call poll budgets:
//
//   - SendFrame just forwards to VirtioNet.TransmitFrame (which has
//     its own internal poll budget for the used-ring publish).
//   - RecvFrame uses a small per-call budget (`virtioRecvPollBudget`)
//     so the Stack's RX goroutine can loop back rapidly. The actual
//     blocking behaviour falls out of the goroutine looping into
//     RecvFrame in a tight loop; each call timing out after the
//     budget exhausts is fine — we just spin again.

//go:build tamago

package ministack

import (
	"net"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// virtioRecvPollBudget is the per-RecvFrame poll budget passed to
// VirtioNet.ReceiveFrame. Tuned for ~10 ms wall on QEMU+EDK2; the
// Stack's RX goroutine loops back into RecvFrame immediately on
// timeout so the effective polling is continuous.
const virtioRecvPollBudget = 1024

// virtioNetLink wraps a `*uefiboard.VirtioNet` as a ministack Link.
type virtioNetLink struct {
	vn *uefiboard.VirtioNet
}

// NewLinkFromVirtioNet returns a Link wrapping the supplied
// (already-initialised) `*uefiboard.VirtioNet`. The caller is
// responsible for keeping `vn` alive for the lifetime of the link.
func NewLinkFromVirtioNet(vn *uefiboard.VirtioNet) Link {
	return &virtioNetLink{vn: vn}
}

// SendFrame submits a frame to the virtio-net TX queue.
func (l *virtioNetLink) SendFrame(frame []byte) error {
	return l.vn.TransmitFrame(frame)
}

// RecvFrame polls the virtio-net RX queue for one frame. Returns the
// raw Ethernet payload (header already stripped by VirtioNet) or
// ErrReceiveTimeout when the budget exhausts.
func (l *virtioNetLink) RecvFrame() ([]byte, error) {
	return l.vn.ReceiveFrame(virtioRecvPollBudget)
}

// MAC returns the MAC the device published in its DeviceCfg block.
func (l *virtioNetLink) MAC() net.HardwareAddr {
	return net.HardwareAddr(append([]byte(nil), l.vn.MAC[:]...))
}
