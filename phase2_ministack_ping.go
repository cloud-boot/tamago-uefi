// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M3-minimal probe — gated on `-tags phase2_ministack_ping`.
//
// First end-to-end test of the hand-rolled ministack
// (`uefiboard/ministack`) sitting on top of our pure-Go virtio-net
// rail. Locates the first modern virtio-net PCI device, brings it up
// via the M2 path, wraps it in a ministack `Link`, configures
// 10.0.2.15/24 with default gateway 10.0.2.2 (QEMU NAT defaults),
// starts the RX goroutine, sends one ICMP Echo Request, and prints
// the round-trip time on Reply.
//
// On QEMU+EDK2 the NAT gateway answers Echo Requests with a
// synthesised reply in microseconds, so a 5-second timeout is two
// or three orders of magnitude more than needed; a failure here
// means the stack is broken, not that the network is slow.
//
// Why this replaces M3 gvisor (R-M3'a CLOSED, 2026-06-08): gvisor
// compiled clean under TamaGo but #GP'd inside EDK2's CpuDxe before
// our dispatcher ran. The ministack is ~1000 LOC, pure Go, no
// timer-driven preemption assumptions, no deep init paths — every
// goroutine and channel is one we own.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_ministack_ping \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `ministack:efi:<arch>` for the per-arch wiring.)
// As with the M2 probe, `phase2_blkprintk` is pulled in alongside
// so the Block-IO side-channel teeing is available; on QEMU the
// ConOut log is sufficient on its own.

//go:build phase2_ministack_ping && tamago

package main

import (
	"net"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// Static IP / gateway / prefix length match QEMU's default
// user-mode (SLIRP) network layout. M4 will replace these with
// DHCPv4-discovered values.
var (
	ministackProbeIP   = net.IPv4(10, 0, 2, 15)
	ministackProbeMask = net.IPv4Mask(255, 255, 255, 0)
	ministackProbeGW   = net.IPv4(10, 0, 2, 2)
)

// runMinistackPingProbe is the entry point the dispatcher calls when
// the `phase2_ministack_ping` build tag is set. Walks PCI for the
// first modern virtio-net device, brings it up, wraps it in a
// ministack Link, configures the addressing, starts the RX
// goroutine, sends one ICMP Echo Request, prints the result.
func runMinistackPingProbe() {
	println("phase2-ministack-ping: M3-minimal — hand-rolled pure-Go stack over virtio-net")

	pciIO := locateVirtioNetForMinistack()
	if pciIO == 0 {
		println("phase2-ministack-ping: no modern virtio-net device found — M3 cannot run")
		println("phase2-ministack-ping: ROUND-TRIP FAIL: no virtio-net device")
		return
	}

	println("phase2-ministack-ping: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-ministack-ping: OpenVirtioNet FAILED:", err.Error())
		println("phase2-ministack-ping: ROUND-TRIP FAIL:", err.Error())
		return
	}
	println("phase2-ministack-ping: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	if err := s.SetIPv4Address(ministackProbeIP, ministackProbeMask); err != nil {
		println("phase2-ministack-ping: SetIPv4Address FAILED:", err.Error())
		println("phase2-ministack-ping: ROUND-TRIP FAIL:", err.Error())
		return
	}
	if err := s.SetDefaultGateway(ministackProbeGW); err != nil {
		println("phase2-ministack-ping: SetDefaultGateway FAILED:", err.Error())
		println("phase2-ministack-ping: ROUND-TRIP FAIL:", err.Error())
		return
	}
	println("phase2-ministack-ping: configured 10.0.2.15/24, gateway 10.0.2.2")

	s.Start()
	println("phase2-ministack-ping: RX goroutine started")

	rt, err := s.PingOnce(ministackProbeGW, []byte("M3-mini"), 5*time.Second)
	if err != nil {
		println("phase2-ministack-ping: ROUND-TRIP FAIL:", err.Error())
		return
	}
	// time.Duration formats as "Nms" automatically via Duration.String().
	// Convert via integer milliseconds for clarity in the log.
	ms := rt.Milliseconds()
	if ms == 0 && rt > 0 {
		// Sub-millisecond — print microseconds for visibility.
		us := rt.Microseconds()
		println("phase2-ministack-ping: ROUND-TRIP OK (", us, "us)")
	} else {
		println("phase2-ministack-ping: ROUND-TRIP OK (", ms, "ms)")
	}
}

// locateVirtioNetForMinistack walks the EFI_PCI_IO_PROTOCOL handle
// space looking for the first 1AF4:1041 (modern virtio-net). Returns
// 0 if none found. Same pattern as the M2 virtio-net probe + the
// archived gvisor probe; kept as a separate helper so this file is
// self-contained.
func locateVirtioNetForMinistack() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-ministack-ping: LocateHandleBuffer FAILED:", err.Error())
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
