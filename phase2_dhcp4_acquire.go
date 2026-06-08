// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M4 probe — gated on `-tags phase2_dhcp4_acquire`.
//
// Builds on M3-minimal: locates the first modern virtio-net PCI
// device, brings it up via the M2 path, wraps it in a ministack Link,
// and — instead of stamping a static 10.0.2.15/24 — runs the pure-Go
// DHCPv4 client (uefiboard/ministack DHCP4Acquire) to learn the IP,
// subnet mask, default gateway, DNS server list, and lease duration
// from QEMU's built-in DHCP server.
//
// After acquisition, applies the lease back to the Stack and sends one
// ICMP Echo Request to the learned gateway to prove end-to-end
// reachability. The live runner greps for "lease acquired" + the
// ping confirmation.
//
// QEMU's `-netdev user` ships a SLIRP DHCP server at 10.0.2.2/24:
//
//   - Offered IP:    10.0.2.15
//   - Gateway:       10.0.2.2
//   - DNS:           10.0.2.3
//   - Lease:         86400 s (24h)
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_dhcp4_acquire \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `dhcp4:efi:<arch>` for the per-arch wiring.)
//
// The two M3/M4 probes both bring up the same virtio-net device and
// would step on each other; the Taskfile builds them into separate
// EFIs so the runtime never sees both active. The dispatcher
// (phase2_dispatch.go) calls every runXProbe unconditionally; the
// stub files resolve to no-ops when the matching tag is not set.

//go:build phase2_dhcp4_acquire && tamago

package main

import (
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// runDHCP4AcquireProbe is the entry point the dispatcher calls when
// the `phase2_dhcp4_acquire` build tag is set. Walks PCI for the
// first modern virtio-net device, brings it up, wraps it in a
// ministack Link, kicks off the RX goroutine, runs DHCP4Acquire,
// applies the learned lease to the Stack, then pings the gateway.
func runDHCP4AcquireProbe() {
	println("phase2-dhcp4: M4 — pure-Go DHCPv4 client over ministack/virtio-net")

	pciIO := locateVirtioNetForDHCP4()
	if pciIO == 0 {
		println("phase2-dhcp4: no modern virtio-net device found — M4 cannot run")
		println("phase2-dhcp4: LEASE FAIL: no virtio-net device")
		return
	}

	println("phase2-dhcp4: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-dhcp4: OpenVirtioNet FAILED:", err.Error())
		println("phase2-dhcp4: LEASE FAIL:", err.Error())
		return
	}
	println("phase2-dhcp4: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	// Deliberately DO NOT call SetIPv4Address — that's exactly what
	// we're about to learn from the server. The Stack's UDP send path
	// uses 0.0.0.0 as the source when no local address is configured.
	s.Start()
	println("phase2-dhcp4: RX goroutine started; sending DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-dhcp4: LEASE FAIL:", err.Error())
		return
	}

	println("phase2-dhcp4: lease acquired")
	println("phase2-dhcp4:   IP      =", lease.IP.String())
	println("phase2-dhcp4:   Mask    =", lease.Mask.String())
	if lease.Gateway != nil {
		println("phase2-dhcp4:   Gateway =", lease.Gateway.String())
	} else {
		println("phase2-dhcp4:   Gateway = <none>")
	}
	for i, d := range lease.DNS {
		switch i {
		case 0:
			println("phase2-dhcp4:   DNS     =", d.String())
		default:
			println("phase2-dhcp4:           ", d.String())
		}
	}
	if lease.Server != nil {
		println("phase2-dhcp4:   Server  =", lease.Server.String())
	}
	println("phase2-dhcp4:   Lease   =", lease.Duration.String())

	// Apply the lease and ping the gateway to verify it's usable
	// end-to-end. Mask + Gateway are the only fields the route table
	// needs.
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-dhcp4: SetIPv4Address FAILED:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-dhcp4: SetDefaultGateway FAILED:", err.Error())
			return
		}
	}

	if lease.Gateway != nil {
		rt, err := s.PingOnce(lease.Gateway, []byte("M4-dhcp4"), 5*time.Second)
		if err != nil {
			println("phase2-dhcp4: gateway ping FAILED:", err.Error())
			return
		}
		ms := rt.Milliseconds()
		if ms == 0 && rt > 0 {
			us := rt.Microseconds()
			println("phase2-dhcp4: gateway ping OK (", us, "us)")
		} else {
			println("phase2-dhcp4: gateway ping OK (", ms, "ms)")
		}
	} else {
		println("phase2-dhcp4: skipping gateway ping — no gateway in lease")
	}
}

// locateVirtioNetForDHCP4 walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first 1AF4:1041 (modern virtio-net). Returns 0 if
// none found. Same pattern as M2/M3.
func locateVirtioNetForDHCP4() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-dhcp4: LocateHandleBuffer FAILED:", err.Error())
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
