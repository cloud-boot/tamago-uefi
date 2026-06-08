// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M5 probe — gated on `-tags phase2_http_get`.
//
// Builds on M4 (DHCPv4) + the M5 additions to ministack (TCP4, DNS,
// HTTP). The probe:
//
//   1. Locates the first modern virtio-net PCI device and brings it up.
//   2. Wraps the device in a ministack Link.
//   3. Acquires a DHCPv4 lease (reusing M4's DHCP4Acquire path).
//   4. Applies the lease to the Stack (SetIPv4Address +
//      SetDefaultGateway).
//   5. Resolves "example.com" via the DHCP-learned DNS server.
//   6. Issues an HTTP/1.1 GET against http://example.com/.
//   7. Prints the status code, content length, total bytes received,
//      and the first 64 bytes of the body.
//   8. Returns (halt is the dispatcher's job).
//
// Under QEMU+EDK2 with -netdev user, SLIRP's built-in DNS forwarder
// (10.0.2.3 by default) resolves real names against the host's
// resolver; SLIRP's NAT forwards outbound TCP/80 to the host's network
// path. The probe therefore exercises the full stack — ARP + IPv4 +
// UDP + DHCP + DNS + TCP + HTTP — against a real endpoint reachable
// over the host's egress.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_http_get \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `http:efi:<arch>` for the per-arch wiring.)

//go:build phase2_http_get && tamago

package main

import (
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// runHTTPGetProbe is the entry point the dispatcher calls when the
// `phase2_http_get` build tag is set. Sequence DHCP → DNS → HTTP, with
// per-stage status prints so the live runner can grep on individual
// phases.
func runHTTPGetProbe() {
	println("phase2-http: M5 — pure-Go DHCP+DNS+HTTP over ministack/virtio-net")

	pciIO := locateVirtioNetForHTTP()
	if pciIO == 0 {
		println("phase2-http: no modern virtio-net device found — M5 cannot run")
		println("phase2-http: HTTP-GET FAIL: no virtio-net device")
		return
	}

	println("phase2-http: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-http: OpenVirtioNet FAILED:", err.Error())
		println("phase2-http: HTTP-GET FAIL:", err.Error())
		return
	}
	println("phase2-http: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	println("phase2-http: RX path active; sending DHCP DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-http: HTTP-GET FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-http: lease acquired")
	println("phase2-http:   IP      =", lease.IP.String())
	println("phase2-http:   Mask    =", lease.Mask.String())
	if lease.Gateway != nil {
		println("phase2-http:   Gateway =", lease.Gateway.String())
	}
	if len(lease.DNS) == 0 {
		println("phase2-http: HTTP-GET FAIL: DHCP returned no DNS server")
		return
	}
	for i, d := range lease.DNS {
		switch i {
		case 0:
			println("phase2-http:   DNS     =", d.String())
		default:
			println("phase2-http:           ", d.String())
		}
	}

	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-http: SetIPv4Address FAILED:", err.Error())
		println("phase2-http: HTTP-GET FAIL:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-http: SetDefaultGateway FAILED:", err.Error())
			println("phase2-http: HTTP-GET FAIL:", err.Error())
			return
		}
	}

	// --- DNS resolution -----------------------------------------
	target := "example.com"
	println("phase2-http: resolving", target, "via DNS server", lease.DNS[0].String())
	ip, err := s.ResolveA(target, lease.DNS[0], 5*time.Second)
	if err != nil {
		println("phase2-http: HTTP-GET FAIL: DNS:", err.Error())
		return
	}
	println("phase2-http: resolved", target, "=>", ip.String())

	// Pre-warm the gateway ARP entry. The HTTP target is off-link
	// (example.com is on the public internet), so the first TCP
	// segment will need the gateway's MAC. A short ICMP echo to the
	// gateway proves M4-level connectivity and primes the ARP cache
	// before the TCP handshake.
	if lease.Gateway != nil {
		if _, perr := s.PingOnce(lease.Gateway, []byte("M5"), 3*time.Second); perr != nil {
			println("phase2-http: gateway pre-ping FAILED:", perr.Error())
		} else {
			println("phase2-http: gateway pre-ping OK")
		}
	}

	// --- HTTP GET ---------------------------------------------
	url := "http://" + target + "/"
	println("phase2-http: GET", url)

	resp, err := s.HTTPGet(url, ministack.HTTPGetOptions{
		DNSServer:      lease.DNS[0],
		DialTimeout:    8 * time.Second,
		RequestTimeout: 15 * time.Second,
	})
	if err != nil {
		println("phase2-http: HTTP-GET FAIL:", err.Error())
		return
	}

	println("phase2-http: status   =", resp.StatusLine)
	println("phase2-http: code     =", resp.StatusCode)
	println("phase2-http: bytes    =", len(resp.Body))
	if cl, ok := resp.Headers["content-length"]; ok {
		println("phase2-http: cl-hdr   =", cl)
	}
	if ct, ok := resp.Headers["content-type"]; ok {
		println("phase2-http: ct-hdr   =", ct)
	}
	preview := resp.Body
	if len(preview) > 64 {
		preview = preview[:64]
	}
	println("phase2-http: preview  =", string(preview))
	println("phase2-http: HTTP-GET OK")
}

// locateVirtioNetForHTTP walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first 1AF4:1041 (modern virtio-net). Returns 0 if
// none found. Same pattern as M2/M3/M4.
func locateVirtioNetForHTTP() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-http: LocateHandleBuffer FAILED:", err.Error())
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
