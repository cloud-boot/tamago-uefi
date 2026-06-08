// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M6 probe — gated on `-tags phase2_https_get`.
//
// Builds on M5 (TCP4 + DNS + HTTP) by layering Go stdlib `crypto/tls`
// over the same ministack TCP4Conn (which already satisfies
// `net.Conn`). The probe:
//
//   1. Locates the first modern virtio-net PCI device and brings it up.
//   2. Wraps the device in a ministack Link.
//   3. Acquires a DHCPv4 lease (reusing M4's DHCP4Acquire path).
//   4. Applies the lease to the Stack (SetIPv4Address +
//      SetDefaultGateway).
//   5. Resolves "example.com" via the DHCP-learned DNS server (M5).
//   6. Issues an HTTPS/1.1 GET against https://example.com/, verifying
//      the server certificate against the embedded CA bundle (see
//      uefiboard/ministack/ca_bundle.pem).
//   7. Prints the status code, content length, total bytes received,
//      embedded-root count, and the first 64 bytes of the body.
//   8. Returns (halt is the dispatcher's job).
//
// Under QEMU+EDK2 with -netdev user, SLIRP's built-in DNS forwarder
// (10.0.2.3 by default) resolves real names against the host's
// resolver; SLIRP's NAT forwards outbound TCP/443 to the host's
// network path. The probe therefore exercises the FULL stack — ARP +
// IPv4 + UDP + DHCP + DNS + TCP + TLS + HTTP — against a real HTTPS
// endpoint reachable over the host's egress.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_https_get \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `https:efi:<arch>` for the per-arch wiring.)

//go:build phase2_https_get && tamago

package main

import (
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// runHTTPSGetProbe is the entry point the dispatcher calls when the
// `phase2_https_get` build tag is set. Sequence DHCP → DNS → TLS →
// HTTPS GET, with per-stage status prints so the live runner can
// grep on individual phases.
func runHTTPSGetProbe() {
	println("phase2-https: M6 — pure-Go DHCP+DNS+TLS+HTTPS over ministack/virtio-net")

	pciIO := locateVirtioNetForHTTPS()
	if pciIO == 0 {
		println("phase2-https: no modern virtio-net device found — M6 cannot run")
		println("phase2-https: HTTPS-GET FAIL: no virtio-net device")
		return
	}

	println("phase2-https: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-https: OpenVirtioNet FAILED:", err.Error())
		println("phase2-https: HTTPS-GET FAIL:", err.Error())
		return
	}
	println("phase2-https: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	println("phase2-https: RX path active; sending DHCP DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-https: HTTPS-GET FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-https: lease acquired")
	println("phase2-https:   IP      =", lease.IP.String())
	println("phase2-https:   Mask    =", lease.Mask.String())
	if lease.Gateway != nil {
		println("phase2-https:   Gateway =", lease.Gateway.String())
	}
	if len(lease.DNS) == 0 {
		println("phase2-https: HTTPS-GET FAIL: DHCP returned no DNS server")
		return
	}
	for i, d := range lease.DNS {
		switch i {
		case 0:
			println("phase2-https:   DNS     =", d.String())
		default:
			println("phase2-https:           ", d.String())
		}
	}

	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-https: SetIPv4Address FAILED:", err.Error())
		println("phase2-https: HTTPS-GET FAIL:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-https: SetDefaultGateway FAILED:", err.Error())
			println("phase2-https: HTTPS-GET FAIL:", err.Error())
			return
		}
	}

	// Warm the embedded root pool BEFORE the DNS/TLS roundtrip so a
	// PEM-parse regression surfaces as a clear "no roots" log line
	// instead of as an opaque cert-verification failure.
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-https: HTTPS-GET FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-https: embedded roots =", ministack.EmbeddedRootCount())

	// --- DNS resolution -----------------------------------------
	target := "example.com"
	println("phase2-https: resolving", target, "via DNS server", lease.DNS[0].String())
	ip, err := s.ResolveA(target, lease.DNS[0], 5*time.Second)
	if err != nil {
		println("phase2-https: HTTPS-GET FAIL: DNS:", err.Error())
		return
	}
	println("phase2-https: resolved", target, "=>", ip.String())

	// Pre-warm the gateway ARP entry. The HTTPS target is off-link,
	// so the first TLS segment needs the gateway's MAC. Same pattern
	// as M5.
	if lease.Gateway != nil {
		if _, perr := s.PingOnce(lease.Gateway, []byte("M6"), 3*time.Second); perr != nil {
			println("phase2-https: gateway pre-ping FAILED:", perr.Error())
		} else {
			println("phase2-https: gateway pre-ping OK")
		}
	}

	// --- HTTPS GET --------------------------------------------
	url := "https://" + target + "/"
	println("phase2-https: GET", url)

	resp, err := s.HTTPSGet(url, ministack.HTTPGetOptions{
		DNSServer:      lease.DNS[0],
		DialTimeout:    15 * time.Second, // TLS handshake adds 1-2 RTT on top of TCP
		RequestTimeout: 20 * time.Second,
	})
	if err != nil {
		println("phase2-https: HTTPS-GET FAIL:", err.Error())
		return
	}

	println("phase2-https: status   =", resp.StatusLine)
	println("phase2-https: code     =", resp.StatusCode)
	println("phase2-https: bytes    =", len(resp.Body))
	if cl, ok := resp.Headers["content-length"]; ok {
		println("phase2-https: cl-hdr   =", cl)
	}
	if ct, ok := resp.Headers["content-type"]; ok {
		println("phase2-https: ct-hdr   =", ct)
	}
	preview := resp.Body
	if len(preview) > 64 {
		preview = preview[:64]
	}
	println("phase2-https: preview  =", string(preview))
	println("phase2-https: HTTPS-GET OK")
}

// locateVirtioNetForHTTPS walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first 1AF4:1041 (modern virtio-net). Returns 0 if
// none found. Same pattern as M2/M3/M4/M5.
func locateVirtioNetForHTTPS() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-https: LocateHandleBuffer FAILED:", err.Error())
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
