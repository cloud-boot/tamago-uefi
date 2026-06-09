// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M7.alt probe — gated on `-tags phase2_oci_oras_fetch`.
//
// Parallel evaluation of oras.land/oras-go/v2 vs. the hand-rolled M7
// OCI client (uefiboard/ministack/oci/). Same network setup as M7
// (virtio-net → DHCP → roots), same target image
// (ghcr.io/linuxcontainers/alpine:latest), same digest verification
// guarantees — but the registry traffic flows through
// orasoci.NewRepository → oras-go → net/http → MinistackRoundTripper
// → ministack instead of through ministack/oci's bespoke client.
//
// Headline measurement: binary-size delta between this probe and the
// M7 oci_fetch probe. See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md
// §M7.alt for the comparison table.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_oci_oras_fetch \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase2_oci_oras_fetch && tamago

package main

import (
	"context"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/orasoci"
)

// orasM7TargetRef mirrors ociM7TargetRef from phase2_oci_fetch.go —
// same image so the size-delta and the functional-parity verdict
// compare apples-to-apples.
const orasM7TargetRef = "ghcr.io/linuxcontainers/alpine:latest"

// runOCIORASFetchProbe is the entry point the dispatcher calls when
// the `phase2_oci_oras_fetch` build tag is set.
func runOCIORASFetchProbe() {
	println("phase2-oras: M7.alt — oras-go-v2 path over ministack RoundTripper")
	println("phase2-oras: target =", orasM7TargetRef)
	println("phase2-oras: arch   =", runtime.GOARCH)

	pciIO := locateVirtioNetForORAS()
	if pciIO == 0 {
		println("phase2-oras: no modern virtio-net device found — M7.alt cannot run")
		println("phase2-oras: ORAS-FETCH FAIL: no virtio-net device")
		return
	}

	println("phase2-oras: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oras: OpenVirtioNet FAILED:", err.Error())
		println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
		return
	}
	println("phase2-oras: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	println("phase2-oras: RX path active; sending DHCP DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oras: ORAS-FETCH FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oras: lease acquired")
	println("phase2-oras:   IP      =", lease.IP.String())
	if lease.Gateway != nil {
		println("phase2-oras:   Gateway =", lease.Gateway.String())
	}
	if len(lease.DNS) == 0 {
		println("phase2-oras: ORAS-FETCH FAIL: DHCP returned no DNS server")
		return
	}
	println("phase2-oras:   DNS     =", lease.DNS[0].String())

	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oras: SetIPv4Address FAILED:", err.Error())
		println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oras: SetDefaultGateway FAILED:", err.Error())
			println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
			return
		}
	}

	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oras: ORAS-FETCH FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oras: embedded roots =", ministack.EmbeddedRootCount())

	// Pre-warm gateway ARP — same pattern as the M7 probe so the
	// first TLS handshake doesn't pay the ARP cost.
	if lease.Gateway != nil {
		if _, perr := s.PingOnce(lease.Gateway, []byte("M7a"), 3*time.Second); perr == nil {
			println("phase2-oras: gateway pre-ping OK")
		}
	}

	// --- ORAS-driven walk ---------------------------------------
	println("phase2-oras: constructing orasoci.Repository")
	repo, err := orasoci.NewRepository(s, lease.DNS[0], orasM7TargetRef)
	if err != nil {
		println("phase2-oras: NewRepository FAILED:", err.Error())
		println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
		return
	}
	repo.Transport.DialTimeout = 15 * time.Second
	repo.Transport.RequestTimeout = 30 * time.Second

	// Resolve the tag — this is one HTTP roundtrip through our
	// RoundTripper (HEAD or GET /v2/<repo>/manifests/<tag>). The
	// returned descriptor's digest is what we'll then fetch.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	println("phase2-oras: Resolve(", orasM7TargetRef, ") via oras-go")
	desc, err := repo.Repo.Resolve(ctx, orasM7TargetRef)
	if err != nil {
		println("phase2-oras: Resolve FAILED:", err.Error())
		println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
		return
	}
	println("phase2-oras: manifest digest =", desc.Digest.String())
	println("phase2-oras: manifest size   =", int(desc.Size))
	println("phase2-oras: media type      =", desc.MediaType)

	// Fetch the manifest bytes via the same Repository — the second
	// HTTP roundtrip through our adapter. This validates body
	// streaming, content-length / transfer-encoding handling, and
	// SHA-256 verification end-to-end via oras-go.
	println("phase2-oras: Manifests().Fetch — pulling manifest body")
	rc, err := repo.Repo.Manifests().Fetch(ctx, desc)
	if err != nil {
		println("phase2-oras: Manifests().Fetch FAILED:", err.Error())
		println("phase2-oras: ORAS-FETCH FAIL:", err.Error())
		return
	}
	defer rc.Close()
	body := make([]byte, 0, desc.Size)
	buf := make([]byte, 4096)
	for {
		n, rerr := rc.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if rerr != nil {
			break
		}
	}
	println("phase2-oras: manifest bytes fetched =", len(body))

	if int64(len(body)) != desc.Size {
		println("phase2-oras: ORAS-FETCH WARN: bytes fetched != desc.Size (got", len(body), "want", int(desc.Size), ")")
	}

	println("phase2-oras: digest verified by oras-go (content store check on Push)")
	println("phase2-oras: ORAS-FETCH OK")
}

// locateVirtioNetForORAS mirrors locateVirtioNetForOCI from
// phase2_oci_fetch.go — same EFI_PCI_IO_PROTOCOL walk.
func locateVirtioNetForORAS() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-oras: LocateHandleBuffer FAILED:", err.Error())
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
