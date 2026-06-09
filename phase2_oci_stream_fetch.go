// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M7.1a probe — gated on `-tags phase2_oci_stream_fetch`.
//
// Streaming sibling of the M7 OCI fetch probe (phase2_oci_fetch.go).
// Where the M7 probe walks the registry but skips any layer over the
// 1 MiB HTTPMaxResponseBytes cap (the alpine arm64 layer is ~3.6 MiB
// — well over the cap), this probe lifts that cap by using the new
// `ministack.HTTPSGetStream` + `oci.FetchBlobStream` path:
//
//   - bytes flow through the TLS conn into a sha256.New() hasher and
//     directly into io.Discard (we don't need the bytes; we want to
//     prove the streaming pipeline + digest verify works on the
//     >1 MiB blob).
//   - on EOF the computed SHA-256 is compared against the manifest's
//     advertised digest; mismatch fails the probe.
//
// Target image:  ghcr.io/linuxcontainers/alpine:latest
//   linux/arm64 layer ~3.6 MiB; on amd64 a similar size; loong64 +
//   riscv64 are not present in the index, so we smoke-fall-back to
//   amd64 the same way the M7 probe does.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_oci_stream_fetch \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `ocistream:efi:<arch>` for the per-arch wiring.)

//go:build phase2_oci_stream_fetch && tamago

package main

import (
	"io"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// ociStreamTargetRef is the public OCI artifact the M7.1a streaming
// probe fetches. Same anchor as the M7 buffered probe — the difference
// is the M7.1a probe streams the per-arch layer (which is >1 MiB on
// most arches) through ministack instead of skipping it.
const ociStreamTargetRef = "ghcr.io/linuxcontainers/alpine:latest"

// runOCIStreamFetchProbe is the entry point the dispatcher calls when
// the `phase2_oci_stream_fetch` build tag is set.
func runOCIStreamFetchProbe() {
	println("phase2-oci-stream: M7.1a — streaming OCI blob fetch over ministack/HTTPS")
	println("phase2-oci-stream: target =", ociStreamTargetRef)
	println("phase2-oci-stream: arch   =", runtime.GOARCH)

	pciIO := locateVirtioNetForOCIStream()
	if pciIO == 0 {
		println("phase2-oci-stream: no modern virtio-net device found — M7.1a cannot run")
		println("phase2-oci-stream: OCI-STREAM FAIL: no virtio-net device")
		return
	}

	println("phase2-oci-stream: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci-stream: OpenVirtioNet FAILED:", err.Error())
		println("phase2-oci-stream: OCI-STREAM FAIL:", err.Error())
		return
	}
	println("phase2-oci-stream: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	println("phase2-oci-stream: RX path active; sending DHCP DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oci-stream: lease acquired")
	println("phase2-oci-stream:   IP      =", lease.IP.String())
	println("phase2-oci-stream:   Mask    =", lease.Mask.String())
	if lease.Gateway != nil {
		println("phase2-oci-stream:   Gateway =", lease.Gateway.String())
	}
	if len(lease.DNS) == 0 {
		println("phase2-oci-stream: OCI-STREAM FAIL: DHCP returned no DNS server")
		return
	}
	for i, d := range lease.DNS {
		switch i {
		case 0:
			println("phase2-oci-stream:   DNS     =", d.String())
		default:
			println("phase2-oci-stream:           ", d.String())
		}
	}

	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oci-stream: SetIPv4Address FAILED:", err.Error())
		println("phase2-oci-stream: OCI-STREAM FAIL:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oci-stream: SetDefaultGateway FAILED:", err.Error())
			println("phase2-oci-stream: OCI-STREAM FAIL:", err.Error())
			return
		}
	}

	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oci-stream: embedded roots =", ministack.EmbeddedRootCount())

	// Pre-warm the gateway ARP entry — same as M7.
	if lease.Gateway != nil {
		if _, perr := s.PingOnce(lease.Gateway, []byte("M7.1a"), 3*time.Second); perr != nil {
			println("phase2-oci-stream: gateway pre-ping FAILED:", perr.Error())
		} else {
			println("phase2-oci-stream: gateway pre-ping OK")
		}
	}

	// --- OCI walk -------------------------------------------------
	ref, err := oci.ParseRef(ociStreamTargetRef)
	if err != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: ParseRef:", err.Error())
		return
	}
	println("phase2-oci-stream: parsed ref scheme=" + ref.Scheme + " host=" + ref.Host + " repo=" + ref.Repo + " reference=" + ref.Reference)

	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 60 * time.Second // streaming a 3.6 MiB layer over user-mode netw can take 30+ s

	// linuxcontainers/alpine ships index entries for amd64 + arm64
	// (+ a few others) but NOT loong64 or riscv64. Mirror the M7
	// probe's smoke-fallback strategy so this probe is exercisable
	// on every arch we still build for.
	probeArch := runtime.GOARCH
	switch probeArch {
	case "loong64", "riscv64":
		println("phase2-oci-stream: target image has no", probeArch, "manifest — smoke-falling-back to amd64")
		probeArch = "amd64"
	}

	if err := reg.Authenticate(); err != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: FetchManifestRaw(latest):", err.Error())
		return
	}
	println("phase2-oci-stream: index size =", len(rawIndex))

	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-oci-stream: OCI-STREAM FAIL: ParseIndex:", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", probeArch)
		if perr != nil {
			println("phase2-oci-stream: OCI-STREAM FAIL: PickPlatform:", perr.Error())
			return
		}
		println("phase2-oci-stream: picked manifest digest =", picked.Digest)
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-oci-stream: OCI-STREAM FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}
	println("phase2-oci-stream: manifest size =", len(rawManifest))

	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: ParseManifest:", err.Error())
		return
	}
	println("phase2-oci-stream: layers in manifest =", len(m.Layers))
	if len(m.Layers) == 0 {
		println("phase2-oci-stream: OCI-STREAM FAIL: manifest has zero layers")
		return
	}

	// Stream the BIGGEST layer (most representative of the M7.1a
	// unlock: pulling a multi-MiB blob that the buffered M7 path
	// can't, capped at 1 MiB). For alpine:latest linux/arm64 the
	// big one is the 4 MiB root tar.gz (index 0); the 7.5 KiB
	// trailing layer is the busybox patch.
	target := m.Layers[0]
	for _, l := range m.Layers {
		if l.Size > target.Size {
			target = l
		}
	}
	println("phase2-oci-stream: streaming layer digest =", target.Digest)
	println("phase2-oci-stream: streaming layer size   =", int(target.Size))

	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(target, io.Discard)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase2-oci-stream: OCI-STREAM FAIL: FetchBlobStream:", ferr.Error())
		println("phase2-oci-stream: bytes-written-before-error =", int(n))
		return
	}
	println("phase2-oci-stream: fetched", int(n), "bytes; SHA-256 OK")
	println("phase2-oci-stream: elapsed (ms) =", int(elapsedMS))
	println("phase2-oci-stream: OCI-STREAM OK")
}

// locateVirtioNetForOCIStream walks the EFI_PCI_IO_PROTOCOL handle
// space looking for the first 1AF4:1041 (modern virtio-net). Returns
// 0 if none found. Same shape as the M7 helper but kept private here
// so the build tags don't accidentally double-define it.
func locateVirtioNetForOCIStream() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-oci-stream: LocateHandleBuffer FAILED:", err.Error())
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
