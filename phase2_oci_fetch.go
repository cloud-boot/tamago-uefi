// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M7 probe — gated on `-tags phase2_oci_fetch`.
//
// Builds on M6 (HTTPS GET over ministack) by layering the pure-Go
// OCI Distribution v2 client on top. The probe:
//
//   1. Locates the first modern virtio-net PCI device and brings it up.
//   2. Wraps the device in a ministack Link + Stack and starts RX.
//   3. Acquires a DHCPv4 lease (reusing M4's DHCP4Acquire path).
//   4. Applies the lease to the Stack (SetIPv4Address +
//      SetDefaultGateway).
//   5. Warms the embedded root CA pool (reusing M6's NewRootCAs).
//   6. Issues the full OCI walk against a tagged public artifact:
//      - GET /v2/<repo>/manifests/<ref> → 401 with Bearer challenge.
//      - GET realm?service=...&scope=...  → anonymous bearer token.
//      - GET /v2/<repo>/manifests/<ref>  → multi-arch index.
//      - PickPlatform(linux, runtime.GOARCH) → manifest digest.
//      - GET /v2/<repo>/manifests/<digest> → image manifest.
//      - GET /v2/<repo>/blobs/<config-digest> → config blob.
//      - GET /v2/<repo>/blobs/<small-layer-digest> → 1 layer
//        (size-filtered to stay under ministack's 1 MiB response cap;
//        large layer fetch is M7.1 streaming follow-up).
//   7. Prints index/manifest digests, layer descriptors, layer
//      previews, and the verification verdict.
//   8. Returns (halt is the dispatcher's job).
//
// Target image (M7 smoke test):
//
//   ghcr.io/linuxcontainers/alpine:latest
//
// Rationale: anonymous-pull, multi-arch (covers amd64/arm64/loong64/
// riscv64), HTTP/1.1 compatible on ghcr.io, blobs hosted directly on
// ghcr.io (no S3 redirect for the small layer + config). Total fetched
// data under 20 KiB for the M7 smoke path.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_oci_fetch \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `oci:efi:<arch>` for the per-arch wiring.)

//go:build phase2_oci_fetch && tamago

package main

import (
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// ociM7TargetRef is the public OCI artifact the M7 smoke test fetches.
// linuxcontainers/alpine is multi-arch (amd64 / arm64 / loong64 /
// riscv64 all present in the index), anonymous-pull, and serves
// directly on ghcr.io for the config + smaller layer (no S3 redirect).
// The 3.6 MiB layer is intentionally skipped (over our 1 MiB response
// cap; streaming fetch is the M7.1 follow-up).
const ociM7TargetRef = "ghcr.io/linuxcontainers/alpine:latest"

// ociM7MaxBlobBytes caps which layers we attempt to fetch. Layers
// bigger than this trip ministack's 1 MiB HTTP response cap and
// surface as ErrHTTPResponseTooBig. Keep this comfortably under
// HTTPMaxResponseBytes so the body fits even with headers on top.
const ociM7MaxBlobBytes = 800 * 1024 // 800 KiB

// runOCIFetchProbe is the entry point the dispatcher calls when the
// `phase2_oci_fetch` build tag is set.
func runOCIFetchProbe() {
	println("phase2-oci: M7 — pure-Go OCI registry client over ministack/HTTPS")
	println("phase2-oci: target =", ociM7TargetRef)
	println("phase2-oci: arch   =", runtime.GOARCH)

	pciIO := locateVirtioNetForOCI()
	if pciIO == 0 {
		println("phase2-oci: no modern virtio-net device found — M7 cannot run")
		println("phase2-oci: OCI-FETCH FAIL: no virtio-net device")
		return
	}

	println("phase2-oci: bringing up virtio-net device")
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci: OpenVirtioNet FAILED:", err.Error())
		println("phase2-oci: OCI-FETCH FAIL:", err.Error())
		return
	}
	println("phase2-oci: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	println("phase2-oci: RX path active; sending DHCP DISCOVER")

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci: OCI-FETCH FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oci: lease acquired")
	println("phase2-oci:   IP      =", lease.IP.String())
	println("phase2-oci:   Mask    =", lease.Mask.String())
	if lease.Gateway != nil {
		println("phase2-oci:   Gateway =", lease.Gateway.String())
	}
	if len(lease.DNS) == 0 {
		println("phase2-oci: OCI-FETCH FAIL: DHCP returned no DNS server")
		return
	}
	for i, d := range lease.DNS {
		switch i {
		case 0:
			println("phase2-oci:   DNS     =", d.String())
		default:
			println("phase2-oci:           ", d.String())
		}
	}

	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oci: SetIPv4Address FAILED:", err.Error())
		println("phase2-oci: OCI-FETCH FAIL:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oci: SetDefaultGateway FAILED:", err.Error())
			println("phase2-oci: OCI-FETCH FAIL:", err.Error())
			return
		}
	}

	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci: OCI-FETCH FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oci: embedded roots =", ministack.EmbeddedRootCount())

	// Pre-warm the gateway ARP entry. The first TLS handshake to a
	// remote host needs the gateway's MAC. Same pattern as M5/M6.
	if lease.Gateway != nil {
		if _, perr := s.PingOnce(lease.Gateway, []byte("M7"), 3*time.Second); perr != nil {
			println("phase2-oci: gateway pre-ping FAILED:", perr.Error())
		} else {
			println("phase2-oci: gateway pre-ping OK")
		}
	}

	// --- OCI walk -------------------------------------------------
	ref, err := oci.ParseRef(ociM7TargetRef)
	if err != nil {
		println("phase2-oci: OCI-FETCH FAIL: ParseRef:", err.Error())
		return
	}
	println("phase2-oci: parsed ref scheme=" + ref.Scheme + " host=" + ref.Host + " repo=" + ref.Repo + " reference=" + ref.Reference)

	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 30 * time.Second

	// Mark layers we want to fetch (small ones) — the 1 MiB cap
	// applies to the whole HTTP response, headers included; the
	// fetch fails closed on bigger blobs.
	var totalLayerBytes int64
	keepSmall := func(d oci.Descriptor) bool {
		keep := d.Size > 0 && d.Size <= ociM7MaxBlobBytes
		println("phase2-oci: layer descriptor: digest=" + d.Digest)
		if keep {
			println("phase2-oci:   size  =", int(d.Size), "(KEEP)")
		} else {
			println("phase2-oci:   size  =", int(d.Size), "(SKIP — over 800 KiB cap)")
		}
		if keep {
			totalLayerBytes += d.Size
		}
		return keep
	}

	// linuxcontainers/alpine ships index entries for amd64 + arm64
	// + a few others but NOT loong64 or riscv64. For the M7 smoke
	// test (proving the OCI client works end-to-end on every
	// supported arch), fall back to amd64 on tamago arches the
	// registry image doesn't cover. When a real M8 boot artifact
	// ships with native loong64 / riscv64 manifests this fallback
	// will go away.
	probeArch := runtime.GOARCH
	switch probeArch {
	case "loong64", "riscv64":
		println("phase2-oci: target image has no", probeArch, "manifest — smoke-falling-back to amd64")
		probeArch = "amd64"
	}

	println("phase2-oci: starting OCI walk against", ref.Host, "(probe-arch="+probeArch+")")
	art, err := oci.FetchArtifact(reg, oci.FetchOptions{
		Arch:        probeArch,
		LayerFilter: keepSmall,
	})
	if err != nil {
		println("phase2-oci: OCI-FETCH FAIL:", err.Error())
		return
	}

	if art.IndexRaw != nil {
		println("phase2-oci: index digest    =", art.IndexDigest)
		println("phase2-oci: index size      =", len(art.IndexRaw))
	} else {
		println("phase2-oci: no index — direct image manifest")
	}
	println("phase2-oci: manifest digest =", art.ManifestDigest)
	println("phase2-oci: manifest size   =", len(art.ManifestRaw))
	println("phase2-oci: config digest   =", art.Manifest.Config.Digest)
	println("phase2-oci: config size     =", len(art.ConfigBlob))
	println("phase2-oci: layers in manifest =", len(art.Manifest.Layers))
	fetchedLayers := 0
	for i, layer := range art.Manifest.Layers {
		body := art.LayerBlobs[i]
		if body == nil {
			continue
		}
		fetchedLayers++
		println("phase2-oci: layer[", i, "] digest =", layer.Digest)
		println("phase2-oci: layer[", i, "] bytes  =", len(body))
		printHexPreview("phase2-oci: layer["+itoa(i)+"] hex0..31 =", body, 32)
	}
	println("phase2-oci: layers fetched  =", fetchedLayers, "/", len(art.Manifest.Layers))
	println("phase2-oci: total layer bytes =", int(totalLayerBytes))
	println("phase2-oci: digest verification OK (manifest, config, and all fetched layers verified by FetchArtifact)")
	println("phase2-oci: OCI-FETCH OK")
}

// itoa is a tiny base-10 unsigned int → string helper (no
// strconv import to keep this file's deps narrow when iterating).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// printHexPreview prints a short hex dump of up to n bytes of body
// under the given prefix line. Same shape as the phase2_hex helper but
// kept inline here so we don't drag yet-another build-tag mismatch
// risk into the dispatcher composition.
func printHexPreview(prefix string, body []byte, n int) {
	const hex = "0123456789abcdef"
	if len(body) < n {
		n = len(body)
	}
	out := make([]byte, 0, n*3+2)
	for i := 0; i < n; i++ {
		if i > 0 {
			out = append(out, ' ')
		}
		out = append(out, hex[body[i]>>4], hex[body[i]&0x0F])
	}
	println(prefix, string(out))
}

// locateVirtioNetForOCI walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first 1AF4:1041 (modern virtio-net). Returns 0 if
// none found. Same pattern as M2/M3/M4/M5/M6.
func locateVirtioNetForOCI() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-oci: LocateHandleBuffer FAILED:", err.Error())
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
