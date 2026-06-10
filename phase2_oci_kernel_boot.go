// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M8.1-minimal probe — gated on `-tags phase2_oci_kernel_boot`.
//
// Closes the M0..M8 Path D roadmap by composing the M7.1a streaming
// OCI fetcher with the M8.0 LoadImage+StartImage chain-boot mechanism:
//
//   stream-OCI(blob)  ->  SHA-256 verify  ->  gBS->LoadImage  ->  gBS->StartImage
//
// MINIMAL scope (per the M8.1 brief revision 2026-06-09):
//
//   - The "kernel" is whatever EFI/PE32+ payload the configured OCI
//     ref serves. The minimum-viable demonstration is our own
//     BOOT*-CHAINED.EFI bytes (which prints a one-line banner on
//     entry and returns cleanly via gBS->Exit). Real upstream Linux
//     kernel + cmdline + initrd + full userspace boot are explicitly
//     OUT OF SCOPE — those land in M8.2 once we have a public OCI
//     ref for a small-enough EFI-stub kernel.
//
//   - The probe runs in one of two MODES:
//
//     * MODE A — REAL REGISTRY (when `kernelBootTargetRef` is set):
//       brings up virtio-net + DHCP + ministack roots, walks the
//       configured ref, streams the bootable layer through ministack,
//       SHA-256-verifies, then hands the bytes to LoadImage+StartImage.
//       Identical wiring to M7.1a + M8.0 stitched end-to-end.
//
//     * MODE B — SELF-TEST (default in this build):
//       constructs an in-process oci.Transport that serves the
//       embedded chained EFI bytes from internal/embed_chained as
//       if they came from a real registry blob endpoint. Exercises
//       `oci.Registry.FetchBlobStream` (proving the streaming +
//       digest-verification path), then hands the verified bytes
//       to LoadImage+StartImage exactly the way MODE A would.
//
//     The current default is MODE B because we do not yet ship a
//     publicly-published BOOT*-CHAINED.EFI as an OCI artifact (the
//     short-term GHCR PAT lacks `write:packages`). MODE A is wired
//     and tested via the in-process Transport — flipping it to a
//     real registry is a one-line constant change.
//
// What this proves (the M8.1-minimal acceptance gate):
//
//   1. `oci.FetchBlobStream` correctly streams a multi-MiB blob into
//      a caller-provided buffer with SHA-256 verification.
//   2. The bytes that come out of OCI streaming can be handed
//      verbatim to `uefiboard.LoadImage` and the firmware accepts
//      them (PE32+ parse + relocations succeed).
//   3. `uefiboard.StartImage` transfers control to the loaded image
//      and returns cleanly when the child invokes gBS->Exit.
//
// What is OUT OF SCOPE for M8.1-minimal:
//
//   - CMDLINE plumbing (Linux EFI-stub reads cmdline from
//     LoadedImageProtocol.LoadOptions — the M8.2 follow-up wires it).
//   - initrd plumbing (M8.2 will publish EFI_LOAD_FILE2_PROTOCOL
//     under LINUX_EFI_INITRD_MEDIA_GUID).
//   - The explicit handoff_<arch>.s shim. The brief revision
//     explicitly notes this is NOT needed for M8.1-minimal: the
//     Linux EFI-stub does its own EBS handoff once StartImage
//     enters it, and our chained payload returns via gBS->Exit.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_oci_kernel_boot \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `kernelboot:efi:<arch>` for the per-arch wiring.)

//go:build phase2_oci_kernel_boot && tamago

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"net"
	"runtime"
	"time"
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/internal/embed_chained"
	"github.com/cloud-boot/tamago-uefi/internal/embed_initramfs"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// kernelBootTargetRef / kernelBootCmdline / kernelBootInitrdRef /
// kernelBootUseEmbeddedInitrd are now defined per-arch in
// kernelboot_<arch>.go (M8.3 per-arch split, 2026-06-10).
//
// Each per-arch file sets the OCI ref + cmdline appropriate for its
// architecture. Arches without a validated public EFI-stub kernel OCI
// artifact (riscv64, loong64, amd64) ship the framework with empty
// constants so the runtime path collapses to MODE B (self-test)
// while keeping the wiring identical.
//
// Documentation:
//
//   - kernelBootTargetRef: OCI artifact for MODE A / MODE C. Empty =
//     MODE B (self-test against in-process Transport). The siderolabs
//     EFI-stub kernel artifact on ghcr.io is the validated arm64 ref;
//     anonymous bearer-token pull; multi-arch index resolves to
//     per-arch manifests; first layer is a tar.gz containing
//     boot/vmlinuz (PE32+ with MZ + 'ARMd' magic at offset 0x38 on
//     arm64).
//
//   - kernelBootCmdline: Linux kernel command line installed via
//     uefiboard.SetLoadOptions before StartImage. Empty = MODE A
//     (no cmdline). Typical values:
//       "console=ttyAMA0,115200 earlyprintk=ttyAMA0,115200"  (arm64 virt)
//       "console=ttyS0,115200 earlyprintk=ttyS0,115200"      (amd64 OVMF)
//       "console=hvc0 earlycon=sbi"                          (riscv64 virt)
//       "console=ttyS0,115200"                               (loong64 virt)
//     The Linux EFI-stub reads it from LoadedImageProtocol.LoadOptions
//     (UEFI 2.10 §9.2 / Documentation/admin-guide/efi-stub.rst).
//
//   - kernelBootInitrdRef: OCI ref to stream as the initrd. Empty =
//     fall back to embedded fallback or skip publication entirely.
//     M8.4 status: empty on all arches (no publicly-pullable
//     standalone initramfs OCI ref discovered).
//
//   - kernelBootUseEmbeddedInitrd: when true and kernelBootInitrdRef
//     is empty, publishes the embedded 260-byte cpio.gz from
//     internal/embed_initramfs as the initrd.
//
// Reference: cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.3/§M8.4.

// kernelBootSelfTestRef is the synthetic ref the MODE B path uses to
// stand up its in-process Registry. The host string is intentionally
// not a real registry — the in-process Transport short-circuits
// every request, so resolving this would fail closed if the test
// ever escaped its sandbox.
const kernelBootSelfTestRef = "https://localhost.m81-selftest.invalid/cloud-boot/chained:latest"

// runOCIKernelBootProbe is the entry point the dispatcher calls when
// the `phase2_oci_kernel_boot` build tag is set.
//
// Three-way mode dispatch (M8.2):
//
//   - MODE B (default): kernelBootTargetRef == "" → self-test against
//     an in-process oci.Transport serving the embedded chained EFI
//     bytes. Proves the streaming + LoadImage + StartImage chain;
//     no cmdline / no initrd path.
//
//   - MODE A: kernelBootTargetRef != "" && kernelBootCmdline == ""
//     → real-registry streaming + LoadImage + StartImage. Same shape
//     as M8.1 minimal MODE A.
//
//   - MODE C: kernelBootTargetRef != "" && kernelBootCmdline != ""
//     → real-registry streaming + (optional) initrd publish +
//     SetLoadOptions + LoadImage + StartImage. The Linux-kernel-
//     specific path; the kernel EFI-stub reads cmdline from
//     LoadedImageProtocol.LoadOptions and initrd via
//     EFI_LOAD_FILE2_PROTOCOL @ LINUX_EFI_INITRD_MEDIA_GUID. The
//     initrd protocol is M8.2-PARTIAL (framework only); see
//     uefiboard/initrd_protocol_tamago.go.
func runOCIKernelBootProbe() {
	println("phase2-oci-kernel-boot: M8.2 -- streaming OCI fetch + LoadImage + StartImage + Linux kernel helpers")
	println("phase2-oci-kernel-boot: arch =", runtime.GOARCH)

	if kernelBootTargetRef == "" {
		println("phase2-oci-kernel-boot: MODE = self-test (no kernelBootTargetRef configured)")
		runKernelBootSelfTest()
		return
	}

	if kernelBootCmdline == "" {
		println("phase2-oci-kernel-boot: MODE = A (real-registry, no cmdline/initrd)")
		println("phase2-oci-kernel-boot: target =", kernelBootTargetRef)
		runKernelBootRealRegistry()
		return
	}

	println("phase2-oci-kernel-boot: MODE = C (real-registry + Linux kernel helpers)")
	println("phase2-oci-kernel-boot: target =", kernelBootTargetRef)
	println("phase2-oci-kernel-boot: cmdline =", kernelBootCmdline)
	if kernelBootInitrdRef != "" {
		println("phase2-oci-kernel-boot: initrd =", kernelBootInitrdRef, "(OCI)")
	} else if kernelBootUseEmbeddedInitrd {
		println("phase2-oci-kernel-boot: initrd = (embedded minimal cpio.gz)")
	} else {
		println("phase2-oci-kernel-boot: initrd = (none)")
	}
	runKernelBootLinuxKernel()
}

// runKernelBootSelfTest exercises the OCI streaming + LoadImage +
// StartImage path end-to-end against an in-process oci.Transport
// that serves the embedded chained EFI bytes as a single blob.
// No network is needed.
func runKernelBootSelfTest() {
	payload, err := embed_chained.Decompress()
	if err != nil {
		println("phase2-oci-kernel-boot: SELFTEST FAIL: embed Decompress:", err.Error())
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: embedded EFI payload size =", len(payload))
	if len(payload) < 2 || payload[0] != 'M' || payload[1] != 'Z' {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: embedded payload is not PE32+ (no MZ)")
		return
	}

	// Build a synthetic descriptor matching the embedded payload —
	// FetchBlobStream verifies the SHA-256 of the streamed bytes
	// against this digest, so even MODE B exercises the verification
	// path (not just the streaming pipeline).
	desc := oci.Descriptor{
		MediaType: "application/vnd.cloud-boot.efi.v1",
		Digest:    oci.DigestFromBytes(payload),
		Size:      int64(len(payload)),
	}
	println("phase2-oci-kernel-boot: synthetic descriptor digest =", desc.Digest)
	println("phase2-oci-kernel-boot: synthetic descriptor size   =", int(desc.Size))

	ref, err := oci.ParseRef(kernelBootSelfTestRef)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: parsed ref host=" + ref.Host + " repo=" + ref.Repo)

	mt := newKernelBootSelfTestTransport(ref, desc.Digest, payload)
	reg := oci.NewRegistryWithTransport(mt, nil, ref)

	println("phase2-oci-kernel-boot: streaming blob via in-process Transport (MODE B)")
	var buf bytes.Buffer
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(desc, &buf)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchBlobStream:", ferr.Error())
		println("phase2-oci-kernel-boot: bytes-written-before-error =", int(n))
		return
	}
	println("phase2-oci-kernel-boot: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase2-oci-kernel-boot: streaming elapsed (ms) =", int(elapsedMS))

	bootStreamedPayload(buf.Bytes())
}

// runKernelBootRealRegistry walks the configured kernelBootTargetRef
// through the full M7/M7.1a network path, streams the picked manifest's
// first layer, and hands the verified bytes to LoadImage+StartImage.
// Disabled in this build (kernelBootTargetRef == ""). Kept as a
// placeholder so the symbol exists and flipping MODE A to "on" is a
// one-line constant change.
func runKernelBootRealRegistry() {
	pciIO := locateVirtioNetForKernelBoot()
	if pciIO == 0 {
		println("phase2-oci-kernel-boot: no modern virtio-net device found")
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: lease acquired")
	println("phase2-oci-kernel-boot:   IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oci-kernel-boot: embedded roots =", ministack.EmbeddedRootCount())

	ref, err := oci.ParseRef(kernelBootTargetRef)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 120 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchManifestRaw(index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseIndex:", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: PickPlatform:", perr.Error())
			return
		}
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}

	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	println("phase2-oci-kernel-boot: streaming layer digest =", target.Digest)
	println("phase2-oci-kernel-boot: streaming layer size   =", int(target.Size))

	var buf bytes.Buffer
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(target, &buf)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchBlobStream:", ferr.Error())
		println("phase2-oci-kernel-boot: bytes-written-before-error =", int(n))
		return
	}
	println("phase2-oci-kernel-boot: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase2-oci-kernel-boot: streaming elapsed (ms) =", int(elapsedMS))

	bootStreamedPayload(buf.Bytes())
}

// bootStreamedPayload runs the M8.0 LoadImage+StartImage sequence
// against payload bytes that came out of the OCI streaming path
// (either MODE A's real-registry fetch or MODE B's in-process
// transport). Shared between the two modes so the chain-boot leg is
// proven identically.
func bootStreamedPayload(payload []byte) {
	if len(payload) < 2 || payload[0] != 'M' || payload[1] != 'Z' {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: streamed payload[0:2] is not 'MZ' (not a PE32+)")
		return
	}
	println("phase2-oci-kernel-boot: streamed payload PE header OK (MZ)")

	handle, err := uefiboard.LoadImage(payload)
	if err != nil {
		println("phase2-oci-kernel-boot: LoadImage FAILED:", err.Error())
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: LoadImage OK, handle =", hexUintptrKernelBoot(handle))

	println("phase2-oci-kernel-boot: StartImage entering loaded image")
	status, sErr := uefiboard.StartImage(handle)
	println("phase2-oci-kernel-boot: StartImage returned exit_status=" + hexUintptrKernelBoot(status))
	if sErr != nil {
		println("phase2-oci-kernel-boot: loaded image reported non-success:", sErr.Error())
	}

	// Same UnloadImage policy as M8.0: skip on clean gBS->Exit (the
	// firmware has already cleaned up), only call on non-zero status
	// where the firmware may have kept the image around for diagnostics.
	if status != 0 {
		if uerr := uefiboard.UnloadImage(handle); uerr != nil {
			println("phase2-oci-kernel-boot: UnloadImage warning:", uerr.Error())
		} else {
			println("phase2-oci-kernel-boot: UnloadImage OK")
		}
	} else {
		println("phase2-oci-kernel-boot: loaded image returned via gBS->Exit; UnloadImage skipped")
	}

	println("phase2-oci-kernel-boot: KERNEL-BOOT OK")
}

// locateVirtioNetForKernelBoot mirrors the cosign / oci-stream
// helpers — find the first 1AF4:1041 (modern virtio-net) by walking
// the EFI_PCI_IO_PROTOCOL handle space. Kept private to this file so
// the build tags don't accidentally double-define the symbol.
func locateVirtioNetForKernelBoot() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
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

// kernelBootSelfTestTransport is an in-process oci.Transport (and
// StreamTransport — so reg.FetchBlobStream can drive it) that serves
// the supplied blob bytes for the expected blob URL. Any other URL
// surfaces as a 404 so a misrouted request can't silently pass.
type kernelBootSelfTestTransport struct {
	blobURL string
	body    []byte
}

func newKernelBootSelfTestTransport(ref *oci.Ref, digest string, body []byte) *kernelBootSelfTestTransport {
	// Mirror Ref.blobURL: scheme://host/v2/repo/blobs/<digest>.
	return &kernelBootSelfTestTransport{
		blobURL: ref.Scheme + "://" + ref.Host + "/v2/" + ref.Repo + "/blobs/" + digest,
		body:    body,
	}
}

// Get satisfies the buffered Transport interface — only called for
// /token + /manifests endpoints, which the selftest doesn't exercise
// (FetchBlobStream goes straight to /blobs via GetStream). Surfaced
// as a 404 so an accidental call fails closed.
func (t *kernelBootSelfTestTransport) Get(url string, _ ministack.HTTPGetOptions) (*ministack.HTTPResponse, error) {
	return &ministack.HTTPResponse{
		StatusCode: 404,
		StatusLine: "HTTP/1.1 404 Not Found (kernelboot selftest)",
		Headers:    map[string]string{},
		Body:       []byte("kernelboot selftest: Get not supported"),
	}, nil
}

// GetStream satisfies oci.StreamTransport — this is the one
// FetchBlobStream calls. We write the body bytes verbatim into dst
// and return content-type + status so the caller's redirect/digest
// machinery walks the same code path as the real registry.
func (t *kernelBootSelfTestTransport) GetStream(url string, dst io.Writer, _ ministack.HTTPGetOptions) (status int, written int64, headers map[string]string, err error) {
	if url != t.blobURL {
		return 404, 0, map[string]string{}, nil
	}
	n, werr := dst.Write(t.body)
	if werr != nil {
		return 500, int64(n), map[string]string{}, werr
	}
	return 200, int64(n), map[string]string{
		"content-type": "application/octet-stream",
	}, nil
}

// hexUintptrKernelBoot renders a uintptr as a 0x-prefixed hex string
// without pulling fmt into the build closure. Local copy of the
// helper in phase2_efi_handover.go (which is only built when the
// `phase2_efi_handover` tag is set — orthogonal to ours). Renamed
// to avoid a redeclaration when both probes are compiled into the
// same parent (e.g. for a future combined diagnostic EFI).
func hexUintptrKernelBoot(v uintptr) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v != 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	i--
	buf[i] = 'x'
	i--
	buf[i] = '0'
	return string(buf[i:])
}

// kernelBootMaxLayerSize caps the streamed first-layer size at 64 MiB
// to prevent a misconfigured ref from exhausting memory. The
// siderolabs arm64 layer used by M8.3 is ~22 MiB compressed; vmlinuz
// after gunzip+untar is ~53 MiB. A 64 MiB cap leaves headroom without
// allowing pathological layers through.
const kernelBootMaxLayerSize = 64 * 1024 * 1024

// kernelBootVmlinuzName is the path inside the tar layer whose
// contents are the EFI-stub Linux kernel. The siderolabs artifact
// places the kernel at `boot/vmlinuz` (verified against the arm64
// pull on 2026-06-09).
const kernelBootVmlinuzName = "boot/vmlinuz"

// runKernelBootLinuxKernel is the MODE C entry — real-registry
// streaming + tar.gz extract + SetLoadOptions(cmdline) + (optional)
// PublishInitrd + LoadImage + StartImage. Fires when
// kernelBootTargetRef AND kernelBootCmdline are both non-empty.
//
// Flow:
//   1. Bring up virtio-net + DHCP + ministack roots (same as MODE A).
//   2. Resolve the multi-arch index and pick the per-arch manifest.
//   3. Stream the first (only) layer through SHA-256 verification.
//   4. gunzip + tar-walk to extract `boot/vmlinuz`.
//   5. Verify PE32+ MZ magic.
//   6. LoadImage the vmlinuz bytes.
//   7. SetLoadOptions(kernelBootCmdline) on the child image handle —
//      the Linux EFI-stub reads it from LoadedImageProtocol.LoadOptions
//      to populate the command line.
//   8. PublishInitrd (optional, gated on kernelBootInitrdRef — empty
//      in M8.3, deferred behind agent #3's asm trampoline).
//   9. StartImage transfers control to the kernel EFI-stub.
//
// Expected M8.3 outcome on arm64: the kernel EFI-stub initialises,
// prints "Booting Linux on physical CPU 0x...", "Linux version ..."
// etc, then either panics for lack of rootfs (no initrd) or hangs
// waiting for it. Either way the handoff is proven — kernel-side
// output is the M8.3 PASS criterion.
func runKernelBootLinuxKernel() {
	pciIO := locateVirtioNetForKernelBoot()
	if pciIO == 0 {
		println("phase2-oci-kernel-boot: no modern virtio-net device found")
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oci-kernel-boot: lease acquired")
	println("phase2-oci-kernel-boot:   IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oci-kernel-boot: embedded roots =", ministack.EmbeddedRootCount())

	ref, err := oci.ParseRef(kernelBootTargetRef)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 120 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchManifestRaw(index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseIndex:", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: PickPlatform:", perr.Error())
			return
		}
		println("phase2-oci-kernel-boot: picked per-arch manifest =", picked.Digest)
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}

	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	println("phase2-oci-kernel-boot: streaming layer digest =", target.Digest)
	println("phase2-oci-kernel-boot: streaming layer size   =", int(target.Size))
	if target.Size > kernelBootMaxLayerSize {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: layer size exceeds 64 MiB cap")
		return
	}

	// M8.3 memory + scheduler note (R-M8.3a + R-M8.3b CLOSED 2026-06-09):
	// the arm64 TamaGo heap is bumped to 128 MiB in
	// uefiboard/board_arm64.go (was 32 MiB) so the full 22 MiB
	// compressed layer fits in bytes.Buffer during streamExtractVmlinuz;
	// the io.Pipe + producer-goroutine pipeline that previously
	// deadlocked against the tamago+UEFI scheduler (no async
	// preemption — same root cause as the ministack RX-inline pattern,
	// commits 91364cf and 8c86f35) has been replaced by a synchronous
	// "buffer then gunzip+tar" pipeline (see streamExtractVmlinuz
	// docstring). The decompressed vmlinuz (~53 MiB) lives in
	// firmware-owned EfiLoaderData pages outside the Go heap.
	println("phase2-oci-kernel-boot: extracting", kernelBootVmlinuzName, "from layer via buffered gunzip+tar (R-M8.3b)")
	startNS := time.Now().UnixNano()
	vmlinuz, streamedN, eerr := streamExtractVmlinuz(reg, target, kernelBootVmlinuzName)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if eerr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: streamExtractVmlinuz:", eerr.Error())
		println("phase2-oci-kernel-boot: streamed-before-error bytes =", int(streamedN))
		return
	}
	println("phase2-oci-kernel-boot: streamed", int(streamedN), "bytes; SHA-256 verified OK")
	println("phase2-oci-kernel-boot: streaming elapsed (ms) =", int(elapsedMS))
	println("phase2-oci-kernel-boot: extracted vmlinuz bytes =", len(vmlinuz))
	if len(vmlinuz) < 2 || vmlinuz[0] != 'M' || vmlinuz[1] != 'Z' {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: vmlinuz is not PE32+ (no MZ)")
		return
	}
	println("phase2-oci-kernel-boot: vmlinuz PE header OK (MZ)")

	// M8.6: publish a DTB via gBS->InstallConfigurationTable BEFORE
	// LoadImage. Closes R-M8.5a (DTB-absence Data Abort) on EDK2
	// arm64, which publishes ACPI + SMBIOS but NOT the DTB; the
	// Linux EFI-stub's empty-DTB fallback path null-derefs (FAR=0x40)
	// and the kernel never starts. Publishing a DTB ourselves lets
	// the EFI-stub's normal devicetree path take over.
	//
	// Source priority:
	//   1. Live fw_cfg read via FetchQemuDTB — the "right" path,
	//      but EDK2 doesn't map the fw_cfg MMIO window on arm64
	//      virt so this faults until a future M8.x adds the
	//      AddMemorySpace plumbing (see uefiboard/embed_dtb_arm64.go
	//      docstring for the full diagnosis). Kept as the primary
	//      attempt so a firmware update that fixes the mapping is
	//      auto-picked up.
	//   2. Embedded baked-in QEMU arm64 virt DTB (EmbeddedArm64VirtDTB) —
	//      the M8.6 fallback. Trimmed DTB generated once at build
	//      time via `qemu-system-aarch64 -M virt,dumpdtb=...`;
	//      content stable across QEMU versions for this board.
	//
	// On amd64 + loong64 + riscv64 both sources return empty and
	// we skip the publish — those targets use ACPI exclusively
	// (amd64) or aren't on the M8.6 critical path (the others).
	var publishedDTB []byte
	fwCfgDTB, fetchErr := uefiboard.FetchQemuDTB()
	if fetchErr == nil && len(fwCfgDTB) > 0 {
		println("phase2-oci-kernel-boot: FetchQemuDTB OK; bytes =", len(fwCfgDTB))
		publishedDTB = fwCfgDTB
	} else {
		if fetchErr != nil {
			println("phase2-oci-kernel-boot: FetchQemuDTB:", fetchErr.Error())
		}
		embedded := uefiboard.EmbeddedArm64VirtDTB()
		if len(embedded) > 0 {
			println("phase2-oci-kernel-boot: using embedded arm64-virt DTB; bytes =", len(embedded))
			publishedDTB = embedded
		}
	}
	if len(publishedDTB) > 0 {
		if perr := uefiboard.PublishDTB(publishedDTB); perr != nil {
			println("phase2-oci-kernel-boot: PublishDTB failed:", perr.Error())
		} else {
			println("phase2-oci-kernel-boot: DTB published (", len(publishedDTB), "bytes)")
		}
	} else {
		println("phase2-oci-kernel-boot: no DTB source available; falling through (kernel may fault)")
	}

	// R-M8.8a CLOSED (M8.9, 2026-06-10): yank EFI_RNG_PROTOCOL from
	// every firmware-installed handle WITHOUT installing our own
	// replacement. This makes the Linux EFI-stub's
	// efi_random_get_seed() (drivers/firmware/efi/libstub/random.c)
	// take the "no RNG available" early-exit path — zero firmware
	// calls instead of (GetRNG → install_configuration_table →
	// free_pool → ...), which is where the M8.7 PublishRNG path was
	// hitting a downstream NULL+0x40 Data Abort (X0=0, X1=0x40,
	// X2=0x40 inside what looks like a memory-map debug string
	// formatter post-GetRNG).
	//
	// Diagnostic history:
	//   - M8.7 PublishRNG: replaced RngDxe with our trampoline. The
	//     R-M8.6a crash (RngDxe.dll +0x3220 on KASLR retry) was
	//     gone; the kernel called our GetRNG successfully (handle
	//     printed in the runner log); the boot then continued into
	//     a NEW pre-EBS abort downstream (R-M8.8a).
	//   - M8.9 disable-PublishRNG probe: confirmed R-M8.8a only
	//     fires when an EFI_RNG_PROTOCOL implementation is
	//     reachable. With PublishRNG skipped AND RngDxe still
	//     present the abort reverts to R-M8.6a inside RngDxe.dll.
	//     The only path that avoids both is "no RNG available at
	//     all" — UninstallAllRNG.
	//
	// Defence in depth: kernelboot_arm64.go still ships
	// `nokaslr random.trust_bootloader=0 random.trust_cpu=0` so
	// even if some downstream EFI-stub path were to re-attempt RNG
	// it wouldn't seed kernel state from it.
	yanked := uefiboard.UninstallAllRNG()
	println("phase2-oci-kernel-boot: UninstallAllRNG: yanked", yanked, "firmware RNG interface(s); LocateProtocol(RNG) will now return NOT_FOUND")

	// LoadImage the kernel bytes. EDK2 parses the PE32+ header and
	// allocates code/data pages; the EFI-stub entry point becomes
	// the StartImage target.
	handle, lerr := uefiboard.LoadImage(vmlinuz)
	if lerr != nil {
		println("phase2-oci-kernel-boot: LoadImage FAILED:", lerr.Error())
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL:", lerr.Error())
		return
	}
	println("phase2-oci-kernel-boot: LoadImage OK, handle =", hexUintptrKernelBoot(handle))

	// Install the cmdline into LoadedImageProtocol.LoadOptions BEFORE
	// StartImage. The Linux EFI-stub reads it during its early-init
	// to populate the command line passed to start_kernel.
	if soErr := uefiboard.SetLoadOptions(handle, kernelBootCmdline); soErr != nil {
		println("phase2-oci-kernel-boot: SetLoadOptions FAILED:", soErr.Error())
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL:", soErr.Error())
		return
	}
	println("phase2-oci-kernel-boot: SetLoadOptions OK; cmdline len =", len(kernelBootCmdline))

	// DTB probe (M8.4). Linux's EFI-stub auto-locates the
	// flattened device tree by scanning gST->ConfigurationTable for
	// EFI_DTB_TABLE_GUID. On EDK2 stable202408 + QEMU virt the
	// firmware itself publishes the DTB at platform-init; we just
	// log whether it's present so a kernel "Generating empty DTB"
	// later in the boot has a documented "expected: <bool>" line
	// alongside it. We do NOT need to publish the DTB ourselves on
	// this acceptance target.
	dtb := uefiboard.ProbeDTBConfigurationTable()
	if dtb.SystemTablePresent {
		println("phase2-oci-kernel-boot: DTB probe: SystemTable.NumberOfTableEntries =", int(dtb.NumberOfTableEntries))
		if dtb.DTBFound {
			println("phase2-oci-kernel-boot: DTB probe: EFI_DTB_TABLE_GUID PRESENT — kernel EFI-stub will auto-locate the DTB")
			println("phase2-oci-kernel-boot: DTB probe: VendorTable =", hexUintptrKernelBoot(dtb.DTBVendorTable))
		} else {
			println("phase2-oci-kernel-boot: DTB probe: EFI_DTB_TABLE_GUID NOT FOUND — kernel will fall back to 'Generating empty DTB'")
		}
		// M8.5 diagnostic dump: print every VendorGuid the firmware
		// exposes. This is how we find out whether the firmware is
		// publishing ACPI (8868e871-…), SMBIOS (eb9d2d31-… / f2fd1544-…),
		// or some other table set in place of (or in addition to) the
		// DTB. With this dump we can decide whether to (a) publish a
		// DTB ourselves via a future PublishDTB helper or (b) flip the
		// kernel cmdline to `acpi=force` if the firmware does ship
		// ACPI tables. Cheap: O(N) prints, N typically < 16.
		for i, g := range dtb.AllGUIDs {
			println("phase2-oci-kernel-boot: DTB probe: GUID[",
				i, "] data1 =", hex32(g.Data1),
				"data2 =", hex16(g.Data2),
				"data3 =", hex16(g.Data3),
				"data4 =", hex8(g.Data4[0]), hex8(g.Data4[1]), hex8(g.Data4[2]), hex8(g.Data4[3]),
				hex8(g.Data4[4]), hex8(g.Data4[5]), hex8(g.Data4[6]), hex8(g.Data4[7]))
		}
	} else {
		println("phase2-oci-kernel-boot: DTB probe: SystemTable not captured (cpuinit didn't run?) — skipping walk")
	}

	// Initrd publish (M8.4). Three sources, in priority order:
	//   1. OCI streaming (kernelBootInitrdRef set) — production path.
	//   2. Embedded minimal cpio.gz (kernelBootUseEmbeddedInitrd) —
	//      M8.4 default, ~260 bytes, no network roundtrip.
	//   3. None — pre-M8.4 cmdline-only behaviour (panics on most
	//      kernels for lack of rootfs).
	//
	// R-M8.4a diagnostic instrumentation (2026-06-10, retained but
	// gated): `uefiboard.LoadFileTraceEnabled` can be flipped to
	// `true` here to paint a per-callback diagnostic line on the
	// serial console (this/fp/bp/sizeP/bufP at entry, registry
	// hit/miss, have/need, EFI_STATUS at return). Used to diagnose
	// the off-by-one Go-ABI0-slot bug in the per-arch trampoline
	// that caused `EFI stub: ERROR: Failed to load initrd!` on
	// every two-call dance. Left wired (and off by default) so a
	// future regression can re-enable in one line without
	// re-developing the helper.
	//   uefiboard.LoadFileTraceEnabled = true
	var initrdHandle uintptr
	switch {
	case kernelBootInitrdRef != "":
		println("phase2-oci-kernel-boot: streaming initrd from OCI:", kernelBootInitrdRef)
		initrdBytes, ierr := fetchInitrdFromOCI(s, lease.DNS[0], kernelBootInitrdRef)
		if ierr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: fetchInitrdFromOCI:", ierr.Error())
			return
		}
		println("phase2-oci-kernel-boot: initrd fetched + decompressed; bytes =", len(initrdBytes))
		ihandle, perr := uefiboard.PublishInitrd(initrdBytes)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: PublishInitrd:", perr.Error())
			return
		}
		initrdHandle = ihandle
		println("phase2-oci-kernel-boot: PublishInitrd OK, initrd handle =", hexUintptrKernelBoot(initrdHandle))

	case kernelBootUseEmbeddedInitrd:
		// The embed is gzip-compressed cpio (per
		// internal/embed_initramfs/doc.go). The Linux EFI-stub /
		// initrd consumer accepts the gzip-wrapped cpio as-is
		// (drivers/firmware/efi/libstub/efi-stub-helper.c just
		// hands the bytes to populate_rootfs which understands the
		// `1f 8b` gzip magic and inflates inline). We therefore
		// publish the raw embedded bytes without decompressing
		// host-side — saves ~30 µs of CPU and lets the kernel's
		// own inflate handle the bookkeeping.
		raw := embed_initramfs.Bytes()
		println("phase2-oci-kernel-boot: using embedded minimal initrd; bytes =", len(raw))
		if len(raw) >= 3 && raw[0] == 0x1f && raw[1] == 0x8b && raw[2] == 0x08 {
			println("phase2-oci-kernel-boot: embedded initrd magic = 1f 8b 08 (gzip)")
		}
		ihandle, perr := uefiboard.PublishInitrd(raw)
		if perr != nil {
			println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: PublishInitrd (embedded):", perr.Error())
			return
		}
		initrdHandle = ihandle
		println("phase2-oci-kernel-boot: PublishInitrd OK, initrd handle =", hexUintptrKernelBoot(initrdHandle))

	default:
		println("phase2-oci-kernel-boot: no initrd source configured; kernel will boot cmdline-only")
	}

	println("phase2-oci-kernel-boot: StartImage entering EFI-stub kernel")
	println("phase2-oci-kernel-boot: ---- kernel-side output below this line ----")
	status, sErr := uefiboard.StartImage(handle)
	println("phase2-oci-kernel-boot: ---- kernel-side output above this line ----")
	println("phase2-oci-kernel-boot: StartImage returned exit_status=" + hexUintptrKernelBoot(status))
	if sErr != nil {
		println("phase2-oci-kernel-boot: kernel reported non-success:", sErr.Error())
	}

	// Cleanup paths mirror MODE A.
	if initrdHandle != 0 {
		if uerr := uefiboard.UnpublishInitrd(initrdHandle); uerr != nil {
			println("phase2-oci-kernel-boot: UnpublishInitrd warning:", uerr.Error())
		}
	}
	// M8.9: no PublishRNG to undo (UninstallAllRNG yanks the
	// firmware's interface but installs no replacement).
	if status != 0 {
		if uerr := uefiboard.UnloadImage(handle); uerr != nil {
			println("phase2-oci-kernel-boot: UnloadImage warning:", uerr.Error())
		} else {
			println("phase2-oci-kernel-boot: UnloadImage OK")
		}
	} else {
		println("phase2-oci-kernel-boot: kernel returned via gBS->Exit; UnloadImage skipped")
	}

	println("phase2-oci-kernel-boot: KERNEL-BOOT MODE C COMPLETE")
}

// extractVmlinuzFromTarGz gunzips the supplied layer bytes and walks
// the tar entries looking for a regular-file entry whose path matches
// `name`. Returns the file contents on first match.
//
// The Linux EFI-stub kernel inside the siderolabs/kernel layer is a
// single regular file at boot/vmlinuz (~53 MiB on arm64). We read it
// fully into memory because LoadImage needs a contiguous byte slice;
// the 64 MiB layer cap above keeps this bounded.
func extractVmlinuzFromTarGz(layer []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(layer))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, herr := tr.Next()
		if herr == io.EOF {
			return nil, errVmlinuzNotFound
		}
		if herr != nil {
			return nil, herr
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		// tar headers in docker layers may start with "./" — normalise
		// before comparison.
		hname := hdr.Name
		if len(hname) >= 2 && hname[0] == '.' && hname[1] == '/' {
			hname = hname[2:]
		}
		if hname != name {
			continue
		}
		body, rerr := io.ReadAll(tr)
		if rerr != nil {
			return nil, rerr
		}
		return body, nil
	}
}

// errVmlinuzNotFound is returned by extractVmlinuzFromTarGz when no
// entry matching kernelBootVmlinuzName is found in the tar stream.
var errVmlinuzNotFound = errorString("vmlinuz entry not found in tar.gz layer")

// streamExtractVmlinuz pulls the OCI layer to a buffered, SHA-256-
// verified in-memory blob, then synchronously gunzips + walks the
// tar entries looking for a regular-file entry whose path matches
// `name`. The vmlinuz body is placed in firmware-owned EfiLoaderData
// pages (NOT the Go heap) so the returned slice survives across
// LoadImage and ExitBootServices, AND so the Go heap can be freed
// after this function returns (the compressed layer + the
// gzip.Reader's window are the only transient holders).
//
// Pipeline shape (R-M8.3b — single thread, no goroutine, no io.Pipe):
//
//   FetchBlobStream --writes-> bytes.Buffer (full layer, SHA-256-verified)
//                              bytes.NewReader -> gzip.Reader -> tar.Reader
//                                                                       |
//                                            (when name matches) -> firmware-pages writer
//
// Why not io.Pipe + a producer goroutine? TamaGo+UEFI has no async
// preemption: the producer goroutine never runs while the consumer
// blocks on Read, so the io.Pipe deadlocks. The same root cause as
// the ministack "drive RX inline" pattern (commits 91364cf, 8c86f35).
//
// Memory budget (M8.3 — arm64, 128 MiB heap per R-M8.3a):
//
//   - Compressed layer in bytes.Buffer:    ~22 MiB.
//   - gzip.Reader sliding window:          ~32 KiB.
//   - Decompressed vmlinuz in firmware:    ~53 MiB (EfiLoaderData,
//                                          OUTSIDE the Go heap).
//   - Working margin (TLS, ministack, OCI client, SHA-256 state):
//                                          ~50 MiB.
//
// Returns (vmlinuz-slice-into-firmware-memory, streamed-byte-count, err).
// The returned slice's backing memory is owned by Boot Services and
// remains valid for the LoadImage call which happens before EBS.
func streamExtractVmlinuz(reg *oci.Registry, desc oci.Descriptor, name string) ([]byte, int64, error) {
	// Stage 1: buffer the full compressed layer into the Go heap.
	// FetchBlobStream verifies the SHA-256 against desc.Digest as it
	// writes, so the buffer is digest-clean on success.
	var buf bytes.Buffer
	n, ferr := reg.FetchBlobStream(desc, &buf)
	if ferr != nil {
		return nil, n, ferr
	}

	// Stage 2: synchronous gunzip + tar walk over the buffered layer.
	gz, gerr := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if gerr != nil {
		return nil, n, gerr
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, herr := tr.Next()
		if herr == io.EOF {
			return nil, n, errVmlinuzNotFound
		}
		if herr != nil {
			return nil, n, herr
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		hname := hdr.Name
		if len(hname) >= 2 && hname[0] == '.' && hname[1] == '/' {
			hname = hname[2:]
		}
		if hname != name {
			continue
		}

		// Found the kernel. Allocate firmware pages and copy the
		// tar entry body into them.
		sz := int(hdr.Size)
		if sz <= 0 {
			return nil, n, errVmlinuzEmpty
		}
		pages := uintptr((sz + int(uefiboard.EfiPageSize) - 1) / int(uefiboard.EfiPageSize))
		addr, aerr := uefiboard.AllocatePages(uefiboard.EfiLoaderData, pages)
		if aerr != nil {
			return nil, n, aerr
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), sz)
		// io.ReadFull into a firmware-pages slice — the tar reader
		// emits at most `hdr.Size` bytes for this entry, then either
		// returns io.EOF or moves on; ReadFull handles short reads.
		nRead, rerr := io.ReadFull(tr, dst)
		if rerr != nil {
			return nil, n, rerr
		}
		if nRead != sz {
			return nil, n, errVmlinuzShortRead
		}
		return dst, n, nil
	}
}

// errVmlinuzEmpty surfaces a tar entry with a non-positive size — the
// siderolabs layer always has a sized vmlinuz so this would indicate a
// corrupt or unexpected artifact.
var errVmlinuzEmpty = errorString("vmlinuz tar entry has zero size")

// errVmlinuzShortRead is reported when ReadFull from the tar entry
// stops short of the announced size — a corrupted or truncated layer.
var errVmlinuzShortRead = errorString("short read on vmlinuz tar entry")

// errorString is a tiny local error type so the M8.3 extractor doesn't
// pull errors.New into the M8.3 build closure (it isn't already
// imported into this file's build closure; SetLoadOptions imports it
// inside the uefiboard package, not here).
type errorString string

func (e errorString) Error() string { return string(e) }

// fetchInitrdFromOCI streams the configured OCI ref's first layer
// through the ministack OCI client + SHA-256 verification (same
// pipeline as the kernel-layer fetch), then auto-detects gzip via
// the `1f 8b 08` magic and inflates synchronously if needed. The
// returned bytes are ready to hand to uefiboard.PublishInitrd.
//
// Why synchronous gunzip: same root cause as streamExtractVmlinuz
// (R-M8.3b — TamaGo+UEFI has no async preemption, so io.Pipe +
// producer goroutine deadlocks). We buffer the full compressed
// layer in the Go heap first; the embedded fallback path makes the
// 64 MiB cap above the only relevant upper bound here.
//
// Returns the raw initrd bytes (gunzipped if the source was gzip,
// passthrough if not) and any error.
func fetchInitrdFromOCI(s *ministack.Stack, dns net.IP, refStr string) ([]byte, error) {
	ref, err := oci.ParseRef(refStr)
	if err != nil {
		return nil, err
	}
	reg := oci.NewRegistry(s, dns, ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 120 * time.Second

	if aerr := reg.Authenticate(); aerr != nil {
		return nil, aerr
	}

	rawIndex, contentType, ferr := reg.FetchManifestRaw(ref.Reference)
	if ferr != nil {
		return nil, ferr
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			return nil, perr
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			return nil, perr
		}
		mraw, _, merr := reg.FetchManifestRaw(picked.Digest)
		if merr != nil {
			return nil, merr
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}
	m, mperr := oci.ParseManifest(rawManifest)
	if mperr != nil {
		return nil, mperr
	}
	if len(m.Layers) == 0 {
		return nil, errInitrdNoLayers
	}
	target := m.Layers[0]
	if target.Size > kernelBootMaxLayerSize {
		return nil, errInitrdLayerTooBig
	}

	var buf bytes.Buffer
	if _, serr := reg.FetchBlobStream(target, &buf); serr != nil {
		return nil, serr
	}
	raw := buf.Bytes()

	// Gzip auto-detect (RFC 1952 §2.3.1: magic 1f 8b, CM=08).
	if len(raw) >= 3 && raw[0] == 0x1f && raw[1] == 0x8b && raw[2] == 0x08 {
		gz, gerr := gzip.NewReader(bytes.NewReader(raw))
		if gerr != nil {
			return nil, gerr
		}
		defer gz.Close()
		out, rerr := io.ReadAll(gz)
		if rerr != nil {
			return nil, rerr
		}
		return out, nil
	}
	return raw, nil
}

// errInitrdNoLayers reports an OCI manifest with zero layers — a
// malformed initrd artifact.
var errInitrdNoLayers = errorString("initrd OCI manifest has zero layers")

// errInitrdLayerTooBig reports an initrd layer exceeding the same
// 64 MiB cap as the kernel layer (kernelBootMaxLayerSize). Distro
// initramfs blobs are 8..64 MiB; anything larger is almost
// certainly a misconfigured ref.
var errInitrdLayerTooBig = errorString("initrd layer size exceeds 64 MiB cap")
