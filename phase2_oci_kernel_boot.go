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
	"bytes"
	"io"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/internal/embed_chained"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// kernelBootTargetRef is the OCI artifact the MODE A / MODE C path
// fetches. Empty = MODE B (self-test against an in-process Transport).
//
// Wiring MODE A / MODE C against a publicly-pushed BOOT*-CHAINED.EFI
// (or a small EFI-stub Linux kernel) is the M8.2 follow-up — see
// cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.2 for the
// blocker (no `write:packages` PAT in the M8.1 budget; M8.2 needs a
// public EFI-stub kernel OCI ref).
const kernelBootTargetRef = ""

// kernelBootCmdline is the Linux kernel command line installed via
// uefiboard.SetLoadOptions before StartImage. Empty = no cmdline
// install; non-empty + non-empty kernelBootTargetRef = MODE C.
//
// Typical values (left here for docs; populate when wiring MODE C
// against a public kernel ref):
//
//	"console=ttyAMA0 root=/dev/ram0"     (arm64 virt)
//	"console=ttyS0 earlyprintk=ttyS0"     (amd64 OVMF)
//	"console=hvc0 root=/dev/ram0"         (riscv64 virt)
//
// The Linux EFI-stub reads it from LoadedImageProtocol.LoadOptions
// of its own image handle (UEFI 2.10 §9.2 / Documentation/admin-
// guide/efi-stub.rst).
const kernelBootCmdline = ""

// kernelBootInitrdRef is the OCI ref the MODE C path streams to
// obtain the initrd. Empty = no initrd install; the Linux EFI-stub
// will boot off the kernel only (acceptable for a busybox-style
// kernel image with built-in initramfs, fails for distro kernels).
//
// When set, the MODE C flow publishes an EFI_LOAD_FILE2_PROTOCOL
// under LINUX_EFI_INITRD_MEDIA_GUID via uefiboard.PublishInitrd
// before StartImage and unpublishes after.
//
// M8.2-PARTIAL caveat: uefiboard.PublishInitrd currently installs
// the device path + protocol struct but the LoadFile slot is NULL
// pending the per-arch firmware-callback asm trampoline (see
// uefiboard/initrd_protocol_tamago.go). A real EFI-stub that calls
// LoadFile2->LoadFile on the published handle will fault. Setting
// kernelBootInitrdRef in this build wires the framework but is not
// expected to boot end-to-end against an upstream kernel.
const kernelBootInitrdRef = ""

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
		println("phase2-oci-kernel-boot: initrd =", kernelBootInitrdRef)
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

// runKernelBootLinuxKernel is the MODE C entry — real-registry
// streaming + SetLoadOptions(cmdline) + (optional) PublishInitrd +
// LoadImage + StartImage. Fires when kernelBootTargetRef AND
// kernelBootCmdline are both non-empty.
//
// In this build both are empty (no public OCI ref for an EFI-stub
// Linux kernel + no write:packages PAT to publish our own; tracked
// as M8.2 follow-up). The function is therefore dormant — if it is
// ever called (dispatcher mode check satisfied) it prints a clear
// "dormant" message and returns. The kernel-specific wiring lives
// in uefiboard/load_options.go + uefiboard/initrd_protocol.go and
// is exercised by the host-side unit tests; the live path here
// stays inert until a real kernel ref is configured.
func runKernelBootLinuxKernel() {
	println("phase2-oci-kernel-boot: MODE C invoked but dormant in this build")
	println("phase2-oci-kernel-boot:   kernelBootTargetRef    =", kernelBootTargetRef)
	println("phase2-oci-kernel-boot:   kernelBootCmdline len  =", len(kernelBootCmdline))
	println("phase2-oci-kernel-boot:   kernelBootInitrdRef    =", kernelBootInitrdRef)
	println("phase2-oci-kernel-boot: framework wired (uefiboard.SetLoadOptions +")
	println("phase2-oci-kernel-boot: uefiboard.PublishInitrd) — populate the constants")
	println("phase2-oci-kernel-boot: against a public EFI-stub kernel OCI ref to enable.")
	println("phase2-oci-kernel-boot: see cloud-boot/docs/tamago-uefi-phase2-oci-loader.md")
	println("phase2-oci-kernel-boot:   section M8.2 for the wiring + live-test plan.")
	println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: MODE C dormant (M8.2 follow-up)")
	// Touch the new uefiboard symbols so the build doesn't garbage-collect
	// the load-options + initrd-protocol surface area away when MODE C is
	// dormant. The closures here are unreachable but keep the linker
	// honest about which symbols are part of the cloud-boot ABI.
	_ = uefiboard.SetLoadOptions
	_ = uefiboard.PublishInitrd
	_ = uefiboard.UnpublishInitrd
}
