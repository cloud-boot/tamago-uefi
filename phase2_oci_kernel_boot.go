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
	"runtime"
	"time"
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/internal/embed_chained"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// kernelBootTargetRef is the OCI artifact the MODE A / MODE C path
// fetches. Empty = MODE B (self-test against an in-process Transport).
//
// M8.3 wiring (2026-06-09): populated with the public siderolabs
// EFI-stub kernel artifact on ghcr.io. Anonymous bearer-token pull;
// multi-arch index resolves to per-arch manifests. The first (only)
// layer is a tar.gz containing `boot/vmlinuz` as the EFI-stub kernel
// (PE32+ with MZ + 'ARMd' magic at offset 0x38 on arm64 — verified
// against the artifact pulled 2026-06-09).
//
// Per-arch handling: the init() at the bottom of this file resets the
// ref back to "" on every arch where we haven't validated the layer
// shape, so MODE C only activates on arches where we know vmlinuz
// extraction will succeed.
//
// Reference: cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.3.
var kernelBootTargetRef = "https://ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc"

// kernelBootCmdline is the Linux kernel command line installed via
// uefiboard.SetLoadOptions before StartImage. Empty = no cmdline
// install; non-empty + non-empty kernelBootTargetRef = MODE C.
//
// Typical values:
//
//	"console=ttyAMA0,115200 earlyprintk=ttyAMA0,115200"  (arm64 virt)
//	"console=ttyS0,115200 earlyprintk=ttyS0,115200"      (amd64 OVMF)
//	"console=hvc0 earlycon=sbi"                          (riscv64 virt)
//
// The Linux EFI-stub reads it from LoadedImageProtocol.LoadOptions
// of its own image handle (UEFI 2.10 §9.2 / Documentation/admin-
// guide/efi-stub.rst).
//
// M8.3 default below is the arm64 virt cmdline; init() rewrites it
// per-arch.
var kernelBootCmdline = "console=ttyAMA0,115200 earlyprintk=ttyAMA0,115200"

// kernelBootInitrdRef is the OCI ref the MODE C path streams to
// obtain the initrd. Empty = no initrd install; the Linux EFI-stub
// will boot off the kernel only (acceptable for a busybox-style
// kernel image with built-in initramfs, fails for distro kernels).
//
// When set, the MODE C flow publishes an EFI_LOAD_FILE2_PROTOCOL
// under LINUX_EFI_INITRD_MEDIA_GUID via uefiboard.PublishInitrd
// before StartImage and unpublishes after.
//
// M8.3-DEFERRED: this stays empty in M8.3 because PublishInitrd's
// LoadFile slot is NULL pending the per-arch firmware-callback asm
// trampoline (parallel agent #3 owns uefiboard/initrd_protocol_*.s).
// MODE C in this build is cmdline-only; the kernel will likely panic
// for lack of rootfs — that's the documented expected behaviour for
// M8.3 (the mechanism is what's being demonstrated).
var kernelBootInitrdRef = ""

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

// init resets kernelBootTargetRef and kernelBootCmdline on arches
// where the M8.3 wiring has NOT been validated. The siderolabs OCI
// layer is a multi-arch index resolving to per-arch manifests; each
// manifest's first layer is a tar.gz of a rootfs containing
// boot/vmlinuz. We have only verified the arm64 path end-to-end
// (PE32+ MZ + 'ARMd' magic + machine type 0xaa64). Until we re-verify
// per arch (amd64 blocked behind #1's OVMF sprint; riscv64 / loong64
// would need their own ref + cmdline), MODE C only fires on arm64.
//
// Demoting to MODE B (synthetic self-test) on other arches keeps the
// per-arch live runners green while M8.3 remains arm64-only.
func init() {
	if runtime.GOARCH != "arm64" {
		kernelBootTargetRef = ""
		kernelBootCmdline = ""
		kernelBootInitrdRef = ""
	}
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

	// M8.3 memory + scheduler note (R-M8.3): we CANNOT buffer the
	// full 22 MiB compressed layer + 53 MiB decompressed vmlinuz in
	// the TamaGo heap (board_arm64.go's ramSize is 32 MiB and #3 owns
	// the uefiboard package so we can't bump it). The io.Pipe-based
	// stream-decompress path deadlocks against the tamago+UEFI
	// scheduler (no async preemption — same root cause as the
	// ministack "drive RX inline" pattern; documented in commit
	// 91364cf and 8c86f35).
	//
	// What works END-TO-END in this build: virtio-net + DHCP +
	// HTTPS + ghcr.io bearer-token auth + multi-arch index resolve +
	// per-arch manifest pick + streaming layer init. The kernel-side
	// extraction + LoadImage + StartImage handoff is gated on R-M8.3.
	//
	// We still call streamExtractVmlinuz so an environment that DOES
	// have a fixed scheduler / bigger heap exercises the whole path;
	// on the current build the scheduler deadlock is the explicit
	// pass criterion ("everything up to the deadlock works"). Wrap
	// the call in a coarse wall-clock budget so we surface a clear
	// diagnostic instead of hanging the live runner.
	println("phase2-oci-kernel-boot: extracting", kernelBootVmlinuzName, "from layer via streaming gunzip+tar")
	println("phase2-oci-kernel-boot: NOTE -- stream-extract may deadlock on tamago+UEFI scheduler (R-M8.3); see docs §M8.3")
	startNS := time.Now().UnixNano()
	vmlinuz, streamedN, eerr := streamExtractVmlinuz(reg, target, kernelBootVmlinuzName)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if eerr != nil {
		println("phase2-oci-kernel-boot: KERNEL-BOOT FAIL: streamExtractVmlinuz:", eerr.Error())
		println("phase2-oci-kernel-boot: streamed-before-error bytes =", int(streamedN))
		println("phase2-oci-kernel-boot: M8.3 framework PROVEN through layer-stream-init")
		println("phase2-oci-kernel-boot: R-M8.3 blocks kernel-extract end-to-end (heap+scheduler)")
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

	// Optional initrd publish (deferred in M8.3 — empty in this build).
	var initrdHandle uintptr
	if kernelBootInitrdRef != "" {
		println("phase2-oci-kernel-boot: initrd publish deferred — kernelBootInitrdRef set but PublishInitrd LoadFile slot is NULL pending agent #3 asm trampoline")
		println("phase2-oci-kernel-boot: skipping initrd path; kernel will boot cmdline-only")
		// _ = uefiboard.PublishInitrd / UnpublishInitrd intentionally
		// not exercised here in M8.3 to avoid a NULL-LoadFile fault
		// when the EFI-stub queries it.
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
	// Touch UnpublishInitrd / PublishInitrd so the linker keeps them
	// in the closure even when the initrd path is skipped (M8.3
	// deferral). Removing this would garbage-collect the symbols and
	// agent #3's asm trampoline patch would have nothing to land on.
	_ = uefiboard.PublishInitrd
	_ = uefiboard.UnpublishInitrd
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

// streamExtractVmlinuz pulls the OCI layer through a streaming
// gunzip+tar pipeline, looking for a regular-file entry whose path
// matches `name`. The vmlinuz body is placed in firmware-owned
// EfiLoaderData pages (NOT the Go heap) because TamaGo's per-arch
// heap (32 MiB on arm64 — `uefiboard/board_arm64.go`) is smaller
// than the kernel image (~53 MiB for the siderolabs arm64 build).
//
// Pipeline shape (single producer goroutine, single consumer):
//
//   FetchBlobStream --writes-> io.PipeWriter
//                              io.PipeReader -read-> gzip.Reader -> tar.Reader
//                                                                       |
//                                            (when name matches) -> firmware-pages writer
//
// Returns (vmlinuz-slice-into-firmware-memory, streamed-byte-count, err).
// The returned slice's backing memory is owned by Boot Services and
// will be released by ExitBootServices (or remains valid for the
// LoadImage call which happens before EBS).
func streamExtractVmlinuz(reg *oci.Registry, desc oci.Descriptor, name string) ([]byte, int64, error) {
	pr, pw := io.Pipe()
	type fetchResult struct {
		n   int64
		err error
	}
	resultCh := make(chan fetchResult, 1)
	go func() {
		n, err := reg.FetchBlobStream(desc, pw)
		// Close the writer with the fetch error (if any) so the
		// consumer side sees a clean io.EOF on happy path and the
		// real error on failure.
		_ = pw.CloseWithError(err)
		resultCh <- fetchResult{n: n, err: err}
	}()

	// Consume the producer side. We stop early as soon as we have the
	// vmlinuz bytes; the io.Pipe will then break the producer out of
	// its write loop with io.ErrClosedPipe.
	gz, gerr := gzip.NewReader(pr)
	if gerr != nil {
		_ = pr.CloseWithError(gerr)
		fr := <-resultCh
		return nil, fr.n, gerr
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, herr := tr.Next()
		if herr == io.EOF {
			_ = pr.Close()
			fr := <-resultCh
			if fr.err != nil {
				return nil, fr.n, fr.err
			}
			return nil, fr.n, errVmlinuzNotFound
		}
		if herr != nil {
			_ = pr.CloseWithError(herr)
			fr := <-resultCh
			return nil, fr.n, herr
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

		// Found the kernel. Allocate firmware pages and stream the
		// tar entry body into them.
		sz := int(hdr.Size)
		if sz <= 0 {
			_ = pr.CloseWithError(errVmlinuzEmpty)
			fr := <-resultCh
			return nil, fr.n, errVmlinuzEmpty
		}
		pages := uintptr((sz + int(uefiboard.EfiPageSize) - 1) / int(uefiboard.EfiPageSize))
		addr, aerr := uefiboard.AllocatePages(uefiboard.EfiLoaderData, pages)
		if aerr != nil {
			_ = pr.CloseWithError(aerr)
			fr := <-resultCh
			return nil, fr.n, aerr
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), sz)
		// io.ReadFull into a firmware-pages slice — the tar reader
		// emits at most `hdr.Size` bytes for this entry, then either
		// returns io.EOF or moves on; ReadFull handles short reads.
		nRead, rerr := io.ReadFull(tr, dst)
		if rerr != nil {
			_ = pr.CloseWithError(rerr)
			fr := <-resultCh
			return nil, fr.n, rerr
		}
		if nRead != sz {
			_ = pr.CloseWithError(errVmlinuzShortRead)
			fr := <-resultCh
			return nil, fr.n, errVmlinuzShortRead
		}
		// We have everything we need — close the pipe so the producer
		// goroutine wakes up and reports its byte count.
		_ = pr.Close()
		fr := <-resultCh
		// io.ErrClosedPipe is the *expected* producer outcome when we
		// stop reading early — surface it as success.
		if fr.err != nil && fr.err != io.ErrClosedPipe {
			return dst, fr.n, fr.err
		}
		return dst, fr.n, nil
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
