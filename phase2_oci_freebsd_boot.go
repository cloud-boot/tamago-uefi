// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-3 sprint-1 probe — OS-agnostic OCI boot, FreeBSD MVP.
// Gated on `-tags phase3_oci_freebsd_boot && tamago && amd64`.
//
// Strategy (per the Phase 3 sprint 1 brief, 2026-06-11):
//
//   1. Bring up virtio-net + DHCP + ministack roots (same wiring as
//      phase2_oci_kernel_boot MODE C).
//   2. Stream a FreeBSD bootable disk image (GPT + FAT ESP + loader.efi)
//      from an OCI artifact. Single-layer, raw bytes, SHA-256 verified.
//   3. uefiboard.PublishBlockIO(imageBytes) installs a synthetic
//      EFI_BLOCK_IO_PROTOCOL backed by the streamed bytes; returns the
//      firmware-assigned controller handle.
//   4. uefiboard.ConnectController(handle) drives EDK2's
//      DiskIoDxe + PartitionDxe + FatDxe binding so the GPT is parsed,
//      the ESP is discovered, and a child handle publishing
//      EFI_SIMPLE_FILE_SYSTEM_PROTOCOL becomes available.
//   5. LocateHandleBuffer(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID) finds
//      the new child handle.
//   6. LoadImage from \EFI\BOOT\BOOTX64.EFI on that file system (which
//      on the FreeBSD bootonly ISO is the FreeBSD loader.efi).
//   7. StartImage transfers control. Expected outcome: the FreeBSD
//      loader.efi banner prints to serial; on a bootonly ISO loader
//      then tries to read kernel + loader.conf from UFS — which sprint
//      1 explicitly does NOT provide (sprint 2 will add go-filesystems/ufs).
//      Reaching the loader banner is the sprint 1 PASS gate.
//
// Sprint 1 explicit out-of-scope:
//   - arm64/riscv64/loong64 (publisher trampolines are amd64-only).
//   - UFS root mount (sprint 2).
//   - Full kernel boot to FreeBSD multi-user (sprint 2).
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase3_oci_freebsd_boot \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase3_oci_freebsd_boot && tamago && amd64

package main

import (
	"bytes"
	"errors"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
	"github.com/go-filesystems/ufs"
)

// freebsdBootTargetRef is the OCI artifact streaming source for the
// FreeBSD disk image. Empty = the probe fails closed (the runner is
// expected to publish a per-run image to ttl.sh and inject the ref
// via a -X linker constant override — same pattern as
// kernelBootTargetRef in kernelboot_<arch>.go).
//
// Sprint 1 MVP uses the FreeBSD-14.3-RELEASE-amd64-bootonly.iso (412
// MiB). The runner pushes it to ttl.sh as a single-layer artifact
// with mediaType application/vnd.cloud-boot.diskimage.raw.v1 and
// overrides this constant at link time.
var freebsdBootTargetRef = ""

// freebsdBootMaxImageSize caps the streamed image at 768 MiB so a
// misconfigured ref can't exhaust memory. The bootonly ISO is ~412
// MiB; a full Install ISO is ~1.2 GiB and would be rejected (and is
// out of scope for sprint 1 anyway).
const freebsdBootMaxImageSize = 768 * 1024 * 1024

// freebsdBootEFIPath is the canonical UEFI fallback boot path the
// FAT ESP must contain. On the FreeBSD bootonly ISO this resolves to
// the FreeBSD loader.efi (~660 KiB on 14.3, BSD-2-Clause).
const freebsdBootEFIPath = "\\EFI\\BOOT\\BOOTX64.EFI"

// runOCIFreeBSDBootProbe is the entry point the dispatcher calls when
// the `phase3_oci_freebsd_boot` build tag is set.
func runOCIFreeBSDBootProbe() {
	println("phase3-oci-freebsd-boot: Sprint 1 MVP -- OCI stream + EFI_BLOCK_IO publish + ConnectController + LoadImage(loader.efi)")
	println("phase3-oci-freebsd-boot: arch =", runtime.GOARCH)

	if freebsdBootTargetRef == "" {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: no freebsdBootTargetRef configured (runner must override via -X linker flag)")
		return
	}
	println("phase3-oci-freebsd-boot: target =", freebsdBootTargetRef)

	pciIO := locateVirtioNetForFreeBSDBoot()
	if pciIO == 0 {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase3-oci-freebsd-boot: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase3-oci-freebsd-boot: lease acquired; IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: NewRootCAs:", perr.Error())
		return
	}

	ref, err := oci.ParseRef(freebsdBootTargetRef)
	if err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 180 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: Authenticate:", err.Error())
		return
	}

	rawManifest, _, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: FetchManifestRaw:", err.Error())
		return
	}
	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	println("phase3-oci-freebsd-boot: streaming disk image layer digest =", target.Digest)
	println("phase3-oci-freebsd-boot: streaming disk image layer size   =", int(target.Size))
	if target.Size > freebsdBootMaxImageSize {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: layer size exceeds 768 MiB cap")
		return
	}

	var buf bytes.Buffer
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(target, &buf)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: FetchBlobStream:", ferr.Error())
		println("phase3-oci-freebsd-boot: bytes-written-before-error =", int(n))
		return
	}
	println("phase3-oci-freebsd-boot: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase3-oci-freebsd-boot: streaming elapsed (ms) =", int(elapsedMS))

	imageBytes := buf.Bytes()
	// Sanity: protective MBR signature at offset 510..511.
	if len(imageBytes) < 512 || imageBytes[510] != 0x55 || imageBytes[511] != 0xAA {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: streamed image missing MBR signature")
		return
	}
	// Sanity: GPT header magic "EFI PART" at LBA 1 (offset 512..519).
	if len(imageBytes) < 520 ||
		imageBytes[512] != 'E' || imageBytes[513] != 'F' || imageBytes[514] != 'I' || imageBytes[515] != ' ' ||
		imageBytes[516] != 'P' || imageBytes[517] != 'A' || imageBytes[518] != 'R' || imageBytes[519] != 'T' {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: streamed image missing 'EFI PART' GPT magic at LBA 1")
		return
	}
	println("phase3-oci-freebsd-boot: streamed image header OK (MBR 0x55AA + GPT 'EFI PART')")

	// Pad image to a 512-byte multiple if the tail is short. UEFI's
	// PartitionDxe + FatDxe both walk fixed 512-byte LBAs and our
	// publisher refuses misaligned images.
	if rem := len(imageBytes) % int(uefiboard.BlockIOLogicalBlockSize); rem != 0 {
		pad := make([]byte, int(uefiboard.BlockIOLogicalBlockSize)-rem)
		imageBytes = append(imageBytes, pad...)
		println("phase3-oci-freebsd-boot: padded image tail by", len(pad), "bytes for 512-aligned LastBlock")
	}

	blkHandle, perr := uefiboard.PublishBlockIO(imageBytes)
	if perr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: PublishBlockIO:", perr.Error())
		return
	}
	println("phase3-oci-freebsd-boot: PublishBlockIO OK; block handle =", hexUintptrFreeBSD(blkHandle))

	if cerr := uefiboard.ConnectController(blkHandle); cerr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: ConnectController:", cerr.Error())
		return
	}
	println("phase3-oci-freebsd-boot: ConnectController OK (DiskIo/PartitionDxe/FatDxe binding done)")

	// Diagnostic: count every SFS handle the firmware sees, then filter
	// to the one whose backing storage is our Block IO. The sprint-1
	// brief explicitly called the unfiltered LocateHandleBuffer a
	// known sprint-1.1 hazard — OVMF connects ALL block devices on
	// boot, so a blind lookup returns the stock startup FAT alongside
	// ours.
	sfsHandles, lerr := uefiboard.LocateHandleBuffer(&uefiboard.EFISimpleFileSystemProtocolGUID)
	if lerr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: LocateHandleBuffer(SFS):", lerr.Error())
		return
	}
	println("phase3-oci-freebsd-boot: LocateHandleBuffer(SFS) found", len(sfsHandles), "total handle(s) (parent + siblings)")
	if len(sfsHandles) == 0 {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: firmware did not surface any SimpleFileSystem handle after ConnectController -- ESP probably not recognised")
		return
	}

	// Filter to the SFS handle whose device path begins with our
	// blkHandle's device path. See sfs_filter_tamago.go for the walk
	// logic; the bytes-level node-aligned prefix match is unit-tested
	// in sfs_filter_test.go.
	childHandle, childDP, ferr := uefiboard.FindSFSChildOf(blkHandle)
	if ferr != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: FindSFSChildOf:", ferr.Error())
		return
	}
	println("phase3-oci-freebsd-boot: matching SFS child handle =", hexUintptrFreeBSD(uintptr(childHandle)))
	println("phase3-oci-freebsd-boot: child device path length =", len(childDP), "bytes")

	// LoadImage \EFI\BOOT\BOOTX64.EFI from the matched SFS. We use the
	// device-path form (NULL SourceBuffer) so the firmware sets the
	// child image's EFI_LOADED_IMAGE.DeviceHandle to our SFS child —
	// FreeBSD's loader.efi keys its filesystem reads off DeviceHandle
	// and would otherwise fail with "Failed to find bootable partition"
	// the way it does when handed a memory-loaded image.
	childImage, lerr2 := uefiboard.LoadImageFromSFS(childDP, freebsdBootEFIPath)
	if lerr2 != nil {
		println("phase3-oci-freebsd-boot: FREEBSD-BOOT FAIL: LoadImageFromSFS:", lerr2.Error())
		return
	}
	println("phase3-oci-freebsd-boot: LoadImage(", freebsdBootEFIPath, ") OK; image handle =", hexUintptrFreeBSD(childImage))

	// Sprint 2B: scan the streamed disk image for a FreeBSD UFS
	// partition. If present, open it via go-filesystems/ufs and
	// install an EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on a fresh handle so
	// loader.efi (which calls LocateHandleBuffer(SFS_GUID) for kernel
	// + loader.conf reads) can find /boot/kernel/kernel on our
	// Go-backed UFS.
	//
	// Graceful degradation: if no UFS partition exists (sprint 1.2's
	// FAT16-only ESP image), log + skip. The architectural goal of
	// sprint 2B is the SFS publish surface itself; a real UFS payload
	// is a follow-on.
	ufsBytes, uerr := findUFSPartitionBytes(imageBytes)
	if uerr != nil {
		if errors.Is(uerr, ErrNoUFSPartition) {
			println("phase3-oci-freebsd-boot: SFS-UFS skip: no UFS partition in GPT (sprint 1.2 FAT16-only ESP image) -- architectural OK, loader.efi may fail at root mount")
		} else {
			println("phase3-oci-freebsd-boot: SFS-UFS skip: GPT parse error:", uerr.Error())
		}
	} else {
		ufsFS, ferr := ufs.Open(&sliceReaderAt{b: ufsBytes}, int64(len(ufsBytes)))
		if ferr != nil {
			println("phase3-oci-freebsd-boot: SFS-UFS skip: ufs.Open failed:", ferr.Error())
		} else {
			sfsHandle, perr := uefiboard.PublishSFS(0, ufsFS)
			if perr != nil {
				println("phase3-oci-freebsd-boot: SFS-UFS PublishSFS FAIL:", perr.Error())
			} else {
				println("phase3-oci-freebsd-boot: PublishSFS OK; UFS-backed SFS handle =", hexUintptrFreeBSD(sfsHandle))
				defer func() {
					if uerr := uefiboard.UnpublishSFS(sfsHandle); uerr != nil {
						println("phase3-oci-freebsd-boot: UnpublishSFS warning:", uerr.Error())
					}
				}()
			}
		}
	}

	// Sprint 1.1 PASS gate: reach this point and StartImage. The
	// FreeBSD loader.efi will print its banner ("FreeBSD/amd64 EFI
	// loader, Revision 3.0") and then either find a kernel + boot it
	// (sprint 2B's UFS support, present if the streamed image carries
	// a UFS partition) or fail with "Failed to find bootable partition"
	// (expected when only the FAT ESP is present).
	println("phase3-oci-freebsd-boot: FREEBSD-BOOT CHAIN COMPLETE -- transferring control to loader.efi")
	if _, serr := uefiboard.StartImage(childImage); serr != nil {
		println("phase3-oci-freebsd-boot: StartImage returned:", serr.Error(), "-- loader.efi exited (sprint-2 UFS will let it boot a kernel)")
	} else {
		println("phase3-oci-freebsd-boot: StartImage returned EFI_SUCCESS -- loader.efi clean exit")
	}

	// Best-effort cleanup so we don't strand the registry slot. May
	// fail if firmware is mid-binding when loader.efi returned — log
	// only.
	if uerr := uefiboard.UnpublishBlockIO(blkHandle); uerr != nil {
		println("phase3-oci-freebsd-boot: UnpublishBlockIO warning:", uerr.Error())
	}
}

// locateVirtioNetForFreeBSDBoot mirrors the cosign/oci-stream/kernel-boot
// helpers. Local copy so the symbol doesn't clash with the
// kernel-boot probe's locateVirtioNetForKernelBoot when both build
// tags are enabled in the same parent (unusual, but defensive).
func locateVirtioNetForFreeBSDBoot() uint64 {
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

// hexUintptrFreeBSD renders a uintptr as a hex string without pulling
// fmt into the build closure. Local copy of hexUintptrKernelBoot.
func hexUintptrFreeBSD(v uintptr) string {
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
