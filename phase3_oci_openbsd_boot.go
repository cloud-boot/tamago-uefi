// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-3 sprint-3 probe — OS-agnostic OCI boot, OpenBSD MVP.
// Gated on `-tags phase3_oci_openbsd_boot && tamago && amd64`.
//
// Strategy: structurally identical to phase2_oci_freebsd_boot.go.
// OpenBSD's FFS family is on-disk-compatible with FreeBSD UFS2 from
// OpenBSD 6.5 (2019) onwards — go-filesystems/ufs reads it as-is.
// Same Block IO + ConnectController + SFS + UFS path applies.
//
// Per-OS divergences captured here:
//
//   - OCI ref: a separate per-run ttl.sh push of an OpenBSD bootable
//     disk image (typically synthesised from an OpenBSD installXX.iso
//     or installXX.img — see internal/liveopenbsdboot/run.sh).
//   - EFI binary path on the ESP: \EFI\BOOT\BOOTX64.EFI (the UEFI
//     fallback boot path; OpenBSD's amd64 EFI loader ships as
//     bootx64.efi and the install media lays it down at exactly this
//     path).
//   - Boot configuration: OpenBSD reads /etc/boot.conf from the root
//     file system (FFS) at loader runtime; we don't synthesise one
//     in sprint 3 (architectural scaffolding only).
//
// Sprint 3 explicit out-of-scope:
//   - arm64/riscv64/loong64 (publisher trampolines are amd64-only).
//   - OpenBSD multi-user (sprint 3.x).
//   - FFSv1 backward compatibility (sprint 3.5 if any cloud image
//     ships pre-6.5 FFSv1; modern releases are FFSv2/UFS2).
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase3_oci_openbsd_boot \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase3_oci_openbsd_boot && tamago && amd64

package main

import (
	"errors"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
	"github.com/go-filesystems/ufs"
)

// openbsdBootTargetRef is the OCI artifact streaming source for the
// OpenBSD disk image. Empty = the probe fails closed (the runner is
// expected to publish a per-run image to ttl.sh and inject the ref
// via -X main.openbsdBootTargetRef= at link time).
var openbsdBootTargetRef = ""

// openbsdBootMaxImageSize caps the streamed image at 768 MiB so a
// misconfigured ref can't exhaust memory.
const openbsdBootMaxImageSize = 768 * 1024 * 1024

// openbsdBootEFIPath is the canonical UEFI fallback boot path. The
// runner extracts OpenBSD's amd64 bootx64.efi from the install media
// and lays it down here.
const openbsdBootEFIPath = "\\EFI\\BOOT\\BOOTX64.EFI"

// runOCIOpenBSDBootProbe is the entry point the dispatcher calls when
// the `phase3_oci_openbsd_boot` build tag is set.
func runOCIOpenBSDBootProbe() {
	println("phase3-oci-openbsd-boot: Sprint 3 MVP -- OCI stream + EFI_BLOCK_IO publish + ConnectController + LoadImage(bootx64.efi)")
	println("phase3-oci-openbsd-boot: arch =", runtime.GOARCH)

	if openbsdBootTargetRef == "" {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: no openbsdBootTargetRef configured (runner must override via -X linker flag)")
		return
	}
	println("phase3-oci-openbsd-boot: target =", openbsdBootTargetRef)

	pciIO := locateVirtioNetForOpenBSDBoot()
	if pciIO == 0 {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase3-oci-openbsd-boot: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase3-oci-openbsd-boot: lease acquired; IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: NewRootCAs:", perr.Error())
		return
	}

	ref, err := oci.ParseRef(openbsdBootTargetRef)
	if err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 180 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: Authenticate:", err.Error())
		return
	}

	rawManifest, _, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: FetchManifestRaw:", err.Error())
		return
	}
	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	println("phase3-oci-openbsd-boot: streaming disk image layer digest =", target.Digest)
	println("phase3-oci-openbsd-boot: streaming disk image layer size   =", int(target.Size))
	if target.Size > openbsdBootMaxImageSize {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: layer size exceeds 768 MiB cap")
		return
	}

	tailPad := 0
	if rem := int(target.Size) % int(uefiboard.BlockIOLogicalBlockSize); rem != 0 {
		tailPad = int(uefiboard.BlockIOLogicalBlockSize) - rem
	}
	imageBytes := make([]byte, int(target.Size)+tailPad)
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobToBuffer(target, imageBytes[:int(target.Size)])
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: FetchBlobToBuffer:", ferr.Error())
		println("phase3-oci-openbsd-boot: bytes-written-before-error =", int(n))
		return
	}
	println("phase3-oci-openbsd-boot: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase3-oci-openbsd-boot: streaming elapsed (ms) =", int(elapsedMS))
	if tailPad > 0 {
		println("phase3-oci-openbsd-boot: pre-padded image tail by", tailPad, "bytes for 512-aligned LastBlock")
	}
	if len(imageBytes) < 512 || imageBytes[510] != 0x55 || imageBytes[511] != 0xAA {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: streamed image missing MBR signature")
		return
	}
	if len(imageBytes) < 520 ||
		imageBytes[512] != 'E' || imageBytes[513] != 'F' || imageBytes[514] != 'I' || imageBytes[515] != ' ' ||
		imageBytes[516] != 'P' || imageBytes[517] != 'A' || imageBytes[518] != 'R' || imageBytes[519] != 'T' {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: streamed image missing 'EFI PART' GPT magic at LBA 1")
		return
	}
	println("phase3-oci-openbsd-boot: streamed image header OK (MBR 0x55AA + GPT 'EFI PART')")

	blkHandle, perr := uefiboard.PublishBlockIO(imageBytes)
	if perr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: PublishBlockIO:", perr.Error())
		return
	}
	println("phase3-oci-openbsd-boot: PublishBlockIO OK; block handle =", hexUintptrOpenBSD(blkHandle))

	if cerr := uefiboard.ConnectController(blkHandle); cerr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: ConnectController:", cerr.Error())
		return
	}
	println("phase3-oci-openbsd-boot: ConnectController OK (DiskIo/PartitionDxe/FatDxe binding done)")

	sfsHandles, lerr := uefiboard.LocateHandleBuffer(&uefiboard.EFISimpleFileSystemProtocolGUID)
	if lerr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: LocateHandleBuffer(SFS):", lerr.Error())
		return
	}
	println("phase3-oci-openbsd-boot: LocateHandleBuffer(SFS) found", len(sfsHandles), "total handle(s) (parent + siblings)")
	if len(sfsHandles) == 0 {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: firmware did not surface any SimpleFileSystem handle after ConnectController -- ESP probably not recognised")
		return
	}

	childHandle, childDP, ferr := uefiboard.FindSFSChildOf(blkHandle)
	if ferr != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: FindSFSChildOf:", ferr.Error())
		return
	}
	println("phase3-oci-openbsd-boot: matching SFS child handle =", hexUintptrOpenBSD(uintptr(childHandle)))
	println("phase3-oci-openbsd-boot: child device path length =", len(childDP), "bytes")

	childImage, lerr2 := uefiboard.LoadImageFromSFS(childDP, openbsdBootEFIPath)
	if lerr2 != nil {
		println("phase3-oci-openbsd-boot: OPENBSD-BOOT FAIL: LoadImageFromSFS:", lerr2.Error())
		return
	}
	println("phase3-oci-openbsd-boot: LoadImage(", openbsdBootEFIPath, ") OK; image handle =", hexUintptrOpenBSD(childImage))

	ufsBytes, uerr := findUFSPartitionBytes(imageBytes)
	if uerr != nil {
		if errors.Is(uerr, ErrNoUFSPartition) {
			println("phase3-oci-openbsd-boot: SFS-UFS skip: no UFS partition in GPT (sprint 3 FAT-only ESP image) -- architectural OK, OpenBSD loader may fail at /etc/boot.conf read")
		} else {
			println("phase3-oci-openbsd-boot: SFS-UFS skip: GPT parse error:", uerr.Error())
		}
	} else {
		ufsFS, ferr := ufs.Open(&sliceReaderAt{b: ufsBytes}, int64(len(ufsBytes)))
		if ferr != nil {
			println("phase3-oci-openbsd-boot: SFS-UFS skip: ufs.Open failed:", ferr.Error())
		} else {
			sfsHandle, perr := uefiboard.PublishSFS(0, ufsFS)
			if perr != nil {
				println("phase3-oci-openbsd-boot: SFS-UFS PublishSFS FAIL:", perr.Error())
			} else {
				println("phase3-oci-openbsd-boot: PublishSFS OK; UFS-backed SFS handle =", hexUintptrOpenBSD(sfsHandle))
				defer func() {
					if uerr := uefiboard.UnpublishSFS(sfsHandle); uerr != nil {
						println("phase3-oci-openbsd-boot: UnpublishSFS warning:", uerr.Error())
					}
				}()
			}
		}
	}

	println("phase3-oci-openbsd-boot: OPENBSD-BOOT CHAIN COMPLETE -- transferring control to bootx64.efi")
	if _, serr := uefiboard.StartImage(childImage); serr != nil {
		println("phase3-oci-openbsd-boot: StartImage returned:", serr.Error(), "-- bootx64.efi exited (sprint-3.x UFS root will let it boot a kernel)")
	} else {
		println("phase3-oci-openbsd-boot: StartImage returned EFI_SUCCESS -- bootx64.efi clean exit")
	}

	if uerr := uefiboard.UnpublishBlockIO(blkHandle); uerr != nil {
		println("phase3-oci-openbsd-boot: UnpublishBlockIO warning:", uerr.Error())
	}
}

// locateVirtioNetForOpenBSDBoot mirrors locateVirtioNetForFreeBSDBoot.
func locateVirtioNetForOpenBSDBoot() uint64 {
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

// hexUintptrOpenBSD is a local fmt-free hex renderer.
func hexUintptrOpenBSD(v uintptr) string {
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
