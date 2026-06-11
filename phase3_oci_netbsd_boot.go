// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-3 sprint-3 probe — OS-agnostic OCI boot, NetBSD MVP.
// Gated on `-tags phase3_oci_netbsd_boot && tamago && amd64`.
//
// Strategy: structurally identical to phase2_oci_freebsd_boot.go
// (sprint 1+1.1+1.2+2A+2B+2C-Integration+2D+2D''). NetBSD uses the
// same FFS family as FreeBSD on-disk; modern NetBSD (>= 5.0, 2009)
// defaults to FFSv2 / UFS2 — the same on-disk format that
// go-filesystems/ufs reads. So the same Block IO + ConnectController
// + SFS + UFS path applies.
//
// Per-OS divergences captured here:
//
//   - OCI ref: a separate per-run ttl.sh push of a NetBSD bootable
//     disk image (typically synthesised from a NetBSD release ISO —
//     see internal/livenetbsdboot/run.sh).
//   - EFI binary path on the ESP: \EFI\BOOT\BOOTX64.EFI (the UEFI
//     fallback boot path, same as FreeBSD). NetBSD's amd64 EFI loader
//     ships as bootx64.efi inside the standard NetBSD distribution
//     and is laid down at the canonical fallback path by the runner.
//   - Boot configuration: NetBSD reads /boot.cfg from the root file
//     system (FFS) at loader runtime; we don't synthesise one in
//     sprint 3 (architectural scaffolding only — runner builds a
//     FAT-ESP image carrying just the loader for now, matching the
//     FreeBSD sprint-1.2 stepping stone).
//
// Sprint 3 explicit out-of-scope:
//   - arm64/riscv64/loong64 (publisher trampolines are amd64-only).
//   - NetBSD multi-user (sprint 3.x; mirrors FreeBSD sprint 2E/2F).
//   - UFS1 backward compatibility (sprint 3.5 if any cloud image
//     ships pre-5.0 FFSv1; modern releases are UFS2).
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase3_oci_netbsd_boot \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase3_oci_netbsd_boot && tamago && amd64

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

// netbsdBootTargetRef is the OCI artifact streaming source for the
// NetBSD disk image. Empty = the probe fails closed (the runner is
// expected to publish a per-run image to ttl.sh and inject the ref
// via -X main.netbsdBootTargetRef= at link time, same pattern as the
// FreeBSD probe's freebsdBootTargetRef).
var netbsdBootTargetRef = ""

// netbsdBootMaxImageSize caps the streamed image at 768 MiB so a
// misconfigured ref can't exhaust memory. The synthesised ESP-only
// image is ~16 MiB; a full NetBSD release ISO is ~500 MiB.
const netbsdBootMaxImageSize = 768 * 1024 * 1024

// netbsdBootEFIPath is the canonical UEFI fallback boot path the FAT
// ESP must contain. The runner extracts NetBSD's amd64 EFI loader
// (bootx64.efi inside the NetBSD distribution) and lays it down here.
const netbsdBootEFIPath = "\\EFI\\BOOT\\BOOTX64.EFI"

// runOCINetBSDBootProbe is the entry point the dispatcher calls when
// the `phase3_oci_netbsd_boot` build tag is set.
func runOCINetBSDBootProbe() {
	println("phase3-oci-netbsd-boot: Sprint 3 MVP -- OCI stream + EFI_BLOCK_IO publish + ConnectController + LoadImage(bootx64.efi)")
	println("phase3-oci-netbsd-boot: arch =", runtime.GOARCH)

	if netbsdBootTargetRef == "" {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: no netbsdBootTargetRef configured (runner must override via -X linker flag)")
		return
	}
	println("phase3-oci-netbsd-boot: target =", netbsdBootTargetRef)

	pciIO := locateVirtioNetForNetBSDBoot()
	if pciIO == 0 {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase3-oci-netbsd-boot: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase3-oci-netbsd-boot: lease acquired; IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: NewRootCAs:", perr.Error())
		return
	}

	ref, err := oci.ParseRef(netbsdBootTargetRef)
	if err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 180 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: Authenticate:", err.Error())
		return
	}

	rawManifest, _, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: FetchManifestRaw:", err.Error())
		return
	}
	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	println("phase3-oci-netbsd-boot: streaming disk image layer digest =", target.Digest)
	println("phase3-oci-netbsd-boot: streaming disk image layer size   =", int(target.Size))
	if target.Size > netbsdBootMaxImageSize {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: layer size exceeds 768 MiB cap")
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
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: FetchBlobToBuffer:", ferr.Error())
		println("phase3-oci-netbsd-boot: bytes-written-before-error =", int(n))
		return
	}
	println("phase3-oci-netbsd-boot: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase3-oci-netbsd-boot: streaming elapsed (ms) =", int(elapsedMS))
	if tailPad > 0 {
		println("phase3-oci-netbsd-boot: pre-padded image tail by", tailPad, "bytes for 512-aligned LastBlock")
	}
	if len(imageBytes) < 512 || imageBytes[510] != 0x55 || imageBytes[511] != 0xAA {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: streamed image missing MBR signature")
		return
	}
	if len(imageBytes) < 520 ||
		imageBytes[512] != 'E' || imageBytes[513] != 'F' || imageBytes[514] != 'I' || imageBytes[515] != ' ' ||
		imageBytes[516] != 'P' || imageBytes[517] != 'A' || imageBytes[518] != 'R' || imageBytes[519] != 'T' {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: streamed image missing 'EFI PART' GPT magic at LBA 1")
		return
	}
	println("phase3-oci-netbsd-boot: streamed image header OK (MBR 0x55AA + GPT 'EFI PART')")

	blkHandle, perr := uefiboard.PublishBlockIO(imageBytes)
	if perr != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: PublishBlockIO:", perr.Error())
		return
	}
	println("phase3-oci-netbsd-boot: PublishBlockIO OK; block handle =", hexUintptrNetBSD(blkHandle))

	if cerr := uefiboard.ConnectController(blkHandle); cerr != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: ConnectController:", cerr.Error())
		return
	}
	println("phase3-oci-netbsd-boot: ConnectController OK (DiskIo/PartitionDxe/FatDxe binding done)")

	sfsHandles, lerr := uefiboard.LocateHandleBuffer(&uefiboard.EFISimpleFileSystemProtocolGUID)
	if lerr != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: LocateHandleBuffer(SFS):", lerr.Error())
		return
	}
	println("phase3-oci-netbsd-boot: LocateHandleBuffer(SFS) found", len(sfsHandles), "total handle(s) (parent + siblings)")
	if len(sfsHandles) == 0 {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: firmware did not surface any SimpleFileSystem handle after ConnectController -- ESP probably not recognised")
		return
	}

	childHandle, childDP, ferr := uefiboard.FindSFSChildOf(blkHandle)
	if ferr != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: FindSFSChildOf:", ferr.Error())
		return
	}
	println("phase3-oci-netbsd-boot: matching SFS child handle =", hexUintptrNetBSD(uintptr(childHandle)))
	println("phase3-oci-netbsd-boot: child device path length =", len(childDP), "bytes")

	childImage, lerr2 := uefiboard.LoadImageFromSFS(childDP, netbsdBootEFIPath)
	if lerr2 != nil {
		println("phase3-oci-netbsd-boot: NETBSD-BOOT FAIL: LoadImageFromSFS:", lerr2.Error())
		return
	}
	println("phase3-oci-netbsd-boot: LoadImage(", netbsdBootEFIPath, ") OK; image handle =", hexUintptrNetBSD(childImage))

	// Sprint 3: NetBSD FFSv2 is on-disk-compatible with FreeBSD UFS2,
	// so go-filesystems/ufs can read it as-is. We probe for a UFS-typed
	// GPT partition the same way the FreeBSD path does — if a NetBSD
	// release image carries a UFS slice (rather than just a FAT ESP)
	// we publish it as a child SFS so the NetBSD loader's /boot.cfg
	// read and kernel pulls can land there. Sprint 3 runner ships an
	// ESP-only image (no UFS), so this path architectural-skips —
	// same stepping-stone shape as FreeBSD sprint 1.2.
	ufsBytes, uerr := findUFSPartitionBytes(imageBytes)
	if uerr != nil {
		if errors.Is(uerr, ErrNoUFSPartition) {
			println("phase3-oci-netbsd-boot: SFS-UFS skip: no UFS partition in GPT (sprint 3 FAT-only ESP image) -- architectural OK, NetBSD loader may fail at /boot.cfg read")
		} else {
			println("phase3-oci-netbsd-boot: SFS-UFS skip: GPT parse error:", uerr.Error())
		}
	} else {
		ufsFS, ferr := ufs.Open(&sliceReaderAt{b: ufsBytes}, int64(len(ufsBytes)))
		if ferr != nil {
			println("phase3-oci-netbsd-boot: SFS-UFS skip: ufs.Open failed:", ferr.Error())
		} else {
			sfsHandle, perr := uefiboard.PublishSFS(0, ufsFS)
			if perr != nil {
				println("phase3-oci-netbsd-boot: SFS-UFS PublishSFS FAIL:", perr.Error())
			} else {
				println("phase3-oci-netbsd-boot: PublishSFS OK; UFS-backed SFS handle =", hexUintptrNetBSD(sfsHandle))
				defer func() {
					if uerr := uefiboard.UnpublishSFS(sfsHandle); uerr != nil {
						println("phase3-oci-netbsd-boot: UnpublishSFS warning:", uerr.Error())
					}
				}()
			}
		}
	}

	println("phase3-oci-netbsd-boot: NETBSD-BOOT CHAIN COMPLETE -- transferring control to bootx64.efi")
	if _, serr := uefiboard.StartImage(childImage); serr != nil {
		println("phase3-oci-netbsd-boot: StartImage returned:", serr.Error(), "-- bootx64.efi exited (sprint-3.x UFS root will let it boot a kernel)")
	} else {
		println("phase3-oci-netbsd-boot: StartImage returned EFI_SUCCESS -- bootx64.efi clean exit")
	}

	if uerr := uefiboard.UnpublishBlockIO(blkHandle); uerr != nil {
		println("phase3-oci-netbsd-boot: UnpublishBlockIO warning:", uerr.Error())
	}
}

// locateVirtioNetForNetBSDBoot mirrors locateVirtioNetForFreeBSDBoot.
// Symbol kept local to avoid clashing with any other locate helpers
// when multiple build tags coexist.
func locateVirtioNetForNetBSDBoot() uint64 {
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

// hexUintptrNetBSD is a local fmt-free hex renderer (mirror of
// hexUintptrFreeBSD).
func hexUintptrNetBSD(v uintptr) string {
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
