// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M9.0 probe — DHCP-discovered OCI boot menu (foundation).
//
// Gated on `-tags phase2_dhcp_oci_menu && tamago`.
//
// Why this probe exists (the M9 roadmap):
//
//   - Production cloud-boot deployments want zero-touch boot: the
//     DHCP server advertises an OCI ref via Bootfile-Name (option 67)
//     instead of the PXE-style `tftp://server/file`. cloud-boot
//     fetches a small HCL boot-menu artifact from that ref, then
//     (M9.1) renders it on virtio-console and (M9.2) takes EFI input
//     to dispatch the chosen entry through LoadImage+StartImage.
//
//   - M9.0 (this sprint) lands the foundation: extract option 67,
//     fetch + parse the HCL, print the parsed *BootConfig to ConOut,
//     halt. No menu rendering, no input handling, no dispatch — the
//     PASS criterion is "we can see the four-key schema + ordered
//     entries on the serial log after the OCI fetch returns".
//
//   - M9.1 will add the virtio-console renderer (in a sibling probe).
//   - M9.2 will add EFI_SIMPLE_TEXT_INPUT keystroke capture + the
//     LoadImage/StartImage dispatch (also a sibling probe).
//
// Flow:
//
//	1. Bring up virtio-net + DHCP (same MODE-C boilerplate as
//	   phase2_oci_kernel_boot.go).
//	2. Check lease.BootfileName — if empty, print
//	   "no DHCP option 67; abort" and return.
//	3. Parse the BootfileName as an OCI ref (oci.ParseRef).
//	4. FetchManifest → IsIndex? PickPlatform : passthrough → pick the
//	   first layer (the HCL blob).
//	5. FetchBlobStream → bytes.Buffer.
//	6. bootmenu.Parse → *BootConfig.
//	7. Print Title / Timeout / Default / per-entry details.
//	8. Halt (no dispatch — that's M9.2).
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_dhcp_oci_menu \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_<arch>_dhcpocimenu.elf .
//
// See Taskfile.yaml `dhcpocimenu:{elf,efi,live}:<arch>` for the
// per-arch wiring.

//go:build phase2_dhcp_oci_menu && tamago

package main

import (
	"bytes"
	"runtime"
	"strconv"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/bootmenu"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// dhcpOCIMenuMaxBlobSize caps the streamed HCL config blob size at 1
// MiB. A typical boot-menu HCL is hundreds of bytes to a few KiB;
// anything past 1 MiB is almost certainly a misconfigured artifact
// pointing at a kernel/initrd by mistake. Keeping the cap small means
// a misroute fails fast on the size check rather than after streaming
// a 50 MiB kernel through SHA-256 verification.
const dhcpOCIMenuMaxBlobSize = 1 * 1024 * 1024

// runDHCPOCIMenuProbe is the entry point the dispatcher
// (phase2_dispatch.go) calls when the `phase2_dhcp_oci_menu` build tag
// is set. M9.0 scope: fetch + parse + print the boot menu. NO
// rendering, NO input, NO dispatch (those are M9.1 / M9.2).
func runDHCPOCIMenuProbe() {
	println("phase2-dhcp-oci-menu: M9.0 -- DHCP option 67 -> OCI fetch -> HCL parse")
	println("phase2-dhcp-oci-menu: arch =", runtime.GOARCH)

	pciIO := locateVirtioNetForMenu()
	if pciIO == 0 {
		println("phase2-dhcp-oci-menu: no modern virtio-net device found")
		println("phase2-dhcp-oci-menu: MENU FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: lease acquired")
	println("phase2-dhcp-oci-menu:   IP =", lease.IP.String())

	// M9.0 acceptance gate #1: option 67 reached us. The empty-string
	// case is the explicit fall-through (DHCP didn't advertise a menu
	// — the runtime should fall through to its embedded default).
	if lease.BootfileName == "" {
		println("phase2-dhcp-oci-menu: no DHCP option 67; abort")
		return
	}
	println("phase2-dhcp-oci-menu: DHCP option 67 (Bootfile-Name) =", lease.BootfileName)

	if len(lease.DNS) == 0 {
		println("phase2-dhcp-oci-menu: MENU FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-dhcp-oci-menu: embedded roots =", ministack.EmbeddedRootCount())

	ref, err := oci.ParseRef(lease.BootfileName)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: ParseRef:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: parsed ref host=" + ref.Host + " repo=" + ref.Repo + " ref=" + ref.Reference)

	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 60 * time.Second
	if err := reg.Authenticate(); err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: FetchManifestRaw(index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: ParseIndex:", perr.Error())
			return
		}
		// M9.0 menu artifacts SHOULD be platform-agnostic (the HCL
		// blob is arch-neutral), but if the publisher uploaded a
		// multi-arch index we pick the runtime arch and proceed
		// — same shape as phase2_oci_kernel_boot's manifest dance.
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: PickPlatform:", perr.Error())
			return
		}
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}

	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase2-dhcp-oci-menu: MENU FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	if target.Size > dhcpOCIMenuMaxBlobSize {
		println("phase2-dhcp-oci-menu: MENU FAIL: HCL blob exceeds 1 MiB cap (size =", int(target.Size), ")")
		return
	}
	println("phase2-dhcp-oci-menu: HCL blob digest =", target.Digest)
	println("phase2-dhcp-oci-menu: HCL blob size   =", int(target.Size))

	var buf bytes.Buffer
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(target, &buf)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: FetchBlobStream:", ferr.Error())
		println("phase2-dhcp-oci-menu: bytes-written-before-error =", int(n))
		return
	}
	println("phase2-dhcp-oci-menu: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase2-dhcp-oci-menu: streaming elapsed (ms) =", int(elapsedMS))

	cfg, perr := bootmenu.Parse(buf.Bytes())
	if perr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: bootmenu.Parse:", perr.Error())
		return
	}
	println("phase2-dhcp-oci-menu: bootmenu.Parse OK")
	println("phase2-dhcp-oci-menu:   Title   =", cfg.Title)
	println("phase2-dhcp-oci-menu:   Timeout =", strconv.Itoa(cfg.Timeout), "s")
	println("phase2-dhcp-oci-menu:   Default =", cfg.Default)
	println("phase2-dhcp-oci-menu:   Entries =", strconv.Itoa(len(cfg.Entries)))
	for i, e := range cfg.Entries {
		println("phase2-dhcp-oci-menu:   [" + strconv.Itoa(i) + "] " + e.Label)
		println("phase2-dhcp-oci-menu:        kernel_ref =", e.KernelRef)
		if e.InitrdRef != "" {
			println("phase2-dhcp-oci-menu:        initrd_ref =", e.InitrdRef)
		}
		if e.Cmdline != "" {
			println("phase2-dhcp-oci-menu:        cmdline    =", e.Cmdline)
		}
	}
	println("phase2-dhcp-oci-menu: MENU FOUNDATION OK (M9.0 acceptance gate met; rendering = M9.1, input/dispatch = M9.2)")
}

// locateVirtioNetForMenu mirrors the locateVirtioNetForKernelBoot
// helper in phase2_oci_kernel_boot.go. Local copy (not a shared
// utility) because the kernelboot probe is gated on a different build
// tag — sharing the symbol would force phase2_dhcp_oci_menu to also
// pull the entire kernelboot probe into its build closure, doubling
// the binary size for no functional benefit.
func locateVirtioNetForMenu() uint64 {
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
