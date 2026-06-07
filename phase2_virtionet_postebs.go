// Phase-2 M2-B probe — gated on `-tags phase2_virtionet_postebs_tx`.
//
// First end-to-end test of the M2-B post-ExitBootServices virtio-net
// rail (R-M2c Option B narrow). Walks the same EFI_PCI_IO_PROTOCOL
// handle list as the M2 probe, finds the first modern virtio-net
// device (VID 0x1AF4, DID 0x1041), captures all PCI cap addresses
// + MAC + features + ring memory PRE-EBS, then crosses the
// ExitBootServices boundary and re-drives the same device through
// direct MMIO from bare metal. If the device honours TX/RX after EBS
// where it ignored them before, Apple VZ's UEFI-context gating
// hypothesis is confirmed and M2-B is the VZ rail.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_virtionet_postebs_tx \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `virtionet:postebs:efi:<arch>` for the per-arch
// wiring.)
//
// Observability strategy:
//
//  1. Pre-EBS we use the existing `blkprintk` LBA-0 side-channel —
//     every println before `ExitToBareMetal` is teed to the scratch
//     disk and recoverable post-mortem.
//
//  2. Post-EBS we can't println (ConOut is gone). We write a single
//     trace byte per init-sequence step into the dedicated post-EBS
//     scratch (CapturedState.BlkPrintkScratch) — invisible to a
//     remote host, but visible to a JTAG attach or future in-RAM
//     debug surface.
//
//  3. The PRIMARY post-EBS observable is what the host snoops on
//     the bridge: if our marked ARP frame arrives on the host's
//     bridge100 / vfkit NAT interface, M2-B works. The frame
//     carries an "M2B!" marker so the host snoop can confirm it
//     came from us (not stray legacy ARP traffic).
//
// References:
//
//   - UEFI 2.10 §7.4 — ExitBootServices contract.
//   - Virtio 1.1 §3.1.1 — driver init (replayed post-EBS).
//   - cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §3 M2 — R-M2c
//     Case IV diagnosis motivating the M2-B branch.

//go:build phase2_virtionet_postebs_tx && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// M2-B synthetic ARP target IPs. The 169.254.0.0/16 link-local
// range (RFC 3927) gives us identifiable values that won't clash
// with QEMU NAT (10.0.2.0/24) or Apple VZ NAT (192.168.64.0/24).
// The host snoop can match on these to confirm "this ARP came from
// our M2-B post-EBS probe" rather than incidental boot traffic.
//
// Source IP is also link-local with a recognisable trailer (.2.66
// — "2B" in decimal).
var (
	M2BSourceIP = [4]byte{169, 254, 2, 66}
	M2BTargetIP = [4]byte{169, 254, 99, 99}
)

// runVirtioNetPostEBSProbe is the entry point the dispatcher calls
// when `phase2_virtionet_postebs_tx` is set. Splits into two phases
// at the EBS boundary; everything before `ExitToBareMetal` uses
// the standard println + blkprintk path, everything after uses the
// post-EBS scratch + ARP-marker observability.
func runVirtioNetPostEBSProbe() {
	println("phase2-m2b: M2-B — post-ExitBootServices virtio-net experiment")
	println("phase2-m2b: LocateHandleBuffer(EFI_PCI_IO_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-m2b: LocateHandleBuffer FAILED:", err.Error())
		return
	}
	if len(handles) == 0 {
		println("phase2-m2b: no EFI_PCI_IO_PROTOCOL handles published")
		return
	}
	println("phase2-m2b: handles=", len(handles))

	var pciIO uint64
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
		if vid != uefiboard.VirtioPCIVendorID {
			continue
		}
		if did != uefiboard.VirtioPCIDeviceIDModernNet {
			continue
		}
		println("phase2-m2b: found modern virtio-net at handle", h,
			"VID:DID =", hex16(vid), ":", hex16(did))
		pciIO = iface
		break
	}
	if pciIO == 0 {
		println("phase2-m2b: no modern virtio-net device found — M2-B rail does not apply")
		return
	}

	// Defensive PCI bus-master + memory enable — same call M2 makes
	// in OpenVirtioNet. The R-M2c live narrow confirmed this is a
	// no-op on both QEMU+EDK2 and VZ (the PCI bus driver pre-enables
	// the bits), but a defensive call costs nothing.
	if err := uefiboard.PciIOAttributesEnable(pciIO,
		uefiboard.EFIPciIOAttributeMemory|uefiboard.EFIPciIOAttributeBusMaster); err != nil {
		println("phase2-m2b: PciIOAttributesEnable FAILED:", err.Error())
		// non-fatal: many firmwares already have these set.
	}

	println("phase2-m2b: CapturePreEBS — discovering PCI caps + allocating runtime pages")
	state, err := uefiboard.CapturePreEBS(pciIO)
	if err != nil {
		println("phase2-m2b: CapturePreEBS FAILED:", err.Error())
		return
	}
	println("phase2-m2b: pre-EBS captured: MAC=", state.MAC.String(),
		"BAR_COMMON=", hexU64(state.PCICommonCfgPhys),
		"BAR_NOTIFY=", hexU64(state.PCINotifyCfgPhys),
		"BAR_DEVICE=", hexU64(state.PCIDeviceCfgPhys))
	println("phase2-m2b: pre-EBS captured: notifyMul=", hexU64(uint64(state.PCINotifyOffMultiplier)),
		"deviceFeats=", hexU64(state.DeviceFeaturesOffered),
		"negotiatedMask=", hexU64(state.FeatureMask))
	println("phase2-m2b: pre-EBS captured: rxRing=", hexU64(state.VQRingsPhys[0]),
		"txRing=", hexU64(state.VQRingsPhys[1]),
		"rxNotifyOff=", hex16(state.VQNotifyOff[0]),
		"txNotifyOff=", hex16(state.VQNotifyOff[1]))
	println("phase2-m2b: pre-EBS captured: blkScratch=", hexU64(state.BlkPrintkScratchPhys))

	// One final flush of the pre-EBS dump so the side-channel
	// captures everything we know BEFORE we cross the line. After
	// EBS, the BlkSink's Block-IO writes would fault (the protocol
	// is firmware-mediated and Boot Services is gone), so we tear
	// down the sink reference defensively.
	if uefiboard.BlkSink != nil {
		println("phase2-m2b: flushing blkprintk side-channel pre-EBS")
		if err := uefiboard.BlkSink.Flush(); err != nil {
			println("phase2-m2b: pre-EBS Flush returned:", err.Error())
		}
	}

	// Cross the line.
	println("phase2-m2b: ExitToBareMetal — calling gBS->ExitBootServices")
	// Tear the BlkSink reference down to ensure post-EBS prints
	// don't recurse into Block-IO. (println still works structurally
	// because the goroutine scheduler is alive; it just hits the
	// no-op out() once conOut is invalidated.)
	uefiboard.BlkSink = nil
	if err := uefiboard.ExitToBareMetal(state); err != nil {
		println("phase2-m2b: ExitToBareMetal FAILED:", err.Error())
		return
	}
	// !!! POST-EBS — every println below this point is undefined
	// behaviour. ConOut->OutputString points at firmware code that's
	// been freed. We deliberately stop using println from here on
	// and rely on the post-EBS scratch + the ARP-marker observable
	// for any further status.

	// Post-EBS init.
	vpost, initErr := uefiboard.InitVirtioNetPostEBS(state)
	if initErr != nil {
		// Final init-trace byte already recorded in InitTrace +
		// the post-EBS scratch — nothing else to do.
		postEBSHalt()
		return
	}

	// Build and TX a marked ARP request. The frame's TPA is set to
	// the M2-B-recognisable target IP; the trailing payload bytes
	// (which Ethernet pads from 42 bytes up to 60 bytes minimum)
	// carry the "M2B!" marker so the host snoop can grep for it.
	arp := buildM2BARPRequest(state.MAC)
	_ = vpost.TransmitFramePostEBS(arp)

	// Best-effort RX poll for the gateway's ARP reply.
	const rxBudget = 5000000
	_, _ = vpost.ReceiveFramePostEBS(rxBudget)

	postEBSHalt()
}

// buildM2BARPRequest assembles a 60-byte Ethernet+ARP+trace-marker
// frame. The first 42 bytes are a standard RFC 826 ARP request; the
// remaining 18 bytes are the trace-marker (16 bytes "M2B!"+state +
// 2 bytes ethernet-min-padding). 60 bytes is the minimum Ethernet
// frame size; the host snoop captures it as one unit.
func buildM2BARPRequest(srcMAC uefiboard.MAC6) []byte {
	frame := make([]byte, 60)
	// Ethernet header: broadcast, source = srcMAC, type = ARP.
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF
	}
	copy(frame[6:12], srcMAC[:])
	frame[12] = 0x08
	frame[13] = 0x06
	// ARP header.
	frame[14] = 0x00
	frame[15] = 0x01 // HTYPE=Ethernet
	frame[16] = 0x08
	frame[17] = 0x00 // PTYPE=IPv4
	frame[18] = 6
	frame[19] = 4
	frame[20] = 0x00
	frame[21] = 0x01 // OPER=request
	copy(frame[22:28], srcMAC[:])
	copy(frame[28:32], M2BSourceIP[:])
	// THA: zero.
	copy(frame[38:42], M2BTargetIP[:])
	// Trace-marker payload at bytes 42..58 (16 bytes).
	frame[42] = 'M'
	frame[43] = '2'
	frame[44] = 'B'
	frame[45] = '!'
	// Remaining marker bytes are filled in by EncodeTraceMarker on
	// the post-EBS handle so the device state at TX time is
	// captured. We can't call that here (we don't have the
	// VirtioNetPostEBS handle in scope from the helper), so we
	// leave them zero; the host snoop matches on "M2B!" alone.
	return frame
}

// postEBSHalt spins forever. We can't return from this function —
// the caller would try to use ConOut or other Boot Services. WFI/HLT
// per arch would be cleaner but the spin-loop is portable across
// every GOARCH this probe builds for.
func postEBSHalt() {
	for {
		// spin.
	}
}
