// Phase-2 M2-A probe — gated on `-tags phase2_virtionet_packed_tx`.
//
// First end-to-end test of the pure-Go virtio-net rail on the
// packed-virtqueue transport (Virtio 1.1 §2.7). R-M2c Option A
// experiment: hypothesis is that Apple VZ's host-side virtio-net
// dispatch ONLY runs when the client negotiates RING_PACKED — Linux
// VZ virtio-net is known to default to packed-ring; the M2 split-ring
// path may simply not be on the VZ dispatch path.
//
// Locates the first EFI_PCI_IO_PROTOCOL handle that publishes
// vendor 0x1AF4 + device 0x1041 (modern virtio-net), brings the
// device up through the full Virtio 1.1 §3.1.1 init sequence with
// the `VirtioNetAcceptedFeaturesWithPacked` mask (which acks bit 34),
// confirms VIRTIO_F_RING_PACKED actually negotiated (vs being silently
// stripped by the device), transmits one ARP request frame, and polls
// the receive queue for a reply.
//
// `phase2_virtionet_packed_tx` IMPLIES `phase2_blkprintk` (the
// Taskfile sets both when building BOOT*-VIRTIONETP.EFI), so the
// dispatcher (phase2_dispatch.go) wires the Block IO side-channel
// for VZ observability. The probe doesn't print to ConOut
// differently; the M1.6 tee captures everything.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_virtionet_packed_tx \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `virtionetp:efi:<arch>` for the per-arch wiring.)
//
// QEMU validation: QEMU only serves packed-ring when the device is
// instantiated with `packed=on`:
//
//	qemu-system-x86_64 ... \
//	    -device virtio-net-pci,disable-legacy=on,disable-modern=off,packed=on,...
//
// Without `packed=on`, QEMU will offer bit 34 = 0 (default split) and
// the M2-A probe will report "device did NOT negotiate RING_PACKED" —
// which is the expected diagnostic, not a failure.

//go:build phase2_virtionet_packed_tx && tamago

package main

import (
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// VirtioNetPackedTxQEMUSourceIP / Target — same default QEMU NAT
// layout as the split-ring probe; on VZ the second pair is used.
var (
	VirtioNetPackedTxQEMUSourceIP = [4]byte{10, 0, 2, 15}
	VirtioNetPackedTxQEMUTargetIP = [4]byte{10, 0, 2, 2}
	VirtioNetPackedTxVZSourceIP   = [4]byte{192, 168, 64, 2}
	VirtioNetPackedTxVZTargetIP   = [4]byte{192, 168, 64, 1}
)

// runVirtioNetPackedTxProbe is the entry point the dispatcher calls
// when the build tag is set. It enumerates EFI_PCI_IO_PROTOCOL
// handles, finds the first virtio-net (1AF4:1041 modern), brings it
// up via the WITH_PACKED accepted-features mask, verifies
// VIRTIO_F_RING_PACKED actually negotiated, transmits two ARP
// requests (one per probable NAT layout), polls for replies, and
// prints a summary.
func runVirtioNetPackedTxProbe() {
	println("phase2-virtionet-packed-tx: M2-A — pure-Go virtio-net rail (packed-ring)")
	println("phase2-virtionet-packed-tx: LocateHandleBuffer(EFI_PCI_IO_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-virtionet-packed-tx: LocateHandleBuffer FAILED:", err.Error())
		return
	}
	if len(handles) == 0 {
		println("phase2-virtionet-packed-tx: no EFI_PCI_IO_PROTOCOL handles published")
		return
	}
	println("phase2-virtionet-packed-tx: handles=", len(handles))

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
		println("phase2-virtionet-packed-tx: found modern virtio-net at handle", h,
			"VID:DID =", hex16(vid), ":", hex16(did))
		pciIO = iface
		break
	}
	if pciIO == 0 {
		println("phase2-virtionet-packed-tx: no modern virtio-net device found among",
			len(handles), "handles — M2-A rail does not apply to this hypervisor")
		return
	}

	// Diagnostic dump — the device-offered feature bitmap before
	// the init runs. Helps the host distinguish "device doesn't
	// offer bit 34 at all" (QEMU without `packed=on`) from "device
	// offers it but won't negotiate it" (FEATURES_OK clears).
	if diagCfg, derr := uefiboard.InitVirtioModernConfig(pciIO); derr == nil {
		_ = diagCfg.SetDeviceStatus(0)
		_ = diagCfg.SetDeviceStatus(uefiboard.VirtioStatusAcknowledge | uefiboard.VirtioStatusDriver)
		if feats, ferr := diagCfg.DeviceFeatures64(); ferr == nil {
			lo := uint32(feats & 0xFFFFFFFF)
			hi := uint32(feats >> 32)
			println("phase2-virtionet-packed-tx: vnet device feats: lo=", hex32(lo), "hi=", hex32(hi))
			if feats&uefiboard.VirtioFeatureRingPacked != 0 {
				println("phase2-virtionet-packed-tx: device OFFERS VIRTIO_F_RING_PACKED (bit 34)")
			} else {
				println("phase2-virtionet-packed-tx: device does NOT offer VIRTIO_F_RING_PACKED (bit 34) — packed path will be unused; falling through")
			}
		}
		_ = diagCfg.SetDeviceStatus(0)
	}

	println("phase2-virtionet-packed-tx: bringing up device (init sequence per Virtio 1.1 §3.1.1, WITH_PACKED mask)")
	v, err := uefiboard.OpenVirtioNetWithFeatures(pciIO, uefiboard.VirtioNetAcceptedFeaturesWithPacked)
	if err != nil {
		println("phase2-virtionet-packed-tx: OpenVirtioNetWithFeatures FAILED:", err.Error())
		return
	}
	println("phase2-virtionet-packed-tx: device UP. MAC =", v.MAC.String())
	println("phase2-virtionet-packed-tx: negotiated features (hex) =", hexU64(v.NegotiatedFeatures))
	if v.UsePacked() {
		println("phase2-virtionet-packed-tx: *** PACKED-RING TRANSPORT ENABLED ***")
	} else {
		println("phase2-virtionet-packed-tx: split-ring transport (device did NOT negotiate RING_PACKED)")
	}

	if v.UsePacked() {
		prxq := v.PackedRxQueue()
		ptxq := v.PackedTxQueue()
		if prxq != nil && ptxq != nil {
			println("phase2-virtionet-packed-tx: notify cfg: BAR=", uint64(v.Cfg.NotifyCfgBAR),
				"offset=", hexU64(v.Cfg.NotifyCfgOffset),
				"length=", hexU64(uint64(v.Cfg.NotifyCfgLength)),
				"multiplier=", hexU64(uint64(v.Cfg.NotifyOffMultiplier)))
			println("phase2-virtionet-packed-tx: prxq notify_off=", hex16(prxq.NotifyOff),
				"doorbell BAR-offset=", hexU64(v.Cfg.PerQueueNotifyOffset(prxq.NotifyOff)),
				"layout size=", uint64(prxq.Layout.Size),
				"base phys=", hexU64(prxq.BasePhys),
				"driver wrap=", uint64(prxq.DriverWrapCounter()),
				"device wrap=", uint64(prxq.DeviceWrapCounter()))
			println("phase2-virtionet-packed-tx: ptxq notify_off=", hex16(ptxq.NotifyOff),
				"doorbell BAR-offset=", hexU64(v.Cfg.PerQueueNotifyOffset(ptxq.NotifyOff)),
				"layout size=", uint64(ptxq.Layout.Size),
				"base phys=", hexU64(ptxq.BasePhys),
				"driver wrap=", uint64(ptxq.DriverWrapCounter()),
				"device wrap=", uint64(ptxq.DeviceWrapCounter()))
			println("phase2-virtionet-packed-tx: ptxq Layout: DescRingOff=", uint64(ptxq.Layout.DescRingOffset),
				"DriverEventOff=", uint64(ptxq.Layout.DriverEventOffset),
				"DeviceEventOff=", uint64(ptxq.Layout.DeviceEventOffset),
				"TotalSize=", uint64(ptxq.Layout.TotalSize))
		}
	}

	// Emit the QEMU-flavoured ARP first via TransmitFrame (which
	// internally dispatches packed vs split based on `usePacked`).
	arpQEMU := buildPackedARPRequest(v.MAC, VirtioNetPackedTxQEMUSourceIP, VirtioNetPackedTxQEMUTargetIP)
	println("phase2-virtionet-packed-tx: TX ARP request (QEMU NAT, 10.0.2.15 -> 10.0.2.2), len =", len(arpQEMU))
	if err := v.TransmitFrame(arpQEMU); err != nil {
		println("phase2-virtionet-packed-tx: TransmitFrame(QEMU) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-packed-tx: TX OK (QEMU)")
	}

	// VZ-flavoured one — route through the diagnostic helper that
	// dumps descriptor/event-region state around the TX.
	arpVZ := buildPackedARPRequest(v.MAC, VirtioNetPackedTxVZSourceIP, VirtioNetPackedTxVZTargetIP)
	println("phase2-virtionet-packed-tx: TX ARP request (VZ NAT, 192.168.64.2 -> 192.168.64.1), len =", len(arpVZ))
	if err := packedTransmitFrameDiag(v, arpVZ); err != nil {
		println("phase2-virtionet-packed-tx: packedTransmitFrameDiag(VZ) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-packed-tx: TX OK (VZ)")
	}

	// Poll for ARP reply.
	const pollBudget = 500000
	println("phase2-virtionet-packed-tx: polling RX for up to", pollBudget, "iterations...")
	for attempt := 0; attempt < 3; attempt++ {
		frame, err := v.ReceiveFrame(pollBudget)
		if err != nil {
			println("phase2-virtionet-packed-tx: RX attempt", attempt, "timed out:", err.Error())
			break
		}
		println("phase2-virtionet-packed-tx: RX attempt", attempt, "got frame, len =", len(frame))
		dumpPackedFrame(frame)
	}
	println("phase2-virtionet-packed-tx: probe complete")
}

// buildPackedARPRequest mirrors the split-ring probe's
// buildARPRequest exactly (IETF RFC 826 layout); duplicated here so
// the M2-A probe has no dependency on the M2 probe file.
func buildPackedARPRequest(srcMAC uefiboard.MAC6, srcIP [4]byte, dstIP [4]byte) []byte {
	frame := make([]byte, 42)
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF
	}
	copy(frame[6:12], srcMAC[:])
	frame[12] = 0x08
	frame[13] = 0x06
	frame[14] = 0x00
	frame[15] = 0x01
	frame[16] = 0x08
	frame[17] = 0x00
	frame[18] = 6
	frame[19] = 4
	frame[20] = 0x00
	frame[21] = 0x01
	copy(frame[22:28], srcMAC[:])
	copy(frame[28:32], srcIP[:])
	copy(frame[38:42], dstIP[:])
	return frame
}

// packedTransmitFrameDiag is an instrumented copy of
// `(*VirtioNet).TransmitFrame`'s packed path that dumps the
// descriptor + event-region state before and after notify + every
// 1000 poll iterations. Exposed via the M1.6 blkprintk side-channel.
func packedTransmitFrameDiag(v *uefiboard.VirtioNet, frame []byte) error {
	if !v.UsePacked() {
		// Diagnostic helper only meaningful on packed-ring; fall
		// back to the production TransmitFrame for split-ring.
		return v.TransmitFrame(frame)
	}
	ptxq := v.PackedTxQueue()
	if ptxq == nil {
		println("phase2-virtionet-packed-tx: diag: ptxq is nil")
		return nil
	}
	totalLen := uefiboard.VirtioNetHdrSize + len(frame)
	phys, addr, err := uefiboard.AllocDMABuffer(uintptr(totalLen))
	if err != nil {
		return err
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), totalLen)
	copy(dst[uefiboard.VirtioNetHdrSize:], frame)
	println("phase2-virtionet-packed-tx: diag: DMA buf phys=", hexU64(phys), "len=", uint64(totalLen))

	preNextAvail := ptxq.NextAvail()
	preLastUsed := ptxq.LastUsed()
	preDriverWrap := ptxq.DriverWrapCounter()
	preDeviceWrap := ptxq.DeviceWrapCounter()
	println("phase2-virtionet-packed-tx: diag: pre-AddBuffer: nextAvail=", hex16(preNextAvail),
		"lastUsed=", hex16(preLastUsed),
		"driverWrap=", uint64(preDriverWrap),
		"deviceWrap=", uint64(preDeviceWrap))

	descIdx, err := ptxq.AddBuffer(addr, phys, uint32(totalLen), false)
	if err != nil {
		return err
	}
	println("phase2-virtionet-packed-tx: diag: AddBuffer descIdx=", hex16(descIdx),
		"nextAvail=", hex16(ptxq.NextAvail()),
		"driverWrap=", uint64(ptxq.DriverWrapCounter()))

	dumpPackedHexBytes("desc[descIdx] (pre-notify)=", ptxq.PackedDescBytes(descIdx))
	dumpPackedHexBytes("drvEvent (pre-notify)=", ptxq.DriverEventBytes())
	dumpPackedHexBytes("devEvent (pre-notify)=", ptxq.DeviceEventBytes())

	doorbellOff := v.Cfg.PerQueueNotifyOffset(ptxq.NotifyOff)
	println("phase2-virtionet-packed-tx: diag: doorbell write: BAR=", uint64(v.Cfg.NotifyCfgBAR),
		"offset=", hexU64(doorbellOff), "value=", hex16(uefiboard.VirtioNetTxQueueIdx))

	if err := v.Cfg.NotifyQueue(uefiboard.VirtioNetTxQueueIdx, ptxq.NotifyOff); err != nil {
		println("phase2-virtionet-packed-tx: diag: NotifyQueue FAILED:", err.Error())
		return err
	}
	println("phase2-virtionet-packed-tx: diag: notify OK; entering poll")

	dumpPackedHexBytes("desc[descIdx] (post-notify)=", ptxq.PackedDescBytes(descIdx))

	const pollBudget = 50000
	const pollSampleEvery = 1000
	for spin := 0; spin < pollBudget; spin++ {
		gotIdx, _, ok := ptxq.PollUsed()
		if !ok {
			if spin%pollSampleEvery == pollSampleEvery-1 {
				println("phase2-virtionet-packed-tx: diag: poll spin=", uint64(spin+1),
					"lastUsed=", hex16(ptxq.LastUsed()),
					"deviceWrap=", uint64(ptxq.DeviceWrapCounter()))
				if spin+1 == pollSampleEvery {
					dumpPackedHexBytes("desc[descIdx] (poll sample)=", ptxq.PackedDescBytes(descIdx))
				}
			}
			continue
		}
		println("phase2-virtionet-packed-tx: diag: TX completion observed at spin=", uint64(spin),
			"descIdx=", hex16(gotIdx))
		dumpPackedHexBytes("desc[descIdx] (post-completion)=", ptxq.PackedDescBytes(gotIdx))
		_ = ptxq.Reclaim(gotIdx)
		return nil
	}

	// Timeout — surface final state.
	if status, statusErr := v.Cfg.DeviceStatus(); statusErr != nil {
		println("phase2-virtionet-packed-tx: diag: final DeviceStatus read FAILED:", statusErr.Error())
	} else {
		println("phase2-virtionet-packed-tx: diag: final DeviceStatus=", hex8(status))
	}
	dumpPackedHexBytes("desc[descIdx] (timeout)=", ptxq.PackedDescBytes(descIdx))
	dumpPackedHexBytes("drvEvent (timeout)=", ptxq.DriverEventBytes())
	dumpPackedHexBytes("devEvent (timeout)=", ptxq.DeviceEventBytes())
	return uefiboard.ErrTransmitTimeout
}

// dumpPackedHexBytes prints a labeled byte slice as "label= 0xXX 0xXX
// ..." — mirrors the split-ring probe's dumpHexBytes shape.
func dumpPackedHexBytes(label string, b []byte) {
	print("phase2-virtionet-packed-tx:   ", label)
	for _, v := range b {
		print(" ", hex8(v))
	}
	print("\n")
}

// dumpPackedFrame prints the first up-to-64 bytes of a received
// frame, plus the source MAC if the frame is at least 12 bytes
// long. Mirrors the split-ring probe's dumpFrame.
func dumpPackedFrame(frame []byte) {
	if len(frame) >= 12 {
		var srcMAC uefiboard.MAC6
		copy(srcMAC[:], frame[6:12])
		println("phase2-virtionet-packed-tx:   src MAC =", srcMAC.String())
	}
	if len(frame) >= 14 {
		etherType := uint16(frame[12])<<8 | uint16(frame[13])
		println("phase2-virtionet-packed-tx:   EtherType =", hex16(etherType))
	}
	n := len(frame)
	if n > 64 {
		n = 64
	}
	print("phase2-virtionet-packed-tx:   bytes[0..", n, "] =")
	for i := 0; i < n; i++ {
		print(" ", hex8(frame[i]))
	}
	print("\n")
}
