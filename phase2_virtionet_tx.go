// Phase-2 M2 probe — gated on `-tags phase2_virtionet_tx`.
//
// First end-to-end test of the pure-Go virtio-net rail (Path Y'' of
// the design doc, §3 M2). Locates the first
// EFI_PCI_IO_PROTOCOL handle that publishes vendor 0x1AF4 +
// device 0x1041 (modern virtio-net), brings the device up through
// the full Virtio 1.1 §3.1.1 init sequence, transmits one ARP
// request frame to the QEMU NAT gateway, and polls the receive
// queue for the reply.
//
// On QEMU+EDK2 (amd64 / arm64 / loong64) the NAT gateway answers
// with a synthesised MAC (typically 52:55:0a:00:02:02 for the
// default 10.0.2.0/24 user-mode network). On Apple VZ (vfkit
// 0.6.3, arm64) the gateway is 192.168.64.1; the same probe runs
// but the source IP and target IP are different.
//
// `phase2_virtionet_tx` IMPLIES `phase2_blkprintk` (the Taskfile
// sets both when building BOOT*-VIRTIONET.EFI), so the dispatcher
// (phase2_dispatch.go) wires the Block IO side-channel for VZ
// observability. The probe doesn't print to ConOut differently;
// the M1.6 tee captures everything.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_virtionet_tx \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `virtionet:efi:<arch>` for the per-arch wiring.)

//go:build phase2_virtionet_tx && tamago

package main

import (
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// VirtioNetTxQEMUSourceIP / VirtioNetTxQEMUTargetIP are the default
// QEMU user-mode NAT addresses (Qemu Networking docs:
// https://wiki.qemu.org/Documentation/Networking#User_Networking_.28SLIRP.29):
//
//	guest          10.0.2.15  (the only "DHCP-assigned" address)
//	gateway        10.0.2.2   (also DNS)
//	host alias     10.0.2.4
//
// On Apple VZ the network is 192.168.64.0/24 (vfkit's default).
// We don't auto-detect — the probe always emits the QEMU ARP first;
// on VZ the gateway won't answer 10.0.2.2 (different subnet), so
// we ALSO emit a second ARP for 192.168.64.1 from 192.168.64.2.
// Both broadcasts are harmless when the network doesn't match.
var (
	VirtioNetTxQEMUSourceIP   = [4]byte{10, 0, 2, 15}
	VirtioNetTxQEMUTargetIP   = [4]byte{10, 0, 2, 2}
	VirtioNetTxVZSourceIP     = [4]byte{192, 168, 64, 2}
	VirtioNetTxVZTargetIP     = [4]byte{192, 168, 64, 1}
)

// runVirtioNetTxProbe is the entry point the dispatcher calls when
// the build tag is set. It enumerates EFI_PCI_IO_PROTOCOL handles,
// finds the first virtio-net (1AF4:1041 modern), brings it up,
// transmits two ARP requests (one per probable NAT layout), polls
// for replies, and prints a summary.
func runVirtioNetTxProbe() {
	println("phase2-virtionet-tx: M2 — pure-Go virtio-net rail")
	println("phase2-virtionet-tx: LocateHandleBuffer(EFI_PCI_IO_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase2-virtionet-tx: LocateHandleBuffer FAILED:", err.Error())
		return
	}
	if len(handles) == 0 {
		println("phase2-virtionet-tx: no EFI_PCI_IO_PROTOCOL handles published")
		return
	}
	println("phase2-virtionet-tx: handles=", len(handles))

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
		println("phase2-virtionet-tx: found modern virtio-net at handle", h,
			"VID:DID =", hex16(vid), ":", hex16(did))
		pciIO = iface
		break
	}
	if pciIO == 0 {
		println("phase2-virtionet-tx: no modern virtio-net device found among",
			len(handles), "handles — M2 rail does not apply to this hypervisor")
		return
	}

	// R-M2b diagnostic — dump the raw device-offered feature bitmap
	// BEFORE OpenVirtioNet runs the full init. The dump is recovered
	// via the M1.6 blkprintk side-channel (println auto-tees to
	// BlkSink) so VZ exposes it even when ConOut captures nothing.
	// On QEMU+EDK2 it also lands in the serial log. Format is the
	// two raw 32-bit halves of DeviceFeature so the host can decode
	// the bitmap without parsing the negotiated mask.
	//
	// We open a transient VirtioModernConfig, reset + ACK + DRIVER,
	// then read both halves. OpenVirtioNet below repeats the reset
	// (idempotent per Virtio 1.1 §3.1.1) and runs the full init —
	// so the probe still surfaces the canonical OpenVirtioNet shape
	// after the diag dump. The dump kept production-side (4 lines)
	// because it's the canonical R-M2b regression artifact and a
	// useful one-line "what does this host's virtio-net offer" smoke
	// test for future hypervisor cells.
	if diagCfg, derr := uefiboard.InitVirtioModernConfig(pciIO); derr != nil {
		println("phase2-virtionet-tx: diag: InitVirtioModernConfig FAILED:", derr.Error())
	} else if derr := diagCfg.SetDeviceStatus(0); derr != nil {
		println("phase2-virtionet-tx: diag: reset FAILED:", derr.Error())
	} else if derr := diagCfg.SetDeviceStatus(uefiboard.VirtioStatusAcknowledge | uefiboard.VirtioStatusDriver); derr != nil {
		println("phase2-virtionet-tx: diag: ACK|DRIVER FAILED:", derr.Error())
	} else if feats, derr := diagCfg.DeviceFeatures64(); derr != nil {
		println("phase2-virtionet-tx: diag: DeviceFeatures64 FAILED:", derr.Error())
	} else {
		lo := uint32(feats & 0xFFFFFFFF)
		hi := uint32(feats >> 32)
		println("phase2-virtionet-tx: vnet device feats: lo=", hex32(lo), "hi=", hex32(hi))
		// Final reset so OpenVirtioNet (below) starts clean.
		_ = diagCfg.SetDeviceStatus(0)
	}

	// R-M2c narrow: try OpenVirtioNet first with the standard mask.
	// If that brings the device up but TX still fails, the next
	// hypothesis is "Apple VZ wants more bits acked." We surface that
	// via the diagnostic sweep at the end of the run; OpenVirtioNet
	// itself stays on the spec-clean narrow mask.
	// R-M2c diagnostic — read the PCI command register before and
	// after OpenVirtioNet. Bit 1 = MemoryEnable, bit 2 = BusMaster.
	// Both MUST be 1 for the device's DMA to flow.
	if cmd, cerr := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgCommand); cerr != nil {
		println("phase2-virtionet-tx: PCI cmd read (pre-open) FAILED:", cerr.Error())
	} else {
		println("phase2-virtionet-tx: PCI command register (pre-open) =", hex16(cmd),
			"(MemEn=", uint64(cmd&0x2)>>1, "BusMaster=", uint64(cmd&0x4)>>2, ")")
	}

	println("phase2-virtionet-tx: bringing up device (init sequence per Virtio 1.1 §3.1.1)")
	v, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-virtionet-tx: OpenVirtioNet FAILED:", err.Error())
		return
	}
	println("phase2-virtionet-tx: device UP. MAC =", v.MAC.String())
	println("phase2-virtionet-tx: negotiated features (hex) =", hexU64(v.NegotiatedFeatures))

	// Read PCI command register AFTER OpenVirtioNet — should now
	// reflect the AttributesEnable we issued at step 0.
	if cmd, cerr := uefiboard.PciIOReadConfigU16(pciIO, uefiboard.PCICfgCommand); cerr != nil {
		println("phase2-virtionet-tx: PCI cmd read (post-open) FAILED:", cerr.Error())
	} else {
		println("phase2-virtionet-tx: PCI command register (post-open) =", hex16(cmd),
			"(MemEn=", uint64(cmd&0x2)>>1, "BusMaster=", uint64(cmd&0x4)>>2, ")")
	}
	if attrs, aerr := uefiboard.PciIOAttributesGet(pciIO); aerr != nil {
		println("phase2-virtionet-tx: PciIOAttributesGet FAILED:", aerr.Error())
	} else {
		println("phase2-virtionet-tx: PciIO attributes (post-open) =", hexU64(attrs))
	}

	// R-M2c diagnostic — also print the device features actually
	// stored by the device side after we wrote FEATURES_OK. The two
	// reads (DeviceFeatures64 here vs the BEFORE-init dump at the
	// top) should match: the device offers the same bitmap before
	// and after the handshake. Discrepancy would signal a
	// re-negotiation issue we missed.
	if feats, err := v.Cfg.DeviceFeatures64(); err == nil {
		lo := uint32(feats & 0xFFFFFFFF)
		hi := uint32(feats >> 32)
		println("phase2-virtionet-tx: vnet device feats (post-init): lo=", hex32(lo), "hi=", hex32(hi))
	}

	// R-M2c diagnostic — dump the doorbell-locator inputs so the
	// host can verify the per-queue notify address arithmetic
	// against the spec (Virtio 1.1 §4.1.4.4):
	//     addr = NotifyCfgOffset + queue_notify_off * NotifyOffMultiplier
	// Both queues are dumped (RX = 0, TX = 1). On VZ the
	// `NotifyCfgLength` is 8 and the multiplier is 4 (per the
	// pre-R-M2c live boot recovery) so the two doorbells are
	// expected at offset 16384 + 0 and 16384 + 4. If VZ publishes a
	// different shape this dump surfaces it before TX touches the
	// queue.
	rxq := v.RxQueue()
	txq := v.TxQueue()
	if rxq != nil && txq != nil {
		println("phase2-virtionet-tx: notify cfg: BAR=", uint64(v.Cfg.NotifyCfgBAR),
			"offset=", hexU64(v.Cfg.NotifyCfgOffset),
			"length=", hexU64(uint64(v.Cfg.NotifyCfgLength)),
			"multiplier=", hexU64(uint64(v.Cfg.NotifyOffMultiplier)))
		println("phase2-virtionet-tx: rxq notify_off=", hex16(rxq.NotifyOff),
			"doorbell BAR-offset=", hexU64(v.Cfg.PerQueueNotifyOffset(rxq.NotifyOff)),
			"layout size=", uint64(rxq.Layout.Size),
			"base phys=", hexU64(rxq.BasePhys))
		println("phase2-virtionet-tx: txq notify_off=", hex16(txq.NotifyOff),
			"doorbell BAR-offset=", hexU64(v.Cfg.PerQueueNotifyOffset(txq.NotifyOff)),
			"layout size=", uint64(txq.Layout.Size),
			"base phys=", hexU64(txq.BasePhys))
		println("phase2-virtionet-tx: txq Layout: DescTableOff=", uint64(txq.Layout.DescTableOffset),
			"AvailRingOff=", uint64(txq.Layout.AvailRingOffset),
			"UsedRingOff=", uint64(txq.Layout.UsedRingOffset),
			"TotalSize=", uint64(txq.Layout.TotalSize))

		// R-M2c diagnostic — re-select each queue and read back the
		// QueueDesc/Driver/Device/Enable registers VZ should have
		// stored when OpenVirtioNet wrote them. A mismatch (e.g.
		// VZ silently dropping the 64-bit MMIO write and reading
		// back zero) would unambiguously point at the address-publish
		// step.
		dumpQueueReadback(v.Cfg, uefiboard.VirtioNetRxQueueIdx, "rxq")
		dumpQueueReadback(v.Cfg, uefiboard.VirtioNetTxQueueIdx, "txq")
	}

	// Emit the QEMU-flavoured ARP first — keep this path on the
	// production TransmitFrame helper so the QEMU 4-arch PASS
	// regression seam is unchanged.
	arpQEMU := buildARPRequest(v.MAC, VirtioNetTxQEMUSourceIP, VirtioNetTxQEMUTargetIP)
	println("phase2-virtionet-tx: TX ARP request (QEMU NAT, 10.0.2.15 -> 10.0.2.2), len =", len(arpQEMU))
	if err := v.TransmitFrame(arpQEMU); err != nil {
		println("phase2-virtionet-tx: TransmitFrame(QEMU) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-tx: TX OK (QEMU)")
	}

	// And the VZ-flavoured one — route through the instrumented
	// path so VZ surfaces the descriptor / avail / used ring state
	// around the TX. On QEMU+EDK2 this path also succeeds (the
	// instrumentation is pure-observability — same writes, extra
	// reads) so the same probe binary covers both cells.
	arpVZ := buildARPRequest(v.MAC, VirtioNetTxVZSourceIP, VirtioNetTxVZTargetIP)
	println("phase2-virtionet-tx: TX ARP request (VZ NAT, 192.168.64.2 -> 192.168.64.1), len =", len(arpVZ))
	if err := transmitFrameDiag(v, arpVZ); err != nil {
		println("phase2-virtionet-tx: transmitFrameDiag(VZ) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-tx: TX OK (VZ)")
	}

	// R-M2c hypothesis sweep #2 — re-open the device with the WIDE
	// mask (everything VZ offers minus RING_PACKED) and retry TX. If
	// this works the diagnosis is Case IV with a clean follow-up:
	// widen `VirtioNetAcceptedFeatures` to match. We never expose
	// the wide-open as production behaviour without the narrow first
	// confirming the QEMU 4 arches stay PASS.
	println("phase2-virtionet-tx: R-M2c narrow — retry with WIDE feature mask")
	if v2, werr := openVirtioNetWideMask(pciIO); werr != nil {
		println("phase2-virtionet-tx: wide-mask OpenVirtioNet FAILED:", werr.Error())
	} else {
		println("phase2-virtionet-tx: wide-mask OpenVirtioNet OK. MAC=", v2.MAC.String(),
			"negotiated=", hexU64(v2.NegotiatedFeatures))
		arpVZ2 := buildARPRequest(v2.MAC, VirtioNetTxVZSourceIP, VirtioNetTxVZTargetIP)
		if terr := transmitFrameDiag(v2, arpVZ2); terr != nil {
			println("phase2-virtionet-tx: wide-mask transmitFrameDiag FAILED:", terr.Error())
		} else {
			println("phase2-virtionet-tx: wide-mask TX OK *** R-M2c CASE IV CONFIRMED ***")
		}
	}

	// Poll for an ARP reply for ~5 seconds (rough — each PollUsed
	// iteration is a PciIo.Mem.Read so the cost is firmware-bound).
	const pollBudget = 500000
	println("phase2-virtionet-tx: polling RX for up to", pollBudget, "iterations...")
	for attempt := 0; attempt < 3; attempt++ {
		frame, err := v.ReceiveFrame(pollBudget)
		if err != nil {
			println("phase2-virtionet-tx: RX attempt", attempt, "timed out:", err.Error())
			break
		}
		println("phase2-virtionet-tx: RX attempt", attempt, "got frame, len =", len(frame))
		dumpFrame(frame)
	}
	println("phase2-virtionet-tx: probe complete")
}

// buildARPRequest assembles a 42-byte Ethernet+ARP request frame.
// Layout (IETF RFC 826 / RFC 5227):
//
//	0..5    Ethernet DST = ff:ff:ff:ff:ff:ff (broadcast)
//	6..11   Ethernet SRC = our MAC
//	12..13  EtherType    = 0x0806 (ARP)
//	14..15  HTYPE        = 0x0001 (Ethernet)
//	16..17  PTYPE        = 0x0800 (IPv4)
//	18      HLEN         = 6
//	19      PLEN         = 4
//	20..21  OPER         = 0x0001 (request)
//	22..27  SHA (sender hardware addr)
//	28..31  SPA (sender protocol addr)
//	32..37  THA (target hardware addr, zero in request)
//	38..41  TPA (target protocol addr)
func buildARPRequest(srcMAC uefiboard.MAC6, srcIP [4]byte, dstIP [4]byte) []byte {
	frame := make([]byte, 42)
	// Ethernet header
	for i := 0; i < 6; i++ {
		frame[i] = 0xFF
	}
	copy(frame[6:12], srcMAC[:])
	frame[12] = 0x08
	frame[13] = 0x06
	// ARP header
	frame[14] = 0x00
	frame[15] = 0x01 // HTYPE=Ethernet
	frame[16] = 0x08
	frame[17] = 0x00 // PTYPE=IPv4
	frame[18] = 6
	frame[19] = 4
	frame[20] = 0x00
	frame[21] = 0x01 // OPER=request
	copy(frame[22:28], srcMAC[:])
	copy(frame[28:32], srcIP[:])
	// THA: zero (don't know it)
	copy(frame[38:42], dstIP[:])
	return frame
}

// dumpQueueReadback re-selects a queue and reads back the four key
// per-queue registers (Desc, Driver, Device, Enable). Used by the
// R-M2c narrow to verify VZ stored the addresses M2 wrote during
// `setupQueue`.
func dumpQueueReadback(cfg *uefiboard.VirtioModernConfig, queueIdx uint16, label string) {
	if err := cfg.SelectQueue(queueIdx); err != nil {
		println("phase2-virtionet-tx: readback ", label, ": SelectQueue FAILED:", err.Error())
		return
	}
	d, derr := cfg.QueueDesc()
	dr, drerr := cfg.QueueDriver()
	de, deerr := cfg.QueueDevice()
	en, enerr := cfg.QueueEnable()
	if derr != nil || drerr != nil || deerr != nil || enerr != nil {
		println("phase2-virtionet-tx: readback ", label, ": one or more reads FAILED")
		return
	}
	println("phase2-virtionet-tx: readback ", label,
		" QueueDesc=", hexU64(d),
		" QueueDriver=", hexU64(dr),
		" QueueDevice=", hexU64(de),
		" QueueEnable=", hex16(en))
}

// openVirtioNetWideMask drives the M2 init sequence with the
// R-M2c-wide accepted-features mask (everything VZ offers minus
// RING_PACKED). On QEMU+EDK2 the device-offered set lacks the
// Apple-private bits, so the negotiated mask collapses to the
// standard QEMU set and behaviour is unchanged. On VZ this widens
// the mask to include bits 28/29 (Apple-private) and the various
// checksum/TSO bits, testing whether any of those is the missing
// dispatch trigger for VZ's TX path.
func openVirtioNetWideMask(pciIO uint64) (*uefiboard.VirtioNet, error) {
	return uefiboard.OpenVirtioNetWithFeatures(pciIO, uefiboard.VirtioNetAcceptedFeaturesNarrow)
}

// transmitFrameDiag is an instrumented copy of
// `(*VirtioNet).TransmitFrame` that dumps the TX descriptor, the
// avail-ring header word, the per-queue notification address arithmetic,
// the used-ring header BEFORE notify, the used-ring header AFTER
// notify, and the used-ring header every 1000 poll iterations during
// the wait. It exists for the R-M2c diagnostic narrow; once R-M2c is
// closed the production VZ TX path can revert to `TransmitFrame`.
//
// Poll budget is capped at 50000 (vs. the production 10000) — a 5x
// bump that's enough to confirm "the device never publishes" on VZ
// without dragging the run wall-clock past the harness timeout. The
// pre-R-M2c prototype bumped to 500000 (50x) and still saw no
// publication, so 5x is a comfortable margin.
//
// The dump shape is deliberately byte-level so the host can decode the
// fields without trusting any Go-side struct interpretation that might
// itself be the bug.
func transmitFrameDiag(v *uefiboard.VirtioNet, frame []byte) error {
	txq := v.TxQueue()
	if txq == nil {
		println("phase2-virtionet-tx: diag: txq is nil")
		return nil
	}
	totalLen := uefiboard.VirtioNetHdrSize + len(frame)
	phys, addr, err := uefiboard.AllocDMABuffer(uintptr(totalLen))
	if err != nil {
		return err
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), totalLen)
	copy(dst[uefiboard.VirtioNetHdrSize:], frame)
	println("phase2-virtionet-tx: diag: DMA buf phys=", hexU64(phys), "len=", uint64(totalLen))

	// Capture state BEFORE AddBuffer publishes the descriptor.
	preAvailIdx := txq.NextAvailIdx()
	preUsedIdx := txq.UsedIdx()
	preUsedIdxRaw := txq.UsedIdxRaw()
	println("phase2-virtionet-tx: diag: pre-AddBuffer: NextAvailIdx=", hex16(preAvailIdx),
		"UsedIdx(atomic)=", hex16(preUsedIdx), "UsedIdx(raw)=", hex16(preUsedIdxRaw))

	descIdx, err := txq.AddBuffer(addr, phys, uint32(totalLen), false)
	if err != nil {
		return err
	}
	println("phase2-virtionet-tx: diag: AddBuffer descIdx=", hex16(descIdx))

	// Dump descriptor[0].
	dumpHexBytes("desc[0]=", txq.DescBytes(descIdx))
	dumpHexBytes("avail[0..8]=", txq.AvailHeaderBytes())
	dumpHexBytes("used[0..16] (pre-notify)=", txq.UsedHeaderBytes())

	// Compute + log the doorbell coordinates.
	doorbellOff := v.Cfg.PerQueueNotifyOffset(txq.NotifyOff)
	println("phase2-virtionet-tx: diag: doorbell write: BAR=", uint64(v.Cfg.NotifyCfgBAR),
		"offset=", hexU64(doorbellOff), "value=", hex16(uefiboard.VirtioNetTxQueueIdx))

	if err := v.Cfg.NotifyQueue(uefiboard.VirtioNetTxQueueIdx, txq.NotifyOff); err != nil {
		println("phase2-virtionet-tx: diag: NotifyQueue FAILED:", err.Error())
		return err
	}
	println("phase2-virtionet-tx: diag: notify OK; entering poll")

	// Dump used immediately after notify (should still be unchanged
	// or already updated if device responded synchronously).
	dumpHexBytes("used[0..16] (post-notify)=", txq.UsedHeaderBytes())

	const pollBudget = 50000
	const pollSampleEvery = 1000
	for spin := 0; spin < pollBudget; spin++ {
		gotIdx, _, ok := txq.PollUsed()
		if !ok {
			if spin%pollSampleEvery == pollSampleEvery-1 {
				rawIdx := txq.UsedIdxRaw()
				atomIdx := txq.UsedIdx()
				println("phase2-virtionet-tx: diag: poll spin=", uint64(spin+1),
					"UsedIdx(atomic)=", hex16(atomIdx),
					"UsedIdx(raw)=", hex16(rawIdx))
				if spin+1 == pollSampleEvery {
					// First sample also dumps the full used header.
					dumpHexBytes("used[0..16] (poll sample)=", txq.UsedHeaderBytes())
				}
			}
			continue
		}
		println("phase2-virtionet-tx: diag: TX completion observed at spin=", uint64(spin),
			"descIdx=", hex16(gotIdx))
		dumpHexBytes("used[0..16] (post-completion)=", txq.UsedHeaderBytes())
		_ = txq.Reclaim(gotIdx)
		return nil
	}

	// Poll timeout — surface the device status one more time so the
	// host can tell if VZ flipped NEEDS_RESET or FAILED.
	if status, statusErr := v.Cfg.DeviceStatus(); statusErr != nil {
		println("phase2-virtionet-tx: diag: final DeviceStatus read FAILED:", statusErr.Error())
	} else {
		println("phase2-virtionet-tx: diag: final DeviceStatus=", hex8(status))
	}
	dumpHexBytes("used[0..16] (timeout)=", txq.UsedHeaderBytes())
	dumpHexBytes("avail[0..8] (timeout)=", txq.AvailHeaderBytes())
	dumpHexBytes("desc[0] (timeout)=", txq.DescBytes(descIdx))

	// R-M2c hypothesis sweep — try alternate doorbell shapes by
	// adding fresh buffers (each bumps avail.idx so the device sees a
	// new entry) and notifying with a different MMIO width / offset.
	// Whichever shape makes used.idx move is the one VZ honors.
	//
	// Order:
	//   1. uint32 write to the per-queue offset (the multiplier-wide
	//      slot).
	//   2. uint16 write to the SHARED offset (NotifyCfgOffset+0) —
	//      tests the "single doorbell" interpretation despite a
	//      published per-queue stride.
	//   3. uint32 write to the SHARED offset.
	rxq := v.RxQueue()
	notifySweep(v, txq, "uint32@perQ", uefiboard.VirtioNetTxQueueIdx, txq.NotifyOff, true)
	notifySweep(v, txq, "uint16@offset0", uefiboard.VirtioNetTxQueueIdx, 0, false)
	notifySweep(v, txq, "uint32@offset0", uefiboard.VirtioNetTxQueueIdx, 0, true)
	if rxq != nil {
		dumpHexBytes("rxq used[0..16] (post-sweep)=", rxq.UsedHeaderBytes())
		println("phase2-virtionet-tx: diag: rxq UsedIdx(atomic)=", hex16(rxq.UsedIdx()),
			"NextAvailIdx=", hex16(rxq.NextAvailIdx()))
	}
	return uefiboard.ErrTransmitTimeout
}

// notifySweep adds a fresh TX buffer and notifies the device with a
// specific MMIO shape (uint32 vs uint16, per-queue vs offset-0), then
// polls the used ring for a short budget. Surfaces whether the device
// honors that particular doorbell shape.
func notifySweep(v *uefiboard.VirtioNet, txq *uefiboard.Virtqueue, label string, queueIdx uint16, notifyOff uint16, useU32 bool) {
	phys, addr, err := uefiboard.AllocDMABuffer(64)
	if err != nil {
		println("phase2-virtionet-tx: sweep ", label, ": AllocDMABuffer FAILED:", err.Error())
		return
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), 64)
	// Re-emit the VZ ARP into the fresh buffer; the device only
	// matters about avail.idx moving, but a valid frame keeps the
	// host stack happy if the doorbell actually fires.
	arp := buildARPRequest(v.MAC, VirtioNetTxVZSourceIP, VirtioNetTxVZTargetIP)
	copy(dst[uefiboard.VirtioNetHdrSize:], arp)
	descIdx, addErr := txq.AddBuffer(addr, phys, uint32(uefiboard.VirtioNetHdrSize+len(arp)), false)
	if addErr != nil {
		println("phase2-virtionet-tx: sweep ", label, ": AddBuffer FAILED:", addErr.Error())
		return
	}
	doorbellOff := v.Cfg.PerQueueNotifyOffset(notifyOff)
	println("phase2-virtionet-tx: sweep ", label, ": descIdx=", hex16(descIdx),
		"avail.idx=", hex16(txq.NextAvailIdx()),
		"writing", map[bool]string{true: "u32", false: "u16"}[useU32],
		"to BAR-offset=", hexU64(doorbellOff),
		"value=", hex16(queueIdx))

	var werr error
	if useU32 {
		werr = uefiboard.PciIOMemWrite32(v.Cfg.PciIO, v.Cfg.NotifyCfgBAR, doorbellOff, uint32(queueIdx))
	} else {
		werr = uefiboard.PciIOMemWrite16(v.Cfg.PciIO, v.Cfg.NotifyCfgBAR, doorbellOff, queueIdx)
	}
	if werr != nil {
		println("phase2-virtionet-tx: sweep ", label, ": MMIO write FAILED:", werr.Error())
		return
	}
	// Short poll for completion — 5000 iterations is enough; if the
	// device honors this shape it'll publish in microseconds.
	for spin := 0; spin < 5000; spin++ {
		gotIdx, _, ok := txq.PollUsed()
		if !ok {
			continue
		}
		println("phase2-virtionet-tx: sweep ", label, ": *** COMPLETION at spin=", uint64(spin),
			"descIdx=", hex16(gotIdx), " ***")
		_ = txq.Reclaim(gotIdx)
		return
	}
	println("phase2-virtionet-tx: sweep ", label, ": no completion in 5000 polls; used[0..16]=")
	dumpHexBytes("", txq.UsedHeaderBytes())
}

// dumpHexBytes prints a labeled byte slice as "label= 0xXX 0xXX ...".
// Used by the R-M2c diagnostic so the host blkprintk-recover output
// carries verbatim virtqueue memory snapshots.
func dumpHexBytes(label string, b []byte) {
	print("phase2-virtionet-tx:   ", label)
	for _, v := range b {
		print(" ", hex8(v))
	}
	print("\n")
}

// dumpFrame prints the first up-to-64 bytes of a received frame in
// hex, plus the source MAC if the frame is at least 12 bytes long.
func dumpFrame(frame []byte) {
	if len(frame) >= 12 {
		var srcMAC uefiboard.MAC6
		copy(srcMAC[:], frame[6:12])
		println("phase2-virtionet-tx:   src MAC =", srcMAC.String())
	}
	if len(frame) >= 14 {
		etherType := uint16(frame[12])<<8 | uint16(frame[13])
		println("phase2-virtionet-tx:   EtherType =", hex16(etherType))
	}
	// First 64 bytes as hex.
	n := len(frame)
	if n > 64 {
		n = 64
	}
	print("phase2-virtionet-tx:   bytes[0..", n, "] =")
	for i := 0; i < n; i++ {
		print(" ", hex8(frame[i]))
	}
	print("\n")
}

