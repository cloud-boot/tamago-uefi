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

	println("phase2-virtionet-tx: bringing up device (init sequence per Virtio 1.1 §3.1.1)")
	v, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-virtionet-tx: OpenVirtioNet FAILED:", err.Error())
		return
	}
	println("phase2-virtionet-tx: device UP. MAC =", v.MAC.String())
	println("phase2-virtionet-tx: negotiated features (hex) =", hexU64(v.NegotiatedFeatures))

	// Emit the QEMU-flavoured ARP first.
	arpQEMU := buildARPRequest(v.MAC, VirtioNetTxQEMUSourceIP, VirtioNetTxQEMUTargetIP)
	println("phase2-virtionet-tx: TX ARP request (QEMU NAT, 10.0.2.15 -> 10.0.2.2), len =", len(arpQEMU))
	if err := v.TransmitFrame(arpQEMU); err != nil {
		println("phase2-virtionet-tx: TransmitFrame(QEMU) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-tx: TX OK (QEMU)")
	}

	// And the VZ-flavoured one.
	arpVZ := buildARPRequest(v.MAC, VirtioNetTxVZSourceIP, VirtioNetTxVZTargetIP)
	println("phase2-virtionet-tx: TX ARP request (VZ NAT, 192.168.64.2 -> 192.168.64.1), len =", len(arpVZ))
	if err := v.TransmitFrame(arpVZ); err != nil {
		println("phase2-virtionet-tx: TransmitFrame(VZ) FAILED:", err.Error())
	} else {
		println("phase2-virtionet-tx: TX OK (VZ)")
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

