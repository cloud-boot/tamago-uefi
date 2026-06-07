// cloud-boot UEFI board — post-ExitBootServices virtio-net rail:
// host-buildable surface (Phase 2, M2-B — R-M2c Option B narrow).
//
// Pure-data + helper surface for the post-EBS virtio-net path. The
// live MMIO accessors and the full init / TX / RX state machine live
// in `virtio_net_postebs_tamago.go` (gated on `//go:build tamago`)
// because they dereference `unsafe.Pointer`-cast physical addresses,
// which only resolve on a real bare-metal target.
//
// What lives here:
//
//   - The `VirtioNetPostEBS` struct shape (host-testable).
//   - The post-EBS init-trace byte constants (host-testable).
//   - `EncodeTraceMarker` / `lastTraceByte` — pure-data, no MMIO.
//
// References:
//
//   - Virtio 1.1 §3.1.1 driver init — same sequence as M2 but with
//     direct MMIO transport (replayed in the _tamago file).
//   - Linux drivers/virtio/virtio_pci_modern.c — canonical pure-MMIO
//     virtio driver; we follow its idioms.

package uefiboard

import "encoding/binary"

// VirtioNetPostEBS is the post-EBS handle for one virtio-net device.
// Symmetric to `VirtioNet` (which uses PciIo.Mem.Read/Write) but
// every register access in the _tamago file is a direct
// `unsafe.Pointer` MMIO read or write against the captured physical
// addresses.
type VirtioNetPostEBS struct {
	// State is the captured pre-EBS snapshot the post-EBS path
	// consumes. Pinned for the lifetime of the handle.
	State *CapturedState

	// RxQ / TxQ are the two virtqueues set up by InitVirtioNetPostEBS.
	// They reuse the M2 `Virtqueue` struct shape — same descriptor
	// table + avail + used ring layout, same `PostAvail` /
	// `PollUsed` semantics. The only difference is the backing
	// memory: RxQ.Base / TxQ.Base point at the EfiRuntimeServicesData
	// pages allocated pre-EBS (which survive EBS), not the
	// EfiBootServicesData pages M2's NewVirtqueue uses.
	RxQ *Virtqueue
	TxQ *Virtqueue

	// NegotiatedFeatures is what the post-EBS handshake settled on.
	// Captured for the diagnostic surface.
	NegotiatedFeatures uint64

	// InitTrace is the per-step status surface from
	// `InitVirtioNetPostEBS`. Encoded as a fixed-size byte array so
	// the host can read it out of `BlkPrintkScratch` after the run.
	InitTrace [16]byte
}

// Post-EBS init-trace byte codes. Written into
// `state.BlkPrintkScratch` (one byte per step) so the host can read
// out how far the post-EBS sequence advanced, even though there's
// no ConOut.
//
// Single byte per step keeps the encoding compact; the host
// recovers them as ASCII from the scratch buffer.
const (
	postEBSTraceStart           byte = 'B' // M2-B: started post-EBS path
	postEBSTraceReset           byte = 'R' // DeviceStatus = 0 written
	postEBSTraceAck             byte = 'A' // ACKNOWLEDGE set
	postEBSTraceDriver          byte = 'D' // DRIVER set
	postEBSTraceFeaturesRead    byte = 'f' // DeviceFeatures read post-EBS
	postEBSTraceFeaturesWritten byte = 'F' // DriverFeatures written
	postEBSTraceFeaturesOK      byte = 'O' // FEATURES_OK accepted
	postEBSTraceQRx             byte = 'r' // RX queue configured
	postEBSTraceQTx             byte = 't' // TX queue configured
	postEBSTraceDriverOK        byte = 'K' // DRIVER_OK set
	postEBSTraceRxFilled        byte = 'p' // RX buffers pre-posted
	postEBSTraceTxSubmit        byte = 'T' // TX frame submitted
	postEBSTraceTxNotify        byte = 'N' // TX doorbell rung
	postEBSTraceTxCompletion    byte = 'C' // TX completion observed
	postEBSTraceRxCompletion    byte = 'X' // RX completion observed
	postEBSTraceFailMarker      byte = '!' // some step failed
)

// EncodeTraceMarker writes a 16-byte M2-B trace marker into `dst`
// suitable for embedding in an ARP packet's payload area. Lets the
// host snoop differentiate "this was an M2-B post-EBS ARP" from any
// other ARP traffic on the bridge.
//
// Layout (16 bytes):
//
//	0..3   magic "M2B!"
//	4      init-trace last byte (= furthest step reached at TX time)
//	5      reserved (0)
//	6..7   negotiated features lo16
//	8..15  reserved (0)
//
// Caller-provides the destination; we treat anything < 16 bytes as
// no-op so an under-sized frame buffer doesn't corrupt the ARP
// header.
func (v *VirtioNetPostEBS) EncodeTraceMarker(dst []byte) {
	if len(dst) < 16 {
		return
	}
	dst[0] = 'M'
	dst[1] = '2'
	dst[2] = 'B'
	dst[3] = '!'
	dst[4] = lastTraceByte(v.InitTrace[:])
	dst[5] = 0
	binary.LittleEndian.PutUint16(dst[6:8], uint16(v.NegotiatedFeatures&0xFFFF))
	for i := 8; i < 16; i++ {
		dst[i] = 0
	}
}

// lastTraceByte returns the last non-zero byte in `trace`, or 0
// if the trace is empty.
func lastTraceByte(trace []byte) byte {
	for i := len(trace) - 1; i >= 0; i-- {
		if trace[i] != 0 {
			return trace[i]
		}
	}
	return 0
}
