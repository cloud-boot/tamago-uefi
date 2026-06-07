// cloud-boot UEFI board — Virtio-net driver: types + frame
// header/strip helpers (Phase 2, M2).
//
// Host-buildable: no //go:build tamago directive. The frame-header
// shape (`VirtioNetHdr`), the prepend/strip helpers, and the
// feature-acceptance mask are all pure Go and host-testable. The
// live `OpenVirtioNet` + TransmitFrame / ReceiveFrame paths that
// drive the actual device live in `virtio_net_tamago.go`.
//
// References:
//
//   - Virtio 1.1 §5.1 "Network Device" — device-type 1 binding.
//   - Virtio 1.1 §5.1.6 "Device Operation" — the per-frame
//     `struct virtio_net_hdr` prepended to every TX/RX packet:
//
//	     u8     flags;
//	     u8     gso_type;
//	     le16   hdr_len;
//	     le16   gso_size;
//	     le16   csum_start;
//	     le16   csum_offset;
//	     le16   num_buffers;     // present iff VIRTIO_NET_F_MRG_RXBUF
//	                              // OR VIRTIO_F_VERSION_1 negotiated.
//
//   - Virtio 1.1 §5.1.4 "Device configuration layout" — `mac[6]`,
//     `status` (link-up bit), `max_virtqueue_pairs`, `mtu`.
//   - Virtio 1.1 §3.1.1 "Driver Requirements: Device Initialization"
//     — the 7-step status-bit choreography we follow in OpenVirtioNet.
//   - Linux drivers/net/virtio_net.c — canonical Go-translatable
//     reference for the init sequence and the rxq pre-post pattern.

package uefiboard

import "errors"

// VirtioNetHdrSize is the on-the-wire byte length of `struct
// virtio_net_hdr` (Virtio 1.1 §5.1.6.1). When VIRTIO_F_VERSION_1 is
// negotiated, the header is ALWAYS 12 bytes regardless of
// VIRTIO_NET_F_MRG_RXBUF — the `num_buffers` field is unconditional
// on modern devices. We negotiate VERSION_1 ON and MRG_RXBUF OFF, so
// 12 bytes is what every TX/RX buffer must reserve.
//
// Field offsets (little-endian within the 12-byte block):
//
//	0      u8     flags
//	1      u8     gso_type
//	2..3   le16   hdr_len
//	4..5   le16   gso_size
//	6..7   le16   csum_start
//	8..9   le16   csum_offset
//	10..11 le16   num_buffers      (driver writes 0 on TX; device fills on RX)
const VirtioNetHdrSize = 12

// VIRTIO_NET_HDR_F_* and VIRTIO_NET_HDR_GSO_* values (Virtio 1.1
// §5.1.6.2). M2 emits all-zero headers (no GSO, no checksum
// offload).
const (
	VirtioNetHdrFNeedsCsum uint8 = 0x1
	VirtioNetHdrFDataValid uint8 = 0x2

	VirtioNetGSONone   uint8 = 0
	VirtioNetGSOTCPv4  uint8 = 1
	VirtioNetGSOUDP    uint8 = 3
	VirtioNetGSOTCPv6  uint8 = 4
	VirtioNetGSOECN    uint8 = 0x80
)

// VirtioNetRxQueueIdx / VirtioNetTxQueueIdx are the canonical queue
// indices for the first virtio-net queue pair (Virtio 1.1 §5.1.2 —
// "queue 0 = receive queue, queue 1 = transmit queue" for a single
// queue-pair device).
const (
	VirtioNetRxQueueIdx uint16 = 0
	VirtioNetTxQueueIdx uint16 = 1
)

// VirtioNetMaxFrameSize is the Ethernet MTU (1500) + Ethernet header
// (14) + 4 bytes for VLAN tag headroom. We pre-post 1518-byte
// buffers on the rxq; on the txq the same size is enough for ARP
// (42 bytes) plus the virtio header.
//
// Real-world frames may exceed 1518 (jumbo), but virtio-net devices
// default to MTU=1500 unless VIRTIO_NET_F_MTU is negotiated to a
// larger value — we don't negotiate that.
const VirtioNetMaxFrameSize = 1518

// VirtioNetRxRingSize is the number of buffers we pre-post on the
// rxq. Sized for "a few simultaneous in-flight frames" — ARP reply
// + spontaneous DHCP offer + a couple of broadcasts. Must be a
// power of two.
const VirtioNetRxRingSize uint16 = 16

// VirtioNetTxRingSize is the txq depth. M2 issues one frame at a
// time so 8 is plenty.
const VirtioNetTxRingSize uint16 = 8

// VirtioNetAcceptedFeatures is the feature mask M2 negotiates ON:
//
//	VIRTIO_NET_F_MTU      (3)   device-provided MTU (REQUIRED by Apple VZ;
//	                            informational/no-op on QEMU+EDK2 — see
//	                            R-M2b below)
//	VIRTIO_NET_F_MAC      (5)   device MAC published in DeviceCfg
//	VIRTIO_NET_F_STATUS   (16)  link-up bit (informational)
//	VIRTIO_F_VERSION_1    (32)  modern transport (non-negotiable)
//
// All other bits are masked OUT. If the device REQUIRES a bit we
// didn't ack, FEATURES_OK will fail to stick after we write it; the
// init sequence catches that and surfaces ErrFeaturesNotOK.
//
// NOTE: We do NOT accept VIRTIO_NET_F_MRG_RXBUF (15). Without it,
// the device places one packet per buffer (no chained descriptors
// on receive), which simplifies the M2 RX path significantly.
// Virtio 1.1 §5.1.6.4 — "The driver MUST set num_buffers to zero in
// transmit headers" — applies regardless; we always write 0 there.
//
// R-M2b (RESOLVED 2026-06-07). Live VZ diagnostic narrow established
// that Apple VZ requires VIRTIO_NET_F_MTU (bit 3) to be acked or it
// clears FEATURES_OK and the init aborts. The bit is informational
// per Virtio 1.1 §5.1.3 ("if VIRTIO_NET_F_MTU is set, the device
// MUST set max_virtqueue_pairs to 1 and the driver MAY read
// virtio_net_config.mtu") — accepting it costs us nothing on the
// driver side and unblocks the VZ cell. The QEMU+EDK2 cells offer
// this bit too (QEMU's virtio-net always sets it) so accepting it
// is a no-op there.
const VirtioNetAcceptedFeatures uint64 = VirtioNetFeatureMTU | VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1

// R-M2c narrow probe constant. To verify whether Apple VZ requires
// extra feature bits beyond the R-M2b mask to actually run TX, we
// temporarily widen the accepted mask to include EVERYTHING VZ offers
// except VIRTIO_F_RING_PACKED (bit 34). The R-M2b narrow established
// that this mask makes FEATURES_OK stick on VZ; the R-M2c question is
// whether it also unblocks TX.
//
// Bits added beyond `VirtioNetAcceptedFeatures` (VZ offered = lo
// 0x300119ab, hi 0x00000005):
//   bit  0  VIRTIO_NET_F_CSUM
//   bit  1  VIRTIO_NET_F_GUEST_CSUM
//   bit  7  VIRTIO_NET_F_GUEST_TSO4
//   bit  8  VIRTIO_NET_F_GUEST_TSO6
//   bit 11  VIRTIO_NET_F_HOST_TSO4
//   bit 12  VIRTIO_NET_F_HOST_TSO6
//   bit 28  (Apple-private / unassigned in Virtio 1.1)
//   bit 29  (Apple-private / unassigned in Virtio 1.1)
//
// Bit 34 (RING_PACKED) is intentionally NOT acknowledged — accepting
// it would force the driver onto the packed-ring layout, which M2
// doesn't implement.
//
// On QEMU+EDK2 the device-offered set lacks bits 28/29 entirely, so
// `deviceFeats & VirtioNetAcceptedFeaturesNarrow` collapses to the
// standard QEMU mask (`MAC | STATUS | VERSION_1`) and the four
// PASS cells stay unchanged.
const VirtioNetAcceptedFeaturesNarrow uint64 = VirtioNetAcceptedFeatures |
	(1 << 0) | (1 << 1) |
	(1 << 7) | (1 << 8) |
	(1 << 11) | (1 << 12) |
	(1 << 28) | (1 << 29)

// VirtioNetAcceptedFeaturesWithPacked is the "absolutely everything VZ
// offers including RING_PACKED" mask. Originally introduced by R-M2c
// as a pure diagnostic — "does FEATURES_OK stick when we ack bit 34?"
// — it is now the production accepted mask for the M2-A experiment
// (packed-ring virtqueue support; see `virtqueue_packed.go`). When the
// device offers VIRTIO_F_RING_PACKED and the M2-A code path is taken,
// the driver switches its queue layout from split (§2.6) to packed
// (§2.7) for both rxq and txq.
//
// On QEMU+EDK2 the device-offered set already includes bit 34 in modern
// QEMU (5.x+), but with the `packed=on` device option NOT set QEMU
// won't actually serve packed-ring semantics — it will fail
// FEATURES_OK after the driver writes the bit. The M2-A QEMU
// validation runs with `-device virtio-net-pci,packed=on` so the
// device genuinely speaks packed-ring.
const VirtioNetAcceptedFeaturesWithPacked uint64 = VirtioNetAcceptedFeaturesNarrow | VirtioFeatureRingPacked

// VirtioNetHdr is the Go view of `struct virtio_net_hdr` (Virtio 1.1
// §5.1.6.1). M2 always emits an all-zero header and ignores the
// received one (no checksum offload, no GSO).
type VirtioNetHdr struct {
	Flags      uint8
	GSOType    uint8
	HdrLen     uint16
	GSOSize    uint16
	CsumStart  uint16
	CsumOffset uint16
	NumBuffers uint16
}

// PrependVirtioNetHdr builds a 12-byte all-zero `virtio_net_hdr`
// followed by the Ethernet frame in `frame`. Returns the full
// per-descriptor buffer the driver passes to AddBuffer.
//
// Caller is responsible for the buffer's lifetime — the device's
// DMA read happens after notify and before the matching used-ring
// publication.
func PrependVirtioNetHdr(frame []byte) []byte {
	out := make([]byte, VirtioNetHdrSize+len(frame))
	// header is already zero-initialised by make.
	copy(out[VirtioNetHdrSize:], frame)
	return out
}

// StripVirtioNetHdr returns the Ethernet frame embedded in a
// device-RX buffer of the given length. Returns nil + an error if
// `len(buf) < VirtioNetHdrSize` — a malformed RX where the device
// didn't even land a header.
func StripVirtioNetHdr(buf []byte) ([]byte, error) {
	if len(buf) < VirtioNetHdrSize {
		return nil, ErrFrameTooShort
	}
	return buf[VirtioNetHdrSize:], nil
}

// AcceptFeatures returns the negotiated feature mask: the
// intersection of what the device offers and what we accept. The
// caller writes this back via DriverFeature.
//
// We require VIRTIO_F_VERSION_1 — if the device doesn't offer it,
// we return ErrNotModernDevice and the init aborts. We require
// VIRTIO_NET_F_MAC because M2's probe needs the device-published
// MAC for the ARP source field.
func AcceptFeatures(deviceFeatures uint64) (uint64, error) {
	if deviceFeatures&VirtioFeatureVersion1 == 0 {
		return 0, ErrNotModernDevice
	}
	// Mask down to our accepted set. `VirtioNetAcceptedFeatures`
	// includes VERSION_1 by construction (compile-time constant), so
	// the bit survives the AND.
	negotiated := deviceFeatures & VirtioNetAcceptedFeatures
	if negotiated&VirtioNetFeatureMAC == 0 {
		return 0, ErrNoMACFeature
	}
	return negotiated, nil
}

// Sentinel errors for the virtio-net path. All exported so the M2
// probe can branch + format them.
var (
	ErrFrameTooShort     = errors.New("uefi: virtio-net: RX buffer shorter than virtio_net_hdr (12 bytes)")
	ErrNotModernDevice   = errors.New("uefi: virtio-net: device doesn't offer VIRTIO_F_VERSION_1 (legacy-only)")
	ErrNoMACFeature      = errors.New("uefi: virtio-net: device doesn't offer VIRTIO_NET_F_MAC")
	ErrFeaturesNotOK     = errors.New("uefi: virtio-net: FEATURES_OK status bit didn't stick after DriverFeature write")
	ErrMACReadFailed     = errors.New("uefi: virtio-net: MAC read returned all-zero (likely R-M1.6a bounds-check failure)")
	ErrInitWrongDeviceID = errors.New("uefi: virtio-net: PCI device ID is not 0x1041 (modern net device)")
)

// MAC6 is the 6-byte EUI-48 MAC address of one virtio-net device.
type MAC6 [6]byte

// IsZero reports whether the MAC is all-zero (used by the probe to
// detect a failed read).
func (m MAC6) IsZero() bool {
	for _, b := range m {
		if b != 0 {
			return false
		}
	}
	return true
}

// String formats the MAC in standard "XX:XX:XX:XX:XX:XX" hex notation.
// Avoids fmt for the dep-light convention used elsewhere in this
// package.
func (m MAC6) String() string {
	const digits = "0123456789abcdef"
	var buf [17]byte
	for i := 0; i < 6; i++ {
		buf[i*3] = digits[(m[i]>>4)&0xF]
		buf[i*3+1] = digits[m[i]&0xF]
		if i < 5 {
			buf[i*3+2] = ':'
		}
	}
	return string(buf[:])
}
