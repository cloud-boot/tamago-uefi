// Host-side tests for virtio_net.go.
//
// Three concerns:
//
//   1. `PrependVirtioNetHdr` / `StripVirtioNetHdr` round-trip
//      correctly, including the spec'd all-zero header.
//   2. `AcceptFeatures` masks down to the accepted set and surfaces
//      ErrNotModernDevice / ErrNoMACFeature when the device offers
//      an incompatible set.
//   3. `MAC6.String()` / `MAC6.IsZero()` format the address
//      correctly.

package uefiboard

import (
	"bytes"
	"errors"
	"testing"
)

func TestPrependVirtioNetHdr(t *testing.T) {
	frame := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	out := PrependVirtioNetHdr(frame)
	if len(out) != VirtioNetHdrSize+len(frame) {
		t.Errorf("len: got %d, want %d", len(out), VirtioNetHdrSize+len(frame))
	}
	// First 12 bytes must be zero (Virtio 1.1 §5.1.6.4 — driver MUST
	// emit all-zero header).
	for i := 0; i < VirtioNetHdrSize; i++ {
		if out[i] != 0 {
			t.Errorf("header byte %d: got 0x%x, want 0x0", i, out[i])
		}
	}
	// Payload starts at offset 12.
	if !bytes.Equal(out[VirtioNetHdrSize:], frame) {
		t.Errorf("payload: got %x, want %x", out[VirtioNetHdrSize:], frame)
	}
}

func TestStripVirtioNetHdr(t *testing.T) {
	buf := []byte{
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 12-byte header
		0x11, 0x22, 0x33,
	}
	frame, err := StripVirtioNetHdr(buf)
	if err != nil {
		t.Fatalf("StripVirtioNetHdr: %v", err)
	}
	want := []byte{0x11, 0x22, 0x33}
	if !bytes.Equal(frame, want) {
		t.Errorf("frame: got %x, want %x", frame, want)
	}
}

func TestStripVirtioNetHdrTooShort(t *testing.T) {
	buf := []byte{0, 0, 0, 0} // 4 bytes — well short of 12
	_, err := StripVirtioNetHdr(buf)
	if !errors.Is(err, ErrFrameTooShort) {
		t.Errorf("got %v, want ErrFrameTooShort", err)
	}
}

func TestAcceptFeatures_HappyPath(t *testing.T) {
	// Device offers all four bits we want + a couple of extras.
	deviceOffers := VirtioNetFeatureMAC |
		VirtioNetFeatureMTU |
		VirtioNetFeatureStatus |
		VirtioFeatureVersion1 |
		(1 << 15) | // VIRTIO_NET_F_MRG_RXBUF — we don't accept
		(1 << 1) // VIRTIO_NET_F_CSUM — we don't accept
	negotiated, err := AcceptFeatures(deviceOffers)
	if err != nil {
		t.Fatalf("AcceptFeatures: %v", err)
	}
	want := VirtioNetFeatureMTU | VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	if negotiated != want {
		t.Errorf("negotiated: got 0x%x, want 0x%x", negotiated, want)
	}
}

// TestAcceptFeatures_DeviceMissingMTU covers the QEMU+EDK2 case where
// the device offers MAC + STATUS + VERSION_1 but not MTU. M2 must
// negotiate the subset cleanly (MTU is informational; missing-MTU is
// not an error). The QEMU+EDK2 4-arch PASS cells exercise this path
// live.
func TestAcceptFeatures_DeviceMissingMTU(t *testing.T) {
	deviceOffers := VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	negotiated, err := AcceptFeatures(deviceOffers)
	if err != nil {
		t.Fatalf("AcceptFeatures: %v", err)
	}
	want := VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	if negotiated != want {
		t.Errorf("negotiated: got 0x%x, want 0x%x", negotiated, want)
	}
	if negotiated&VirtioNetFeatureMTU != 0 {
		t.Errorf("MTU bit set in negotiated mask despite device not offering it")
	}
}

func TestAcceptFeatures_DeviceMissingVersion1(t *testing.T) {
	// Pure legacy device — VERSION_1 not offered.
	deviceOffers := VirtioNetFeatureMAC | VirtioNetFeatureStatus
	_, err := AcceptFeatures(deviceOffers)
	if !errors.Is(err, ErrNotModernDevice) {
		t.Errorf("got %v, want ErrNotModernDevice", err)
	}
}

func TestAcceptFeatures_DeviceMissingMAC(t *testing.T) {
	// Modern device but doesn't publish a MAC — M2's probe needs it
	// for the ARP source field.
	deviceOffers := VirtioNetFeatureStatus | VirtioFeatureVersion1
	_, err := AcceptFeatures(deviceOffers)
	if !errors.Is(err, ErrNoMACFeature) {
		t.Errorf("got %v, want ErrNoMACFeature", err)
	}
}

func TestMAC6_String(t *testing.T) {
	m := MAC6{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	got := m.String()
	want := "52:55:0a:00:02:02"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMAC6_StringEdge(t *testing.T) {
	m := MAC6{0x00, 0xff, 0xab, 0xcd, 0x01, 0xef}
	got := m.String()
	want := "00:ff:ab:cd:01:ef"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestMAC6_IsZero(t *testing.T) {
	if !(MAC6{}).IsZero() {
		t.Errorf("zero MAC: IsZero = false")
	}
	if (MAC6{0, 0, 0, 0, 0, 1}).IsZero() {
		t.Errorf("MAC ending 01: IsZero = true")
	}
	if (MAC6{1, 0, 0, 0, 0, 0}).IsZero() {
		t.Errorf("MAC starting 01: IsZero = true")
	}
}

func TestVirtioNetHdrSize(t *testing.T) {
	// Sanity: spec mandates 12 bytes on a VERSION_1 device.
	if VirtioNetHdrSize != 12 {
		t.Errorf("VirtioNetHdrSize: got %d, want 12", VirtioNetHdrSize)
	}
}

func TestVirtioNetQueueIndices(t *testing.T) {
	// Virtio 1.1 §5.1.2: queue 0 = receive, queue 1 = transmit.
	if VirtioNetRxQueueIdx != 0 {
		t.Errorf("RX queue idx: got %d, want 0", VirtioNetRxQueueIdx)
	}
	if VirtioNetTxQueueIdx != 1 {
		t.Errorf("TX queue idx: got %d, want 1", VirtioNetTxQueueIdx)
	}
}

func TestVirtioNetAcceptedFeatures(t *testing.T) {
	// R-M2b (RESOLVED 2026-06-07): the M2 accepted-features mask MUST
	// include VIRTIO_NET_F_MTU (bit 3) in addition to MAC | STATUS |
	// VERSION_1. Apple VZ clears FEATURES_OK if MTU isn't negotiated;
	// without it the bi-rail Y'' is unable to cover its primary prod
	// target (vfkit). On QEMU+EDK2 the bit is informational/no-op.
	// Live empirical narrow on vfkit 0.6.3 arm64 (BOOTAA64-VIRTIONET.EFI
	// against an ESP virtio-blk + scratch virtio-blk pair) established
	// that ADDING ONLY MTU to the baseline mask makes FEATURES_OK
	// stick; no other offered bit on its own does.
	want := VirtioNetFeatureMTU | VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	if VirtioNetAcceptedFeatures != want {
		t.Errorf("AcceptedFeatures: got 0x%x, want 0x%x", VirtioNetAcceptedFeatures, want)
	}
	if VirtioNetAcceptedFeatures&VirtioNetFeatureMTU == 0 {
		t.Errorf("R-M2b regression: MTU bit missing from VirtioNetAcceptedFeatures (Apple VZ will fail FEATURES_OK)")
	}
}

// TestVirtioNetFeatureMTU pins the bit number for VIRTIO_NET_F_MTU
// (Virtio 1.1 §5.1.3 — `VIRTIO_NET_F_MTU = 3`). A typo here would
// either reintroduce R-M2b (if shifted away from bit 3) or silently
// ack a wrong-named bit (if mistyped to a different identifier).
func TestVirtioNetFeatureMTU(t *testing.T) {
	if VirtioNetFeatureMTU != (1 << 3) {
		t.Errorf("VirtioNetFeatureMTU: got 0x%x, want 0x%x (Virtio 1.1 §5.1.3 — bit 3)",
			VirtioNetFeatureMTU, uint64(1<<3))
	}
}

// TestVirtioNetAcceptedFeaturesNarrow pins the R-M2c-wide accepted
// mask: every bit Apple VZ offers (lo=0x300119ab hi=0x00000005)
// EXCEPT VIRTIO_F_RING_PACKED (bit 34). The constant is used by the
// `OpenVirtioNetWithFeatures` narrow probe in
// `phase2_virtionet_tx.go`; widening it without the matching live
// validation would mis-direct the next R-M2c iteration.
func TestVirtioNetAcceptedFeaturesNarrow(t *testing.T) {
	want := VirtioNetAcceptedFeatures |
		(uint64(1) << 0) | (uint64(1) << 1) |
		(uint64(1) << 7) | (uint64(1) << 8) |
		(uint64(1) << 11) | (uint64(1) << 12) |
		(uint64(1) << 28) | (uint64(1) << 29)
	if VirtioNetAcceptedFeaturesNarrow != want {
		t.Errorf("VirtioNetAcceptedFeaturesNarrow: got 0x%x, want 0x%x",
			VirtioNetAcceptedFeaturesNarrow, want)
	}
	// Sanity: the narrow set MUST NOT include RING_PACKED (bit 34).
	// The driver doesn't implement packed-ring semantics, and the
	// device must stay in split-ring mode for this driver to work.
	if VirtioNetAcceptedFeaturesNarrow&(uint64(1)<<34) != 0 {
		t.Errorf("VirtioNetAcceptedFeaturesNarrow must NOT include VIRTIO_F_RING_PACKED (bit 34)")
	}
	// The narrow set is a SUPERSET of the standard mask — the
	// standard cell can always be reproduced by intersecting the
	// device's offer with the narrow set when the device doesn't
	// offer the extra bits.
	if VirtioNetAcceptedFeaturesNarrow&VirtioNetAcceptedFeatures != VirtioNetAcceptedFeatures {
		t.Errorf("VirtioNetAcceptedFeaturesNarrow must be a superset of VirtioNetAcceptedFeatures")
	}
}

// TestVirtioNetAcceptedFeaturesWithPacked confirms the diagnostic-only
// "everything including RING_PACKED" mask is the narrow set ORed with
// bit 34. Used by future R-M2c sub-narrows that want to probe whether
// the device behaves differently when packed is acked.
func TestVirtioNetAcceptedFeaturesWithPacked(t *testing.T) {
	want := VirtioNetAcceptedFeaturesNarrow | (uint64(1) << 34)
	if VirtioNetAcceptedFeaturesWithPacked != want {
		t.Errorf("VirtioNetAcceptedFeaturesWithPacked: got 0x%x, want 0x%x",
			VirtioNetAcceptedFeaturesWithPacked, want)
	}
}
