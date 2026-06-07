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
	// Device offers all three we want + a couple of extras.
	deviceOffers := VirtioNetFeatureMAC |
		VirtioNetFeatureStatus |
		VirtioFeatureVersion1 |
		(1 << 15) | // VIRTIO_NET_F_MRG_RXBUF — we don't accept
		(1 << 1) // VIRTIO_NET_F_CSUM — we don't accept
	negotiated, err := AcceptFeatures(deviceOffers)
	if err != nil {
		t.Fatalf("AcceptFeatures: %v", err)
	}
	want := VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	if negotiated != want {
		t.Errorf("negotiated: got 0x%x, want 0x%x", negotiated, want)
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
	want := VirtioNetFeatureMAC | VirtioNetFeatureStatus | VirtioFeatureVersion1
	if VirtioNetAcceptedFeatures != want {
		t.Errorf("AcceptedFeatures: got 0x%x, want 0x%x", VirtioNetAcceptedFeatures, want)
	}
}
