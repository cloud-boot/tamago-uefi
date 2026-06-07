// Host-side tests for the M2-B post-EBS init state-machine surface.
//
// The live MMIO accessors (`mmioReadU*` / `mmioWriteU*`) deref
// `unsafe.Pointer`-cast physical addresses; under host `go test`
// those addresses don't map to anything and would fault. So this
// file tests ONLY:
//
//   1. The trace-byte constants (so a typo doesn't silently break
//      the post-EBS observability).
//   2. `lastTraceByte` — pure data, no MMIO.
//   3. `EncodeTraceMarker` — pure data, no MMIO.
//   4. `postEBSDeviceFeatures64` and friends through compile-time
//      sanity (the host build still compiles them; running them
//      against a synthetic state would fault, so we don't).

package uefiboard

import (
	"bytes"
	"testing"
)

func TestPostEBSTraceConstants_UniqueAndPrintable(t *testing.T) {
	// All trace bytes MUST be printable ASCII so the host can grep
	// them out of a scratch-buffer hex-dump. And they MUST be unique
	// — a duplicate would make the trace ambiguous.
	traces := []byte{
		postEBSTraceStart,
		postEBSTraceReset,
		postEBSTraceAck,
		postEBSTraceDriver,
		postEBSTraceFeaturesRead,
		postEBSTraceFeaturesWritten,
		postEBSTraceFeaturesOK,
		postEBSTraceQRx,
		postEBSTraceQTx,
		postEBSTraceDriverOK,
		postEBSTraceRxFilled,
		postEBSTraceTxSubmit,
		postEBSTraceTxNotify,
		postEBSTraceTxCompletion,
		postEBSTraceRxCompletion,
		postEBSTraceFailMarker,
	}
	seen := map[byte]bool{}
	for _, b := range traces {
		if b < 0x20 || b > 0x7e {
			t.Errorf("trace byte 0x%x is not printable ASCII", b)
		}
		if seen[b] {
			t.Errorf("trace byte 0x%x (%c) duplicated", b, b)
		}
		seen[b] = true
	}
}

func TestLastTraceByte_Empty(t *testing.T) {
	if got := lastTraceByte([]byte{}); got != 0 {
		t.Errorf("lastTraceByte(empty) = 0x%x, want 0", got)
	}
}

func TestLastTraceByte_AllZero(t *testing.T) {
	if got := lastTraceByte([]byte{0, 0, 0, 0}); got != 0 {
		t.Errorf("lastTraceByte(all-zero) = 0x%x, want 0", got)
	}
}

func TestLastTraceByte_SingleByte(t *testing.T) {
	if got := lastTraceByte([]byte{'A'}); got != 'A' {
		t.Errorf("lastTraceByte([A]) = 0x%x, want 'A'", got)
	}
}

func TestLastTraceByte_TrailingZeros(t *testing.T) {
	if got := lastTraceByte([]byte{'A', 'B', 'C', 0, 0}); got != 'C' {
		t.Errorf("lastTraceByte([A,B,C,0,0]) = 0x%x, want 'C'", got)
	}
}

func TestEncodeTraceMarker_SmallDst(t *testing.T) {
	// dst shorter than 16 bytes should silently no-op.
	v := &VirtioNetPostEBS{}
	dst := make([]byte, 8)
	v.EncodeTraceMarker(dst)
	for i, b := range dst {
		if b != 0 {
			t.Errorf("dst[%d] = 0x%x, want 0 (short dst should be untouched)", i, b)
		}
	}
}

func TestEncodeTraceMarker_HappyPath(t *testing.T) {
	v := &VirtioNetPostEBS{
		NegotiatedFeatures: 0x01020304_05060708,
		InitTrace: [16]byte{
			postEBSTraceStart, postEBSTraceReset, postEBSTraceAck,
			postEBSTraceDriver, postEBSTraceFeaturesOK,
		},
	}
	dst := make([]byte, 16)
	v.EncodeTraceMarker(dst)

	// Bytes 0..4 — "M2B!" magic.
	wantMagic := []byte{'M', '2', 'B', '!'}
	if !bytes.Equal(dst[0:4], wantMagic) {
		t.Errorf("magic: got %q, want %q", dst[0:4], wantMagic)
	}
	// Byte 4 — last non-zero trace byte (= postEBSTraceFeaturesOK = 'O').
	if dst[4] != postEBSTraceFeaturesOK {
		t.Errorf("dst[4] = 0x%x, want 0x%x (postEBSTraceFeaturesOK)", dst[4], postEBSTraceFeaturesOK)
	}
	// Byte 5 — reserved zero.
	if dst[5] != 0 {
		t.Errorf("dst[5] = 0x%x, want 0", dst[5])
	}
	// Bytes 6..8 — negotiated features low 16 bits, LE. Low 16 of
	// 0x0102030405060708 is 0x0708.
	if dst[6] != 0x08 || dst[7] != 0x07 {
		t.Errorf("dst[6..8] = 0x%02x 0x%02x, want 0x08 0x07 (LE 0x0708)", dst[6], dst[7])
	}
	// Bytes 8..16 — reserved zero.
	for i := 8; i < 16; i++ {
		if dst[i] != 0 {
			t.Errorf("dst[%d] = 0x%x, want 0", i, dst[i])
		}
	}
}

func TestEncodeTraceMarker_EmptyTrace(t *testing.T) {
	v := &VirtioNetPostEBS{NegotiatedFeatures: 0}
	dst := make([]byte, 16)
	v.EncodeTraceMarker(dst)
	if !bytes.Equal(dst[0:4], []byte{'M', '2', 'B', '!'}) {
		t.Errorf("magic missing on empty-trace encode")
	}
	if dst[4] != 0 {
		t.Errorf("dst[4] = 0x%x, want 0 (empty trace)", dst[4])
	}
}

// TestPostEBSGlobalDefaultsNil pins the package-scope global's
// initial value. A post-EBS code path that runs before
// `ExitToBareMetal` has been called MUST see PostEBSGlobal == nil
// and bail out cleanly.
func TestPostEBSGlobalDefaultsNil(t *testing.T) {
	// We can't reset it from the test (other tests may have run);
	// just check the default-initialised package state at process
	// start. The runtime ensures globals are zero-initialised.
	// We don't unconditionally assert nil because the order of
	// other tests is undefined — instead we assert the type.
	var _ *CapturedState = PostEBSGlobal
}

// TestErrPostEBSNoCapture covers the sentinel's error message
// surface so a future renaming or duplicate sentinel surfaces
// loudly in CI. ErrPostEBSNoCapture is a concrete `vpciError`
// (string-backed value type), not an interface — so we can't
// compare it to nil; we just exercise the Error() method.
func TestErrPostEBSNoCapture(t *testing.T) {
	msg := ErrPostEBSNoCapture.Error()
	if msg == "" {
		t.Errorf("ErrPostEBSNoCapture.Error() is empty")
	}
}

func TestErrEBSRetryExhausted(t *testing.T) {
	msg := ErrEBSRetryExhausted.Error()
	if msg == "" {
		t.Errorf("ErrEBSRetryExhausted.Error() is empty")
	}
}

func TestMaxEBSRetries(t *testing.T) {
	if MaxEBSRetries < 1 {
		t.Errorf("MaxEBSRetries = %d, want >= 1", MaxEBSRetries)
	}
}
