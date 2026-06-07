// Host-side tests for blkprintk.go.
//
// Exercises the ring buffer's append / wrap / chronological-order
// guarantees and the (write count, payload) frame serializer +
// decoder pair. The live Flush method (blkprintk_tamago.go) is
// firmware-only and not tested here — but its preconditions
// (Increment + Serialize + ResetAutoFlush) all live in the
// host-testable file and ARE covered.

package uefiboard

import (
	"strings"
	"testing"
)

func TestBlkRingNew(t *testing.T) {
	r := NewBlkRingBuffer()
	if r == nil {
		t.Fatal("NewBlkRingBuffer returned nil")
	}
	if r.IsBound() {
		t.Error("fresh ring should not be bound")
	}
	if r.Total() != 0 {
		t.Errorf("fresh ring Total = %d, want 0", r.Total())
	}
	if r.WriteCount() != 0 {
		t.Errorf("fresh ring WriteCount = %d, want 0", r.WriteCount())
	}
	if r.Wrapped() {
		t.Error("fresh ring should not be wrapped")
	}
}

func TestBlkRingAppendBelowCapacity(t *testing.T) {
	r := NewBlkRingBuffer()
	for i := 0; i < 100; i++ {
		r.Append(byte('a' + i%26))
	}
	if r.Total() != 100 {
		t.Errorf("Total after 100 appends = %d, want 100", r.Total())
	}
	if r.Wrapped() {
		t.Error("100 < BlkRingPayloadCapacity, should not be wrapped")
	}
	payload := r.PayloadBytes()
	if len(payload) != 100 {
		t.Errorf("PayloadBytes len = %d, want 100", len(payload))
	}
	for i := 0; i < 100; i++ {
		want := byte('a' + i%26)
		if payload[i] != want {
			t.Errorf("payload[%d] = 0x%02x, want 0x%02x", i, payload[i], want)
		}
	}
}

func TestBlkRingAppendString(t *testing.T) {
	r := NewBlkRingBuffer()
	n := r.AppendString("hello world\n")
	if n != 12 {
		t.Errorf("AppendString returned %d, want 12", n)
	}
	if r.Total() != 12 {
		t.Errorf("Total = %d, want 12", r.Total())
	}
	payload := r.PayloadBytes()
	if string(payload) != "hello world\n" {
		t.Errorf("payload = %q, want %q", string(payload), "hello world\n")
	}
}

// TestBlkRingWrapAround pins the ring's wrap behavior: the OLDEST
// bytes are dropped to make room for the newest; the serialized
// payload always presents bytes in chronological order. Specifically,
// after writing N bytes where N > capacity, the payload contains the
// LAST `capacity` bytes (i.e., bytes [N-capacity, N)).
func TestBlkRingWrapAround(t *testing.T) {
	r := NewBlkRingBuffer()
	// Write capacity + 100 bytes; each byte's value = lower 8 bits of
	// its global index, so we can spot-check positions in the payload.
	total := BlkRingPayloadCapacity + 100
	for i := 0; i < total; i++ {
		r.Append(byte(i))
	}
	if !r.Wrapped() {
		t.Errorf("ring should be wrapped after %d appends; Total=%d, cap=%d",
			total, r.Total(), BlkRingPayloadCapacity)
	}
	if r.Total() != uint64(total) {
		t.Errorf("Total = %d, want %d", r.Total(), total)
	}
	payload := r.PayloadBytes()
	if len(payload) != BlkRingPayloadCapacity {
		t.Errorf("post-wrap payload len = %d, want %d", len(payload), BlkRingPayloadCapacity)
	}
	// The payload should be bytes [total-capacity, total), so
	// payload[0] = byte(total-capacity), payload[capacity-1] =
	// byte(total-1).
	wantFirst := byte(total - BlkRingPayloadCapacity)
	if payload[0] != wantFirst {
		t.Errorf("payload[0] = 0x%02x, want 0x%02x", payload[0], wantFirst)
	}
	wantLast := byte(total - 1)
	if payload[len(payload)-1] != wantLast {
		t.Errorf("payload[-1] = 0x%02x, want 0x%02x", payload[len(payload)-1], wantLast)
	}
}

// TestBlkRingExactlyAtCapacity verifies the "ring has filled but
// not yet wrapped" boundary. Total == capacity is the spec boundary
// where Wrapped() should still report false.
func TestBlkRingExactlyAtCapacity(t *testing.T) {
	r := NewBlkRingBuffer()
	for i := 0; i < BlkRingPayloadCapacity; i++ {
		r.Append(byte(i))
	}
	if r.Wrapped() {
		t.Errorf("ring at exactly capacity should not yet be wrapped (Total=%d)", r.Total())
	}
	payload := r.PayloadBytes()
	if len(payload) != BlkRingPayloadCapacity {
		t.Errorf("payload len at capacity = %d, want %d",
			len(payload), BlkRingPayloadCapacity)
	}
	if payload[0] != 0 {
		t.Errorf("first byte = 0x%02x, want 0x00", payload[0])
	}
	// Adding ONE more byte should flip the wrap flag.
	r.Append(0xff)
	if !r.Wrapped() {
		t.Errorf("ring at capacity+1 should be wrapped")
	}
}

// TestBlkRingMonotonicWriteCount pins the write counter: it starts at
// 0, every IncrementWriteCount increments it by 1, and the serialized
// frame embeds the current value at offset 0..7 little-endian.
func TestBlkRingMonotonicWriteCount(t *testing.T) {
	r := NewBlkRingBuffer()
	if r.WriteCount() != 0 {
		t.Errorf("initial WriteCount = %d, want 0", r.WriteCount())
	}
	r.AppendString("first\n")
	r.IncrementWriteCount()
	if r.WriteCount() != 1 {
		t.Errorf("WriteCount after first increment = %d, want 1", r.WriteCount())
	}
	frame := r.Serialize()
	if got := leU64(frame[0:8]); got != 1 {
		t.Errorf("frame header writeCount = %d, want 1", got)
	}

	r.AppendString("second\n")
	r.IncrementWriteCount()
	if r.WriteCount() != 2 {
		t.Errorf("WriteCount after second increment = %d, want 2", r.WriteCount())
	}
	frame = r.Serialize()
	if got := leU64(frame[0:8]); got != 2 {
		t.Errorf("frame header writeCount = %d, want 2", got)
	}
}

// TestBlkRingSerializeFrameShape pins the on-disk frame layout: the
// frame is exactly BlkRingCapacity bytes long, header at offset 0,
// payload starting at offset 16, with trailing zero-fill.
func TestBlkRingSerializeFrameShape(t *testing.T) {
	r := NewBlkRingBuffer()
	r.AppendString("ABC")
	r.IncrementWriteCount()
	frame := r.Serialize()
	if len(frame) != BlkRingCapacity {
		t.Fatalf("frame len = %d, want %d", len(frame), BlkRingCapacity)
	}
	if got := leU64(frame[0:8]); got != 1 {
		t.Errorf("writeCount in frame = %d, want 1", got)
	}
	if got := leU64(frame[8:16]); got != 3 {
		t.Errorf("payload byte count = %d, want 3", got)
	}
	if frame[16] != 'A' || frame[17] != 'B' || frame[18] != 'C' {
		t.Errorf("payload at offset 16..19 = %q, want %q",
			string(frame[16:19]), "ABC")
	}
	// Tail must be zero-filled.
	for i := 19; i < BlkRingCapacity; i++ {
		if frame[i] != 0 {
			t.Errorf("frame[%d] = 0x%02x, want 0x00 (zero-fill)", i, frame[i])
			break
		}
	}
}

// TestBlkRingDecodeFrameRoundTrip pins the host-side decode path: a
// serialized frame from a ring must decode back to the same
// (writeCount, payload) pair. This is what the host CI / operator
// tooling uses to read the disk file post-halt.
func TestBlkRingDecodeFrameRoundTrip(t *testing.T) {
	r := NewBlkRingBuffer()
	r.AppendString("phase2-blkprintk: probe output line 1\n")
	r.AppendString("phase2-blkprintk: probe output line 2\n")
	r.IncrementWriteCount()
	r.IncrementWriteCount()
	r.IncrementWriteCount()
	frame := r.Serialize()

	gotCount, gotPayload, err := DecodeBlkRingFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBlkRingFrame: %v", err)
	}
	if gotCount != 3 {
		t.Errorf("decoded writeCount = %d, want 3", gotCount)
	}
	want := "phase2-blkprintk: probe output line 1\nphase2-blkprintk: probe output line 2\n"
	if string(gotPayload) != want {
		t.Errorf("decoded payload = %q, want %q", string(gotPayload), want)
	}
}

// TestBlkRingDecodeShortFrame surfaces malformed input handling.
func TestBlkRingDecodeShortFrame(t *testing.T) {
	if _, _, err := DecodeBlkRingFrame([]byte{0, 1, 2, 3, 4, 5}); err == nil {
		t.Error("expected error on too-short frame")
	}
}

// TestBlkRingDecodeOversizedPayload surfaces a malicious / corrupted
// frame whose declared payload length exceeds capacity.
func TestBlkRingDecodeOversizedPayload(t *testing.T) {
	frame := make([]byte, BlkRingCapacity)
	putLE64(frame[0:8], 1)
	putLE64(frame[8:16], uint64(BlkRingPayloadCapacity+1))
	if _, _, err := DecodeBlkRingFrame(frame); err == nil {
		t.Error("expected error on oversized payload")
	}
}

// TestBlkRingDecodeShortPayload surfaces a frame whose declared
// payload length exceeds the actual frame's tail.
func TestBlkRingDecodeShortPayload(t *testing.T) {
	frame := make([]byte, 24) // 16-byte header + 8 bytes
	putLE64(frame[0:8], 1)
	putLE64(frame[8:16], 100) // declare 100 bytes of payload
	if _, _, err := DecodeBlkRingFrame(frame); err == nil {
		t.Error("expected error on short payload tail")
	}
}

// TestBlkRingDecodeWrappedRing verifies that a ring that has wrapped
// serializes the most-recent capacity bytes, and the host decodes
// those bytes exactly.
func TestBlkRingDecodeWrappedRing(t *testing.T) {
	r := NewBlkRingBuffer()
	// Push enough data to wrap twice; the recoverable payload is the
	// last `capacity` bytes.
	const totalWrites = BlkRingPayloadCapacity*2 + 73
	for i := 0; i < totalWrites; i++ {
		r.Append(byte(i & 0xFF))
	}
	r.IncrementWriteCount()
	frame := r.Serialize()
	_, payload, err := DecodeBlkRingFrame(frame)
	if err != nil {
		t.Fatalf("DecodeBlkRingFrame: %v", err)
	}
	if len(payload) != BlkRingPayloadCapacity {
		t.Errorf("decoded payload len = %d, want %d", len(payload), BlkRingPayloadCapacity)
	}
	// First decoded byte should be byte((totalWrites - capacity) & 0xFF).
	wantFirst := byte((totalWrites - BlkRingPayloadCapacity) & 0xFF)
	if payload[0] != wantFirst {
		t.Errorf("decoded payload[0] = 0x%02x, want 0x%02x", payload[0], wantFirst)
	}
}

// TestBlkRingAutoFlushTrigger pins the auto-flush threshold logic.
func TestBlkRingAutoFlushTrigger(t *testing.T) {
	r := NewBlkRingBuffer()
	if r.AutoFlushReady() {
		t.Error("fresh ring should not be auto-flush ready")
	}
	// Write fewer than threshold bytes.
	for i := 0; i < BlkAutoFlushBytes-1; i++ {
		r.Append('x')
	}
	if r.AutoFlushReady() {
		t.Error("ring should not be auto-flush ready at threshold-1")
	}
	// One more byte should trip the threshold.
	r.Append('x')
	if !r.AutoFlushReady() {
		t.Error("ring should be auto-flush ready at threshold")
	}
	// ResetAutoFlush should clear the flag.
	r.ResetAutoFlush()
	if r.AutoFlushReady() {
		t.Error("ring should not be auto-flush ready after ResetAutoFlush")
	}
}

// TestBlkRingBindBlockIO exercises the bind validation.
func TestBlkRingBindBlockIO(t *testing.T) {
	r := NewBlkRingBuffer()
	// BlockSize=0 is invalid.
	if err := r.BindBlockIO(0xDEAD, 1, 0, 0); err == nil {
		t.Error("expected error on BlockSize=0")
	}
	// BlockSize that doesn't divide capacity is invalid.
	if err := r.BindBlockIO(0xDEAD, 1, 1024+1, 0); err == nil {
		t.Error("expected error on non-dividing BlockSize")
	}
	// Standard cases must succeed.
	for _, bs := range []uint32{512, 1024, 2048, 4096} {
		r2 := NewBlkRingBuffer()
		if err := r2.BindBlockIO(0xDEAD, 1, bs, 0); err != nil {
			t.Errorf("BindBlockIO(blockSize=%d): %v", bs, err)
		}
		if !r2.IsBound() {
			t.Errorf("ring should be bound after BindBlockIO(blockSize=%d)", bs)
		}
	}
}

// TestBlkRingPayloadCapacityIsSane sanity-checks that the named
// constants line up arithmetically.
func TestBlkRingPayloadCapacityIsSane(t *testing.T) {
	if BlkRingCapacity != 32*1024 {
		t.Errorf("BlkRingCapacity = %d, want %d", BlkRingCapacity, 32*1024)
	}
	if BlkRingHeaderSize != 16 {
		t.Errorf("BlkRingHeaderSize = %d, want 16", BlkRingHeaderSize)
	}
	if BlkRingPayloadCapacity != BlkRingCapacity-BlkRingHeaderSize {
		t.Errorf("BlkRingPayloadCapacity = %d, want %d",
			BlkRingPayloadCapacity, BlkRingCapacity-BlkRingHeaderSize)
	}
	if BlkSentinel != 0x04 {
		t.Errorf("BlkSentinel = 0x%02x, want 0x04", BlkSentinel)
	}
}

// TestBlkRingPutLE64 pins the little-endian writer used by Serialize.
func TestBlkRingPutLE64(t *testing.T) {
	var buf [8]byte
	putLE64(buf[:], 0xCAFEBABEDEADBEEF)
	want := [8]byte{0xEF, 0xBE, 0xAD, 0xDE, 0xBE, 0xBA, 0xFE, 0xCA}
	if buf != want {
		t.Errorf("putLE64 got % x, want % x", buf, want)
	}
}

// TestBlkPrintkScratchMagic pins the 16-byte magic that identifies
// the dedicated scratch disk among all writable bare-disk handles
// the firmware exposes. The probe reads LBA 0 of each candidate and
// matches the first 16 bytes against this. The constant MUST stay
// in sync with the host-side seeding tool
// (cmd/blkprintk-seed/main.go).
func TestBlkPrintkScratchMagic(t *testing.T) {
	if len(BlkPrintkScratchMagic) != 16 {
		t.Errorf("BlkPrintkScratchMagic len = %d, want 16", len(BlkPrintkScratchMagic))
	}
	// The "cloudboot-M1.6" prefix is human-readable; the last two
	// bytes are NUL. A typo here would silently break the side-channel.
	wantPrefix := "cloudboot-M1.6"
	for i, c := range wantPrefix {
		if BlkPrintkScratchMagic[i] != byte(c) {
			t.Errorf("BlkPrintkScratchMagic[%d] = 0x%02x, want 0x%02x (%q)",
				i, BlkPrintkScratchMagic[i], byte(c), string(c))
		}
	}
	if BlkPrintkScratchMagic[14] != 0 || BlkPrintkScratchMagic[15] != 0 {
		t.Errorf("BlkPrintkScratchMagic tail bytes = 0x%02x 0x%02x, want 0x00 0x00",
			BlkPrintkScratchMagic[14], BlkPrintkScratchMagic[15])
	}
}

// TestBlkRingFlushUnboundFails surfaces the ErrNoBlockIOSink error
// path. The Flush method itself lives in blkprintk_tamago.go and
// is not host-buildable, but the precondition error chain is — we
// confirm the sentinel error value is correct + non-nil.
func TestBlkRingFlushUnbound_ErrorIsDistinct(t *testing.T) {
	if ErrNoBlockIOSink == nil {
		t.Error("ErrNoBlockIOSink should not be nil")
	}
	if !strings.Contains(ErrNoBlockIOSink.Error(), "Block IO") {
		t.Errorf("ErrNoBlockIOSink message = %q, should mention Block IO", ErrNoBlockIOSink.Error())
	}
	if ErrBufferSizeMismatch == nil {
		t.Error("ErrBufferSizeMismatch should not be nil")
	}
	if !strings.Contains(ErrBufferSizeMismatch.Error(), "BlockSize") {
		t.Errorf("ErrBufferSizeMismatch message = %q, should mention BlockSize", ErrBufferSizeMismatch.Error())
	}
}
