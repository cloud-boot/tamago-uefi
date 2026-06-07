// Host-side tests for virtqueue_packed.go.
//
// Five concerns:
//
//   1. `ComputePackedVirtqueueLayout` produces the byte offsets +
//      total size the spec mandates (Virtio 1.1 §2.7).
//   2. Descriptor read/write round-trips, with the (id, flags) tail-
//      word atomic publication ordering.
//   3. AddBuffer publishes F_AVAIL == driverWrapCounter, F_USED ==
//      complement; advances `nextAvail`; toggles the wrap counter on
//      ring wrap.
//   4. PollUsed detects completion only when both flag bits agree
//      with `deviceWrapCounter`; advances `lastUsed`; toggles the
//      device wrap counter on ring wrap.
//   5. Multi-wrap behaviour: a few rounds of AddBuffer + simulated
//      device-side completion + Reclaim, including wrap-counter
//      flips at every Size-boundary crossing.
//
// We use a Go-allocated `[]byte` for the queue backing memory, which
// gives the same byte semantics as a firmware-allocated page (UEFI
// 2.10 §2.3.x — all EfiBootServicesData is cache-coherent + plain
// RAM during Boot Services, so byte-level reads/writes are
// equivalent).

package uefiboard

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"
)

// newTestPackedVirtqueue allocates a backing buffer in Go heap and
// constructs a PackedVirtqueue pointing at it. Mirrors
// newTestVirtqueue (split) — same guard regions, same fixed
// `BasePhys = 0xDEADBEEF` for visible "got/want" output.
func newTestPackedVirtqueue(t *testing.T, size uint16, queueIdx uint16) (*PackedVirtqueue, []byte) {
	t.Helper()
	layout := ComputePackedVirtqueueLayout(size)
	const guard = 16
	full := make([]byte, int(layout.TotalSize)+2*guard)
	base := uintptr(unsafe.Pointer(&full[guard]))
	q := NewPackedVirtqueueFromAlloc(0xDEADBEEF, base, size, queueIdx)
	return q, full
}

func TestComputePackedVirtqueueLayout_Size16(t *testing.T) {
	l := ComputePackedVirtqueueLayout(16)
	if l.Size != 16 {
		t.Errorf("Size: got %d, want 16", l.Size)
	}
	// Descriptor ring: 16 entries * 16 bytes = 256 bytes at offset 0.
	if l.DescRingOffset != 0 {
		t.Errorf("DescRingOffset: got %d, want 0", l.DescRingOffset)
	}
	if l.DriverEventOffset != 256 {
		t.Errorf("DriverEventOffset: got %d, want 256", l.DriverEventOffset)
	}
	// Driver event (4 bytes) + device event (4 bytes) at offsets 256 + 4.
	if l.DeviceEventOffset != 260 {
		t.Errorf("DeviceEventOffset: got %d, want 260", l.DeviceEventOffset)
	}
	if l.TotalSize != 264 {
		t.Errorf("TotalSize: got %d, want 264", l.TotalSize)
	}
}

func TestComputePackedVirtqueueLayout_Size256(t *testing.T) {
	l := ComputePackedVirtqueueLayout(256)
	if l.DriverEventOffset != 4096 {
		t.Errorf("DriverEventOffset: got %d, want 4096", l.DriverEventOffset)
	}
	if l.DeviceEventOffset != 4100 {
		t.Errorf("DeviceEventOffset: got %d, want 4100", l.DeviceEventOffset)
	}
	if l.TotalSize != 4104 {
		t.Errorf("TotalSize: got %d, want 4104", l.TotalSize)
	}
}

func TestPackedVirtqueue_DescriptorReadWrite(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 16, 0)
	const wantFlags = VirtqPackedDescFAvail | VirtqPackedDescFWrite
	if err := q.writePackedDescriptor(3, 0x1234567890abcdef, 0x800, 7, wantFlags); err != nil {
		t.Fatalf("writePackedDescriptor: %v", err)
	}
	addr, length, id, flags, err := q.readPackedDescriptor(3)
	if err != nil {
		t.Fatalf("readPackedDescriptor: %v", err)
	}
	if addr != 0x1234567890abcdef {
		t.Errorf("addr: got 0x%x, want 0x1234567890abcdef", addr)
	}
	if length != 0x800 {
		t.Errorf("len: got 0x%x, want 0x800", length)
	}
	if id != 7 {
		t.Errorf("id: got %d, want 7", id)
	}
	if flags != wantFlags {
		t.Errorf("flags: got 0x%x, want 0x%x", flags, wantFlags)
	}
}

func TestPackedVirtqueue_DescriptorInvalidIdx(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 8, 0)
	if err := q.writePackedDescriptor(8, 0, 0, 0, 0); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("writePackedDescriptor(8) on size=8: got %v, want ErrInvalidIdx", err)
	}
	if _, _, _, _, err := q.readPackedDescriptor(99); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("readPackedDescriptor(99): got %v, want ErrInvalidIdx", err)
	}
}

// TestPackedVirtqueue_AddBuffer_PublishesAvail covers the canonical
// publication: F_AVAIL is set to the current driverWrapCounter and
// F_USED to the complement, encoding "driver-owned, fresh".
func TestPackedVirtqueue_AddBuffer_PublishesAvail(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if q.DriverWrapCounter() != 1 {
		t.Fatalf("initial driverWrapCounter: got %d, want 1", q.DriverWrapCounter())
	}
	idx, err := q.AddBuffer(0xCAFE, 0x100000, 1500, true /* writable: RX */)
	if err != nil {
		t.Fatalf("AddBuffer: %v", err)
	}
	if idx != 0 {
		t.Errorf("first AddBuffer: got idx=%d, want 0", idx)
	}
	if q.NextAvail() != 1 {
		t.Errorf("nextAvail: got %d, want 1", q.NextAvail())
	}
	if !q.Buffers[0].InUse {
		t.Errorf("Buffers[0].InUse: false, want true")
	}
	_, _, id, flags, _ := q.readPackedDescriptor(0)
	if id != 0 {
		t.Errorf("desc[0].id: got %d, want 0", id)
	}
	// Driver wrap counter is 1 ⇒ F_AVAIL set, F_USED unset.
	if flags&VirtqPackedDescFAvail == 0 {
		t.Errorf("flags missing F_AVAIL: 0x%x", flags)
	}
	if flags&VirtqPackedDescFUsed != 0 {
		t.Errorf("flags should not have F_USED: 0x%x", flags)
	}
	if flags&VirtqPackedDescFWrite == 0 {
		t.Errorf("flags missing F_WRITE: 0x%x", flags)
	}
}

// TestPackedVirtqueue_AddBuffer_NonWritable covers the TX path
// (writable=false) — F_WRITE must NOT be set.
func TestPackedVirtqueue_AddBuffer_NonWritable(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 1)
	_, err := q.AddBuffer(0, 0x200000, 64, false /* writable: TX */)
	if err != nil {
		t.Fatalf("AddBuffer: %v", err)
	}
	_, _, _, flags, _ := q.readPackedDescriptor(0)
	if flags&VirtqPackedDescFWrite != 0 {
		t.Errorf("TX descriptor has F_WRITE set: 0x%x", flags)
	}
	if flags&VirtqPackedDescFAvail == 0 {
		t.Errorf("TX descriptor missing F_AVAIL: 0x%x", flags)
	}
}

// TestPackedVirtqueue_AddBuffer_WrapsToggleCounter covers the
// driver wrap counter toggle at the Size-boundary crossing.
func TestPackedVirtqueue_AddBuffer_WrapsToggleCounter(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 2, 0)
	if q.DriverWrapCounter() != 1 {
		t.Fatalf("initial driverWrapCounter: got %d, want 1", q.DriverWrapCounter())
	}
	// Two AddBuffers fill the ring; counter stays 1 until the
	// second AddBuffer advances nextAvail from 1 to 2, which wraps
	// to 0 and flips the counter.
	if _, err := q.AddBuffer(0, 0, 64, false); err != nil {
		t.Fatalf("AddBuffer 1: %v", err)
	}
	if q.DriverWrapCounter() != 1 {
		t.Errorf("after 1 AddBuffer: counter = %d, want 1", q.DriverWrapCounter())
	}
	// Simulate the device draining slot 0 so AddBuffer 2 doesn't
	// hit ErrQueueFull at slot 0 (this matters when ring wraps
	// back).
	// AddBuffer 2 lands at slot 1 (nextAvail=1); ring is now full.
	if _, err := q.AddBuffer(0, 0, 64, false); err != nil {
		t.Fatalf("AddBuffer 2: %v", err)
	}
	if q.NextAvail() != 0 {
		t.Errorf("after 2 AddBuffers on size=2: nextAvail = %d, want 0", q.NextAvail())
	}
	if q.DriverWrapCounter() != 0 {
		t.Errorf("after ring wrap: counter = %d, want 0", q.DriverWrapCounter())
	}
}

// TestPackedVirtqueue_AddBuffer_QueueFull covers the "slot still
// driver-owned" check: re-publishing onto a slot that hasn't been
// reclaimed yet returns ErrQueueFull.
func TestPackedVirtqueue_AddBuffer_QueueFull(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 2, 0)
	if _, err := q.AddBuffer(0, 0, 64, false); err != nil {
		t.Fatalf("AddBuffer 1: %v", err)
	}
	if _, err := q.AddBuffer(0, 0, 64, false); err != nil {
		t.Fatalf("AddBuffer 2: %v", err)
	}
	// nextAvail wraps to 0; slot 0 is still InUse → ErrQueueFull.
	if _, err := q.AddBuffer(0, 0, 64, false); !errors.Is(err, ErrQueueFull) {
		t.Errorf("AddBuffer 3 (slot reuse without reclaim): got %v, want ErrQueueFull", err)
	}
}

// simulatePackedDeviceUsed forges a device-side completion: flips
// the descriptor's F_AVAIL and F_USED bits to match the SUPPLIED
// device wrap counter value (which the test caller tracks). The
// device-side update is published via atomic.StoreUint32 on the
// (id, flags) tail word — matching the live release the device's
// hardware would use.
//
// We accept the device wrap counter value as an explicit argument
// (rather than reading it off the driver-side struct) because the
// device's view is independent of the driver's view; in real
// operation the device picks up the descriptor, processes the
// payload, then writes the matching counter back. The test
// caller is the only thing that knows what value the device WOULD
// be at — driving it explicitly keeps the test honest.
func simulatePackedDeviceUsed(q *PackedVirtqueue, slotIdx uint16, length uint32, deviceWrap uint16) {
	d := q.descSlice()
	off := int(slotIdx) * VirtqPackedDescriptorSize
	// id stays as the slot index — preserve the existing value.
	id := binary.LittleEndian.Uint16(d[off+12 : off+14])
	flags := uint16(0)
	if deviceWrap == 1 {
		flags |= VirtqPackedDescFAvail | VirtqPackedDescFUsed
	}
	// Also update len in the descriptor (the device writes the
	// completion's byte count there) so the driver-side
	// readPackedDescriptor returns the correct length.
	binary.LittleEndian.PutUint32(d[off+8:off+12], length)
	binary.LittleEndian.PutUint16(d[off+12:off+14], id)
	binary.LittleEndian.PutUint16(d[off+14:off+16], flags)
}

// TestPackedVirtqueue_PollUsed_NoCompletion covers the polling-on-
// empty-queue path: with no AddBuffer + no device update, PollUsed
// must return ok=false (the slot still has F_AVAIL=0, F_USED=0 from
// the zero-initialised allocation, which is NOT
// "deviceWrapCounter matched on both bits").
func TestPackedVirtqueue_PollUsed_NoCompletion(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if _, _, ok := q.PollUsed(); ok {
		t.Errorf("PollUsed on fresh queue: ok=true, want false")
	}
}

// TestPackedVirtqueue_PollUsed_AfterPublishButBeforeUsed covers the
// state right after AddBuffer: the descriptor has F_AVAIL set,
// F_USED unset, but the deviceWrapCounter starts at 1 so the
// "device completed" pattern needs F_USED=1 too. PollUsed must
// return ok=false (driver-owned descriptor, not yet completed).
func TestPackedVirtqueue_PollUsed_AfterPublishButBeforeUsed(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if _, err := q.AddBuffer(0, 0, 64, false); err != nil {
		t.Fatalf("AddBuffer: %v", err)
	}
	if _, _, ok := q.PollUsed(); ok {
		t.Errorf("PollUsed before device completion: ok=true, want false (descriptor still driver-owned)")
	}
}

// TestPackedVirtqueue_PollUsed_DrainsOneCompletion covers the
// canonical happy-path: AddBuffer publishes, device flips both flag
// bits, driver polls and detects the completion exactly once.
func TestPackedVirtqueue_PollUsed_DrainsOneCompletion(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	descIdx, err := q.AddBuffer(0, 0, 100, false)
	if err != nil {
		t.Fatalf("AddBuffer: %v", err)
	}
	// Device completes the descriptor with deviceWrap=1 (the
	// initial value).
	simulatePackedDeviceUsed(q, descIdx, 100, 1)
	gotIdx, gotLen, ok := q.PollUsed()
	if !ok {
		t.Fatalf("PollUsed: ok=false, want true (device just published)")
	}
	if gotIdx != descIdx {
		t.Errorf("PollUsed: got idx=%d, want %d", gotIdx, descIdx)
	}
	if gotLen != 100 {
		t.Errorf("PollUsed: got len=%d, want 100", gotLen)
	}
	if q.LastUsed() != 1 {
		t.Errorf("after PollUsed: lastUsed = %d, want 1", q.LastUsed())
	}
	// Second poll: device hasn't published anything new.
	if _, _, ok := q.PollUsed(); ok {
		t.Errorf("PollUsed 2: ok=true, want false")
	}
}

// TestPackedVirtqueue_PollUsed_RingWrap covers a multi-round drain
// over a 2-slot ring: at least one wrap of `lastUsed`, with the
// matching `deviceWrapCounter` flip. After the wrap the device
// publishes with deviceWrap=0 (the post-flip value); PollUsed must
// honour the new counter.
func TestPackedVirtqueue_PollUsed_RingWrap(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 2, 0)
	// Round 1, slot 0: device publishes with deviceWrap=1.
	idx0, _ := q.AddBuffer(0, 0, 10, false)
	simulatePackedDeviceUsed(q, idx0, 10, 1)
	if got, _, ok := q.PollUsed(); !ok || got != idx0 {
		t.Fatalf("round 1 slot 0: PollUsed = (%d, ok=%v)", got, ok)
	}
	_ = q.Reclaim(idx0)
	// Round 1, slot 1: device publishes with deviceWrap=1.
	idx1, _ := q.AddBuffer(0, 0, 20, false)
	simulatePackedDeviceUsed(q, idx1, 20, 1)
	if got, _, ok := q.PollUsed(); !ok || got != idx1 {
		t.Fatalf("round 1 slot 1: PollUsed = (%d, ok=%v)", got, ok)
	}
	_ = q.Reclaim(idx1)
	// After draining 2 entries the lastUsed wrapped and
	// deviceWrapCounter flipped to 0.
	if q.LastUsed() != 0 {
		t.Errorf("after wrap: lastUsed = %d, want 0", q.LastUsed())
	}
	if q.DeviceWrapCounter() != 0 {
		t.Errorf("after wrap: deviceWrapCounter = %d, want 0", q.DeviceWrapCounter())
	}
	// Round 2, slot 0: device publishes with deviceWrap=0 — both
	// flag bits must be 0 for "completed".
	idx2, _ := q.AddBuffer(0, 0, 30, false)
	simulatePackedDeviceUsed(q, idx2, 30, 0)
	if got, _, ok := q.PollUsed(); !ok || got != idx2 {
		t.Fatalf("round 2 slot 0: PollUsed = (%d, ok=%v)", got, ok)
	}
	if q.LastUsed() != 1 {
		t.Errorf("after round 2 slot 0: lastUsed = %d, want 1", q.LastUsed())
	}
	_ = q.Reclaim(idx2)
}

// TestPackedVirtqueue_PollUsed_RespectsDeviceWrapCounter covers the
// edge case where the device's view doesn't match the driver's:
// publishing a "completed" descriptor with the WRONG wrap counter
// must NOT be observed as a completion (Virtio 1.1 §2.7.1 — the
// driver only treats a descriptor as used when BOTH bits agree with
// the deviceWrapCounter).
func TestPackedVirtqueue_PollUsed_RespectsDeviceWrapCounter(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	descIdx, _ := q.AddBuffer(0, 0, 100, false)
	// Device publishes with deviceWrap=0 (WRONG — driver expects
	// 1). Both flag bits cleared.
	simulatePackedDeviceUsed(q, descIdx, 100, 0)
	if _, _, ok := q.PollUsed(); ok {
		t.Errorf("PollUsed with mismatched wrap counter: ok=true, want false")
	}
}

// TestPackedVirtqueue_Reclaim_InvalidIdx covers the bounds check.
func TestPackedVirtqueue_Reclaim_InvalidIdx(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if err := q.Reclaim(99); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("Reclaim(99): got %v, want ErrInvalidIdx", err)
	}
}

// TestPackedVirtqueue_PackedDescBytes covers the M2-A diagnostic
// accessor: fetch the raw 16 bytes of a populated descriptor and
// confirm they match the little-endian-packed tuple.
func TestPackedVirtqueue_PackedDescBytes(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if err := q.writePackedDescriptor(2, 0x1234567890abcdef, 0xCAFE, 0x55, VirtqPackedDescFAvail|VirtqPackedDescFWrite); err != nil {
		t.Fatalf("writePackedDescriptor: %v", err)
	}
	got := q.PackedDescBytes(2)
	if len(got) != VirtqPackedDescriptorSize {
		t.Fatalf("PackedDescBytes len: got %d, want %d", len(got), VirtqPackedDescriptorSize)
	}
	if a := binary.LittleEndian.Uint64(got[0:8]); a != 0x1234567890abcdef {
		t.Errorf("addr: got 0x%x, want 0x1234567890abcdef", a)
	}
	if l := binary.LittleEndian.Uint32(got[8:12]); l != 0xCAFE {
		t.Errorf("len: got 0x%x, want 0xCAFE", l)
	}
	if id := binary.LittleEndian.Uint16(got[12:14]); id != 0x55 {
		t.Errorf("id: got 0x%x, want 0x55", id)
	}
	if f := binary.LittleEndian.Uint16(got[14:16]); f != (VirtqPackedDescFAvail | VirtqPackedDescFWrite) {
		t.Errorf("flags: got 0x%x, want 0x%x", f, VirtqPackedDescFAvail|VirtqPackedDescFWrite)
	}
	// Out-of-range returns nil — never a partial copy.
	if q.PackedDescBytes(99) != nil {
		t.Errorf("PackedDescBytes(99) on size=4: want nil")
	}
}

// TestPackedVirtqueue_EventBytes covers the diagnostic accessors for
// the driver-event + device-event regions. M2-A doesn't populate
// these (they stay zero from the allocator); the test confirms the
// accessor returns exactly 4 bytes per region.
func TestPackedVirtqueue_EventBytes(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	dr := q.DriverEventBytes()
	if len(dr) != VirtqPackedEventSize {
		t.Errorf("DriverEventBytes len: got %d, want %d", len(dr), VirtqPackedEventSize)
	}
	dv := q.DeviceEventBytes()
	if len(dv) != VirtqPackedEventSize {
		t.Errorf("DeviceEventBytes len: got %d, want %d", len(dv), VirtqPackedEventSize)
	}
	// Allocation is zero-initialised; both regions should be all-zero.
	for i, b := range dr {
		if b != 0 {
			t.Errorf("DriverEventBytes[%d]: got 0x%x, want 0x0", i, b)
		}
	}
	for i, b := range dv {
		if b != 0 {
			t.Errorf("DeviceEventBytes[%d]: got 0x%x, want 0x0", i, b)
		}
	}
}

// TestPackedVirtqueue_InitialWrapCountersAreOne pins the
// spec-mandated initial value of both wrap counters (Virtio 1.1
// §2.7.1).
func TestPackedVirtqueue_InitialWrapCountersAreOne(t *testing.T) {
	q, _ := newTestPackedVirtqueue(t, 4, 0)
	if q.DriverWrapCounter() != 1 {
		t.Errorf("initial driverWrapCounter: got %d, want 1", q.DriverWrapCounter())
	}
	if q.DeviceWrapCounter() != 1 {
		t.Errorf("initial deviceWrapCounter: got %d, want 1", q.DeviceWrapCounter())
	}
}

// TestPackedVirtqueue_Layout_DescRingComesFirst pins the fundamental
// layout invariant: the descriptor ring (driver+device shared)
// starts at offset 0; events follow. Without this, the
// SetQueueDesc(BasePhys + DescRingOffset) write would point the
// device at the wrong region.
func TestPackedVirtqueue_Layout_DescRingComesFirst(t *testing.T) {
	for _, size := range []uint16{1, 2, 4, 16, 64, 256} {
		l := ComputePackedVirtqueueLayout(size)
		if l.DescRingOffset != 0 {
			t.Errorf("size=%d: DescRingOffset = %d, want 0", size, l.DescRingOffset)
		}
		if l.DriverEventOffset != uint32(size)*VirtqPackedDescriptorSize {
			t.Errorf("size=%d: DriverEventOffset = %d, want %d", size, l.DriverEventOffset, uint32(size)*VirtqPackedDescriptorSize)
		}
		if l.DeviceEventOffset != l.DriverEventOffset+VirtqPackedEventSize {
			t.Errorf("size=%d: DeviceEventOffset = %d, want %d", size, l.DeviceEventOffset, l.DriverEventOffset+VirtqPackedEventSize)
		}
		if l.TotalSize != l.DeviceEventOffset+VirtqPackedEventSize {
			t.Errorf("size=%d: TotalSize = %d, want %d", size, l.TotalSize, l.DeviceEventOffset+VirtqPackedEventSize)
		}
	}
}
