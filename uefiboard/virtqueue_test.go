// Host-side tests for virtqueue.go.
//
// Four concerns:
//
//   1. `ComputeVirtqueueLayout` produces the byte offsets the spec
//      mandates (Virtio 1.1 §2.6).
//   2. Descriptor read/write round-trips.
//   3. AddBuffer + PostAvail + PollUsed state-machine, including
//      ring-wrap (we simulate the device by writing the used ring
//      bytes directly).
//   4. ErrQueueFull / ErrInvalidIdx surfacing.
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

// newTestVirtqueue allocates a backing buffer in Go heap memory and
// constructs a Virtqueue pointing at it. The buffer is large enough
// for the computed layout (`TotalSize`) plus 16 bytes of guard at
// each end to detect out-of-bounds writes.
func newTestVirtqueue(t *testing.T, size uint16, queueIdx uint16) (*Virtqueue, []byte) {
	t.Helper()
	layout := ComputeVirtqueueLayout(size)
	const guard = 16
	full := make([]byte, int(layout.TotalSize)+2*guard)
	base := uintptr(unsafe.Pointer(&full[guard]))
	q := NewVirtqueueFromAlloc(0xDEADBEEF, base, size, queueIdx)
	return q, full
}

func TestComputeVirtqueueLayout_Size16(t *testing.T) {
	l := ComputeVirtqueueLayout(16)
	if l.Size != 16 {
		t.Errorf("Size: got %d, want 16", l.Size)
	}
	// Descriptor table starts at 0; 16 entries * 16 bytes = 256.
	if l.DescTableOffset != 0 {
		t.Errorf("DescTableOffset: got %d, want 0", l.DescTableOffset)
	}
	if l.AvailRingOffset != 256 {
		t.Errorf("AvailRingOffset: got %d, want 256", l.AvailRingOffset)
	}
	// Available ring: header(4) + 16 entries*2 = 36 bytes; used_event
	// follows at offset 256+36 = 292.
	if l.AvailUsedEventOffset != 256+36 {
		t.Errorf("AvailUsedEventOffset: got %d, want %d", l.AvailUsedEventOffset, 256+36)
	}
	// used_event is 2 bytes; used ring starts at next 4-byte boundary
	// from 294 = 296.
	if l.UsedRingOffset != 296 {
		t.Errorf("UsedRingOffset: got %d, want 296", l.UsedRingOffset)
	}
	// Used ring: header(4) + 16 entries*8 = 132; avail_event at +132.
	if l.UsedAvailEventOffset != 296+132 {
		t.Errorf("UsedAvailEventOffset: got %d, want %d", l.UsedAvailEventOffset, 296+132)
	}
	if l.TotalSize != 296+132+2 {
		t.Errorf("TotalSize: got %d, want %d", l.TotalSize, 296+132+2)
	}
}

func TestComputeVirtqueueLayout_Size256(t *testing.T) {
	// Bigger queue — exercise the same arithmetic with size=256.
	l := ComputeVirtqueueLayout(256)
	// 256 * 16 = 4096 byte descriptor table — exactly one page.
	if l.AvailRingOffset != 4096 {
		t.Errorf("AvailRingOffset: got %d, want 4096", l.AvailRingOffset)
	}
	// Avail body: 4 + 256*2 = 516
	if l.AvailUsedEventOffset != 4096+516 {
		t.Errorf("AvailUsedEventOffset: got %d, want %d", l.AvailUsedEventOffset, 4096+516)
	}
}

func TestVirtqueue_DescriptorReadWrite(t *testing.T) {
	q, _ := newTestVirtqueue(t, 16, 0)
	if err := q.writeDescriptor(3, 0x1000, 0x800, VirtqDescFWrite, 7); err != nil {
		t.Fatalf("writeDescriptor: %v", err)
	}
	addr, length, flags, next, err := q.readDescriptor(3)
	if err != nil {
		t.Fatalf("readDescriptor: %v", err)
	}
	if addr != 0x1000 || length != 0x800 || flags != VirtqDescFWrite || next != 7 {
		t.Errorf("readDescriptor: got (0x%x, 0x%x, 0x%x, %d)", addr, length, flags, next)
	}
}

func TestVirtqueue_DescriptorInvalidIdx(t *testing.T) {
	q, _ := newTestVirtqueue(t, 8, 0)
	if err := q.writeDescriptor(8, 0, 0, 0, 0); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("writeDescriptor(8) on size=8: got %v, want ErrInvalidIdx", err)
	}
	if _, _, _, _, err := q.readDescriptor(99); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("readDescriptor(99): got %v, want ErrInvalidIdx", err)
	}
}

func TestVirtqueue_AddBufferAndPostAvail(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	// First add: descriptor 0, available[0] = 0, avail.idx = 1.
	idx, err := q.AddBuffer(0xCAFE, 0x100000, 1500, true /* writable: RX */)
	if err != nil {
		t.Fatalf("AddBuffer: %v", err)
	}
	if idx != 0 {
		t.Errorf("first AddBuffer: got idx=%d, want 0", idx)
	}
	if q.NextAvailIdx() != 1 {
		t.Errorf("nextAvailIdx: got %d, want 1", q.NextAvailIdx())
	}
	if !q.Buffers[0].InUse {
		t.Errorf("Buffers[0].InUse: false, want true")
	}
	// Descriptor 0 should have the VIRTQ_DESC_F_WRITE flag.
	_, _, flags, _, _ := q.readDescriptor(0)
	if flags&VirtqDescFWrite == 0 {
		t.Errorf("descriptor 0 flags: got 0x%x, want VIRTQ_DESC_F_WRITE set", flags)
	}
	// Available ring[0] should be 0.
	a := q.availSlice()
	if got := binary.LittleEndian.Uint16(a[VirtqAvailHeaderSize : VirtqAvailHeaderSize+2]); got != 0 {
		t.Errorf("available[0]: got %d, want 0", got)
	}
	if q.AvailIdx() != 1 {
		t.Errorf("avail.idx: got %d, want 1", q.AvailIdx())
	}
}

func TestVirtqueue_AddBufferQueueFull(t *testing.T) {
	q, _ := newTestVirtqueue(t, 2, 0)
	if _, err := q.AddBuffer(0, 0, 100, false); err != nil {
		t.Fatalf("AddBuffer 1: %v", err)
	}
	if _, err := q.AddBuffer(0, 0, 100, false); err != nil {
		t.Fatalf("AddBuffer 2: %v", err)
	}
	if _, err := q.AddBuffer(0, 0, 100, false); !errors.Is(err, ErrQueueFull) {
		t.Errorf("AddBuffer 3 (queue full): got %v, want ErrQueueFull", err)
	}
}

func TestVirtqueue_AddBufferReclaimReusesSlot(t *testing.T) {
	q, _ := newTestVirtqueue(t, 2, 0)
	idx0, _ := q.AddBuffer(0, 0, 100, false)
	idx1, _ := q.AddBuffer(0, 0, 100, false)
	if idx0 != 0 || idx1 != 1 {
		t.Fatalf("initial AddBuffer indices: got (%d, %d), want (0, 1)", idx0, idx1)
	}
	// Reclaim slot 0; next AddBuffer should pick slot 0 again
	// (linear scan finds the first free slot).
	if err := q.Reclaim(0); err != nil {
		t.Fatalf("Reclaim(0): %v", err)
	}
	if q.Buffers[0].InUse {
		t.Errorf("after Reclaim: Buffers[0].InUse = true")
	}
	idx2, err := q.AddBuffer(0, 0, 100, false)
	if err != nil {
		t.Fatalf("AddBuffer after reclaim: %v", err)
	}
	if idx2 != 0 {
		t.Errorf("after reclaim: got idx=%d, want 0", idx2)
	}
}

func TestVirtqueue_PostAvailInvalidIdx(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	if err := q.PostAvail(99); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("PostAvail(99): got %v, want ErrInvalidIdx", err)
	}
}

func TestVirtqueue_ReclaimInvalidIdx(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	if err := q.Reclaim(99); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("Reclaim(99): got %v, want ErrInvalidIdx", err)
	}
}

// simulateDeviceUsed writes one used-ring entry as if the device
// completed descriptor `descIdx` with `length` bytes. Used for the
// PollUsed test below — we don't have a real device to drive the
// rings, so we forge the device-side writes ourselves.
func simulateDeviceUsed(q *Virtqueue, descIdx uint16, length uint32) {
	u := q.usedSlice()
	usedIdx := binary.LittleEndian.Uint16(u[2:4]) // current device-side idx
	slot := int(VirtqUsedHeaderSize) + (int(usedIdx)%int(q.Layout.Size))*VirtqUsedRingEntrySize
	binary.LittleEndian.PutUint32(u[slot:slot+4], uint32(descIdx))
	binary.LittleEndian.PutUint32(u[slot+4:slot+8], length)
	binary.LittleEndian.PutUint16(u[2:4], usedIdx+1)
}

func TestVirtqueue_PollUsedDrainsOneEntry(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	// Add 2 buffers + simulate the device returning both.
	_, _ = q.AddBuffer(0, 0, 100, false)
	_, _ = q.AddBuffer(0, 0, 100, false)
	simulateDeviceUsed(q, 0, 100)
	simulateDeviceUsed(q, 1, 200)

	// First poll: descriptor 0.
	idx, length, ok := q.PollUsed()
	if !ok {
		t.Fatalf("PollUsed 1: ok=false, want true")
	}
	if idx != 0 || length != 100 {
		t.Errorf("PollUsed 1: got (%d, %d), want (0, 100)", idx, length)
	}
	// Second poll: descriptor 1.
	idx, length, ok = q.PollUsed()
	if !ok {
		t.Fatalf("PollUsed 2: ok=false, want true")
	}
	if idx != 1 || length != 200 {
		t.Errorf("PollUsed 2: got (%d, %d), want (1, 200)", idx, length)
	}
	// Third poll: device hasn't published anything new.
	if _, _, ok := q.PollUsed(); ok {
		t.Errorf("PollUsed 3: ok=true, want false")
	}
}

func TestVirtqueue_PollUsedRingWrap(t *testing.T) {
	q, _ := newTestVirtqueue(t, 2, 0)
	// Fill+drain enough times to wrap the 2-slot used ring at least once.
	for round := 0; round < 5; round++ {
		_, _ = q.AddBuffer(0, 0, 100, false)
		_, _ = q.AddBuffer(0, 0, 100, false)
		simulateDeviceUsed(q, 0, 100)
		simulateDeviceUsed(q, 1, 200)
		idx0, _, ok := q.PollUsed()
		if !ok || idx0 != 0 {
			t.Errorf("round %d: PollUsed 0 = (%d, ok=%v)", round, idx0, ok)
		}
		idx1, _, ok := q.PollUsed()
		if !ok || idx1 != 1 {
			t.Errorf("round %d: PollUsed 1 = (%d, ok=%v)", round, idx1, ok)
		}
		_ = q.Reclaim(0)
		_ = q.Reclaim(1)
	}
	if q.LastSeenUsedIdx() != 10 {
		t.Errorf("after 5 rounds: lastSeenUsedIdx = %d, want 10", q.LastSeenUsedIdx())
	}
}

func TestVirtqueue_AvailFlags(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	if got := q.AvailFlags(); got != 0 {
		t.Errorf("default AvailFlags: got 0x%x, want 0", got)
	}
	// Manually set the flag bit to simulate the driver disabling
	// interrupts; verify the round-trip read.
	a := q.availSlice()
	binary.LittleEndian.PutUint16(a[0:2], 0x0001)
	if got := q.AvailFlags(); got != 0x0001 {
		t.Errorf("after set: AvailFlags = 0x%x, want 0x1", got)
	}
}

func TestVirtqueue_UsedRingAtWrapping(t *testing.T) {
	q, _ := newTestVirtqueue(t, 4, 0)
	// Forge two entries at logical indices 6 and 7, which after %4
	// wrap to slots 2 and 3.
	u := q.usedSlice()
	slot6 := int(VirtqUsedHeaderSize) + 2*VirtqUsedRingEntrySize
	binary.LittleEndian.PutUint32(u[slot6:slot6+4], 0xAAAA)
	binary.LittleEndian.PutUint32(u[slot6+4:slot6+8], 0xBBBB)
	id, length := q.UsedRingAt(6)
	if id != 0xAAAA || length != 0xBBBB {
		t.Errorf("UsedRingAt(6): got (0x%x, 0x%x), want (0xAAAA, 0xBBBB)", id, length)
	}
}

func TestVirtqueue_AddBufferInvalidDescriptorIdx(t *testing.T) {
	// The internal writeDescriptor validates idx range; sized 4
	// queue tries to write desc[5] — out of range.
	q, _ := newTestVirtqueue(t, 4, 0)
	if err := q.writeDescriptor(5, 0, 0, 0, 0); !errors.Is(err, ErrInvalidIdx) {
		t.Errorf("writeDescriptor(5) on size=4: got %v, want ErrInvalidIdx", err)
	}
}
