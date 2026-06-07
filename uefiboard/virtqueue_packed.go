// cloud-boot UEFI board — Virtio packed-ring virtqueue layout +
// driver-side data structures (Phase 2, M2-A experiment).
//
// Host-buildable: no //go:build tamago directive. The layout
// constants, the `PackedVirtqueue` struct, the descriptor-ring
// arithmetic, and the AddBuffer / Recv state machine are all pure Go
// data manipulation; the live page allocation (via
// gBS->AllocatePages) is reused from `virtqueue_tamago.go` through
// the shared `AllocatePages` / `zeroPages` helpers. This split lets
// the host test the layout + the wrap-counter logic + the AddBuffer /
// Recv state machine without pulling efiCall in.
//
// References:
//
//   - Virtio 1.1 §2.7 "Packed Virtqueues" — the layout this file
//     implements. A SINGLE ring of `vring_packed_desc` carries both
//     "available" (driver-published) and "used" (device-completed)
//     descriptors, distinguished by the VIRTQ_DESC_F_AVAIL /
//     VIRTQ_DESC_F_USED flag bits plus the driver/device wrap
//     counters. There is NO separate avail ring and NO separate
//     used ring — the bidirectional state lives entirely on each
//     descriptor's `flags` word.
//
//   - Virtio 1.1 §2.7.5 "Packed Virtqueue Descriptor Table":
//
//	     struct vring_packed_desc {
//	         le64 addr;
//	         le32 len;
//	         le16 id;
//	         le16 flags;
//	     };
//
//   - Virtio 1.1 §2.7.13 "Driver Event Suppression" — 4-byte
//     `struct vring_packed_desc_event { le16 off_wrap; le16 flags; }`
//     The driver writes it; the device reads it. M2-A allocates the
//     region (so the device-side reads have something defined to
//     read) but does NOT enable interrupt suppression — we drive the
//     queue by polling.
//
//   - Virtio 1.1 §2.7.14 "Device Event Suppression" — same 4-byte
//     struct, written by the device, read by the driver. Same: we
//     allocate but don't consult it.
//
//   - Virtio 1.1 §2.7.1 "Driver and Device Ring Wrap Counters" —
//     both wrap counters start at 1. The driver toggles its counter
//     each time `nextAvail % Size == 0` AFTER an AddBuffer; the
//     device toggles its counter on the matching used-side wrap.
//     The pair of bits (VIRTQ_DESC_F_AVAIL, VIRTQ_DESC_F_USED) per
//     descriptor encodes the descriptor's current owner:
//
//          driver-owned (avail): F_AVAIL == driverWrapCounter,
//                                F_USED  != driverWrapCounter
//          device-owned (used):  F_AVAIL == F_USED == deviceWrapCounter
//
//     A descriptor in the "buffer flag" state (driver-owned, ready
//     for the device to consume) has F_AVAIL set to the current
//     driver wrap counter and F_USED set to the opposite.
//
//   - Linux drivers/virtio/virtio_ring.c (`virtqueue_add_packed` and
//     `virtqueue_get_buf_ctx_packed`) — canonical Go-translatable
//     reference for the wrap-counter / flag-bit dance we follow.

package uefiboard

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"unsafe"
)

// VirtqPackedDescriptorSize is the on-the-wire size of one packed
// descriptor (Virtio 1.1 §2.7.5). Sixteen bytes:
//
//	0..7   addr   (le64) — guest-physical address of the buffer
//	8..11  len    (le32) — buffer length
//	12..13 id     (le16) — opaque caller-chosen identifier (M2-A uses
//	                       the descriptor's own index)
//	14..15 flags  (le16) — VIRTQ_DESC_F_* (including the AVAIL/USED
//	                       wrap-counter bits)
const VirtqPackedDescriptorSize = 16

// Packed-ring flag bits (Virtio 1.1 §2.7.5 + §2.7.1). The first three
// share their numeric value with the split-ring flags
// (VirtqDescFNext / VirtqDescFWrite / VirtqDescFIndirect) — only the
// AVAIL / USED bits are packed-specific.
const (
	// VirtqPackedDescFNext continues a descriptor chain — bit 0.
	// M2-A doesn't chain descriptors, but we surface the constant
	// for parity with the split-ring path.
	VirtqPackedDescFNext uint16 = 0x1

	// VirtqPackedDescFWrite marks the buffer as device-write-only
	// (RX) — bit 1.
	VirtqPackedDescFWrite uint16 = 0x2

	// VirtqPackedDescFIndirect refers to an indirect table — bit 2.
	// M2-A doesn't use indirect descriptors.
	VirtqPackedDescFIndirect uint16 = 0x4

	// VirtqPackedDescFAvail (bit 7) encodes the driver wrap counter.
	// The driver sets this bit to the current wrap counter value when
	// publishing the descriptor.
	VirtqPackedDescFAvail uint16 = 0x80

	// VirtqPackedDescFUsed (bit 15) encodes the device wrap counter.
	// The device flips it to its own wrap counter when completing the
	// descriptor. Equality of AVAIL and USED bits + the device-wrap
	// counter tells the driver the descriptor is used (Virtio 1.1
	// §2.7.1).
	VirtqPackedDescFUsed uint16 = 0x8000
)

// VirtqPackedEventSize is the byte size of the driver/device event
// suppression area (Virtio 1.1 §2.7.13/14):
//
//	0..1  off_wrap (le16) — descriptor index + wrap bit (bit 15)
//	2..3  flags    (le16) — VIRTQ_PACKED_EVENT_FLAG_*
//
// 4 bytes total; both regions have the same layout.
const VirtqPackedEventSize = 4

// VirtqPackedEventFlagEnable / VirtqPackedEventFlagDisable /
// VirtqPackedEventFlagDesc are the packed-ring event-suppression
// flag values (Virtio 1.1 §2.7.10). M2-A leaves the regions at
// their zero-initialised "enable" state (i.e. "notify on every used
// descriptor publication" — which matches our polling loop's
// expectation that nothing changes between polls if the device
// hasn't completed anything).
const (
	VirtqPackedEventFlagEnable  uint16 = 0
	VirtqPackedEventFlagDisable uint16 = 1
	VirtqPackedEventFlagDesc    uint16 = 2
)

// PackedVirtqueueLayout describes the byte-offset layout of one
// packed virtqueue inside a single contiguous allocation.
//
// Per Virtio 1.1 §2.7 the three regions are independently aligned:
//
//	descriptor ring     : 16-byte aligned
//	driver-event region : 4-byte aligned
//	device-event region : 4-byte aligned
//
// We allocate ALL THREE on a single 4 KiB (= EfiPageSize) page so
// every alignment constraint is trivially met. The driver writes to
// the descriptor ring and the driver-event region; the device writes
// to the device-event region (it ALSO writes the device-side fields
// of each descriptor — its `flags` word — but the descriptor ring
// itself is shared). There's no in-page padding between the regions
// beyond the natural alignment rounding the descriptor ring already
// gives us (16-byte descriptors leave the next byte at a 4-byte
// boundary).
type PackedVirtqueueLayout struct {
	// Size is the queue size (power-of-two count of descriptors).
	Size uint16

	// DescRingOffset is the byte offset of the descriptor ring from
	// the allocation base. Always 0.
	DescRingOffset uint32

	// DriverEventOffset is the byte offset of the driver-event-
	// suppression region from the allocation base. = Size * 16.
	DriverEventOffset uint32

	// DeviceEventOffset is the byte offset of the device-event-
	// suppression region from the allocation base. =
	// DriverEventOffset + VirtqPackedEventSize.
	DeviceEventOffset uint32

	// TotalSize is the total byte size of the allocation needed to
	// hold all three regions.
	TotalSize uint32
}

// ComputePackedVirtqueueLayout returns the byte-offset layout for a
// packed virtqueue of the given size. Size MUST be a power of two
// between 1 and 32768 (Virtio 1.1 §2.7 — `queue_size` is le16 with
// the power-of-two constraint, same as split).
func ComputePackedVirtqueueLayout(size uint16) PackedVirtqueueLayout {
	l := PackedVirtqueueLayout{Size: size}
	l.DescRingOffset = 0
	descRingSize := uint32(size) * VirtqPackedDescriptorSize
	l.DriverEventOffset = descRingSize
	l.DeviceEventOffset = l.DriverEventOffset + VirtqPackedEventSize
	l.TotalSize = l.DeviceEventOffset + VirtqPackedEventSize
	return l
}

// PackedVirtqueue is the driver-side handle for one packed
// virtqueue.
//
// `Base` is the host-virtual address that AllocatePages returned (on
// every UEFI arch we target, identity-mapped to the physical address
// during Boot Services). `BasePhys` is the same value as a uint64;
// we keep both for clarity at the MMIO-write boundary.
//
// `Buffers` is the per-descriptor driver-side bookkeeping; M2-A
// uses the descriptor's own index as the `id` field so the device's
// completion report names the same slot the driver-side `Buffers[]`
// is keyed by.
type PackedVirtqueue struct {
	// Index is the queue's index inside the device (0 = rxq, 1 = txq
	// for virtio-net per Virtio 1.1 §5.1.2).
	Index uint16

	// Layout is the byte-offset map for this queue's allocation.
	Layout PackedVirtqueueLayout

	// Base is a uintptr to the queue's allocation; the driver
	// dereferences it through `unsafe.Slice` to write descriptors
	// and read device-side flag updates.
	Base uintptr

	// BasePhys is the physical address as a uint64; passed to
	// SetQueueDesc / SetQueueDriver / SetQueueDevice.
	BasePhys uint64

	// NotifyOff is the device-published `queue_notify_off` (read
	// from COMMON_CFG after QueueSelect). Used to compute the
	// per-queue notification BAR offset — same as split.
	NotifyOff uint16

	// nextAvail is the driver's running index into the descriptor
	// ring (modulo Size). The raw value (un-modulo'd) plus the
	// driverWrapCounter together identify the next slot to publish.
	nextAvail uint16

	// driverWrapCounter is the driver's wrap-counter bit (0 or 1).
	// Starts at 1 per Virtio 1.1 §2.7.1; toggled each time nextAvail
	// crosses a Size-boundary (i.e. wraps from Size-1 back to 0).
	// The driver writes this value into VIRTQ_DESC_F_AVAIL on each
	// publication.
	driverWrapCounter uint16

	// lastUsed is the driver's running index into the descriptor
	// ring for completion polling. Distinct from `nextAvail` — both
	// the driver and the device walk the ring at their own pace.
	lastUsed uint16

	// deviceWrapCounter is the device's wrap-counter bit, mirrored
	// driver-side so we can decode the F_USED bit on each
	// descriptor we poll. Starts at 1 per Virtio 1.1 §2.7.1;
	// toggled each time lastUsed crosses a Size-boundary.
	deviceWrapCounter uint16

	// Buffers holds the driver-side bookkeeping for each descriptor.
	// `Addr` is the host-visible pointer (for the driver to read/
	// write the buffer payload); `Len` is the byte length the
	// descriptor publishes; `InUse` marks a slot the device hasn't
	// returned yet.
	Buffers []VirtqueueBuffer
}

// NewPackedVirtqueueFromAlloc constructs a PackedVirtqueue from a
// pre-zeroed memory allocation returned by AllocatePages. `phys` is
// the page's physical base; `size` is the queue size (power of two).
// The allocator MUST have zeroed the region — Virtio 1.1 §2.7
// doesn't strictly require it, but a stale flags word would make a
// fresh queue look like the device already published completions on
// every descriptor.
func NewPackedVirtqueueFromAlloc(phys uint64, base uintptr, size uint16, index uint16) *PackedVirtqueue {
	return &PackedVirtqueue{
		Index:             index,
		Layout:            ComputePackedVirtqueueLayout(size),
		Base:              base,
		BasePhys:          phys,
		driverWrapCounter: 1, // §2.7.1 — both wrap counters start at 1
		deviceWrapCounter: 1,
		Buffers:           make([]VirtqueueBuffer, size),
	}
}

// descSlice returns a Go-side view of the descriptor ring as a
// `[]byte` of (Size * 16) bytes. Caller writes / reads bytes
// directly via binary.LittleEndian; the device reads / writes them
// through DMA (Virtio 1.1 §2.7.5).
func (q *PackedVirtqueue) descSlice() []byte {
	n := int(q.Layout.Size) * VirtqPackedDescriptorSize
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.DescRingOffset))), n)
}

// driverEventSlice returns a Go-side view of the driver-event
// suppression region (4 bytes).
func (q *PackedVirtqueue) driverEventSlice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.DriverEventOffset))), VirtqPackedEventSize)
}

// deviceEventSlice returns a Go-side view of the device-event
// suppression region (4 bytes).
func (q *PackedVirtqueue) deviceEventSlice() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.DeviceEventOffset))), VirtqPackedEventSize)
}

// writePackedDescriptor populates desc[idx] with (addr, length, id,
// flags). Mirrors `struct vring_packed_desc` from Linux's
// virtio_ring.h.
//
// The flags write is the publication step — the device polls the
// flags word and acts on it as soon as it sees F_AVAIL == its
// expected wrap counter. We therefore write addr / len / id FIRST
// and the flags word LAST, with an atomic.StoreUint32 release on the
// (id, flags) pair so the device's matching acquire-load observes
// the address/length writes before it sees the flag transition.
//
// Implementation detail: id (le16) + flags (le16) sit at offsets
// 12..13 and 14..15, together forming a 4-byte naturally-aligned
// word at the descriptor's tail. We publish it via
// atomic.StoreUint32 on that word, putting `id` in the low 16 bits
// and `flags` in the high 16 bits. This is a release-store on every
// Go-supported architecture (amd64 / arm64 / loong64 / riscv64 —
// `STLR` on arm64, `dbar` on loong64, `fence rw,w` on riscv64), so
// the device-side acquire-load on the same 4 bytes sees a complete
// descriptor.
func (q *PackedVirtqueue) writePackedDescriptor(idx uint16, addr uint64, length uint32, id uint16, flags uint16) error {
	if idx >= q.Layout.Size {
		return ErrInvalidIdx
	}
	d := q.descSlice()
	off := int(idx) * VirtqPackedDescriptorSize
	binary.LittleEndian.PutUint64(d[off:off+8], addr)
	binary.LittleEndian.PutUint32(d[off+8:off+12], length)
	// Atomic release-store on the (id, flags) tail word — this is
	// the publication step the device observes.
	tail := uint32(id) | uint32(flags)<<16
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&d[off+12])), tail)
	return nil
}

// readPackedDescriptor reads desc[idx] back. The flags load is an
// atomic acquire so the matching device-side release publishes the
// address/length bytes before we observe a flag transition. Used by
// `Recv` to poll for completions and by the diagnostic dump.
func (q *PackedVirtqueue) readPackedDescriptor(idx uint16) (addr uint64, length uint32, id uint16, flags uint16, err error) {
	if idx >= q.Layout.Size {
		err = ErrInvalidIdx
		return
	}
	d := q.descSlice()
	off := int(idx) * VirtqPackedDescriptorSize
	// Atomic acquire on the (id, flags) tail word — this is the
	// completion-detection step. Read addr/len AFTER the acquire so
	// the device's release of those fields is observed.
	tail := atomic.LoadUint32((*uint32)(unsafe.Pointer(&d[off+12])))
	id = uint16(tail & 0xFFFF)
	flags = uint16(tail >> 16)
	addr = binary.LittleEndian.Uint64(d[off : off+8])
	length = binary.LittleEndian.Uint32(d[off+8 : off+12])
	return
}

// AddBuffer publishes one buffer to the packed ring. The driver
// picks the next slot at `nextAvail`, writes the descriptor with
// F_AVAIL set to the current `driverWrapCounter` and F_USED set to
// its complement (so the device knows the descriptor is fresh, not
// a stale completion), and advances `nextAvail` (toggling the wrap
// counter on roll-over).
//
// `writable=true` ⇒ F_WRITE set (RX buffer, device-write-only).
//
// Returns the descriptor index (== id, since M2-A keys by index)
// for the caller to track + later reclaim.
//
// Note on slot reuse: unlike the split ring, the packed ring does
// NOT have a "find first free" search — descriptor slots are used
// in strict ring order, and the driver MUST wait for slot `i` to be
// reclaimed before re-using it. This matches the device-side
// expectation that "the next descriptor I expect at `lastUsed` is
// the next one the driver published". M2-A's TX path issues one
// buffer at a time and waits for its completion, so the queue is
// never more than 1 buffer deep; this constraint is benign.
func (q *PackedVirtqueue) AddBuffer(addr uintptr, phys uint64, length uint32, writable bool) (uint16, error) {
	descIdx := q.nextAvail % q.Layout.Size
	if q.Buffers[descIdx].InUse {
		return 0, ErrQueueFull
	}
	flags := q.driverWrapCounter * VirtqPackedDescFAvail
	// F_USED is set to the OPPOSITE of the driver wrap counter so
	// the descriptor's (F_AVAIL, F_USED) pair encodes "driver-
	// owned, fresh" — see Virtio 1.1 §2.7.1.
	if q.driverWrapCounter == 0 {
		flags |= VirtqPackedDescFUsed
	}
	if writable {
		flags |= VirtqPackedDescFWrite
	}
	if err := q.writePackedDescriptor(descIdx, phys, length, descIdx, flags); err != nil {
		return 0, err
	}
	q.Buffers[descIdx] = VirtqueueBuffer{
		Addr:  addr,
		Phys:  phys,
		Len:   length,
		InUse: true,
	}
	q.nextAvail++
	if q.nextAvail == q.Layout.Size {
		q.nextAvail = 0
		// Toggle the wrap counter — Virtio 1.1 §2.7.1.
		q.driverWrapCounter ^= 1
	}
	return descIdx, nil
}

// Reclaim marks descriptor `descIdx` as free (caller has consumed
// the device's completion report and copied the data out).
// Idempotent.
func (q *PackedVirtqueue) Reclaim(descIdx uint16) error {
	if descIdx >= q.Layout.Size {
		return ErrInvalidIdx
	}
	q.Buffers[descIdx].InUse = false
	return nil
}

// PollUsed checks whether the device has completed the next
// descriptor at `lastUsed`. Returns (descIdx, length, ok=true) if
// so; (0, 0, false) otherwise. Mutates `lastUsed` and
// `deviceWrapCounter` only on a successful poll, so retrying after a
// false result is cheap.
//
// Completion detection (Virtio 1.1 §2.7.1): the device-owned-and-
// completed state has F_AVAIL == F_USED == `deviceWrapCounter`. The
// driver checks the descriptor at slot `lastUsed` and treats it as
// completed iff both flag bits agree with the wrap counter.
func (q *PackedVirtqueue) PollUsed() (uint16, uint32, bool) {
	descIdx := q.lastUsed % q.Layout.Size
	_, length, id, flags, err := q.readPackedDescriptor(descIdx)
	if err != nil {
		return 0, 0, false
	}
	availBit := (flags & VirtqPackedDescFAvail) != 0
	usedBit := (flags & VirtqPackedDescFUsed) != 0
	wantBit := q.deviceWrapCounter == 1
	if availBit != wantBit || usedBit != wantBit {
		// Device hasn't flipped both flag bits to match the
		// device wrap counter yet — slot is still driver-owned.
		return 0, 0, false
	}
	q.lastUsed++
	if q.lastUsed == q.Layout.Size {
		q.lastUsed = 0
		q.deviceWrapCounter ^= 1
	}
	return id, length, true
}

// DriverWrapCounter / DeviceWrapCounter / NextAvail / LastUsed
// expose the wrap counters and queue indices for tests +
// diagnostics. NOT used by the live driver — those are package-
// private fields the driver methods mutate directly.
func (q *PackedVirtqueue) DriverWrapCounter() uint16 { return q.driverWrapCounter }
func (q *PackedVirtqueue) DeviceWrapCounter() uint16 { return q.deviceWrapCounter }
func (q *PackedVirtqueue) NextAvail() uint16         { return q.nextAvail }
func (q *PackedVirtqueue) LastUsed() uint16          { return q.lastUsed }

// PackedDescBytes returns the first 16 bytes of descriptor[idx] as a
// freshly allocated slice. Exposed for the M2-A diagnostic dump
// (mirrors the split-ring `Virtqueue.DescBytes`).
func (q *PackedVirtqueue) PackedDescBytes(idx uint16) []byte {
	if idx >= q.Layout.Size {
		return nil
	}
	d := q.descSlice()
	off := int(idx) * VirtqPackedDescriptorSize
	out := make([]byte, VirtqPackedDescriptorSize)
	copy(out, d[off:off+VirtqPackedDescriptorSize])
	return out
}

// DriverEventBytes / DeviceEventBytes return the 4-byte event-
// suppression regions for the diagnostic dump.
func (q *PackedVirtqueue) DriverEventBytes() []byte {
	out := make([]byte, VirtqPackedEventSize)
	copy(out, q.driverEventSlice())
	return out
}

func (q *PackedVirtqueue) DeviceEventBytes() []byte {
	out := make([]byte, VirtqPackedEventSize)
	copy(out, q.deviceEventSlice())
	return out
}

// ErrPackedQueueSizeTooSmall is returned when a queue size of 0 (or
// other unsupported value) is requested for a packed virtqueue.
// Mirrors split-ring's ErrInvalidQueueSize but with a packed-
// specific message so the failure is unambiguous in diagnostics.
var ErrPackedQueueSizeTooSmall = errors.New("uefi: packed virtqueue: queue size must be a non-zero power of two")
