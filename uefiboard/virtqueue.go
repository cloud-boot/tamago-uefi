// cloud-boot UEFI board — Virtio split-virtqueue layout + driver-side
// data structures (Phase 2, M2).
//
// Host-buildable: no //go:build tamago directive. The layout
// constants, the `Virtqueue` struct, the descriptor-table /
// available-ring / used-ring offset math, and the driver-side
// AddBuffer / Recv state machine are all pure Go data manipulation;
// the live page allocation (via gBS->AllocatePages) lives in
// `virtqueue_tamago.go`. This split lets the host test the layout +
// the ring-wrap arithmetic + the AddBuffer / Recv state without
// pulling efiCall in.
//
// References:
//
//   - Virtio 1.1 §2.6 "Virtqueues" — the split-ring layout this file
//     implements: descriptor table, available ring (driver area),
//     used ring (device area). The "packed virtqueue" variant from
//     Virtio 1.1 §2.7 is NOT supported here; we negotiate it OUT in
//     virtio_net.go's feature mask.
//   - Virtio 1.1 §2.6.5 "The Virtqueue Descriptor Table" — desc[i] is
//     16 bytes: { addr (le64), len (le32), flags (le16), next (le16) }.
//   - Virtio 1.1 §2.6.6 "The Virtqueue Available Ring":
//         struct { le16 flags; le16 idx; le16 ring[queue_size]; le16 used_event; }
//     Length: 6 + 2*queue_size bytes.
//   - Virtio 1.1 §2.6.8 "The Virtqueue Used Ring":
//         struct { le16 flags; le16 idx; struct { le32 id; le32 len; } ring[queue_size]; le16 avail_event; }
//     Length: 6 + 8*queue_size bytes (4-byte aligned within page).
//   - Linux drivers/virtio/virtio_ring.c — canonical Go-translatable
//     reference for the descriptor + ring helpers; we follow its
//     idioms (esp. `vring_avail_event` / `vring_used_event` placement
//     at the trailing 2-byte slot of the respective ring).

package uefiboard

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"unsafe"
)

// VirtqDescriptorSize is the on-the-wire size of one descriptor
// (Virtio 1.1 §2.6.5). Sixteen bytes:
//
//	0..7   addr   (le64) — guest-physical address of the buffer
//	8..11  len    (le32) — buffer length
//	12..13 flags  (le16) — VIRTQ_DESC_F_*
//	14..15 next   (le16) — descriptor index for chains
const VirtqDescriptorSize = 16

// VIRTQ_DESC_F_* flags (Virtio 1.1 §2.6.5).
const (
	VirtqDescFNext     uint16 = 0x1 // descriptor chain continues at .next
	VirtqDescFWrite    uint16 = 0x2 // buffer is device-write-only (RX)
	VirtqDescFIndirect uint16 = 0x4 // descriptor refers to an indirect table (Virtio 1.1 §2.6.5.3) — M2 doesn't use this
)

// VirtqAvailHeaderSize / VirtqAvailRingEntrySize / VirtqAvailUsedEventSize
// — components of the available ring (Virtio 1.1 §2.6.6).
const (
	VirtqAvailHeaderSize    = 4 // flags + idx (2 + 2)
	VirtqAvailRingEntrySize = 2 // ring[i] is le16
	VirtqAvailUsedEventSize = 2 // trailing `used_event` field
)

// VirtqUsedHeaderSize / VirtqUsedRingEntrySize / VirtqUsedAvailEventSize
// — components of the used ring (Virtio 1.1 §2.6.8).
const (
	VirtqUsedHeaderSize     = 4 // flags + idx (2 + 2)
	VirtqUsedRingEntrySize  = 8 // ring[i] is { id (le32), len (le32) }
	VirtqUsedAvailEventSize = 2 // trailing `avail_event` field
)

// VirtqueueLayout describes the byte-offset layout of one split
// virtqueue inside a single contiguous allocation.
//
// Per Virtio 1.1 §2.6, the three regions are independently aligned:
//
//	descriptor table : 16-byte aligned
//	available ring   : 2-byte aligned
//	used ring        : 4-byte aligned
//
// We allocate ALL THREE on a single 4 KiB (= EfiPageSize) page so
// every alignment constraint is trivially met. The driver writes to
// the descriptor table + available ring; the device writes to the
// used ring. There's no in-page padding between them — the available
// ring follows the descriptor table immediately; the used ring is
// placed at the next 4-byte boundary after the available ring.
type VirtqueueLayout struct {
	// Size is the queue size (power-of-two count of descriptors).
	Size uint16

	// DescTableOffset is the byte offset of the descriptor table
	// from the allocation base. Always 0.
	DescTableOffset uint32

	// AvailRingOffset is the byte offset of the available ring's
	// `flags` field from the allocation base. = Size * 16.
	AvailRingOffset uint32

	// AvailUsedEventOffset is the byte offset of the
	// `used_event` field (Virtio 1.1 §2.6.7) — appended after the
	// available ring's `ring[]`.
	AvailUsedEventOffset uint32

	// UsedRingOffset is the byte offset of the used ring's `flags`
	// field from the allocation base. 4-byte aligned.
	UsedRingOffset uint32

	// UsedAvailEventOffset is the byte offset of the `avail_event`
	// field — appended after the used ring's `ring[]`.
	UsedAvailEventOffset uint32

	// TotalSize is the total byte size of the allocation needed to
	// hold all three regions.
	TotalSize uint32
}

// ComputeVirtqueueLayout returns the byte-offset layout for a split
// virtqueue of the given size. Size MUST be a power of two between 1
// and 32768 (Virtio 1.1 §2.6 — `queue_size` is le16 with the
// power-of-two constraint).
func ComputeVirtqueueLayout(size uint16) VirtqueueLayout {
	l := VirtqueueLayout{Size: size}
	l.DescTableOffset = 0
	descTableSize := uint32(size) * VirtqDescriptorSize
	l.AvailRingOffset = descTableSize
	availBodySize := uint32(VirtqAvailHeaderSize) + uint32(size)*uint32(VirtqAvailRingEntrySize)
	l.AvailUsedEventOffset = l.AvailRingOffset + availBodySize
	// used ring is 4-byte aligned within the page; round up the
	// available-ring end (incl. used_event).
	availEnd := l.AvailUsedEventOffset + uint32(VirtqAvailUsedEventSize)
	l.UsedRingOffset = (availEnd + 3) &^ 3
	usedBodySize := uint32(VirtqUsedHeaderSize) + uint32(size)*uint32(VirtqUsedRingEntrySize)
	l.UsedAvailEventOffset = l.UsedRingOffset + usedBodySize
	l.TotalSize = l.UsedAvailEventOffset + uint32(VirtqUsedAvailEventSize)
	return l
}

// Virtqueue is the driver-side handle for one split virtqueue.
//
// `Base` is the host-virtual address that AllocatePages returned (on
// every UEFI arch we target, identity-mapped to the physical address
// during Boot Services). `BasePhys` is the same value as a uint64; we
// keep both for clarity at the MMIO-write boundary.
//
// `Buffers` is the per-descriptor BAR-side buffer the driver pre-
// posted for this descriptor; on RX, the device fills it; on TX, the
// driver writes into it before AddBuffer.
type Virtqueue struct {
	// Index is the queue's index inside the device (0 = rxq, 1 = txq
	// for virtio-net per Virtio 1.1 §5.1.2).
	Index uint16

	// Layout is the byte-offset map for this queue's allocation.
	Layout VirtqueueLayout

	// Base is a uintptr to the queue's allocation; the driver
	// dereferences it through `unsafe.Slice` to write descriptors and
	// available-ring entries.
	Base uintptr

	// BasePhys is the physical address as a uint64; passed to
	// SetQueueDesc / SetQueueDriver / SetQueueDevice.
	BasePhys uint64

	// NotifyOff is the device-published `queue_notify_off` (read
	// from COMMON_CFG after QueueSelect). Used to compute the
	// per-queue notification BAR offset.
	NotifyOff uint16

	// nextAvailIdx is the driver's running index into the available
	// ring (Virtio 1.1 §2.6.6). Modulo Size determines the ring slot;
	// the raw value is what we write to `available.idx`.
	nextAvailIdx uint16

	// lastSeenUsedIdx is the driver's view of the used ring's `idx`
	// field — used by Recv() to know whether the device added a new
	// entry since the last poll.
	lastSeenUsedIdx uint16

	// Buffers holds the driver-side bookkeeping for each descriptor.
	// `Addr` is the host-visible pointer (for the driver to read/write
	// the buffer payload); `Len` is the byte length the descriptor
	// publishes; `InUse` marks a slot the device hasn't returned yet.
	Buffers []VirtqueueBuffer
}

// VirtqueueBuffer is the driver's per-descriptor bookkeeping. NOT
// part of the on-the-wire layout; lives in normal Go heap.
type VirtqueueBuffer struct {
	Addr  uintptr // host-virtual address of the data buffer
	Phys  uint64  // physical address (== Addr on identity-mapped Boot Services)
	Len   uint32  // buffer length in bytes
	InUse bool    // true between AddBuffer and Reclaim
}

// ErrQueueFull is returned by AddBuffer when every descriptor slot is
// already InUse. M2's caller pre-posts N RX buffers (N = queue size)
// and refills as the device returns them; on TX, we always have at
// least one free slot before AddBuffer.
var ErrQueueFull = errors.New("uefi: virtqueue: descriptor table full")

// ErrInvalidIdx is returned when a descriptor index is outside
// [0, Size). Either firmware misbehaved or the driver miscalculated.
var ErrInvalidIdx = errors.New("uefi: virtqueue: descriptor index out of range")

// NewVirtqueueFromAlloc constructs a Virtqueue from a pre-zeroed
// memory allocation returned by AllocatePages. `phys` is the page's
// physical base; `size` is the queue size (power of two). The
// allocator MUST have zeroed the region — Virtio 1.1 §2.6 doesn't
// require it but a stale used-ring idx would make Recv think the
// device already published frames.
func NewVirtqueueFromAlloc(phys uint64, base uintptr, size uint16, index uint16) *Virtqueue {
	return &Virtqueue{
		Index:    index,
		Layout:   ComputeVirtqueueLayout(size),
		Base:     base,
		BasePhys: phys,
		Buffers:  make([]VirtqueueBuffer, size),
	}
}

// descSlice returns a Go-side view of the descriptor table as a
// `[]byte` of (Size * 16) bytes. Caller writes bytes directly via
// binary.LittleEndian; the device reads them through DMA / PCI
// IO (Virtio 1.1 §2.6.5).
func (q *Virtqueue) descSlice() []byte {
	n := int(q.Layout.Size) * VirtqDescriptorSize
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.DescTableOffset))), n)
}

// availSlice returns a Go-side view of the available ring region
// (header + ring[] + used_event), as one byte slice.
func (q *Virtqueue) availSlice() []byte {
	n := int(q.Layout.AvailUsedEventOffset+uint32(VirtqAvailUsedEventSize)) - int(q.Layout.AvailRingOffset)
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.AvailRingOffset))), n)
}

// usedSlice returns a Go-side view of the used ring region.
func (q *Virtqueue) usedSlice() []byte {
	n := int(q.Layout.UsedAvailEventOffset+uint32(VirtqUsedAvailEventSize)) - int(q.Layout.UsedRingOffset)
	return unsafe.Slice((*byte)(unsafe.Pointer(q.Base+uintptr(q.Layout.UsedRingOffset))), n)
}

// writeDescriptor populates desc[idx] with (addr, length, flags,
// next). Mirrors `struct vring_desc` from Linux's virtio_ring.h.
func (q *Virtqueue) writeDescriptor(idx uint16, addr uint64, length uint32, flags uint16, next uint16) error {
	if idx >= q.Layout.Size {
		return ErrInvalidIdx
	}
	d := q.descSlice()
	off := int(idx) * VirtqDescriptorSize
	binary.LittleEndian.PutUint64(d[off:off+8], addr)
	binary.LittleEndian.PutUint32(d[off+8:off+12], length)
	binary.LittleEndian.PutUint16(d[off+12:off+14], flags)
	binary.LittleEndian.PutUint16(d[off+14:off+16], next)
	return nil
}

// readDescriptor reads desc[idx] back. Used by tests + the M2 probe
// for diagnostics.
func (q *Virtqueue) readDescriptor(idx uint16) (addr uint64, length uint32, flags uint16, next uint16, err error) {
	if idx >= q.Layout.Size {
		err = ErrInvalidIdx
		return
	}
	d := q.descSlice()
	off := int(idx) * VirtqDescriptorSize
	addr = binary.LittleEndian.Uint64(d[off : off+8])
	length = binary.LittleEndian.Uint32(d[off+8 : off+12])
	flags = binary.LittleEndian.Uint16(d[off+12 : off+14])
	next = binary.LittleEndian.Uint16(d[off+14 : off+16])
	return
}

// PostAvail publishes descriptor[descIdx] in the available ring at
// position `nextAvailIdx % Size` and bumps the published `idx`
// counter. Per Virtio 1.1 §2.6.13 ("Drivers MUST suppress device
// interrupts before checking the available ring"), the device MUST
// observe `ring[]` before `idx`.
//
// Ordering: the available ring's header is two adjacent uint16
// fields — `flags` at offset 0, `idx` at offset 2 — together forming
// a 4-byte naturally-aligned word at the start of the region. We
// publish `idx` via an `atomic.StoreUint32` on that word, preserving
// the current `flags` value in the low 16 bits and writing the new
// idx into the high 16 bits. This is a release-store on every Go-
// supported architecture (amd64 / arm64 / loong64 / riscv64 — `STLR`
// on arm64, `dbar` on loong64, `fence rw,w` on riscv64), so the
// device's subsequent read of `idx` happens-after our write to
// `ring[]`.
//
// Single-driver invariant: only this PostAvail writes to the
// available-ring header word. M2 is single-goroutine; no other
// caller can race the `flags` half.
func (q *Virtqueue) PostAvail(descIdx uint16) error {
	if descIdx >= q.Layout.Size {
		return ErrInvalidIdx
	}
	a := q.availSlice()
	// Slot is at offset (header(=4) + (nextAvailIdx % Size) * 2).
	slot := int(VirtqAvailHeaderSize) + (int(q.nextAvailIdx)%int(q.Layout.Size))*VirtqAvailRingEntrySize
	binary.LittleEndian.PutUint16(a[slot:slot+2], descIdx)
	q.nextAvailIdx++
	// Atomic release-store on the 4-byte header word: preserve
	// `flags` (low 16 bits) and publish the new `idx` (high 16 bits).
	flags := binary.LittleEndian.Uint16(a[0:2])
	headerWord := uint32(flags) | uint32(q.nextAvailIdx)<<16
	atomic.StoreUint32((*uint32)(unsafe.Pointer(&a[0])), headerWord)
	return nil
}

// AvailFlags returns the current `flags` field of the available ring
// (Virtio 1.1 §2.6.6 — VIRTQ_AVAIL_F_NO_INTERRUPT). The M2 probe
// doesn't use interrupts; this is for diagnostics.
func (q *Virtqueue) AvailFlags() uint16 {
	a := q.availSlice()
	return binary.LittleEndian.Uint16(a[0:2])
}

// AvailIdx returns the current `idx` field — the running count of
// available-ring publications. Used by tests + diagnostics.
func (q *Virtqueue) AvailIdx() uint16 {
	a := q.availSlice()
	return binary.LittleEndian.Uint16(a[2:4])
}

// UsedIdx returns the device-side `idx` field of the used ring. The
// driver polls this; when it differs from `lastSeenUsedIdx`, the
// device has added a new entry. Read with acquire semantics so the
// subsequent ring[] read sees a committed entry.
//
// Layout mirror of the available ring: used-ring header is two
// adjacent uint16 fields at offset 0 (`flags` at +0, `idx` at +2),
// together forming a 4-byte naturally-aligned word. We
// atomic.LoadUint32 the word and extract `idx` from the high 16
// bits. The load is an acquire on every Go-supported arch — the
// matching release lives in firmware/device-side code on QEMU and
// on Apple VZ.
func (q *Virtqueue) UsedIdx() uint16 {
	u := q.usedSlice()
	headerWord := atomic.LoadUint32((*uint32)(unsafe.Pointer(&u[0])))
	return uint16(headerWord >> 16)
}

// UsedRingAt returns the device's `(id, len)` tuple at slot
// `usedIdx % Size`. Caller computes usedIdx as a counter; this
// function reads the ring entry at the wrapping position.
func (q *Virtqueue) UsedRingAt(usedIdx uint16) (id uint32, length uint32) {
	u := q.usedSlice()
	slot := int(VirtqUsedHeaderSize) + (int(usedIdx)%int(q.Layout.Size))*VirtqUsedRingEntrySize
	id = binary.LittleEndian.Uint32(u[slot : slot+4])
	length = binary.LittleEndian.Uint32(u[slot+4 : slot+8])
	return
}

// AddBuffer finds the first free descriptor slot, fills it with the
// given buffer's (phys, len, flags), bookkeeps it, publishes it in
// the available ring, and returns the descriptor index. `writable`
// drives the VIRTQ_DESC_F_WRITE flag (true = device-write-only, i.e.
// RX; false = device-read-only, i.e. TX).
func (q *Virtqueue) AddBuffer(addr uintptr, phys uint64, length uint32, writable bool) (uint16, error) {
	// Linear scan for a free slot. M2 queue sizes are small (16..64)
	// so this is fine.
	for i := uint16(0); i < q.Layout.Size; i++ {
		if q.Buffers[i].InUse {
			continue
		}
		flags := uint16(0)
		if writable {
			flags |= VirtqDescFWrite
		}
		if err := q.writeDescriptor(i, phys, length, flags, 0); err != nil {
			return 0, err
		}
		q.Buffers[i] = VirtqueueBuffer{
			Addr:  addr,
			Phys:  phys,
			Len:   length,
			InUse: true,
		}
		if err := q.PostAvail(i); err != nil {
			return 0, err
		}
		return i, nil
	}
	return 0, ErrQueueFull
}

// Reclaim marks descriptor `descIdx` as free (caller has consumed
// the device's used-ring report and copied the data out). Idempotent.
func (q *Virtqueue) Reclaim(descIdx uint16) error {
	if descIdx >= q.Layout.Size {
		return ErrInvalidIdx
	}
	q.Buffers[descIdx].InUse = false
	return nil
}

// PollUsed checks whether the device has added a new used-ring
// entry since the last call. Returns (descIdx, length, ok=true) if
// so; (0, 0, false) otherwise. Mutates `lastSeenUsedIdx` only on a
// successful poll, so retrying after a false result is cheap.
func (q *Virtqueue) PollUsed() (uint16, uint32, bool) {
	curUsed := q.UsedIdx()
	if curUsed == q.lastSeenUsedIdx {
		return 0, 0, false
	}
	// One frame at a time — read at the slot `lastSeenUsedIdx`.
	id, length := q.UsedRingAt(q.lastSeenUsedIdx)
	q.lastSeenUsedIdx++
	return uint16(id), length, true
}

// LastSeenUsedIdx returns the driver's view of the used-ring index.
// Exposed for tests + diagnostics.
func (q *Virtqueue) LastSeenUsedIdx() uint16 { return q.lastSeenUsedIdx }

// NextAvailIdx returns the driver's view of the available-ring
// index. Exposed for tests + diagnostics.
func (q *Virtqueue) NextAvailIdx() uint16 { return q.nextAvailIdx }
