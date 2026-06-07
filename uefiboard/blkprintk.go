// cloud-boot UEFI board — Block IO side-channel print sink (Phase 2, M1.6).
//
// `BlkRingBuffer` accumulates probe output bytes into a fixed-size
// in-RAM ring buffer; `Flush` writes the ring's serialized form
// (8-byte monotonic write count + ring payload) to a known LBA region
// of a writable virtio-blk device via EFI_BLOCK_IO_PROTOCOL.WriteBlocks.
//
// The ring exists because on Apple VZ (vfkit 0.6.3) the EFI ConOut
// path captures zero bytes through `virtio-serial,logFilePath` (see
// R-M1'a) — we need a different observability channel. virtio-blk
// is reliably exposed by VZ (the firmware boots BOOTAA64.EFI off it),
// so EFI_BLOCK_IO_PROTOCOL writes are the lowest-overhead probe
// output sink.
//
// Format on disk (little-endian, fixed 32 KiB region starting at the
// configured LBA):
//
//	  0..7   uint64  monotonic write count (host detects partial vs
//	                  full writes — after N flushes this is N)
//	  8..15  uint64  number of payload bytes valid (clamped to 32 KiB - 16)
//	 16..    payload (UTF-8 / ASCII text printed by the probe)
//
// The payload is "ring with wrap" — when more than 32 KiB - 16 bytes
// have been written, the oldest are dropped to make room for the
// newest. The serialized form always presents bytes in chronological
// order starting at offset 16; the host doesn't have to decode a
// circular layout.
//
// Host-buildable: no //go:build tamago directive. The ring + serializer
// + wrap-around are pure Go and tested in `blkprintk_test.go`. The
// `Flush` method's `WriteBlocks` call is gated separately
// (block_io_protocol_tamago.go).

package uefiboard

import "errors"

// BlkRingCapacity is the total on-disk slot size in bytes. 32 KiB is
// large enough to hold the full M1.6 probe output (pcienum walk + SNP
// walk + a few diagnostic lines), block-aligned at any common UEFI
// device block size (512, 1024, 2048, 4096), and tiny enough not to
// pressure the firmware's allocator.
const BlkRingCapacity = 32 * 1024

// BlkRingHeaderSize is the 16-byte header on every flush: 8-byte
// monotonic counter + 8-byte payload-byte count.
const BlkRingHeaderSize = 16

// BlkRingPayloadCapacity is the max payload size in one frame.
const BlkRingPayloadCapacity = BlkRingCapacity - BlkRingHeaderSize

// BlkSentinel is the special byte that flushes the ring immediately
// (without waiting for the auto-flush threshold). The M1.6 probe
// writes it as the last byte before halting so the host sees the
// final state.
const BlkSentinel byte = 0x04 // ASCII EOT — chosen to never appear in our hex-only probe output.

// BlkPrintkScratchMagic is the 16-byte sentinel the host pre-stages at
// LBA 0 of the dedicated scratch disk so the probe can identify it
// among all the writable bare-disk handles the firmware exposes
// (typically the ESP image, when the boot ISO is also a virtio-blk
// drive). The probe reads LBA 0 of every candidate and matches the
// first `len(BlkPrintkScratchMagic)` bytes against this constant.
//
// The 16th byte is `\0` so the magic ends cleanly at a 2-pow boundary
// and any host tool can use it as a C string. The chosen text is
// distinctive enough that random PE/FAT/ELF/ZIP/etc. boot sectors
// won't collide with it.
//
// Host harnesses stage the marker by:
//
//	echo -n "cloudboot-M1.6\0\0" > scratch.img    # 16 bytes
//	dd if=/dev/zero of=scratch.img bs=1m count=1 conv=notrunc oflag=append
//
// or equivalently with the helper at
// `tamago-uefi/internal/blkprintk-host/seed.go`.
var BlkPrintkScratchMagic = [16]byte{
	'c', 'l', 'o', 'u', 'd', 'b', 'o', 'o', 't', '-', 'M', '1', '.', '6', 0x00, 0x00,
}

// BlkAutoFlushBytes is the byte threshold at which BlkPrintk auto-flushes
// (so output dribbles to disk across the probe's lifetime rather than
// only at end). Picked at 4 KiB = 8 blocks at 512-byte BlockSize so the
// host can observe partial progress mid-run.
const BlkAutoFlushBytes = 4096

// ErrNoBlockIOSink is returned by Flush if the sink hasn't been bound
// to a Block IO handle yet (BindBlockIO was never called).
var ErrNoBlockIOSink = errors.New("uefi: BlkRingBuffer not bound to a Block IO handle (BindBlockIO not called)")

// ErrBufferSizeMismatch is returned by Flush when the device block
// size doesn't divide BlkRingCapacity. Spec-required behaviour
// (UEFI 2.10 §13.9.4: BufferSize must be a multiple of BlockSize).
var ErrBufferSizeMismatch = errors.New("uefi: BlkRingCapacity is not a multiple of the device BlockSize")

// BlkRingBuffer is the in-RAM ring + the firmware-side sink it flushes
// to. The ring is `BlkRingPayloadCapacity` bytes; `len` tracks the
// total bytes EVER written (before wrap), so callers can detect
// dropped-due-to-wrap output by comparing `len > capacity`.
//
// Thread-safety: M1.6 is single-goroutine on the firmware side (we
// haven't started any goroutines that share state at the probe-print
// path); no locking is required.
type BlkRingBuffer struct {
	// payload is the in-RAM ring; bytes are appended modulo capacity.
	payload [BlkRingPayloadCapacity]byte

	// head is the next-write position in payload. Always in [0, cap).
	head int

	// total is the cumulative number of bytes ever appended. When
	// `total > BlkRingPayloadCapacity`, the ring has wrapped and the
	// oldest bytes are gone.
	total uint64

	// writeCount is the monotonic flush counter, incremented at the
	// START of each successful Flush (so even a partial-write flush
	// bumps the count, and the host can detect "no flush has happened
	// yet" as writeCount == 0).
	writeCount uint64

	// blockIO is the EFI_BLOCK_IO_PROTOCOL instance pointer this ring
	// flushes to. Set by BindBlockIO, zero before binding.
	blockIO uint64

	// mediaID is the firmware's media identifier at bind time
	// (firmware-allocated uint32, opaque to us; required by
	// ReadBlocks / WriteBlocks).
	mediaID uint32

	// lba is the starting LBA on the bound device that this ring
	// writes to. Set by BindBlockIO.
	lba uint64

	// blockSize is the bound device's block size in bytes, captured at
	// bind time so Flush can validate alignment without re-reading the
	// firmware's Media struct on every call.
	blockSize uint32

	// pendingAutoFlush is the byte count since the last auto-flush
	// trigger; resets each time we cross the threshold.
	pendingAutoFlush int
}

// NewBlkRingBuffer constructs an unbound ring. Call `BindBlockIO`
// before the first `Flush` (or the first auto-flush will fail with
// `ErrNoBlockIOSink`).
func NewBlkRingBuffer() *BlkRingBuffer {
	return &BlkRingBuffer{}
}

// BindBlockIO ties the ring to a firmware Block IO instance + a
// starting LBA. The `blockIO` pointer must remain valid for the
// lifetime of the ring (until ExitBootServices); `mediaID` and
// `blockSize` are captured at bind time from `Media`. Returns
// `ErrBufferSizeMismatch` if `blockSize` doesn't divide
// `BlkRingCapacity` (firmware-side spec violation against UEFI 2.10
// §13.9.4).
func (r *BlkRingBuffer) BindBlockIO(blockIO uint64, mediaID, blockSize uint32, lba uint64) error {
	if blockSize == 0 || BlkRingCapacity%int(blockSize) != 0 {
		return ErrBufferSizeMismatch
	}
	r.blockIO = blockIO
	r.mediaID = mediaID
	r.blockSize = blockSize
	r.lba = lba
	return nil
}

// IsBound reports whether the ring has been bound to a Block IO sink.
// Useful for tests + for the dispatcher to skip the side-channel when
// no writable virtio-blk is present.
func (r *BlkRingBuffer) IsBound() bool {
	return r.blockIO != 0
}

// Total returns the cumulative byte count appended to the ring (NOT
// modulo capacity). When `Total() > BlkRingPayloadCapacity`, the
// ring has wrapped at least once — see WriteCount() and Wrapped().
func (r *BlkRingBuffer) Total() uint64 {
	return r.total
}

// WriteCount returns the monotonic flush counter — the number of
// times Flush has begun writing to disk since the ring was created.
// Useful for the host to confirm progress across multiple runs.
func (r *BlkRingBuffer) WriteCount() uint64 {
	return r.writeCount
}

// Wrapped reports whether the ring has wrapped (some early bytes are
// no longer recoverable). The on-disk format does NOT distinguish
// pre-wrap vs post-wrap state explicitly; callers must check
// `Total()` against `BlkRingPayloadCapacity`.
func (r *BlkRingBuffer) Wrapped() bool {
	return r.total > uint64(BlkRingPayloadCapacity)
}

// PayloadBytes returns the up-to-32KiB serialized payload in
// chronological order (oldest first). The byte slice is a freshly
// allocated copy — modifying it does not affect the ring. Useful for
// host tests + by the live Flush path.
func (r *BlkRingBuffer) PayloadBytes() []byte {
	n := r.total
	if n > uint64(BlkRingPayloadCapacity) {
		n = uint64(BlkRingPayloadCapacity)
	}
	out := make([]byte, n)
	if !r.Wrapped() {
		// No wrap — payload[0:head] is the chronological order.
		copy(out, r.payload[:r.head])
		return out
	}
	// Wrap: oldest byte sits at payload[head]; payload[head:] then
	// payload[:head] is the chronological order.
	first := BlkRingPayloadCapacity - r.head
	copy(out[:first], r.payload[r.head:])
	copy(out[first:], r.payload[:r.head])
	return out
}

// Append writes one byte into the ring. Wrap is silently handled —
// overwriting the oldest byte. The total counter bumps unconditionally
// so callers can detect drops.
func (r *BlkRingBuffer) Append(b byte) {
	r.payload[r.head] = b
	r.head++
	if r.head == BlkRingPayloadCapacity {
		r.head = 0
	}
	r.total++
	r.pendingAutoFlush++
}

// AppendString writes every byte of s into the ring, in order.
// Convenience wrapper for one-line prints. Returns the number of
// bytes appended (always len(s)).
func (r *BlkRingBuffer) AppendString(s string) int {
	for i := 0; i < len(s); i++ {
		r.Append(s[i])
	}
	return len(s)
}

// AutoFlushReady reports whether the ring has accumulated enough
// bytes since the last auto-flush to warrant a flush call. The probe
// queries this after each line print; the live host-tamago glue
// then calls Flush if true.
func (r *BlkRingBuffer) AutoFlushReady() bool {
	return r.pendingAutoFlush >= BlkAutoFlushBytes
}

// ResetAutoFlush clears the pending-auto-flush counter. Called by the
// live Flush path after a successful WriteBlocks. Host tests use this
// to reset state between scenarios.
func (r *BlkRingBuffer) ResetAutoFlush() {
	r.pendingAutoFlush = 0
}

// Serialize returns the full BlkRingCapacity-byte disk frame:
//
//	bytes [0..8)   little-endian uint64 monotonic write count
//	bytes [8..16)  little-endian uint64 payload byte count (<= capacity)
//	bytes [16..)   payload, chronological, oldest first; trailing
//	               zero-fill up to BlkRingCapacity.
//
// The returned slice has length BlkRingCapacity exactly, suitable for
// passing to BlockIOWriteBlocks if BlkRingCapacity is a multiple of
// the device block size (the bind-time check enforces that).
//
// Note: this method does NOT bump writeCount. The live Flush path
// bumps it BEFORE serializing so the in-frame count reflects the
// flush that's about to happen, not the previous one.
func (r *BlkRingBuffer) Serialize() []byte {
	out := make([]byte, BlkRingCapacity)
	// Header: writeCount + payload byte count.
	putLE64(out[0:8], r.writeCount)
	payload := r.PayloadBytes()
	putLE64(out[8:16], uint64(len(payload)))
	copy(out[BlkRingHeaderSize:], payload)
	return out
}

// IncrementWriteCount bumps the monotonic counter. Called by the
// live Flush path immediately before Serialize so the serialized
// frame reflects the about-to-happen write. Exposed for host tests
// so they can pre-stage the counter before testing serialization.
func (r *BlkRingBuffer) IncrementWriteCount() {
	r.writeCount++
}

// putLE64 writes v as 8 little-endian bytes into b (must be >= 8 bytes).
func putLE64(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

// DecodeBlkRingFrame parses a serialized BlkRingCapacity-byte frame
// back into (writeCount, payload). Used by host post-halt analysis
// tooling and by the tests. Returns error if the frame is too short
// or claims a payload length larger than capacity.
func DecodeBlkRingFrame(frame []byte) (writeCount uint64, payload []byte, err error) {
	if len(frame) < BlkRingHeaderSize {
		return 0, nil, errors.New("uefi: BlkRingFrame too short for header")
	}
	writeCount = leU64(frame[0:8])
	n := leU64(frame[8:16])
	if n > uint64(BlkRingPayloadCapacity) {
		return writeCount, nil, errors.New("uefi: BlkRingFrame claims payload > capacity")
	}
	if uint64(len(frame)) < uint64(BlkRingHeaderSize)+n {
		return writeCount, nil, errors.New("uefi: BlkRingFrame shorter than declared payload")
	}
	payload = make([]byte, n)
	copy(payload, frame[BlkRingHeaderSize:BlkRingHeaderSize+int(n)])
	return writeCount, payload, nil
}
