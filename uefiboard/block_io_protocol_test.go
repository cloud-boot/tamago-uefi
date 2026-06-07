// Host-side tests for block_io_protocol.go.
//
// Pure type-surface checks: GUID round-trip + on-wire bytes, struct
// field offsets + size for EFI_BLOCK_IO_MEDIA, protocol-slot offsets
// (Revision, Media, Reset, ReadBlocks, WriteBlocks, FlushBlocks), and
// revision constants. The live thunks live in
// block_io_protocol_tamago.go and are not host-buildable; what we
// exercise here is everything that catches a GUID typo, an offset
// drift, or a field-reorder mistake at `go test` time.
//
// Reference values: MdePkg/Include/Protocol/BlockIo.h (edk2.git
// stable/202408).

package uefiboard

import (
	"encoding/binary"
	"testing"
	"unsafe"
)

func TestEFIBlockIOProtocolGUID_RoundTrip(t *testing.T) {
	// Canonical text per MdePkg/Include/Protocol/BlockIo.h (edk2.git
	// stable/202408 lines 15..18):
	//
	//   #define EFI_BLOCK_IO_PROTOCOL_GUID \
	//     { 0x964e5b21, 0x6459, 0x11d2, \
	//       {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
	const text = "964e5b21-6459-11d2-8e39-00a0c969723b"
	expect := guidFromText(t, text)
	got := EFIBlockIOProtocolGUID
	if got != expect {
		t.Fatalf("EFIBlockIOProtocolGUID mismatch:\n got    = %+v\n expect = %+v", got, expect)
	}
}

// TestEFIBlockIOProtocolGUID_WireLayout pins the on-wire 16-byte
// pattern firmware compares against (mixed-endian: Data1/Data2/Data3
// little-endian, Data4 byte-array as-is). Catches an endianness slip
// the struct comparison above would miss if `guidFromText` shared a
// bug with the GUID constant.
func TestEFIBlockIOProtocolGUID_WireLayout(t *testing.T) {
	g := EFIBlockIOProtocolGUID
	var wire [16]byte
	binary.LittleEndian.PutUint32(wire[0:4], g.Data1)
	binary.LittleEndian.PutUint16(wire[4:6], g.Data2)
	binary.LittleEndian.PutUint16(wire[6:8], g.Data3)
	copy(wire[8:], g.Data4[:])
	// Expected bytes for {0x964e5b21, 0x6459, 0x11d2,
	//                     {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}}
	expect := [16]byte{
		0x21, 0x5b, 0x4e, 0x96, // Data1 little-endian
		0x59, 0x64, // Data2 little-endian
		0xd2, 0x11, // Data3 little-endian
		0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b, // Data4 raw
	}
	if wire != expect {
		t.Fatalf("EFIBlockIOProtocolGUID wire layout wrong:\n got    = % x\n expect = % x", wire, expect)
	}
}

// TestBlockIOProtocolStructOffsets pins the offsets of the
// EFI_BLOCK_IO_PROTOCOL function-table slots so the
// `blkIOReadBlocksOffset` / `blkIOWriteBlocksOffset` constants the
// live probe relies on stay in sync with the EDK2 header. Function
// pointers are opaque on the Go side, so we just pin the arithmetic.
func TestBlockIOProtocolStructOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"Revision", blkIORevisionOffset, 0},
		{"Media", blkIOMediaOffset, 8},
		{"Reset", blkIOResetOffset, 16},
		{"ReadBlocks", blkIOReadBlocksOffset, 24},
		{"WriteBlocks", blkIOWriteBlocksOffset, 32},
		{"FlushBlocks", blkIOFlushBlocksOffset, 40},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("blkIO%sOffset = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestBlockIORevisionConstants pins the three published revision
// values (BlockIo.h lines 202..204). A typo here would make a future
// rev-branching path (if any) silently dispatch wrong.
func TestBlockIORevisionConstants(t *testing.T) {
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"Revision (1)", EFIBlockIOProtocolRevision, 0x00010000},
		{"Revision2", EFIBlockIOProtocolRevision2, 0x00020001},
		{"Revision3", EFIBlockIOProtocolRevision3, 0x0002001F},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%08x, want 0x%08x", c.name, c.got, c.want)
		}
	}
}

// TestBlockIOMediaLayout pins every field offset of
// EFI_BLOCK_IO_MEDIA. A field reordering, a missing field, or a
// padding miscount would surface here rather than silently misalign
// the live `Media.ReadOnly` / `Media.BlockSize` reads the M1.6 probe
// relies on.
func TestBlockIOMediaLayout(t *testing.T) {
	var m EFIBlockIOMedia
	cases := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"MediaId", unsafe.Offsetof(m.MediaId), 0},
		{"RemovableMedia", unsafe.Offsetof(m.RemovableMedia), 4},
		{"MediaPresent", unsafe.Offsetof(m.MediaPresent), 5},
		{"LogicalPartition", unsafe.Offsetof(m.LogicalPartition), 6},
		{"ReadOnly", unsafe.Offsetof(m.ReadOnly), 7},
		{"WriteCaching", unsafe.Offsetof(m.WriteCaching), 8},
		{"BlockSize", unsafe.Offsetof(m.BlockSize), 12},
		{"IoAlign", unsafe.Offsetof(m.IoAlign), 16},
		{"LastBlock", unsafe.Offsetof(m.LastBlock), 24},
		{"LowestAlignedLba", unsafe.Offsetof(m.LowestAlignedLba), 32},
		{"LogicalBlocksPerPhysicalBlock", unsafe.Offsetof(m.LogicalBlocksPerPhysicalBlock), 40},
		{"OptimalTransferLengthGranularity", unsafe.Offsetof(m.OptimalTransferLengthGranularity), 44},
	}
	for _, c := range cases {
		if c.off != c.want {
			t.Errorf("%s offset = %d, want %d", c.name, c.off, c.want)
		}
	}
	if got, want := unsafe.Sizeof(m), uintptr(efiBlockIOMediaSize); got != want {
		t.Errorf("sizeof(EFIBlockIOMedia) = %d, want %d", got, want)
	}
}

// TestBlockIOMediaFlagsRoundTrip exercises the boolean field semantics
// the M1.6 probe interprets: `ReadOnly == 0` selects writable disks;
// `LogicalPartition == 0` selects bare disks (not partitions). A
// reordering of the byte fields would corrupt these checks silently.
func TestBlockIOMediaFlagsRoundTrip(t *testing.T) {
	var m EFIBlockIOMedia
	m.MediaId = 0xdeadbeef
	m.RemovableMedia = 1
	m.MediaPresent = 1
	m.LogicalPartition = 0
	m.ReadOnly = 0
	m.WriteCaching = 1
	m.BlockSize = 512
	m.IoAlign = 0
	m.LastBlock = 2047 // 1 MiB at 512-byte blocks - 1
	if m.MediaId != 0xdeadbeef {
		t.Errorf("MediaId round-trip failed: got 0x%x", m.MediaId)
	}
	if m.ReadOnly != 0 {
		t.Errorf("ReadOnly should be 0 (writable); got %d", m.ReadOnly)
	}
	if m.LogicalPartition != 0 {
		t.Errorf("LogicalPartition should be 0 (bare disk); got %d", m.LogicalPartition)
	}
	if m.BlockSize != 512 {
		t.Errorf("BlockSize should be 512; got %d", m.BlockSize)
	}
	if m.LastBlock != 2047 {
		t.Errorf("LastBlock should be 2047; got %d", m.LastBlock)
	}
}

// TestBlockIOMediaWireBytesAtOffsetsReadbackCorrectly walks a raw byte
// view of the struct and verifies that the flag byte at offset 7
// (ReadOnly) carries the value we wrote — pinning the on-the-wire
// layout the firmware populates.
func TestBlockIOMediaWireBytesAtOffsetsReadbackCorrectly(t *testing.T) {
	var m EFIBlockIOMedia
	m.ReadOnly = 0x01
	m.LogicalPartition = 0x01
	m.MediaPresent = 0x01
	base := (*[efiBlockIOMediaSize]byte)(unsafe.Pointer(&m))
	if got := base[5]; got != 1 {
		t.Errorf("MediaPresent byte (offset 5) = 0x%02x, want 0x01", got)
	}
	if got := base[6]; got != 1 {
		t.Errorf("LogicalPartition byte (offset 6) = 0x%02x, want 0x01", got)
	}
	if got := base[7]; got != 1 {
		t.Errorf("ReadOnly byte (offset 7) = 0x%02x, want 0x01", got)
	}
}
