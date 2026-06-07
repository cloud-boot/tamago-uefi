// cloud-boot UEFI board — EFI_BLOCK_IO_PROTOCOL type surface (Phase 2, M1.6).
//
// Pure type + GUID + offset surface for EFI_BLOCK_IO_PROTOCOL
// (UEFI 2.10 §13.9 — "Block I/O Protocol"). M1.6 uses Block IO as a
// side-channel observability mechanism on Apple VZ (vfkit), where the
// EFI ConOut → virtio-console path is documented broken in vfkit
// 0.6.3 (see R-M1'a). The probe writes its captured-output ring buffer
// to a known LBA on a writable virtio-blk scratch disk; the host then
// reads the disk file post-halt and recovers the probe output.
//
// **No driver implementation here** — M1.6 ONLY uses ReadBlocks /
// WriteBlocks against the firmware-provided protocol; we do not
// reimplement block-device drivers.
//
// Upstream reference (cite before changing layouts):
//
//   - MdePkg/Include/Protocol/BlockIo.h (edk2.git stable/202408)
//     — GUID at lines 15..18; EFI_BLOCK_IO_MEDIA at lines 128..200;
//     EFI_BLOCK_IO_PROTOCOL struct at lines 214..230.
//   - UEFI 2.10 §13.9 — protocol semantics.
//
// Host-buildable (no //go:build tamago): the GUID round-trip + the
// `EFI_BLOCK_IO_MEDIA` struct-layout assertions run under host
// `go test`. The live ReadBlocks / WriteBlocks thunks live in
// block_io_protocol_tamago.go.

package uefiboard

// EFI_BLOCK_IO_PROTOCOL_GUID
//
//	964e5b21-6459-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Protocol/BlockIo.h (edk2.git stable/202408,
// lines 15..18):
//
//	#define EFI_BLOCK_IO_PROTOCOL_GUID \
//	  { 0x964e5b21, 0x6459, 0x11d2, \
//	    {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
var EFIBlockIOProtocolGUID = EFIGUID{
	Data1: 0x964e5b21,
	Data2: 0x6459,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_BLOCK_IO_PROTOCOL struct layout (UEFI 2.10 §13.9, mirrored
// against `MdePkg/Include/Protocol/BlockIo.h` lines 214..230):
//
//	struct _EFI_BLOCK_IO_PROTOCOL {
//	    UINT64                 Revision;     //  0
//	    EFI_BLOCK_IO_MEDIA    *Media;        //  8
//	    EFI_BLOCK_RESET        Reset;        // 16
//	    EFI_BLOCK_READ         ReadBlocks;   // 24
//	    EFI_BLOCK_WRITE        WriteBlocks;  // 32
//	    EFI_BLOCK_FLUSH        FlushBlocks;  // 40
//	};
//
// All function-pointer slots are sizeof(void*) on a 64-bit UEFI image;
// `Media` is also 8 bytes (pointer to EFI_BLOCK_IO_MEDIA). M1.6 uses
// `blkIOMediaOffset` (read-only peek at `*Media`) and the
// `blkIOReadBlocksOffset` / `blkIOWriteBlocksOffset` slots; the rest
// are named for completeness.
const (
	blkIORevisionOffset    = 0
	blkIOMediaOffset       = 8
	blkIOResetOffset       = 16
	blkIOReadBlocksOffset  = 24
	blkIOWriteBlocksOffset = 32
	blkIOFlushBlocksOffset = 40
)

// EFI_BLOCK_IO_PROTOCOL_REVISION values (BlockIo.h lines 202..204).
// Revision1 ships only the spec-original fields; Revision2 adds
// LowestAlignedLba + LogicalBlocksPerPhysicalBlock to Media;
// Revision3 adds OptimalTransferLengthGranularity. M1.6 never branches
// on revision — we only touch the rev1 fields — but the constants are
// exposed so callers can interpret the firmware-reported value.
const (
	EFIBlockIOProtocolRevision  uint64 = 0x00010000
	EFIBlockIOProtocolRevision2 uint64 = 0x00020001
	EFIBlockIOProtocolRevision3 uint64 = 0x0002001F
)

// EFIBlockIOMedia mirrors EFI_BLOCK_IO_MEDIA (UEFI 2.10 §13.9,
// `MdePkg/Include/Protocol/BlockIo.h` lines 128..200).
//
// EDK2 packs `BOOLEAN` as `UINT8` and `EFI_LBA` as `UINT64`. On-the-wire
// layout (with explicit alignment padding shown):
//
//	  0  UINT32   MediaId
//	  4  BOOLEAN  RemovableMedia
//	  5  BOOLEAN  MediaPresent
//	  6  BOOLEAN  LogicalPartition
//	  7  BOOLEAN  ReadOnly
//	  8  BOOLEAN  WriteCaching
//	  9  (pad to 4-byte align BlockSize)
//	 12  UINT32   BlockSize
//	 16  UINT32   IoAlign
//	 20  (pad to 8-byte align LastBlock)
//	 24  EFI_LBA  LastBlock
//	 32  EFI_LBA  LowestAlignedLba          (rev2+)
//	 40  UINT32   LogicalBlocksPerPhysicalBlock (rev2+)
//	 44  UINT32   OptimalTransferLengthGranularity (rev3+)
//
// Total size: 48 bytes (with the rev2/rev3 trailing fields). On a
// rev1 device firmware MAY still allocate 48 bytes and leave the
// trailing fields zero — Go's `unsafe.Sizeof` will agree.
//
// We expose every field; M1.6 only reads `ReadOnly`, `BlockSize`,
// `LastBlock`, and `LogicalPartition` (the latter is used to filter
// for bare disks over partitions, matching the design-doc requirement
// that LBA 0..7 is firmware-scratch on the dedicated probe disk).
type EFIBlockIOMedia struct {
	MediaId                          uint32
	RemovableMedia                   uint8
	MediaPresent                     uint8
	LogicalPartition                 uint8
	ReadOnly                         uint8
	WriteCaching                     uint8
	_pad0                            [3]uint8 // align BlockSize on 4 bytes
	BlockSize                        uint32
	IoAlign                          uint32
	_pad1                            [4]uint8 // align LastBlock on 8 bytes
	LastBlock                        uint64
	LowestAlignedLba                 uint64 // rev2+
	LogicalBlocksPerPhysicalBlock    uint32 // rev2+
	OptimalTransferLengthGranularity uint32 // rev3+
}

// efiBlockIOMediaSize is the Go-side `unsafe.Sizeof` of the mirror
// struct. Pinned by `TestBlockIOMediaLayout` so a reordering or pad
// mistake shows up at host `go test`.
const efiBlockIOMediaSize = 48
