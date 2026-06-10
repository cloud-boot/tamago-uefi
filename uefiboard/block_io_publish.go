// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_BLOCK_IO_PROTOCOL publish-side
// (Phase 3 sprint 1 — first OS-agnostic OCI boot).
//
// What this is: the publish-side companion to the existing
// block_io_protocol*.go consumer surface. PublishBlockIO takes a
// read-only byte slice (a complete bootable disk image — GPT + ESP,
// streamed from an OCI artifact) and installs a synthetic
// EFI_BLOCK_IO_PROTOCOL backed by it.
//
// After install the caller drives gBS->ConnectController(handle,
// NULL, NULL, TRUE) so EDK2's DiskIoDxe + PartitionDxe + FatDxe
// auto-discover the GPT, find the ESP, and surface
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on a child handle. From there
// LoadImage(\EFI\BOOT\BOOTX64.EFI) lands the FreeBSD loader.efi
// (or any other OS's EFI loader on its ESP).
//
// Architecture (UEFI 2.10 §13.9):
//
//   ┌────────────────────────────────────────────┐
//   │  EFI_BLOCK_IO_PROTOCOL  (this file)        │
//   │  ─ MediaId / BlockSize=512 / LastBlock     │
//   │  ─ Reset / ReadBlocks / WriteBlocks / ...  │ <- our trampolines
//   └────────────────────────────────────────────┘
//                       │
//   gBS->ConnectController(handle, NULL, NULL, TRUE)
//                       ▼
//   ┌────────────────────────────────────────────┐
//   │  DiskIoDxe (EDK2 binds automatically)      │
//   │  PartitionDxe (parses GPT/MBR/ElTorito)    │
//   │  FatDxe (mounts FAT on ESP child handle)   │
//   └────────────────────────────────────────────┘
//                       │
//                       ▼
//   ┌────────────────────────────────────────────┐
//   │  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on        │
//   │  child handle representing the ESP         │
//   │  LocateHandleBuffer(SFS_GUID) finds it     │
//   └────────────────────────────────────────────┘
//
// Read/Write semantics (sprint 1 — read-only):
//   - ReadBlocks: copy bytes from imageBytes[lba*512 : lba*512+size] to
//     the firmware-provided buffer.
//   - WriteBlocks: return EFI_WRITE_PROTECTED (sprint 1 is read-only).
//   - FlushBlocks: no-op return EFI_SUCCESS.
//   - Reset: no-op return EFI_SUCCESS.
//
// Sprint scope:
//   - amd64 only (no asm trampolines for arm64/riscv64/loong64 yet —
//     deferred to sprint 2 alongside their UFS/NTFS surfaces).
//   - Read-only. WriteBlocks fails fast so a misbehaving loader can't
//     corrupt the streamed image; sprint 2 may revisit.
//   - One published image at a time (a fixed-size 4-slot registry).
//
// Reference: MdePkg/Include/Protocol/BlockIo.h (edk2.git stable/202408)
// — already cited in block_io_protocol.go; same GUID, same Media
// struct layout. This file re-uses both.

package uefiboard

import (
	"errors"
)

// ErrEmptyBlockImage is returned by PublishBlockIO when called with
// no bytes — would result in a Block IO device with LastBlock=0 (UEFI
// undefined behaviour) so we surface the caller bug early.
var ErrEmptyBlockImage = errors.New("uefi: PublishBlockIO image is empty")

// ErrBlockIONotPublished is returned by UnpublishBlockIO when called
// with a zero handle.
var ErrBlockIONotPublished = errors.New("uefi: BlockIO handle is zero (not published or already unpublished)")

// ErrBlockIORegistryFull is returned by PublishBlockIO when the
// fixed-size publisher registry has no free slot.
var ErrBlockIORegistryFull = errors.New("uefi: PublishBlockIO registry full (bump blockIOPublishRegistrySize)")

// ErrBlockIOImageNotAligned is returned by PublishBlockIO when the
// image size is not a multiple of the 512-byte block size. UEFI
// PartitionDxe + FatDxe assume the last block is fully present; a
// short tail trips an EFI_INVALID_PARAMETER on first read.
var ErrBlockIOImageNotAligned = errors.New("uefi: PublishBlockIO image size not aligned to 512 bytes")

// BlockIOLogicalBlockSize is the block size we publish to the firmware
// (UEFI 2.10 §13.9.1.4). 512 is universal — GPT + MBR + ISO9660 +
// FAT all assume it. A FreeBSD bootonly ISO is naturally 2048-byte
// (ISO9660 sector), but UEFI's PartitionDxe walks the LBA-0/1 protective
// MBR + GPT header at 512-byte LBA anyway, and ElToritoDxe re-reads
// the El Torito catalog at 2048. So 512 is the right call for the
// FreeBSD-on-ESP MVP.
const BlockIOLogicalBlockSize uint32 = 512

// blockIOPublishRegistrySize bounds how many concurrently-published
// block images the per-arch asm trampolines can serve. Sprint 1 MVP
// publishes exactly one (the FreeBSD bootonly ISO image), so 4 leaves
// generous headroom.
const blockIOPublishRegistrySize = 4

// blockIOPublishEntry is one slot in the publisher registry. A
// non-zero `proto` marks the slot as live; UnpublishBlockIO zeroes
// the slot. body+size pin the in-memory disk image the trampolines
// serve reads from.
type blockIOPublishEntry struct {
	proto uintptr // address of the published EFI_BLOCK_IO_PROTOCOL struct (== "this" the firmware passes)
	media uintptr // address of the EFIBlockIOMedia struct firmware reads via blockIO+blkIOMediaOffset
	body  uintptr // address of byte[0] of the disk image (read inside nosplit trampolines)
	size  uintptr // byte length of the disk image (must be multiple of BlockIOLogicalBlockSize)

	// bodyKeepAlive holds a real Go-typed reference to the same disk
	// image bytes `body` points at. Same GC-pinning rationale as
	// loadFileEntry.bodyKeepAlive in initrd_protocol.go: the trampoline
	// reads via the uintptr to avoid runtime helpers, but the GC needs
	// a typed slice header to keep the underlying allocation alive
	// across the indefinite window from PublishBlockIO to UnpublishBlockIO.
	bodyKeepAlive []byte

	// mediaKeepAlive holds a typed reference to the Media struct so it
	// doesn't get GC'd while firmware retains the pointer.
	mediaKeepAlive *EFIBlockIOMedia
}

// blockIOPublishRegistry is the package-private array the per-arch
// asm trampoline-driven blockIO*Go handlers scan on every firmware
// callback. Static storage — no map, no slice header — so accesses
// inside the nosplit body do not pull in runtime helpers.
var blockIOPublishRegistry [blockIOPublishRegistrySize]blockIOPublishEntry

// EFI_STATUS values used by the block-IO trampoline handlers.
const (
	blockIOEFISuccess          uintptr = 0
	blockIOEFIInvalidParameter uintptr = 0x8000000000000002
	blockIOEFIUnsupported      uintptr = 0x8000000000000003
	blockIOEFINotFound         uintptr = 0x800000000000000E
	blockIOEFIDeviceError      uintptr = 0x8000000000000007
	blockIOEFIWriteProtected   uintptr = 0x8000000000000008
	blockIOEFIMediaChanged     uintptr = 0x800000000000000B
	blockIOEFINoMedia          uintptr = 0x800000000000000C
	blockIOEFIBadBufferSize    uintptr = 0x8000000000000005
)

// EFI_BLOCK_IO_PROTOCOL_REVISION value we publish (UEFI 2.10 §13.9.1.1).
// Use Revision (the original — Rev1) since we only fill the rev1
// Media fields (LastBlock + BlockSize + flags) and leave the rev2/rev3
// trailing fields zero.
const blockIOPublishedRevision uint64 = 0x00010000

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
//
//	964e5b22-6459-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Protocol/SimpleFileSystem.h (edk2.git
// stable/202408). Notice Data1 is `964e5b22` (BlockIO is `964e5b21` —
// neighbouring slots in the original EFI spec). Host-buildable so
// the GUID round-trip is unit-testable independent of the tamago
// install path.
var EFISimpleFileSystemProtocolGUID = EFIGUID{
	Data1: 0x964e5b22,
	Data2: 0x6459,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFIBlockIOProtocolPublished is the publish-side struct that
// firmware reads. Layout MUST match the offsets in block_io_protocol.go
// (Revision=+0, Media=+8, Reset=+16, ReadBlocks=+24, WriteBlocks=+32,
// FlushBlocks=+40 — same as the consumer-side view, just populated
// instead of read).
type EFIBlockIOProtocolPublished struct {
	Revision    uint64 //  0
	Media       uint64 //  8 — pointer to EFIBlockIOMedia
	Reset       uint64 // 16 — function pointer to blockIO_reset_trampoline
	ReadBlocks  uint64 // 24 — function pointer to blockIO_read_trampoline
	WriteBlocks uint64 // 32 — function pointer to blockIO_write_trampoline
	FlushBlocks uint64 // 40 — function pointer to blockIO_flush_trampoline
}
