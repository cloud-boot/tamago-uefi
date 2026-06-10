// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — Go-side handlers for the published
// EFI_BLOCK_IO_PROTOCOL callbacks (Phase 3 sprint 1).
//
// Four entry points, all called by the per-arch asm trampoline after
// it marshals firmware-ABI args into Go-ABI0 positions:
//
//   blockIOResetGo(this, extended) -> EFI_STATUS
//   blockIOReadBlocksGo(this, mediaID, lba, bufferSize, buffer) -> EFI_STATUS
//   blockIOWriteBlocksGo(this, mediaID, lba, bufferSize, buffer) -> EFI_STATUS
//   blockIOFlushBlocksGo(this) -> EFI_STATUS
//
// Each is //go:nosplit (no stack growth) — same constraints as
// loadFileGo in initrd_protocol.go: we entered on the firmware's
// stack with no usable Go scheduler state. Manual byte loops; no
// runtime.memmove; no slice headers; no map lookups.
//
// Host-buildable (no //go:build tamago) so the handler semantics are
// exercised under host `go test` without going anywhere near
// firmware. The asm trampoline + InstallProtocolInterface wiring
// lives in block_io_publish_tamago.go + block_io_publish_amd64.s.

package uefiboard

import "unsafe"

// blockIOLookup linearly scans blockIOPublishRegistry for the slot
// whose `proto` matches `this`. Returns the entry + ok=true on hit;
// zero entry + ok=false on miss.
//
//go:nosplit
func blockIOLookup(this uintptr) (blockIOPublishEntry, bool) {
	for i := 0; i < blockIOPublishRegistrySize; i++ {
		if blockIOPublishRegistry[i].proto == this && blockIOPublishRegistry[i].proto != 0 {
			return blockIOPublishRegistry[i], true
		}
	}
	return blockIOPublishEntry{}, false
}

// blockIOResetGo handles EFI_BLOCK_IO_PROTOCOL.Reset (UEFI 2.10
// §13.9.2). For our synthetic in-memory device there is nothing to
// reset; any registered `this` returns EFI_SUCCESS and unknown
// `this` returns EFI_NOT_FOUND.
//
//   EFI_STATUS Reset(IN EFI_BLOCK_IO_PROTOCOL *This,
//                    IN BOOLEAN                ExtendedVerification);
//
//go:nosplit
func blockIOResetGo(this uintptr, extended uintptr) uintptr {
	if _, ok := blockIOLookup(this); !ok {
		return blockIOEFINotFound
	}
	return blockIOEFISuccess
}

// blockIOReadBlocksGo handles EFI_BLOCK_IO_PROTOCOL.ReadBlocks (UEFI
// 2.10 §13.9.3):
//
//   EFI_STATUS ReadBlocks(IN  EFI_BLOCK_IO_PROTOCOL *This,
//                         IN  UINT32                 MediaId,
//                         IN  EFI_LBA                Lba,
//                         IN  UINTN                  BufferSize,
//                         OUT VOID                  *Buffer );
//
// Spec-derived error preference (UEFI 2.10 §13.9.3 table 188):
//   - This not registered            -> EFI_NOT_FOUND   (sprint-local)
//   - BufferSize % BlockSize != 0    -> EFI_BAD_BUFFER_SIZE
//   - Lba > LastBlock                -> EFI_INVALID_PARAMETER
//   - Buffer == NULL && BufferSize>0 -> EFI_INVALID_PARAMETER
//   - else                            -> EFI_SUCCESS after copy
//
//go:nosplit
func blockIOReadBlocksGo(this uintptr, mediaID uintptr, lba uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	ent, ok := blockIOLookup(this)
	if !ok {
		return blockIOEFINotFound
	}
	if bufferSize == 0 {
		return blockIOEFISuccess
	}
	if (bufferSize % uintptr(BlockIOLogicalBlockSize)) != 0 {
		return blockIOEFIBadBufferSize
	}
	if buffer == 0 {
		return blockIOEFIInvalidParameter
	}
	// Byte-offset arithmetic in uintptr space. The image total size is
	// at most ~4 GiB on the FreeBSD MVP target — fits comfortably in a
	// uintptr on every 64-bit arch we support.
	off := lba * uintptr(BlockIOLogicalBlockSize)
	if off > ent.size {
		return blockIOEFIInvalidParameter
	}
	end := off + bufferSize
	if end > ent.size || end < off /* overflow */ {
		return blockIOEFIInvalidParameter
	}
	// Manual byte copy (no runtime.memmove — same rationale as
	// loadFileGo's transfer loop).
	for i := uintptr(0); i < bufferSize; i++ {
		*(*byte)(unsafe.Pointer(buffer + i)) = *(*byte)(unsafe.Pointer(ent.body + off + i))
	}
	return blockIOEFISuccess
}

// blockIOWriteBlocksGo handles EFI_BLOCK_IO_PROTOCOL.WriteBlocks (UEFI
// 2.10 §13.9.4). Sprint 1 is read-only — every call returns
// EFI_WRITE_PROTECTED so a misbehaving loader can't corrupt the
// streamed image bytes (and the spec defines this as the canonical
// response for a read-only device, see Media.ReadOnly=1 in §13.9.1.4
// — firmware-side drivers (FatDxe / PartitionDxe) respect it).
//
//go:nosplit
func blockIOWriteBlocksGo(this uintptr, mediaID uintptr, lba uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	if _, ok := blockIOLookup(this); !ok {
		return blockIOEFINotFound
	}
	return blockIOEFIWriteProtected
}

// blockIOFlushBlocksGo handles EFI_BLOCK_IO_PROTOCOL.FlushBlocks (UEFI
// 2.10 §13.9.5). Read-only no-op: always EFI_SUCCESS for a known
// `this`, EFI_NOT_FOUND for an unknown one.
//
//go:nosplit
func blockIOFlushBlocksGo(this uintptr) uintptr {
	if _, ok := blockIOLookup(this); !ok {
		return blockIOEFINotFound
	}
	return blockIOEFISuccess
}
