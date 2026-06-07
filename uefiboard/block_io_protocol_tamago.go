// cloud-boot UEFI board — EFI_BLOCK_IO_PROTOCOL call thunks (Phase 2, M1.6).
//
// Live wrappers for the three entry points M1.6 uses:
//
//   - BlockIOReadBlocks   (Block IO Read — for round-trip verification)
//   - BlockIOWriteBlocks  (Block IO Write — the side-channel print sink)
//   - BlockIOFlushBlocks  (Block IO Flush — committed-write guarantee)
//
// The type-surface (GUID, struct, offsets) lives in
// block_io_protocol.go and is host-buildable.
//
// Reference: MdePkg/Include/Protocol/BlockIo.h (edk2.git stable/202408)
// — every signature below is transcribed verbatim.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// BlockIOMedia returns a Go view of the `Media` struct the firmware
// has populated for this protocol instance. The pointer is read out
// of the protocol slot at +blkIOMediaOffset and dereferenced; the
// returned struct is a COPY so the caller can safely keep it after
// the firmware has updated the underlying buffer (e.g. on a media
// change). Returns nil + ok=false if the firmware put a NULL pointer
// in the Media slot (spec-illegal but defensive).
func BlockIOMedia(blockIO uint64) (*EFIBlockIOMedia, bool) {
	if blockIO == 0 {
		return nil, false
	}
	mediaSlot := blockIO + blkIOMediaOffset
	mediaPtr := *(*uint64)(unsafe.Pointer(uintptr(mediaSlot)))
	if mediaPtr == 0 {
		return nil, false
	}
	src := (*EFIBlockIOMedia)(unsafe.Pointer(uintptr(mediaPtr)))
	out := *src
	return &out, true
}

// BlockIOReadBlocks issues `EFI_BLOCK_IO_PROTOCOL.ReadBlocks` against
// the protocol instance at `blockIO`. `lba` is the starting logical
// block address; `buf` is a Go-side byte slice whose length is the
// transfer size in bytes (must be a multiple of the device block size
// per UEFI 2.10 §13.9.3).
//
// EFI_BLOCK_IO_PROTOCOL.ReadBlocks signature (UEFI 2.10 §13.9.3):
//
//	EFI_STATUS ReadBlocks(
//	    IN  EFI_BLOCK_IO_PROTOCOL *This,
//	    IN  UINT32                 MediaId,
//	    IN  EFI_LBA                Lba,
//	    IN  UINTN                  BufferSize,
//	    OUT VOID                  *Buffer );
//
// (5 args — exactly the M1-widened efiCall envelope.)
//
// Note on calling convention: efiCall expects the ADDRESS of the
// function-pointer slot (it issues `MOVD (R8), R9; BL (R9)` on arm64
// — load fn from slot, indirect-call). The ReadBlocks slot sits at
// `blockIO + blkIOReadBlocksOffset`; we pass that directly, mirroring
// `pci_io_protocol_tamago.go`'s `pciIO + pciIOPciRead` pattern (which
// is itself the salvage-commit-validated idiom).
func BlockIOReadBlocks(blockIO uint64, mediaID uint32, lba uint64, buf []byte) error {
	if blockIO == 0 {
		return ErrNoBootServices
	}
	if len(buf) == 0 {
		return nil
	}
	status := efiCall(
		blockIO+blkIOReadBlocksOffset,
		blockIO,
		uint64(mediaID),
		lba,
		uint64(len(buf)),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "BlockIO.ReadBlocks"}
	}
	return nil
}

// BlockIOWriteBlocks issues `EFI_BLOCK_IO_PROTOCOL.WriteBlocks` against
// the protocol instance at `blockIO`. Same shape as ReadBlocks; UEFI
// 2.10 §13.9.4 requires `BufferSize` to be a multiple of the device
// block size and the LBA to be in range.
//
// EFI_BLOCK_IO_PROTOCOL.WriteBlocks signature (UEFI 2.10 §13.9.4):
//
//	EFI_STATUS WriteBlocks(
//	    IN EFI_BLOCK_IO_PROTOCOL *This,
//	    IN UINT32                 MediaId,
//	    IN EFI_LBA                Lba,
//	    IN UINTN                  BufferSize,
//	    IN VOID                  *Buffer );
//
// (5 args.)
func BlockIOWriteBlocks(blockIO uint64, mediaID uint32, lba uint64, buf []byte) error {
	if blockIO == 0 {
		return ErrNoBootServices
	}
	if len(buf) == 0 {
		return nil
	}
	status := efiCall(
		blockIO+blkIOWriteBlocksOffset,
		blockIO,
		uint64(mediaID),
		lba,
		uint64(len(buf)),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "BlockIO.WriteBlocks"}
	}
	return nil
}

// BlockIOFlushBlocks issues `EFI_BLOCK_IO_PROTOCOL.FlushBlocks`. UEFI
// 2.10 §13.9.5 — pushes any cached writes through to the device. M1.6
// calls this after WriteBlocks so the host's post-halt disk-file read
// observes the latest payload.
//
// EFI_BLOCK_IO_PROTOCOL.FlushBlocks signature (UEFI 2.10 §13.9.5):
//
//	EFI_STATUS FlushBlocks(IN EFI_BLOCK_IO_PROTOCOL *This);
//
// (1 arg — trivially within the 5-arg envelope; trailing slots passed 0.)
func BlockIOFlushBlocks(blockIO uint64) error {
	if blockIO == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		blockIO+blkIOFlushBlocksOffset,
		blockIO,
		0, 0, 0, 0, 0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "BlockIO.FlushBlocks"}
	}
	return nil
}
