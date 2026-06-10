// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — PublishBlockIO / UnpublishBlockIO live
// wrappers + ConnectController + SimpleFileSystem discovery (Phase 3
// sprint 1).
//
// What ships:
//   - PublishBlockIO(image []byte) allocates a Go-owned copy of the
//     disk image, constructs the EFI_BLOCK_IO_PROTOCOL struct +
//     EFIBlockIOMedia struct, wires the 4 function-pointer slots to
//     the per-arch blockIO_*_trampoline asm symbols, and calls
//     gBS->InstallMultipleProtocolInterfaces to publish a fresh
//     handle.
//
//   - ConnectController(handle) calls gBS->ConnectController so
//     EDK2's DiskIoDxe + PartitionDxe + FatDxe auto-bind to our Block
//     IO handle. Side-effect: a child handle representing the FAT
//     ESP gets created, publishing EFI_SIMPLE_FILE_SYSTEM_PROTOCOL.
//
//   - UnpublishBlockIO(handle) reverses the install.
//
// Sprint 1 status:
//   - amd64 only (asm trampolines for arm64/riscv64/loong64 deferred).
//   - Read-only Block IO (WriteBlocks returns EFI_WRITE_PROTECTED).
//
// The asm trampolines (block_io_publish_<arch>.s) bridge firmware
// ABI (MS x64) into Go ABI0 and call into the *Go handlers in
// block_io_publish_handlers.go.

//go:build tamago && amd64

package uefiboard

import (
	"errors"
	"unsafe"
)

// EFI_BOOT_SERVICES offsets we need beyond what's already in
// efi_events.go + initrd_protocol.go + rng_protocol.go. From
// MdePkg/Include/Uefi/UefiSpec.h:
//
//	128 InstallProtocolInterface             (already in rng_protocol.go)
//	304 ConnectController                    <-- new
//	312 LocateHandleBuffer                   (already in efi_events.go)
//	320 LocateProtocol                       (already in efi_events.go)
//	328 InstallMultipleProtocolInterfaces    (already in initrd_protocol.go)
//	336 UninstallMultipleProtocolInterfaces  (already in initrd_protocol.go)
const (
	efiBSConnectController = 304
)

// EFISimpleFileSystemProtocolGUID + EFIBlockIOProtocolPublished are
// defined in block_io_publish.go (host-buildable) so the GUID
// round-trip + struct-offset assertions can run under host `go test`
// without dragging the asm trampoline + InstallProtocolInterface
// closure in.

// blockIOPublishState holds the per-publish backing memory. The
// firmware retains pointers into protocol + media for the lifetime of
// the installed handle, so we keep typed Go references to keep the
// GC away.
type blockIOPublishState struct {
	protocol *EFIBlockIOProtocolPublished
	media    *EFIBlockIOMedia
	body     []byte
	slot     int
	handle   uint64 // firmware-assigned BlockIO controller handle
}

// publishedBlockIOs tracks active PublishBlockIO installs so
// UnpublishBlockIO can find the backing buffers + clear the registry
// slot.
var publishedBlockIOs = map[uintptr]*blockIOPublishState{}

// Per-arch asm trampoline symbols. Each one bridges the firmware-side
// ABI (MS x64 on amd64) into Go ABI0 and calls into the matching *Go
// handler in block_io_publish_handlers.go.
//
//	Reset       -> ·blockIOResetGo(SB)        (2 args)
//	ReadBlocks  -> ·blockIOReadBlocksGo(SB)   (5 args)
//	WriteBlocks -> ·blockIOWriteBlocksGo(SB)  (5 args)
//	FlushBlocks -> ·blockIOFlushBlocksGo(SB)  (1 arg)
func blockIO_reset_trampoline()
func blockIO_read_trampoline()
func blockIO_write_trampoline()
func blockIO_flush_trampoline()

var (
	blockIO_reset_trampolineFV = blockIO_reset_trampoline
	blockIO_read_trampolineFV  = blockIO_read_trampoline
	blockIO_write_trampolineFV = blockIO_write_trampoline
	blockIO_flush_trampolineFV = blockIO_flush_trampoline
)

// PublishBlockIO installs a synthetic EFI_BLOCK_IO_PROTOCOL backed
// by the given disk-image bytes under a fresh handle. The image MUST
// be a multiple of BlockIOLogicalBlockSize (512) bytes long — short
// tails violate PartitionDxe's last-block expectations.
//
// Returns the firmware-assigned handle (caller passes to
// ConnectController + UnpublishBlockIO) and an error.
func PublishBlockIO(image []byte) (uintptr, error) {
	if len(image) == 0 {
		return 0, ErrEmptyBlockImage
	}
	if (len(image) % int(BlockIOLogicalBlockSize)) != 0 {
		return 0, ErrBlockIOImageNotAligned
	}
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}

	// Stable Go-owned copy of the image. The firmware will keep
	// reading from `body` for the lifetime of the install via the
	// trampolines (which look it up by `this`), so we MUST hold a
	// typed reference (bodyKeepAlive below) to keep the GC away.
	body := make([]byte, len(image))
	copy(body, image)

	// Media struct — heap-allocated so the firmware can take its
	// address and remember it via protocol.Media. UEFI 2.10 §13.9.1.4
	// — only the rev1 fields are populated; rev2/rev3 trailing fields
	// are zero per Go's zero-initialisation, which is spec-compatible
	// (firmware that branches on revision sees Revision=0x00010000
	// and ignores them).
	media := &EFIBlockIOMedia{
		MediaId:          1, // any non-zero ID; firmware compares against ReadBlocks(MediaId)
		RemovableMedia:   0,
		MediaPresent:     1,
		LogicalPartition: 0, // we ARE the bare disk; PartitionDxe will create logical-partition children
		ReadOnly:         1, // sprint 1: read-only
		WriteCaching:     0,
		BlockSize:        BlockIOLogicalBlockSize,
		IoAlign:          0, // no alignment requirement
		LastBlock:        uint64(len(body))/uint64(BlockIOLogicalBlockSize) - 1,
	}

	// Resolve the 4 asm trampoline entry PCs. unsafe.Pointer on a Go
	// function value yields a *funcval; the first word is the entry PC.
	resetPC := **(**uintptr)(unsafe.Pointer(&blockIO_reset_trampolineFV))
	readPC := **(**uintptr)(unsafe.Pointer(&blockIO_read_trampolineFV))
	writePC := **(**uintptr)(unsafe.Pointer(&blockIO_write_trampolineFV))
	flushPC := **(**uintptr)(unsafe.Pointer(&blockIO_flush_trampolineFV))

	protocol := &EFIBlockIOProtocolPublished{
		Revision:    blockIOPublishedRevision,
		Media:       uint64(uintptr(unsafe.Pointer(media))),
		Reset:       uint64(resetPC),
		ReadBlocks:  uint64(readPC),
		WriteBlocks: uint64(writePC),
		FlushBlocks: uint64(flushPC),
	}

	// Reserve a registry slot BEFORE the firmware install so a racing
	// callback sees a fully populated entry (same defensive pattern as
	// loadFileRegistry).
	slot := -1
	for i := range blockIOPublishRegistry {
		if blockIOPublishRegistry[i].proto == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0, ErrBlockIORegistryFull
	}
	blockIOPublishRegistry[slot] = blockIOPublishEntry{
		proto:          uintptr(unsafe.Pointer(protocol)),
		media:          uintptr(unsafe.Pointer(media)),
		body:           uintptr(unsafe.Pointer(&body[0])),
		size:           uintptr(len(body)),
		bodyKeepAlive:  body,
		mediaKeepAlive: media,
	}

	// gBS->InstallProtocolInterface(IN OUT EFI_HANDLE *Handle,
	//                               IN EFI_GUID *Protocol,
	//                               IN EFI_INTERFACE_TYPE InterfaceType,  (always EFI_NATIVE_INTERFACE=0)
	//                               IN VOID *Interface);
	//
	// With *Handle = NULL on entry the firmware allocates a fresh
	// handle. Using InstallProtocolInterface (not the multi variant)
	// because we install exactly one protocol; the simpler API path
	// avoids the variadic NULL-terminator footgun.
	var handle uint64
	status := efiCall(
		bs+efiBSInstallProtocolInterface,
		uint64(uintptr(unsafe.Pointer(&handle))),
		uint64(uintptr(unsafe.Pointer(&EFIBlockIOProtocolGUID))),
		0, // EFI_NATIVE_INTERFACE
		uint64(uintptr(unsafe.Pointer(protocol))),
		0,
		0,
	)
	if status != efiSuccess {
		blockIOPublishRegistry[slot] = blockIOPublishEntry{}
		return 0, &EFIError{Status: status, Op: "InstallProtocolInterface(BlockIO)"}
	}

	publishedBlockIOs[uintptr(handle)] = &blockIOPublishState{
		protocol: protocol,
		media:    media,
		body:     body,
		slot:     slot,
		handle:   handle,
	}
	return uintptr(handle), nil
}

// UnpublishBlockIO undoes PublishBlockIO. Calls
// gBS->UninstallMultipleProtocolInterfaces (same shape as the
// initrd unpublish; the protocol pointer must match what we
// installed) and frees the registry slot + Go-side state.
func UnpublishBlockIO(handle uintptr) error {
	if handle == 0 {
		return ErrBlockIONotPublished
	}
	state, ok := publishedBlockIOs[handle]
	if !ok {
		return ErrBlockIONotPublished
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSUninstallMultipleProtocolInterfaces,
		uint64(handle),
		uint64(uintptr(unsafe.Pointer(&EFIBlockIOProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(state.protocol))),
		0, // NULL terminator
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "UninstallMultipleProtocolInterfaces(BlockIO)"}
	}
	if state.slot >= 0 && state.slot < blockIOPublishRegistrySize {
		blockIOPublishRegistry[state.slot] = blockIOPublishEntry{}
	}
	delete(publishedBlockIOs, handle)
	return nil
}

// ConnectController calls gBS->ConnectController on the given handle
// with no driver-image restrictions, no remaining-device-path, and
// Recursive=TRUE. This drives the EDK2 driver-binding machinery to
// load DiskIoDxe + PartitionDxe + FatDxe against our Block IO handle
// — after which a child handle representing the FAT ESP becomes
// available with EFI_SIMPLE_FILE_SYSTEM_PROTOCOL installed.
//
//	EFI_STATUS ConnectController(IN EFI_HANDLE ControllerHandle,
//	                             IN EFI_HANDLE *DriverImageHandle OPTIONAL,
//	                             IN EFI_DEVICE_PATH *RemainingDevicePath OPTIONAL,
//	                             IN BOOLEAN Recursive);
//
// Reference: UEFI 2.10 §7.3.12 + MdeModulePkg/Core/Dxe/Hand/DriverSupport.c
// CoreConnectController().
func ConnectController(controllerHandle uintptr) error {
	if controllerHandle == 0 {
		return errors.New("uefi: ConnectController called with zero handle")
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSConnectController,
		uint64(controllerHandle),
		0, // no driver-image restrictions
		0, // no remaining device path
		1, // Recursive = TRUE
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "ConnectController"}
	}
	return nil
}
