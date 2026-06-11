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
// MdePkg/Include/Uefi/UefiSpec.h (verified against UEFI 2.10 §4.2,
// table 4.2 "EFI Boot Services Table"):
//
//	128 InstallProtocolInterface             (already in rng_protocol.go)
//	264 ConnectController                    <-- new (NOT 304! 304 is ProtocolsPerHandle)
//	272 DisconnectController
//	312 LocateHandleBuffer                   (already in efi_events.go)
//	320 LocateProtocol                       (already in efi_events.go)
//	328 InstallMultipleProtocolInterfaces    (already in initrd_protocol.go)
//	336 UninstallMultipleProtocolInterfaces  (already in initrd_protocol.go)
//
// Sprint 1.1 footnote: the original sprint-1 commit had this at 304
// (i.e. pointing at ProtocolsPerHandle). The off-by-five blew up
// ConnectController with EFI_INVALID_PARAMETER (status 0x8...02)
// because ProtocolsPerHandle's (Handle, ProtocolBuffer**,
// ProtocolBufferCount*) shape doesn't accept our (Handle, NULL, NULL,
// Recursive) args. Live test confirmed; offset corrected here.
const (
	efiBSConnectController    = 264
	efiBSDisconnectController = 272
)

// EFISimpleFileSystemProtocolGUID + EFIBlockIOProtocolPublished are
// defined in block_io_publish.go (host-buildable) so the GUID
// round-trip + struct-offset assertions can run under host `go test`
// without dragging the asm trampoline + InstallProtocolInterface
// closure in.

// blockIOPublishState holds the per-publish backing memory. The
// firmware retains pointers into protocol + media + devicePath for
// the lifetime of the installed handle, so we keep typed Go
// references to keep the GC away.
type blockIOPublishState struct {
	protocol   *EFIBlockIOProtocolPublished
	media      *EFIBlockIOMedia
	body       []byte
	devicePath []byte
	slot       int
	handle     uint64 // firmware-assigned BlockIO controller handle
}

// blockIOPublishMediaGUID is the Vendor-Defined Media Device Path GUID
// we slap onto the synthetic Block IO handle so PartitionDxe's
// driver-binding Supported() callback (which OpenProtocol's
// EFI_DEVICE_PATH_PROTOCOL_GUID) finds something concrete. Any unique
// GUID works — this one was generated randomly and is reserved for
// cloud-boot's synthetic block-IO publish path.
//
//	c10ddb00-7e1a-4001-91b0-070cb1ec80b1
//
// (Chosen specifically so we can fingerprint our own published
// handle by its DevicePath GUID — a quick alternative to the
// parent-prefix walk if a sub-component ever needs to identify
// "is this one of mine?".)
var blockIOPublishMediaGUID = EFIGUID{
	Data1: 0xc10ddb00,
	Data2: 0x7e1a,
	Data3: 0x4001,
	Data4: [8]uint8{0x91, 0xb0, 0x07, 0x0c, 0xb1, 0xec, 0x80, 0xb1},
}

// buildBlockIOPublishDevicePath returns a 24-byte vendor-defined
// media device path + END node, byte-formatted per UEFI 2.10 §10.3.5.3:
//
//	Type    = 0x04 (MEDIA_DEVICE_PATH)
//	SubType = 0x03 (MEDIA_VENDOR_DP)
//	Length  = 0x14 (20 LE)
//	Guid    = blockIOPublishMediaGUID
//	+ END node (4 bytes).
func buildBlockIOPublishDevicePath() []byte {
	out := make([]byte, 0, 24)
	out = append(out, devPathTypeMedia, devPathSubTypeVendor)
	out = append(out, 0x14, 0x00)
	g := blockIOPublishMediaGUID
	out = append(out,
		byte(g.Data1), byte(g.Data1>>8), byte(g.Data1>>16), byte(g.Data1>>24),
		byte(g.Data2), byte(g.Data2>>8),
		byte(g.Data3), byte(g.Data3>>8),
	)
	out = append(out, g.Data4[:]...)
	out = append(out, devPathTypeEnd, devPathSubTypeEndWhole)
	out = append(out, 0x04, 0x00)
	return out
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

// blockIO_*_trampolinePC return the .abi0 entry PC of each trampoline
// directly (via asm `LEAQ ·sym(SB)`), bypassing the Go ABIInternal
// wrapper that taking a function-value would otherwise interpose.
//
// R-fbsd1a (sprint 1.2): the autogen ABIInternal wrapper on amd64 ends
// with `XORPS X15,X15` + `MOVQ FS:0(g),R14` — both clobber MS x64
// callee-saved regs (X15, R14) AFTER our .abi0 epilogue restored them,
// which the firmware-side PartitionDxe driver-binding probe observes as
// register corruption → delayed firmware-side #PF
// (CR2=0xFFFFFFFF98009898 fingerprint pattern). The PC-helper symbols
// resolve to the .abi0 entry directly so firmware lands in our
// XMM-saving prologue and returns through our XMM-restoring epilogue,
// with no wrapper post-process to corrupt state.
func blockIO_reset_trampolinePC() uintptr
func blockIO_read_trampolinePC() uintptr
func blockIO_write_trampolinePC() uintptr
func blockIO_flush_trampolinePC() uintptr

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

	// Sprint 2D' (2026-06-11): use the caller's slice DIRECTLY rather
	// than allocating + copying. The caller (phase2_oci_freebsd_boot)
	// already owns a stable buffer from the streaming pipeline, and
	// the duplicate make+copy doubled transient memory pressure
	// (240 MiB → OOM on TamaGo's 256 MiB heap for 64 MiB images). The
	// bodyKeepAlive registry below holds a typed reference to keep the
	// GC from collecting the caller's slice.
	body := image

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

	// Resolve the 4 asm trampoline entry PCs via the dedicated asm
	// PC-helpers — these return the .abi0 entry PC directly, bypassing
	// the Go ABIInternal wrapper (whose XORPS X15 / MOVQ FS:0,R14
	// trailer would clobber MS x64 callee-saved regs on return to
	// firmware; see R-fbsd1a sprint-1.2 commentary on the asm side).
	resetPC := blockIO_reset_trampolinePC()
	readPC := blockIO_read_trampolinePC()
	writePC := blockIO_write_trampolinePC()
	flushPC := blockIO_flush_trampolinePC()

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

	// Per UEFI 2.10 §7.3.12 + EDK2 PartitionDxe driver-binding
	// (MdeModulePkg/Universal/Disk/PartitionDxe/Partition.c
	// PartitionDriverBindingSupported), the binding requires BOTH
	// EFI_BLOCK_IO_PROTOCOL and EFI_DEVICE_PATH_PROTOCOL on the
	// controller handle. Without the latter ConnectController returns
	// EFI_INVALID_PARAMETER (status 0x80...02). So we install both via
	// InstallMultipleProtocolInterfaces on the same handle.
	devicePath := buildBlockIOPublishDevicePath()
	var handle uint64
	status := efiCall(
		bs+efiBSInstallMultipleProtocolInterfaces,
		uint64(uintptr(unsafe.Pointer(&handle))),
		uint64(uintptr(unsafe.Pointer(&EFIDevicePathProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(&devicePath[0]))),
		uint64(uintptr(unsafe.Pointer(&EFIBlockIOProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(protocol))),
		0, // NULL terminator
	)
	if status != efiSuccess {
		blockIOPublishRegistry[slot] = blockIOPublishEntry{}
		return 0, &EFIError{Status: status, Op: "InstallMultipleProtocolInterfaces(BlockIO+DevicePath)"}
	}

	publishedBlockIOs[uintptr(handle)] = &blockIOPublishState{
		protocol:   protocol,
		media:      media,
		body:       body,
		devicePath: devicePath,
		slot:       slot,
		handle:     handle,
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
	// Mirror PublishBlockIO's install pair order; the firmware
	// matches pointers exactly (UEFI 2.10 §7.3.14).
	status := efiCall(
		bs+efiBSUninstallMultipleProtocolInterfaces,
		uint64(handle),
		uint64(uintptr(unsafe.Pointer(&EFIDevicePathProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(&state.devicePath[0]))),
		uint64(uintptr(unsafe.Pointer(&EFIBlockIOProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(state.protocol))),
		0, // NULL terminator
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "UninstallMultipleProtocolInterfaces(BlockIO+DevicePath)"}
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

// DisconnectController calls gBS->DisconnectController(handle, NULL, NULL)
// to detach ALL drivers from `controllerHandle`. Use this before
// OpenProtocol(PCI_IO) on a virtio device that EDK2 OvmfPkg already
// bound BY_DRIVER (e.g., VirtioGpuDxe holds virtio-gpu); without it our
// OpenProtocol blocks waiting for the firmware driver to release.
// R-doom1a: unblocks DOOM probe's openGPU/openSound/openInput paths.
func DisconnectController(controllerHandle uintptr) error {
	if controllerHandle == 0 {
		return errors.New("uefi: DisconnectController called with zero handle")
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSDisconnectController,
		uint64(controllerHandle),
		0, // DriverImageHandle = NULL → disconnect ALL drivers
		0, // ChildHandle = NULL → no child filter
		0,
		0,
		0,
	)
	// EFI_NOT_FOUND (0x...0e) is acceptable: means no driver was bound
	// to begin with. Surface only the genuinely-bad errors.
	if status != efiSuccess && status != efiNotFound {
		return &EFIError{Status: status, Op: "DisconnectController"}
	}
	return nil
}
