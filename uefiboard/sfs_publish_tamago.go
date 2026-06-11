// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — PublishSFS / UnpublishSFS live wrappers
// (Phase 3 sprint 2B).
//
// What ships:
//   - PublishSFS(handle, fs) installs an EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
//     on the firmware-supplied handle (typically a partition-child
//     handle whose parent Block IO came from PublishBlockIO). The SFS
//     instance + its volume-root EFI_FILE_PROTOCOL vtable are
//     constructed Go-side; the 11 function-pointer slots point at
//     per-arch asm trampolines that bridge MS x64 ABI -> Go ABI0 and
//     defer to ·sfs*Go(SB) handlers in sfs_publish_handlers.go.
//
//   - UnpublishSFS(handle) reverses the install.
//
// Sprint 2B status: amd64 only — the 11 asm trampolines live in
// sfs_publish_amd64.s. arm64/riscv64/loong64 ports inherit the Go
// handlers + struct layouts but currently land on the host-stub path
// (sfs_publish_host.go).

//go:build tamago && amd64

package uefiboard

import (
	"unsafe"

	filesystem "github.com/go-filesystems/interface"
)

// Per-arch asm trampoline symbols. Each one bridges MS x64 ABI into
// Go ABI0 and calls into the matching *Go handler.
func sfs_open_volume_trampoline()
func sfs_file_open_trampoline()
func sfs_file_close_trampoline()
func sfs_file_delete_trampoline()
func sfs_file_read_trampoline()
func sfs_file_write_trampoline()
func sfs_file_getpos_trampoline()
func sfs_file_setpos_trampoline()
func sfs_file_getinfo_trampoline()
func sfs_file_setinfo_trampoline()
func sfs_file_flush_trampoline()

// Per-arch trampoline PC helpers. See R-fbsd1a rationale in
// block_io_publish_amd64.s — these resolve to the .abi0 entry
// directly to bypass the Go ABIInternal wrapper that would otherwise
// trail with XORPS X15,X15 + MOVQ FS:0(g),R14 and clobber MS x64
// callee-saved regs.
func sfs_open_volume_trampolinePC() uintptr
func sfs_file_open_trampolinePC() uintptr
func sfs_file_close_trampolinePC() uintptr
func sfs_file_delete_trampolinePC() uintptr
func sfs_file_read_trampolinePC() uintptr
func sfs_file_write_trampolinePC() uintptr
func sfs_file_getpos_trampolinePC() uintptr
func sfs_file_setpos_trampolinePC() uintptr
func sfs_file_getinfo_trampolinePC() uintptr
func sfs_file_setinfo_trampolinePC() uintptr
func sfs_file_flush_trampolinePC() uintptr

// sfsInitVtable populates the package-level sfsFileVtable PCs once.
// Each fresh per-handle EFIFileProtocolPublished struct copies these
// PCs into its function-pointer slots so all handles share the same
// trampoline targets.
//
// Idempotent: a second call re-writes the same values.
func sfsInitVtable() {
	sfsFileVtable.openPC = uint64(sfs_file_open_trampolinePC())
	sfsFileVtable.closePC = uint64(sfs_file_close_trampolinePC())
	sfsFileVtable.deletePC = uint64(sfs_file_delete_trampolinePC())
	sfsFileVtable.readPC = uint64(sfs_file_read_trampolinePC())
	sfsFileVtable.writePC = uint64(sfs_file_write_trampolinePC())
	sfsFileVtable.getPositionPC = uint64(sfs_file_getpos_trampolinePC())
	sfsFileVtable.setPositionPC = uint64(sfs_file_setpos_trampolinePC())
	sfsFileVtable.getInfoPC = uint64(sfs_file_getinfo_trampolinePC())
	sfsFileVtable.setInfoPC = uint64(sfs_file_setinfo_trampolinePC())
	sfsFileVtable.flushPC = uint64(sfs_file_flush_trampolinePC())
	sfsFileVtable.openVolumePC = uint64(sfs_open_volume_trampolinePC())
}

// publishedSFS tracks active PublishSFS installs so UnpublishSFS can
// find the backing buffers + free the registry slot.
var publishedSFS = map[uintptr]*sfsPublishState{}

// sfsPublishState holds per-publish backing memory + the registry
// slot index for fast cleanup. The firmware retains pointers into
// `proto` and `rootProto` for the lifetime of the install.
type sfsPublishState struct {
	protocol  *EFISimpleFileSystemProtocolPublished
	rootProto *EFIFileProtocolPublished
	slot      int
	handle    uintptr
	fs        filesystem.Filesystem
}

// PublishSFS installs an EFI_SIMPLE_FILE_SYSTEM_PROTOCOL on the given
// firmware handle (typically a partition-child created by
// PartitionDxe), backed by the supplied filesystem.Filesystem. The
// caller must keep `fs` alive — the registry slot holds a typed
// reference (sfsPublishEntry.fs) so the GC won't collect it across
// the indefinite firmware-callback window.
//
// Sprint 2B contract: read-only. All write/delete/setinfo callbacks
// short-circuit to EFI_WRITE_PROTECTED / EFI_ACCESS_DENIED so a
// misbehaving loader can't corrupt the backing image.
func PublishSFS(handle uintptr, fs filesystem.Filesystem) (uintptr, error) {
	if fs == nil {
		return 0, ErrSFSNilFilesystem
	}
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	// Resolve trampoline PCs (idempotent).
	sfsInitVtable()

	// Allocate the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL struct + the
	// volume-root EFI_FILE_PROTOCOL struct. The root handle's "this"
	// pointer is the address of `rootProto` — OpenVolume returns it
	// through *Root so loader.efi calls Open/Read/GetInfo against that
	// pointer.
	rootProto := &EFIFileProtocolPublished{
		Revision:    sfsFilePublishedRevision,
		Open:        sfsFileVtable.openPC,
		Close:       sfsFileVtable.closePC,
		Delete:      sfsFileVtable.deletePC,
		Read:        sfsFileVtable.readPC,
		Write:       sfsFileVtable.writePC,
		GetPosition: sfsFileVtable.getPositionPC,
		SetPosition: sfsFileVtable.setPositionPC,
		GetInfo:     sfsFileVtable.getInfoPC,
		SetInfo:     sfsFileVtable.setInfoPC,
		Flush:       sfsFileVtable.flushPC,
	}
	protocol := &EFISimpleFileSystemProtocolPublished{
		Revision:   sfsPublishedRevision,
		OpenVolume: sfsFileVtable.openVolumePC,
	}

	// Reserve registry slots BEFORE the firmware install so a racing
	// callback sees a fully populated entry.
	slot := -1
	for i := range sfsPublishRegistry {
		if sfsPublishRegistry[i].proto == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0, ErrSFSRegistryFull
	}
	sfsPublishRegistry[slot] = sfsPublishEntry{
		proto:              uintptr(unsafe.Pointer(protocol)),
		rootFileProto:      uintptr(unsafe.Pointer(rootProto)),
		fs:                 fs,
		protoKeepAlive:     protocol,
		rootProtoKeepAlive: rootProto,
	}

	// Reserve a file-handle slot for the volume root.
	rootSlot, ok := sfsAllocFileHandle()
	if !ok {
		sfsPublishRegistry[slot] = sfsPublishEntry{}
		return 0, ErrSFSHandleRegistryFull
	}
	sfsFileHandleRegistry[rootSlot] = sfsFileHandleEntry{
		proto:          uintptr(unsafe.Pointer(rootProto)),
		owner:          uintptr(unsafe.Pointer(protocol)),
		path:           "/",
		isDir:          true,
		protoKeepAlive: rootProto,
	}

	// Install via gBS->InstallProtocolInterface. UEFI 2.10 §7.3.2:
	//
	//   EFI_STATUS InstallProtocolInterface(
	//       IN OUT EFI_HANDLE *Handle,        // NULL on entry → firmware allocates
	//       IN EFI_GUID *Protocol,
	//       IN EFI_INTERFACE_TYPE InterfaceType,
	//       IN VOID *Interface);
	//
	// Sprint 2B: `handle == 0` means "let firmware allocate" — we don't
	// need to attach to a specific partition-child because loader.efi
	// uses LocateHandleBuffer(SFS_GUID) and walks every SFS publisher
	// looking for /boot/kernel. Non-zero `handle` installs SFS on an
	// existing handle (typically the firmware's partition-child).
	hSlot := uint64(handle)
	status := efiCall(
		bs+efiBSInstallProtocolInterface,
		uint64(uintptr(unsafe.Pointer(&hSlot))),
		uint64(uintptr(unsafe.Pointer(&EFISimpleFileSystemProtocolGUID))),
		uint64(efiNativeInterface),
		uint64(uintptr(unsafe.Pointer(protocol))),
		0,
		0,
	)
	if status != efiSuccess {
		sfsPublishRegistry[slot] = sfsPublishEntry{}
		sfsFileHandleRegistry[rootSlot] = sfsFileHandleEntry{}
		return 0, &EFIError{Status: status, Op: "InstallProtocolInterface(SFS)"}
	}
	out := uintptr(hSlot)
	publishedSFS[out] = &sfsPublishState{
		protocol:  protocol,
		rootProto: rootProto,
		slot:      slot,
		handle:    out,
		fs:        fs,
	}
	return out, nil
}

// UnpublishSFS reverses PublishSFS. The handle MUST match what was
// returned by PublishSFS.
func UnpublishSFS(handle uintptr) error {
	if handle == 0 {
		return ErrSFSNotPublished
	}
	state, ok := publishedSFS[handle]
	if !ok {
		return ErrSFSNotPublished
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSUninstallProtocolInterface,
		uint64(handle),
		uint64(uintptr(unsafe.Pointer(&EFISimpleFileSystemProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(state.protocol))),
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "UninstallProtocolInterface(SFS)"}
	}
	if state.slot >= 0 && state.slot < sfsPublishRegistrySize {
		sfsPublishRegistry[state.slot] = sfsPublishEntry{}
	}
	// Free the volume-root file handle + any open handles still
	// owned by this SFS.
	for i := range sfsFileHandleRegistry {
		if sfsFileHandleRegistry[i].owner == uintptr(unsafe.Pointer(state.protocol)) {
			sfsFileHandleRegistry[i] = sfsFileHandleEntry{}
		}
	}
	delete(publishedSFS, handle)
	return nil
}
