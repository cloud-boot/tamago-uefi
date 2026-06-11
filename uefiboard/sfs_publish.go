// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_SIMPLE_FILE_SYSTEM_PROTOCOL publish-side
// (Phase 3 sprint 2B — read-only SFS backed by go-filesystems.Filesystem).
//
// What this is: the publish-side companion to the existing
// EFI_BLOCK_IO_PROTOCOL publisher. PublishSFS takes a handle (typically
// the firmware-created partition-child handle whose Block IO descends
// from PublishBlockIO) plus a backing `filesystem.Filesystem` (e.g.
// go-filesystems/ufs.FS) and installs an
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL whose trampolines defer all
// open/read/info calls to the backing Go-side filesystem.
//
// Layout (UEFI 2.10 §13.4, §13.5):
//
//   EFI_SIMPLE_FILE_SYSTEM_PROTOCOL  (this file, "sfs proto")
//     Revision      uint64                 // 0x00010000
//     OpenVolume    fn(this, **EFI_FILE)   // single function pointer
//
//   EFI_FILE_PROTOCOL                (this file, "file proto")
//     Revision      uint64                 // 0x00010000
//     Open          fn(this, **f, name, mode, attr)
//     Close         fn(this)
//     Delete        fn(this)
//     Read          fn(this, *size, buf)
//     Write         fn(this, *size, buf)
//     GetPosition   fn(this, *pos)
//     SetPosition   fn(this, pos)
//     GetInfo       fn(this, *type_guid, *size, buf)
//     SetInfo       fn(this, *type_guid,  size, buf)
//     Flush         fn(this)
//
// All file methods read-only. Write/Delete/SetInfo return EFI_ACCESS_DENIED;
// Flush returns EFI_SUCCESS; everything else is implemented against the
// backing filesystem.Filesystem.
//
// This file is host-buildable (no //go:build tamago) so the helper
// types + GUID round-trips + handler semantics can be unit-tested with
// `go test`. The asm trampoline + InstallProtocolInterface wiring
// lives in sfs_publish_tamago.go + sfs_publish_amd64.s.

package uefiboard

import (
	"errors"

	filesystem "github.com/go-filesystems/interface"
)

// ErrSFSNotPublished is returned by UnpublishSFS when called with a
// zero handle (PublishSFS never called, or already uninstalled).
var ErrSFSNotPublished = errors.New("uefi: SFS handle is zero (not published or already unpublished)")

// ErrSFSRegistryFull is returned by PublishSFS when the fixed-size
// publisher registry has no free slot.
var ErrSFSRegistryFull = errors.New("uefi: PublishSFS registry full (bump sfsPublishRegistrySize)")

// ErrSFSNilFilesystem is returned by PublishSFS when called with a nil
// backing filesystem.
var ErrSFSNilFilesystem = errors.New("uefi: PublishSFS called with nil filesystem")

// ErrSFSHandleRegistryFull is returned by the OpenVolume / Open
// handlers when the per-file-handle registry overflows. Sprint 2B
// caps this generously; loader.efi typically holds one volume root +
// one open file at a time.
var ErrSFSHandleRegistryFull = errors.New("uefi: SFS file-handle registry full (bump sfsFileHandleRegistrySize)")

// EFI_STATUS values used by the SFS + File trampoline handlers. The
// blockIOEFI* constants in block_io_publish.go are the same values;
// we duplicate the names locally so the SFS layer is grep-able as a
// unit.
const (
	sfsEFISuccess           uintptr = 0
	sfsEFILoadError         uintptr = 0x8000000000000001
	sfsEFIInvalidParameter  uintptr = 0x8000000000000002
	sfsEFIUnsupported       uintptr = 0x8000000000000003
	sfsEFIBufferTooSmall    uintptr = 0x8000000000000005
	sfsEFIDeviceError       uintptr = 0x8000000000000007
	sfsEFIWriteProtected    uintptr = 0x8000000000000008
	sfsEFIOutOfResources    uintptr = 0x8000000000000009
	sfsEFINotFound          uintptr = 0x800000000000000E
	sfsEFIAccessDenied      uintptr = 0x800000000000000F
	sfsEFIEndOfFile         uintptr = 0x8000000000000020 // 0x20 == 32
	sfsEFIWarnDeleteFailure uintptr = 0x0000000000000002 // non-error warning
)

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_REVISION (UEFI 2.10 §13.4.1).
const sfsPublishedRevision uint64 = 0x00010000

// EFI_FILE_PROTOCOL_REVISION (UEFI 2.10 §13.5.1).
//
// We publish REVISION (the original — Rev1) since we only implement
// the 10 rev1 methods; OpenEx/ReadEx/WriteEx/FlushEx (Rev2) are NULL.
const sfsFilePublishedRevision uint64 = 0x00010000

// EFI_FILE_INFO_GUID = 09576e92-6d3f-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Guid/FileInfo.h (edk2.git stable/202408).
// Used by EFI_FILE_PROTOCOL.GetInfo to discriminate between
// FileInfo, FileSystemInfo and VolumeLabel queries. Sprint 2B
// supports only FileInfo; the other two return EFI_UNSUPPORTED.
var EFIFileInfoGUID = EFIGUID{
	Data1: 0x09576e92,
	Data2: 0x6d3f,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_FILE attribute bits (UEFI 2.10 §13.5.16).
const (
	sfsFileAttrReadOnly  uint64 = 0x01
	sfsFileAttrHidden    uint64 = 0x02
	sfsFileAttrSystem    uint64 = 0x04
	sfsFileAttrReserved  uint64 = 0x08
	sfsFileAttrDirectory uint64 = 0x10
	sfsFileAttrArchive   uint64 = 0x20
)

// EFI_FILE_MODE bits (UEFI 2.10 §13.5.2) — for EFI_FILE_PROTOCOL.Open.
// We only honour READ; READ|WRITE or READ|WRITE|CREATE return
// EFI_WRITE_PROTECTED.
const (
	sfsFileModeRead   uint64 = 0x0000000000000001
	sfsFileModeWrite  uint64 = 0x0000000000000002
	sfsFileModeCreate uint64 = 0x8000000000000000
)

// SFS_POSITION_END is the magic "seek to end of file" position
// (UEFI 2.10 §13.5.13). SetPosition(0xFFFFFFFFFFFFFFFF) on a regular
// file moves the cursor to FileSize.
const sfsPositionEnd uint64 = 0xFFFFFFFFFFFFFFFF

// sfsPublishRegistrySize bounds how many EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
// instances the asm trampolines can serve concurrently. Sprint 2B's
// FreeBSD MVP publishes exactly one (the UFS root SFS); 4 leaves
// headroom for ports that mount multiple filesystems in one boot.
const sfsPublishRegistrySize = 4

// sfsFileHandleRegistrySize bounds how many open file handles the
// trampolines can serve. The volume root counts as one; loader.efi
// typically opens /boot/loader.conf + /boot/kernel/kernel + the
// directory walk, so 32 is generous.
const sfsFileHandleRegistrySize = 32

// EFISimpleFileSystemProtocolPublished is the publish-side struct that
// firmware reads. Layout MUST match UEFI 2.10 §13.4.1:
//
//	typedef struct _EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
//	    UINT64                                       Revision;
//	    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME  OpenVolume;
//	} EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
type EFISimpleFileSystemProtocolPublished struct {
	Revision   uint64 //  0
	OpenVolume uint64 //  8 — fn ptr to sfs_open_volume_trampoline
}

// EFIFileProtocolPublished is the publish-side EFI_FILE_PROTOCOL
// (UEFI 2.10 §13.5.1). 11 contiguous function-pointer slots after
// Revision:
//
//	typedef struct _EFI_FILE_PROTOCOL {
//	    UINT64               Revision;       //  0
//	    EFI_FILE_OPEN        Open;            //  8
//	    EFI_FILE_CLOSE       Close;           // 16
//	    EFI_FILE_DELETE      Delete;          // 24
//	    EFI_FILE_READ        Read;            // 32
//	    EFI_FILE_WRITE       Write;           // 40
//	    EFI_FILE_GET_POSITION GetPosition;    // 48
//	    EFI_FILE_SET_POSITION SetPosition;    // 56
//	    EFI_FILE_GET_INFO    GetInfo;         // 64
//	    EFI_FILE_SET_INFO    SetInfo;         // 72
//	    EFI_FILE_FLUSH       Flush;           // 80
//	    // Rev2 OpenEx/ReadEx/WriteEx/FlushEx left NULL.
//	} EFI_FILE_PROTOCOL;
type EFIFileProtocolPublished struct {
	Revision    uint64 //  0
	Open        uint64 //  8
	Close       uint64 // 16
	Delete      uint64 // 24
	Read        uint64 // 32
	Write       uint64 // 40
	GetPosition uint64 // 48
	SetPosition uint64 // 56
	GetInfo     uint64 // 64
	SetInfo     uint64 // 72
	Flush       uint64 // 80
}

// sfsPublishEntry is one slot in the SFS publisher registry. A
// non-zero `proto` marks the slot live. Pinned typed references keep
// the EFI_SIMPLE_FILE_SYSTEM_PROTOCOL struct + EFI_FILE_PROTOCOL
// vtable + backing filesystem.Filesystem alive across the indefinite
// firmware-callback window.
type sfsPublishEntry struct {
	proto        uintptr             // address of the EFISimpleFileSystemProtocolPublished struct (== "this")
	rootFileProto uintptr            // address of the volume-root EFIFileProtocolPublished struct
	fs           filesystem.Filesystem
	// pinned references — typed Go-side handles so the GC keeps the
	// underlying allocations alive while firmware retains pointers.
	protoKeepAlive    *EFISimpleFileSystemProtocolPublished
	rootProtoKeepAlive *EFIFileProtocolPublished
}

// sfsFileHandleEntry is one open file/directory. `proto` is the
// "this" address the trampolines see; the rest is the per-handle Go
// state.
type sfsFileHandleEntry struct {
	proto   uintptr           // address of this handle's EFIFileProtocolPublished (== "this")
	owner   uintptr           // proto address of the owning SFS instance (for cross-lookup)
	path    string            // absolute path (always starts with "/")
	isDir   bool              // true for directories
	pos     uint64            // current cursor position
	body    []byte            // cached file contents (lazy-loaded once per handle for regular files)
	bodyErr bool              // true if a previous ReadFile attempt failed (re-tries return DEVICE_ERROR)
	dirents []dirEntryCached  // cached directory entries for directories
	direntI int               // next index to return on Read for directories

	// Pinned reference so the per-handle vtable stays alive while
	// firmware holds the protocol pointer.
	protoKeepAlive *EFIFileProtocolPublished
}

// dirEntryCached caches one directory entry for the iterative Read
// semantics on a directory (UEFI 2.10 §13.5.5 — each Read returns
// one EFI_FILE_INFO struct until empty).
type dirEntryCached struct {
	name    string
	inode   uint64
	isDir   bool
	size    uint64
	mode    uint16
}

// sfsPublishRegistry holds active SFS instances. Linear scan on every
// handler call (sprint 2B only ever has 1 live — the UFS root —
// but the registry keeps the open-coded design uniform with
// blockIOPublishRegistry / loadFileRegistry).
var sfsPublishRegistry [sfsPublishRegistrySize]sfsPublishEntry

// sfsFileHandleRegistry holds open file handles. Each handle is its
// own EFIFileProtocolPublished struct allocated by Open(); the entry
// caches the resolved-and-loaded backing data.
var sfsFileHandleRegistry [sfsFileHandleRegistrySize]sfsFileHandleEntry
