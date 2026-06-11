// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — Go-side handlers for the published
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL + EFI_FILE_PROTOCOL callbacks
// (Phase 3 sprint 2B).
//
// 11 entry points, all called by the per-arch asm trampoline after it
// marshals firmware-ABI args into Go-ABI0 positions:
//
//   SFS:    sfsOpenVolumeGo(this, *outRoot) -> EFI_STATUS
//   FILE:   sfsFileOpenGo(this, *outNew, name, mode, attr) -> EFI_STATUS
//           sfsFileCloseGo(this) -> EFI_STATUS
//           sfsFileDeleteGo(this) -> EFI_STATUS
//           sfsFileReadGo(this, *size, buf) -> EFI_STATUS
//           sfsFileWriteGo(this, *size, buf) -> EFI_STATUS
//           sfsFileGetPositionGo(this, *outPos) -> EFI_STATUS
//           sfsFileSetPositionGo(this, pos) -> EFI_STATUS
//           sfsFileGetInfoGo(this, *typeGUID, *size, buf) -> EFI_STATUS
//           sfsFileSetInfoGo(this, *typeGUID, size, buf) -> EFI_STATUS
//           sfsFileFlushGo(this) -> EFI_STATUS
//
// Read/Open semantics derived from UEFI 2.10 §13.5. Sprint 2B is
// read-only, so the four mutation methods (Delete, Write, SetInfo,
// and any Open with WRITE/CREATE) return EFI_ACCESS_DENIED /
// EFI_WRITE_PROTECTED.
//
// Unlike block_io_publish_handlers.go these CANNOT be //go:nosplit:
// resolving paths through the backing filesystem.Filesystem may need
// to allocate (ReadFile / ListDir return Go-managed slices), and
// real-world filesystem drivers iterate maps and call into the heap.
// That's a tradeoff: the firmware-side LoadImage of loader.efi goes
// through gBS->LoadImage (which is a *firmware* call into firmware
// code), and the FREEBSD loader.efi then makes SFS calls into us from
// its own EFI thread — at which point we DO have a Go-runtime stack
// available because StartImage(loader.efi) returns through our
// dispatcher first, so the Go scheduler is still healthy.
//
// Host-buildable: no //go:build tag. The handler semantics are exercised
// from sfs_publish_test.go against a tiny in-memory filesystem.Filesystem
// fixture without touching firmware.

package uefiboard

import (
	"strings"
	"unsafe"

	filesystem "github.com/go-filesystems/interface"
)

// ---------------------------------------------------------------------
// Registry lookups.
// ---------------------------------------------------------------------

// sfsPublishLookup linearly scans sfsPublishRegistry for the slot
// whose `proto` matches `this`.
func sfsPublishLookup(this uintptr) (sfsPublishEntry, int, bool) {
	for i := 0; i < sfsPublishRegistrySize; i++ {
		if sfsPublishRegistry[i].proto == this && sfsPublishRegistry[i].proto != 0 {
			return sfsPublishRegistry[i], i, true
		}
	}
	return sfsPublishEntry{}, -1, false
}

// sfsFileHandleLookup linearly scans sfsFileHandleRegistry.
func sfsFileHandleLookup(this uintptr) (*sfsFileHandleEntry, int, bool) {
	for i := 0; i < sfsFileHandleRegistrySize; i++ {
		if sfsFileHandleRegistry[i].proto == this && sfsFileHandleRegistry[i].proto != 0 {
			return &sfsFileHandleRegistry[i], i, true
		}
	}
	return nil, -1, false
}

// sfsAllocFileHandle reserves a registry slot for a new handle. Caller
// fills `proto` + the other fields and returns the slot index.
func sfsAllocFileHandle() (int, bool) {
	for i := 0; i < sfsFileHandleRegistrySize; i++ {
		if sfsFileHandleRegistry[i].proto == 0 {
			return i, true
		}
	}
	return -1, false
}

// ---------------------------------------------------------------------
// UCS-2 / UTF-16 conversion helpers.
// ---------------------------------------------------------------------

// sfsReadUCS2 reads a NUL-terminated UCS-2 / UTF-16LE string from
// firmware-supplied memory at `p` and returns it as a Go string.
//
// UEFI 2.10 §13.5 file names are CHAR16 (UTF-16LE) terminated by 0.
// Surrogate pairs are not used for typical filesystem paths; we fold
// any high surrogate into '?' rather than risking a misencode.
func sfsReadUCS2(p uintptr) string {
	if p == 0 {
		return ""
	}
	var out []rune
	for i := uintptr(0); i < 65536; i++ {
		w := *(*uint16)(unsafe.Pointer(p + 2*i))
		if w == 0 {
			break
		}
		if w >= 0xD800 && w <= 0xDFFF {
			out = append(out, '?')
			continue
		}
		out = append(out, rune(w))
		// 64 KiB CHAR16 cap (16 KiB rune cap) keeps a malformed input
		// from looping forever; real loader.efi paths are <= 256 chars.
	}
	return string(out)
}

// sfsWriteUCS2 writes Go string `s` as UTF-16LE + NUL into `dst`. Returns
// total bytes written (including the trailing NUL bytes). The caller
// is responsible for ensuring `dst` is large enough — sfsFileInfoSize
// computes the right size for GetInfo.
func sfsWriteUCS2(s string, dst []byte) int {
	off := 0
	for _, r := range s {
		if r > 0xFFFF {
			r = '?'
		}
		if off+2 > len(dst) {
			return off
		}
		dst[off+0] = byte(r)
		dst[off+1] = byte(r >> 8)
		off += 2
	}
	if off+2 <= len(dst) {
		dst[off+0] = 0
		dst[off+1] = 0
		off += 2
	}
	return off
}

// ---------------------------------------------------------------------
// Path joining + normalisation.
// ---------------------------------------------------------------------

// sfsJoinPath resolves UEFI-style `name` (backslash-separated, with
// "..", "." and absolute-vs-relative rules) against the current dir
// `cur`. Result is a clean POSIX-style absolute path (forward slashes,
// no trailing slash except "/").
//
// UEFI 2.10 §13.5.2 rules:
//   - "\" prefix → absolute (rooted at the volume)
//   - "..", ".", embedded "\\" all collapse normally
//   - All separators are backslash.
//
// We accept either backslash or forward slash so loader.efi's
// occasional POSIX-style inputs don't surprise us.
func sfsJoinPath(cur, name string) string {
	// Normalise separators.
	in := strings.ReplaceAll(name, "\\", "/")
	var stack []string
	if strings.HasPrefix(in, "/") {
		stack = nil
	} else {
		// Seed stack from current dir.
		for _, p := range strings.Split(strings.TrimPrefix(cur, "/"), "/") {
			if p != "" {
				stack = append(stack, p)
			}
		}
	}
	for _, p := range strings.Split(in, "/") {
		switch p {
		case "", ".":
			continue
		case "..":
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, p)
		}
	}
	if len(stack) == 0 {
		return "/"
	}
	return "/" + strings.Join(stack, "/")
}

// sfsBaseName returns the trailing component of an SFS path. "/" maps
// to an empty name (volume root has no filename to report).
func sfsBaseName(path string) string {
	if path == "" || path == "/" {
		return ""
	}
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

// ---------------------------------------------------------------------
// Backing-filesystem helpers.
// ---------------------------------------------------------------------

// sfsLoadDirents resolves `path` against `fs` and caches its dirents
// in the slot. Returns ok=false if the path can't be listed.
func sfsLoadDirents(slot *sfsFileHandleEntry, fs filesystem.Filesystem, path string) bool {
	entries, err := fs.ListDir(path)
	if err != nil {
		return false
	}
	cached := make([]dirEntryCached, 0, len(entries))
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			// UEFI 2.10 §13.5.5 — directory iteration explicitly
			// excludes "." and ".." entries.
			continue
		}
		full := sfsJoinPath(path, name)
		isDir := false
		var size uint64
		var mode uint16
		if st, err := fs.Stat(full); err == nil {
			mode = st.Mode()
			size = st.Size()
			isDir = (mode & 0xF000) == 0x4000
		} else {
			// Fall back to dirent file-type byte when stat fails (mostly
			// won't happen on UFS but be lenient).
			isDir = e.FileType() == 4 // DT_DIR
		}
		cached = append(cached, dirEntryCached{
			name:  name,
			inode: e.Inode(),
			isDir: isDir,
			size:  size,
			mode:  mode,
		})
	}
	slot.dirents = cached
	slot.direntI = 0
	return true
}

// ---------------------------------------------------------------------
// EFI_FILE_INFO marshalling.
// ---------------------------------------------------------------------

// sfsFileInfoHeaderSize is the byte size of the fixed prefix of
// EFI_FILE_INFO (everything up to and including the FileName flexible
// array's zeroth char). UEFI 2.10 §13.5.16:
//
//   UINT64 Size              //  0
//   UINT64 FileSize          //  8
//   UINT64 PhysicalSize      // 16
//   EFI_TIME CreateTime      // 24 (16 bytes)
//   EFI_TIME LastAccessTime  // 40
//   EFI_TIME ModificationTime// 56
//   UINT64 Attribute         // 72
//   CHAR16 FileName[]        // 80
//
// → 80 bytes header + (len(name)+1)*2 CHAR16 trailer.
const sfsFileInfoHeaderSize = 80

// sfsFileInfoSizeForName returns the total size in bytes of an
// EFI_FILE_INFO carrying the given FileName.
func sfsFileInfoSizeForName(name string) uint64 {
	return uint64(sfsFileInfoHeaderSize) + 2*uint64(len([]rune(name))+1)
}

// sfsWriteFileInfo marshals an EFI_FILE_INFO into `dst`. Returns true
// on success (dst large enough) and the bytes written.
func sfsWriteFileInfo(dst []byte, name string, size uint64, attr uint64) (uint64, bool) {
	total := sfsFileInfoSizeForName(name)
	if uint64(len(dst)) < total {
		return total, false
	}
	// Zero the whole region first so the EFI_TIME structs are well-defined.
	for i := uint64(0); i < total; i++ {
		dst[i] = 0
	}
	putU64 := func(off uint64, v uint64) {
		dst[off+0] = byte(v)
		dst[off+1] = byte(v >> 8)
		dst[off+2] = byte(v >> 16)
		dst[off+3] = byte(v >> 24)
		dst[off+4] = byte(v >> 32)
		dst[off+5] = byte(v >> 40)
		dst[off+6] = byte(v >> 48)
		dst[off+7] = byte(v >> 56)
	}
	putU64(0, total)
	putU64(8, size)
	putU64(16, size)
	// EFI_TIME slots stay zero (CreateTime / LastAccessTime / ModificationTime).
	putU64(72, attr)
	sfsWriteUCS2(name, dst[sfsFileInfoHeaderSize:total])
	return total, true
}

// ---------------------------------------------------------------------
// SFS protocol entry point.
// ---------------------------------------------------------------------

// sfsOpenVolumeGo handles EFI_SIMPLE_FILE_SYSTEM_PROTOCOL.OpenVolume
// (UEFI 2.10 §13.4.2):
//
//   EFI_STATUS OpenVolume(IN  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *This,
//                         OUT EFI_FILE_PROTOCOL              **Root);
//
// Behaviour: the SFS instance has a pre-allocated "root" EFI_FILE
// vtable struct (built at PublishSFS time, path="/", isDir=true).
// OpenVolume just returns its pointer through *Root.
func sfsOpenVolumeGo(this uintptr, outRoot uintptr) uintptr {
	ent, _, ok := sfsPublishLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	if outRoot == 0 {
		return sfsEFIInvalidParameter
	}
	*(*uintptr)(unsafe.Pointer(outRoot)) = ent.rootFileProto
	return sfsEFISuccess
}

// ---------------------------------------------------------------------
// EFI_FILE_PROTOCOL methods.
// ---------------------------------------------------------------------

// sfsFileOpenGo handles EFI_FILE_PROTOCOL.Open (UEFI 2.10 §13.5.2).
//
//   EFI_STATUS Open(IN  EFI_FILE_PROTOCOL *This,
//                   OUT EFI_FILE_PROTOCOL **NewHandle,
//                   IN  CHAR16            *FileName,
//                   IN  UINT64             OpenMode,
//                   IN  UINT64             Attributes);
func sfsFileOpenGo(this uintptr, outNew uintptr, fileName uintptr, openMode uintptr, attributes uintptr) uintptr {
	parent, _, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	// Find the owning SFS instance.
	owner, _, ok := sfsPublishLookup(parent.owner)
	if !ok {
		return sfsEFINotFound
	}
	if outNew == 0 {
		return sfsEFIInvalidParameter
	}
	mode := uint64(openMode)
	// Sprint 2B: read-only. Any write/create bit is rejected before we
	// even resolve the path.
	if (mode & sfsFileModeWrite) != 0 || (mode & sfsFileModeCreate) != 0 {
		return sfsEFIWriteProtected
	}
	if (mode & sfsFileModeRead) == 0 {
		return sfsEFIInvalidParameter
	}
	name := sfsReadUCS2(fileName)
	if name == "" {
		return sfsEFIInvalidParameter
	}
	// Resolve relative to parent's path (which is "/" for the root).
	full := sfsJoinPath(parent.path, name)

	// Stat to learn whether this is a file or a directory. If the path
	// doesn't exist, EFI_NOT_FOUND.
	st, err := owner.fs.Stat(full)
	if err != nil {
		return sfsEFINotFound
	}
	isDir := (st.Mode() & 0xF000) == 0x4000

	// Allocate a new handle.
	slot, ok := sfsAllocFileHandle()
	if !ok {
		return sfsEFIOutOfResources
	}
	proto := &EFIFileProtocolPublished{
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
	sfsFileHandleRegistry[slot] = sfsFileHandleEntry{
		proto:          uintptr(unsafe.Pointer(proto)),
		owner:          parent.owner,
		path:           full,
		isDir:          isDir,
		pos:            0,
		protoKeepAlive: proto,
	}
	*(*uintptr)(unsafe.Pointer(outNew)) = uintptr(unsafe.Pointer(proto))
	_ = st // silence unused-warning when isDir doesn't read size
	return sfsEFISuccess
}

// sfsFileCloseGo handles EFI_FILE_PROTOCOL.Close (UEFI 2.10 §13.5.3).
// Always returns EFI_SUCCESS per spec.
func sfsFileCloseGo(this uintptr) uintptr {
	slot, idx, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFISuccess // spec: Close always succeeds
	}
	// Don't allow closing the volume root — OpenVolume's pointer must
	// stay live across loader.efi's reads. Detect by matching `proto`
	// against the owning SFS instance's rootFileProto.
	owner, _, _ := sfsPublishLookup(slot.owner)
	if owner.rootFileProto != 0 && slot.proto == owner.rootFileProto {
		return sfsEFISuccess
	}
	sfsFileHandleRegistry[idx] = sfsFileHandleEntry{}
	return sfsEFISuccess
}

// sfsFileDeleteGo handles EFI_FILE_PROTOCOL.Delete (UEFI 2.10 §13.5.4).
// Read-only filesystem: spec-mandated EFI_WARN_DELETE_FAILURE response.
func sfsFileDeleteGo(this uintptr) uintptr {
	if _, _, ok := sfsFileHandleLookup(this); !ok {
		return sfsEFINotFound
	}
	// Per UEFI 2.10 §13.5.4: a Delete on a read-only handle returns
	// EFI_WARN_DELETE_FAILURE (a *warning*, low bit clear) AND the
	// handle is closed. We follow suit.
	sfsFileCloseGo(this)
	return sfsEFIWarnDeleteFailure
}

// sfsFileReadGo handles EFI_FILE_PROTOCOL.Read (UEFI 2.10 §13.5.5).
//
//   EFI_STATUS Read(IN     EFI_FILE_PROTOCOL *This,
//                   IN OUT UINTN             *BufferSize,
//                   OUT    VOID              *Buffer);
//
// For a regular file: lazy-load the backing bytes once (cached on the
// handle), then copy min(remaining, *bufferSize) bytes from current
// position. Advance position. Set *bufferSize to bytes actually read.
//
// For a directory: each call returns the NEXT directory entry as an
// EFI_FILE_INFO. *bufferSize on entry is the caller's buffer capacity;
// on return it's the bytes consumed (== 0 once iteration exhausted).
func sfsFileReadGo(this uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	slot, _, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	if bufferSize == 0 {
		return sfsEFIInvalidParameter
	}
	owner, _, ok := sfsPublishLookup(slot.owner)
	if !ok {
		return sfsEFINotFound
	}
	bs := *(*uint64)(unsafe.Pointer(bufferSize))
	if slot.isDir {
		// Lazy-load dirents the first time Read hits.
		if slot.dirents == nil {
			if !sfsLoadDirents(slot, owner.fs, slot.path) {
				return sfsEFIDeviceError
			}
		}
		if slot.direntI >= len(slot.dirents) {
			// End of directory: per spec set *BufferSize = 0 and return
			// EFI_SUCCESS.
			*(*uint64)(unsafe.Pointer(bufferSize)) = 0
			return sfsEFISuccess
		}
		e := slot.dirents[slot.direntI]
		var attr uint64 = sfsFileAttrReadOnly
		if e.isDir {
			attr |= sfsFileAttrDirectory
		}
		need := sfsFileInfoSizeForName(e.name)
		if bs < need {
			*(*uint64)(unsafe.Pointer(bufferSize)) = need
			return sfsEFIBufferTooSmall
		}
		if buffer == 0 {
			return sfsEFIInvalidParameter
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(need))
		written, ok := sfsWriteFileInfo(dst, e.name, e.size, attr)
		if !ok {
			return sfsEFIDeviceError
		}
		*(*uint64)(unsafe.Pointer(bufferSize)) = written
		slot.direntI++
		return sfsEFISuccess
	}
	// Regular file path: lazy-load body once.
	if slot.body == nil && !slot.bodyErr {
		body, err := owner.fs.ReadFile(slot.path)
		if err != nil {
			slot.bodyErr = true
			return sfsEFIDeviceError
		}
		slot.body = body
	}
	if slot.bodyErr {
		return sfsEFIDeviceError
	}
	remaining := uint64(0)
	if slot.pos < uint64(len(slot.body)) {
		remaining = uint64(len(slot.body)) - slot.pos
	}
	want := bs
	if want > remaining {
		want = remaining
	}
	if want == 0 {
		*(*uint64)(unsafe.Pointer(bufferSize)) = 0
		return sfsEFISuccess
	}
	if buffer == 0 {
		return sfsEFIInvalidParameter
	}
	src := slot.body[slot.pos : slot.pos+want]
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(want))
	copy(dst, src)
	slot.pos += want
	*(*uint64)(unsafe.Pointer(bufferSize)) = want
	return sfsEFISuccess
}

// sfsFileWriteGo handles EFI_FILE_PROTOCOL.Write (UEFI 2.10 §13.5.6).
// Read-only: always EFI_WRITE_PROTECTED (more specific than ACCESS_DENIED
// since loader.efi may use the bit to fall back gracefully).
func sfsFileWriteGo(this uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	if _, _, ok := sfsFileHandleLookup(this); !ok {
		return sfsEFINotFound
	}
	return sfsEFIWriteProtected
}

// sfsFileGetPositionGo handles EFI_FILE_PROTOCOL.GetPosition
// (UEFI 2.10 §13.5.11). Directories return EFI_UNSUPPORTED.
func sfsFileGetPositionGo(this uintptr, outPos uintptr) uintptr {
	slot, _, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	if slot.isDir {
		return sfsEFIUnsupported
	}
	if outPos == 0 {
		return sfsEFIInvalidParameter
	}
	*(*uint64)(unsafe.Pointer(outPos)) = slot.pos
	return sfsEFISuccess
}

// sfsFileSetPositionGo handles EFI_FILE_PROTOCOL.SetPosition
// (UEFI 2.10 §13.5.13). For files: SetPosition(0xFF..FF) means seek
// to EOF; otherwise set to `pos`. For directories: only SetPosition(0)
// (rewind) is supported.
func sfsFileSetPositionGo(this uintptr, pos uintptr) uintptr {
	slot, _, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	if slot.isDir {
		if uint64(pos) != 0 {
			return sfsEFIUnsupported
		}
		slot.direntI = 0
		return sfsEFISuccess
	}
	owner, _, ok := sfsPublishLookup(slot.owner)
	if !ok {
		return sfsEFINotFound
	}
	if uint64(pos) == sfsPositionEnd {
		// Resolve EOF lazily; on success we know the body size.
		if slot.body == nil && !slot.bodyErr {
			body, err := owner.fs.ReadFile(slot.path)
			if err != nil {
				slot.bodyErr = true
				return sfsEFIDeviceError
			}
			slot.body = body
		}
		if slot.bodyErr {
			return sfsEFIDeviceError
		}
		slot.pos = uint64(len(slot.body))
		return sfsEFISuccess
	}
	slot.pos = uint64(pos)
	return sfsEFISuccess
}

// sfsFileGetInfoGo handles EFI_FILE_PROTOCOL.GetInfo (UEFI 2.10 §13.5.15).
//
// We support only EFI_FILE_INFO_GUID; everything else returns
// EFI_UNSUPPORTED (sprint 2B doesn't expose volume labels or
// filesystem-info beyond the read-only flag).
func sfsFileGetInfoGo(this uintptr, typeGUID uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	slot, _, ok := sfsFileHandleLookup(this)
	if !ok {
		return sfsEFINotFound
	}
	if typeGUID == 0 || bufferSize == 0 {
		return sfsEFIInvalidParameter
	}
	// Compare the requested GUID against EFIFileInfoGUID. We compare
	// the 16 raw bytes directly so the host-side test can craft GUID
	// buffers without going through unsafe.Sizeof gymnastics.
	g := *(*EFIGUID)(unsafe.Pointer(typeGUID))
	if g != EFIFileInfoGUID {
		return sfsEFIUnsupported
	}
	owner, _, ok := sfsPublishLookup(slot.owner)
	if !ok {
		return sfsEFINotFound
	}
	// File metadata.
	name := sfsBaseName(slot.path)
	if name == "" {
		// The volume root reports an empty filename per UEFI 2.10
		// §13.5.16 (the root has no filename).
		name = ""
	}
	var size uint64
	var attr uint64 = sfsFileAttrReadOnly
	if slot.isDir {
		attr |= sfsFileAttrDirectory
	} else {
		// Stat once to learn the size — cheaper than ReadFile.
		if st, err := owner.fs.Stat(slot.path); err == nil {
			size = st.Size()
		} else if slot.body != nil {
			size = uint64(len(slot.body))
		}
	}
	need := sfsFileInfoSizeForName(name)
	have := *(*uint64)(unsafe.Pointer(bufferSize))
	if have < need {
		*(*uint64)(unsafe.Pointer(bufferSize)) = need
		return sfsEFIBufferTooSmall
	}
	if buffer == 0 {
		return sfsEFIInvalidParameter
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(buffer)), int(need))
	written, ok := sfsWriteFileInfo(dst, name, size, attr)
	if !ok {
		return sfsEFIDeviceError
	}
	*(*uint64)(unsafe.Pointer(bufferSize)) = written
	return sfsEFISuccess
}

// sfsFileSetInfoGo handles EFI_FILE_PROTOCOL.SetInfo (UEFI 2.10 §13.5.17).
// Read-only.
func sfsFileSetInfoGo(this uintptr, typeGUID uintptr, bufferSize uintptr, buffer uintptr) uintptr {
	if _, _, ok := sfsFileHandleLookup(this); !ok {
		return sfsEFINotFound
	}
	return sfsEFIWriteProtected
}

// sfsFileFlushGo handles EFI_FILE_PROTOCOL.Flush (UEFI 2.10 §13.5.18).
// No-op success for read-only filesystems.
func sfsFileFlushGo(this uintptr) uintptr {
	if _, _, ok := sfsFileHandleLookup(this); !ok {
		return sfsEFINotFound
	}
	return sfsEFISuccess
}

// ---------------------------------------------------------------------
// Per-arch trampoline PC table (populated by sfs_publish_<arch>.s on
// tamago builds; left zero on host so tests use the Go handlers
// directly via the *Go entry points).
// ---------------------------------------------------------------------

// sfsFileVtable holds the trampoline entry-point PCs that get patched
// into every fresh EFIFileProtocolPublished struct. On tamago this is
// populated by sfsInstallVtable() in sfs_publish_tamago.go; on host it
// stays zero and the unit tests call the *Go handlers directly.
var sfsFileVtable struct {
	openPC        uint64
	closePC       uint64
	deletePC      uint64
	readPC        uint64
	writePC       uint64
	getPositionPC uint64
	setPositionPC uint64
	getInfoPC     uint64
	setInfoPC     uint64
	flushPC       uint64
	openVolumePC  uint64
}
