// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side tests for the publisher-side EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
// + EFI_FILE_PROTOCOL surface (Phase 3 sprint 2B).
//
// The 11 Go handlers (sfsOpenVolumeGo, sfsFile*Go) are host-buildable
// so we exercise them directly against:
//
//   1. A tiny in-memory filesystem.Filesystem fixture (no UFS image
//      needed for protocol semantics).
//   2. Hand-crafted registry entries to simulate a live install.
//
// The asm trampolines + InstallProtocolInterface wiring are not
// host-buildable — those land in the live test.

package uefiboard

import (
	"errors"
	"os"
	"testing"
	"time"
	"unsafe"

	filesystem "github.com/go-filesystems/interface"
)

// ---------------------------------------------------------------------
// Fake filesystem fixture.
// ---------------------------------------------------------------------

// fakeFS is a tiny filesystem.Filesystem implementation used purely for
// the SFS protocol tests. Files are keyed by absolute path; directories
// are inferred from their contents.
type fakeFS struct {
	files map[string][]byte
	dirs  map[string][]string // dir path -> child names
}

func newFakeFS() *fakeFS {
	return &fakeFS{files: map[string][]byte{}, dirs: map[string][]string{}}
}

func (f *fakeFS) addFile(path string, body []byte) {
	f.files[path] = body
	// Wire up parent dir listing.
	dir, name := splitDirBase(path)
	f.dirs[dir] = append(f.dirs[dir], name)
}

func (f *fakeFS) addDir(path string) {
	if _, ok := f.dirs[path]; !ok {
		f.dirs[path] = nil
	}
	if path == "/" {
		return
	}
	dir, name := splitDirBase(path)
	// Only add to parent listing once.
	for _, e := range f.dirs[dir] {
		if e == name {
			return
		}
	}
	f.dirs[dir] = append(f.dirs[dir], name)
}

func splitDirBase(path string) (string, string) {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/", path[1:]
			}
			return path[:i], path[i+1:]
		}
	}
	return "/", path
}

func (f *fakeFS) Close() error { return nil }

func (f *fakeFS) ReadFile(path string) ([]byte, error) {
	b, ok := f.files[path]
	if !ok {
		return nil, errors.New("not found: " + path)
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

func (f *fakeFS) ListDir(path string) ([]filesystem.DirEntry, error) {
	entries, ok := f.dirs[path]
	if !ok {
		return nil, errors.New("not a dir: " + path)
	}
	out := make([]filesystem.DirEntry, 0, len(entries))
	for _, name := range entries {
		full := joinTestPath(path, name)
		var ft uint8 = 8 // DT_REG
		if _, isDir := f.dirs[full]; isDir {
			ft = 4 // DT_DIR
		}
		out = append(out, filesystem.NewDirEntry(0, name, ft))
	}
	return out, nil
}

func (f *fakeFS) Stat(path string) (filesystem.Stat, error) {
	if b, ok := f.files[path]; ok {
		return filesystem.NewStat(0x8180 /* regular file 0o600 */, uint64(len(b)), 0), nil
	}
	if _, ok := f.dirs[path]; ok {
		return filesystem.NewStat(0x41ED /* dir 0o755 */, 0, 0), nil
	}
	return nil, errors.New("stat: not found: " + path)
}

func (f *fakeFS) ReadLink(path string) (string, error) { return "", errors.New("no links") }
func (f *fakeFS) WriteFile(path string, data []byte, perm os.FileMode) error {
	return errors.New("read-only")
}
func (f *fakeFS) MkDir(path string, perm os.FileMode) error { return errors.New("read-only") }
func (f *fakeFS) DeleteFile(path string) error             { return errors.New("read-only") }
func (f *fakeFS) DeleteDir(path string) error              { return errors.New("read-only") }
func (f *fakeFS) Rename(o, n string) error                 { return errors.New("read-only") }

func joinTestPath(dir, name string) string {
	if dir == "/" {
		return "/" + name
	}
	return dir + "/" + name
}

// avoid unused-import warning if the test set shrinks.
var _ = time.Time{}

// ---------------------------------------------------------------------
// GUID + constant pinning.
// ---------------------------------------------------------------------

func TestEFIFileInfoGUID_RoundTrip(t *testing.T) {
	expect := guidFromText(t, "09576e92-6d3f-11d2-8e39-00a0c969723b")
	if EFIFileInfoGUID != expect {
		t.Fatalf("EFIFileInfoGUID mismatch:\n got    = %+v\n expect = %+v", EFIFileInfoGUID, expect)
	}
}

func TestSFSPublishedRevisionConstants(t *testing.T) {
	if sfsPublishedRevision != 0x00010000 {
		t.Errorf("sfsPublishedRevision = 0x%08x, want 0x00010000", sfsPublishedRevision)
	}
	if sfsFilePublishedRevision != 0x00010000 {
		t.Errorf("sfsFilePublishedRevision = 0x%08x, want 0x00010000", sfsFilePublishedRevision)
	}
}

// ---------------------------------------------------------------------
// Path joiner.
// ---------------------------------------------------------------------

func TestSFSJoinPath(t *testing.T) {
	cases := []struct {
		cur, name, want string
	}{
		{"/", "boot", "/boot"},
		{"/boot", "kernel", "/boot/kernel"},
		{"/boot/kernel", "..", "/boot"},
		{"/boot/kernel", "/etc/passwd", "/etc/passwd"},
		{"/boot", "\\EFI\\BOOT\\BOOTX64.EFI", "/EFI/BOOT/BOOTX64.EFI"},
		{"/boot", ".", "/boot"},
		{"/", "..", "/"},
		{"/boot", "kernel/..", "/boot"},
	}
	for _, c := range cases {
		got := sfsJoinPath(c.cur, c.name)
		if got != c.want {
			t.Errorf("sfsJoinPath(%q, %q) = %q, want %q", c.cur, c.name, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------
// UCS-2 round trip.
// ---------------------------------------------------------------------

func TestSFSReadUCS2_RoundTrip(t *testing.T) {
	src := "boot\\kernel"
	// Encode to UCS-2 + NUL.
	buf := make([]byte, 2*(len(src)+1))
	off := 0
	for _, r := range src {
		buf[off+0] = byte(r)
		buf[off+1] = byte(r >> 8)
		off += 2
	}
	got := sfsReadUCS2(uintptr(unsafe.Pointer(&buf[0])))
	if got != src {
		t.Errorf("sfsReadUCS2 = %q, want %q", got, src)
	}
}

func TestSFSReadUCS2_Nil(t *testing.T) {
	if got := sfsReadUCS2(0); got != "" {
		t.Errorf("sfsReadUCS2(0) = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------
// EFI_FILE_INFO marshalling.
// ---------------------------------------------------------------------

func TestSFSFileInfoSizeAndWrite(t *testing.T) {
	name := "kernel"
	need := sfsFileInfoSizeForName(name)
	// Header(80) + (6+1)*2 = 80 + 14 = 94.
	if need != 94 {
		t.Errorf("sfsFileInfoSizeForName(%q) = %d, want 94", name, need)
	}
	dst := make([]byte, need)
	written, ok := sfsWriteFileInfo(dst, name, 4096, sfsFileAttrReadOnly)
	if !ok {
		t.Fatal("sfsWriteFileInfo returned ok=false")
	}
	if written != need {
		t.Errorf("written = %d, want %d", written, need)
	}
	// Size at offset 0 == total.
	if got := readU64(dst, 0); got != need {
		t.Errorf("Size = %d, want %d", got, need)
	}
	if got := readU64(dst, 8); got != 4096 {
		t.Errorf("FileSize = %d, want 4096", got)
	}
	if got := readU64(dst, 72); got != sfsFileAttrReadOnly {
		t.Errorf("Attribute = 0x%x, want 0x%x", got, sfsFileAttrReadOnly)
	}
}

func TestSFSWriteFileInfo_BufferTooSmall(t *testing.T) {
	dst := make([]byte, 8)
	_, ok := sfsWriteFileInfo(dst, "kernel", 0, 0)
	if ok {
		t.Error("sfsWriteFileInfo(small buf) ok=true; want false")
	}
}

func readU64(b []byte, off int) uint64 {
	return uint64(b[off]) | uint64(b[off+1])<<8 | uint64(b[off+2])<<16 | uint64(b[off+3])<<24 |
		uint64(b[off+4])<<32 | uint64(b[off+5])<<40 | uint64(b[off+6])<<48 | uint64(b[off+7])<<56
}

// ---------------------------------------------------------------------
// Handler tests against a hand-crafted SFS + root handle.
// ---------------------------------------------------------------------

// installSFSTestEntry crafts an SFS publish entry + a volume-root
// file handle entry, and returns the "this" addresses for each.
// t.Cleanup restores both registries.
func installSFSTestEntry(t *testing.T, fs filesystem.Filesystem) (sfsThis uintptr, rootThis uintptr) {
	t.Helper()
	// Use real Go-allocated structs so unsafe.Pointer round-trips work.
	proto := &EFISimpleFileSystemProtocolPublished{Revision: sfsPublishedRevision}
	rootProto := &EFIFileProtocolPublished{Revision: sfsFilePublishedRevision}

	sfsSlot := -1
	for i := range sfsPublishRegistry {
		if sfsPublishRegistry[i].proto == 0 {
			sfsSlot = i
			break
		}
	}
	if sfsSlot < 0 {
		t.Fatal("sfsPublishRegistry full")
	}
	sfsPublishRegistry[sfsSlot] = sfsPublishEntry{
		proto:              uintptr(unsafe.Pointer(proto)),
		rootFileProto:      uintptr(unsafe.Pointer(rootProto)),
		fs:                 fs,
		protoKeepAlive:     proto,
		rootProtoKeepAlive: rootProto,
	}
	rootSlot, ok := sfsAllocFileHandle()
	if !ok {
		t.Fatal("sfsFileHandleRegistry full")
	}
	sfsFileHandleRegistry[rootSlot] = sfsFileHandleEntry{
		proto:          uintptr(unsafe.Pointer(rootProto)),
		owner:          uintptr(unsafe.Pointer(proto)),
		path:           "/",
		isDir:          true,
		protoKeepAlive: rootProto,
	}
	t.Cleanup(func() {
		sfsPublishRegistry[sfsSlot] = sfsPublishEntry{}
		// Clear any handle owned by this SFS instance (Open may have
		// allocated more).
		for i := range sfsFileHandleRegistry {
			if sfsFileHandleRegistry[i].owner == uintptr(unsafe.Pointer(proto)) {
				sfsFileHandleRegistry[i] = sfsFileHandleEntry{}
			}
		}
	})
	return uintptr(unsafe.Pointer(proto)), uintptr(unsafe.Pointer(rootProto))
}

func TestSFSOpenVolume(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	sfsThis, rootThis := installSFSTestEntry(t, fs)
	var outRoot uintptr
	if got := sfsOpenVolumeGo(sfsThis, uintptr(unsafe.Pointer(&outRoot))); got != sfsEFISuccess {
		t.Fatalf("OpenVolume = 0x%x, want SUCCESS", got)
	}
	if outRoot != rootThis {
		t.Errorf("OpenVolume *Root = 0x%x, want 0x%x", outRoot, rootThis)
	}
}

func TestSFSOpenVolume_Unknown(t *testing.T) {
	var outRoot uintptr
	if got := sfsOpenVolumeGo(0xDEAD, uintptr(unsafe.Pointer(&outRoot))); got != sfsEFINotFound {
		t.Errorf("OpenVolume(unknown) = 0x%x, want NOT_FOUND", got)
	}
}

func TestSFSFileOpen_FileRead(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	fs.addDir("/boot")
	body := []byte("Hello, FreeBSD!\n")
	fs.addFile("/boot/loader.conf", body)
	_, rootThis := installSFSTestEntry(t, fs)

	// Open(\boot\loader.conf, READ)
	name := encodeUCS2("\\boot\\loader.conf")
	var fh uintptr
	rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead), 0)
	if rc != sfsEFISuccess {
		t.Fatalf("Open = 0x%x", rc)
	}
	if fh == 0 {
		t.Fatal("Open returned NULL handle")
	}

	// Read in 8-byte chunks.
	buf := make([]byte, 8)
	var sz uint64 = uint64(len(buf))
	rc = sfsFileReadGo(fh, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFISuccess {
		t.Fatalf("Read = 0x%x", rc)
	}
	if sz != 8 {
		t.Fatalf("first Read size = %d, want 8", sz)
	}
	if string(buf) != "Hello, F" {
		t.Errorf("first Read = %q, want %q", string(buf), "Hello, F")
	}

	// Second read consumes the rest.
	sz = uint64(len(buf))
	rc = sfsFileReadGo(fh, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFISuccess {
		t.Fatalf("second Read = 0x%x", rc)
	}
	if sz != 8 {
		t.Fatalf("second Read size = %d, want 8", sz)
	}
	if string(buf) != "reeBSD!\n" {
		t.Errorf("second Read = %q, want %q", string(buf), "reeBSD!\n")
	}

	// Third read -> EOF.
	sz = uint64(len(buf))
	rc = sfsFileReadGo(fh, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFISuccess || sz != 0 {
		t.Errorf("EOF Read rc=0x%x size=%d, want SUCCESS size=0", rc, sz)
	}

	// Close.
	if rc := sfsFileCloseGo(fh); rc != sfsEFISuccess {
		t.Errorf("Close = 0x%x", rc)
	}
}

func TestSFSFileOpen_NotFound(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	name := encodeUCS2("\\does\\not\\exist")
	var fh uintptr
	rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead), 0)
	if rc != sfsEFINotFound {
		t.Errorf("Open(missing) = 0x%x, want NOT_FOUND", rc)
	}
}

func TestSFSFileOpen_WriteRejected(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	name := encodeUCS2("\\foo")
	var fh uintptr
	rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead|sfsFileModeWrite), 0)
	if rc != sfsEFIWriteProtected {
		t.Errorf("Open(WRITE) = 0x%x, want WRITE_PROTECTED", rc)
	}
}

func TestSFSFileWrite_AlwaysProtected(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	var sz uint64 = 4
	buf := []byte("test")
	rc := sfsFileWriteGo(rootThis, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFIWriteProtected {
		t.Errorf("Write = 0x%x, want WRITE_PROTECTED", rc)
	}
}

func TestSFSFileSetInfo_AlwaysProtected(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	g := EFIFileInfoGUID
	rc := sfsFileSetInfoGo(rootThis, uintptr(unsafe.Pointer(&g)), 0, 0)
	if rc != sfsEFIWriteProtected {
		t.Errorf("SetInfo = 0x%x, want WRITE_PROTECTED", rc)
	}
}

func TestSFSFileDelete_WarnDeleteFailure(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	rc := sfsFileDeleteGo(rootThis)
	if rc != sfsEFIWarnDeleteFailure {
		t.Errorf("Delete = 0x%x, want WARN_DELETE_FAILURE (0x%x)", rc, sfsEFIWarnDeleteFailure)
	}
}

func TestSFSFileFlush_Success(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	if rc := sfsFileFlushGo(rootThis); rc != sfsEFISuccess {
		t.Errorf("Flush = 0x%x, want SUCCESS", rc)
	}
}

func TestSFSFileSetGetPosition(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	fs.addFile("/boot/loader.conf", []byte("12345"))
	_, rootThis := installSFSTestEntry(t, fs)
	name := encodeUCS2("/boot/loader.conf")
	var fh uintptr
	if rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead), 0); rc != sfsEFISuccess {
		t.Fatalf("Open = 0x%x", rc)
	}
	if rc := sfsFileSetPositionGo(fh, 3); rc != sfsEFISuccess {
		t.Errorf("SetPosition(3) = 0x%x", rc)
	}
	var pos uint64
	if rc := sfsFileGetPositionGo(fh, uintptr(unsafe.Pointer(&pos))); rc != sfsEFISuccess {
		t.Errorf("GetPosition = 0x%x", rc)
	}
	if pos != 3 {
		t.Errorf("GetPosition = %d, want 3", pos)
	}
	// Seek-to-EOF.
	if rc := sfsFileSetPositionGo(fh, uintptr(sfsPositionEnd)); rc != sfsEFISuccess {
		t.Errorf("SetPosition(EOF) = 0x%x", rc)
	}
	if rc := sfsFileGetPositionGo(fh, uintptr(unsafe.Pointer(&pos))); rc != sfsEFISuccess {
		t.Errorf("GetPosition(after EOF seek) = 0x%x", rc)
	}
	if pos != 5 {
		t.Errorf("GetPosition after EOF = %d, want 5", pos)
	}
}

func TestSFSFileGetInfo_FileInfo(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	fs.addFile("/loader.conf", []byte("hello"))
	_, rootThis := installSFSTestEntry(t, fs)
	name := encodeUCS2("/loader.conf")
	var fh uintptr
	if rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead), 0); rc != sfsEFISuccess {
		t.Fatalf("Open = 0x%x", rc)
	}
	// Query buffer size first.
	g := EFIFileInfoGUID
	var sz uint64
	rc := sfsFileGetInfoGo(fh, uintptr(unsafe.Pointer(&g)), uintptr(unsafe.Pointer(&sz)), 0)
	if rc != sfsEFIBufferTooSmall {
		t.Fatalf("GetInfo(0) = 0x%x, want BUFFER_TOO_SMALL", rc)
	}
	if sz == 0 {
		t.Fatal("GetInfo did not set required size")
	}
	buf := make([]byte, sz)
	rc = sfsFileGetInfoGo(fh, uintptr(unsafe.Pointer(&g)),
		uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFISuccess {
		t.Fatalf("GetInfo = 0x%x", rc)
	}
	// FileSize at offset 8 must be 5.
	if got := readU64(buf, 8); got != 5 {
		t.Errorf("FileInfo.FileSize = %d, want 5", got)
	}
}

func TestSFSFileGetInfo_UnsupportedGUID(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	_, rootThis := installSFSTestEntry(t, fs)
	// Use the wrong GUID (block IO).
	g := EFIBlockIOProtocolGUID
	var sz uint64 = 1024
	buf := make([]byte, sz)
	rc := sfsFileGetInfoGo(rootThis, uintptr(unsafe.Pointer(&g)),
		uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFIUnsupported {
		t.Errorf("GetInfo(wrong GUID) = 0x%x, want UNSUPPORTED", rc)
	}
}

func TestSFSFileRead_Directory(t *testing.T) {
	fs := newFakeFS()
	fs.addDir("/")
	fs.addDir("/boot")
	fs.addFile("/boot/loader.conf", []byte("x"))
	fs.addFile("/boot/kernel.bin", []byte("y"))
	_, rootThis := installSFSTestEntry(t, fs)

	// Open /boot
	name := encodeUCS2("/boot")
	var fh uintptr
	if rc := sfsFileOpenGo(rootThis, uintptr(unsafe.Pointer(&fh)),
		uintptr(unsafe.Pointer(&name[0])), uintptr(sfsFileModeRead), 0); rc != sfsEFISuccess {
		t.Fatalf("Open(/boot) = 0x%x", rc)
	}

	// First iteration — should land on loader.conf.
	got := readNextDirent(t, fh)
	if got != "loader.conf" {
		t.Errorf("first dirent = %q, want loader.conf", got)
	}
	got = readNextDirent(t, fh)
	if got != "kernel.bin" {
		t.Errorf("second dirent = %q, want kernel.bin", got)
	}
	// Third iteration — exhausted, size=0.
	buf := make([]byte, 256)
	var sz uint64 = uint64(len(buf))
	if rc := sfsFileReadGo(fh, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0]))); rc != sfsEFISuccess {
		t.Fatalf("exhausted Read rc=0x%x", rc)
	}
	if sz != 0 {
		t.Errorf("exhausted Read size = %d, want 0", sz)
	}
}

// readNextDirent calls sfsFileReadGo against a directory handle and
// decodes the first dirent's FileName.
func readNextDirent(t *testing.T, fh uintptr) string {
	t.Helper()
	buf := make([]byte, 512)
	var sz uint64 = uint64(len(buf))
	rc := sfsFileReadGo(fh, uintptr(unsafe.Pointer(&sz)), uintptr(unsafe.Pointer(&buf[0])))
	if rc != sfsEFISuccess {
		t.Fatalf("Read(dir) rc=0x%x", rc)
	}
	// FileName starts at offset 80.
	var name []byte
	for i := uint64(0); i+1 < sz-80; i += 2 {
		w := uint16(buf[80+i]) | uint16(buf[81+i])<<8
		if w == 0 {
			break
		}
		name = append(name, byte(w))
	}
	return string(name)
}

// encodeUCS2 builds a UCS-2 + NUL byte slice for a Go string.
func encodeUCS2(s string) []byte {
	out := make([]byte, 0, 2*(len(s)+1))
	for _, r := range s {
		out = append(out, byte(r), byte(r>>8))
	}
	out = append(out, 0, 0)
	return out
}

// ---------------------------------------------------------------------
// Host-stub guards.
// ---------------------------------------------------------------------

func TestPublishSFSHostStub_NilFilesystem(t *testing.T) {
	_, err := PublishSFS(0xCAFE, nil)
	if err != ErrSFSNilFilesystem {
		t.Errorf("PublishSFS(nil fs) err = %v, want ErrSFSNilFilesystem", err)
	}
}

func TestUnpublishSFSHostStub_ZeroHandle(t *testing.T) {
	if err := UnpublishSFS(0); err != ErrSFSNotPublished {
		t.Errorf("UnpublishSFS(0) err = %v, want ErrSFSNotPublished", err)
	}
}
