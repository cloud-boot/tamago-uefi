// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side tests for the publisher-side EFI_BLOCK_IO_PROTOCOL surface
// (Phase 3 sprint 1).
//
// The Go-side handlers (blockIOResetGo, blockIOReadBlocksGo,
// blockIOWriteBlocksGo, blockIOFlushBlocksGo) are host-buildable, so
// we exercise them directly against a hand-crafted registry entry.
// The asm trampolines + InstallProtocolInterface wiring are not
// host-buildable — those land in the live-test gate.

package uefiboard

import (
	"testing"
	"unsafe"
)

// TestEFISimpleFileSystemProtocolGUID_RoundTrip pins the SFS GUID we
// look up after ConnectController to find the FAT ESP child handle.
func TestEFISimpleFileSystemProtocolGUID_RoundTrip(t *testing.T) {
	// Canonical text per MdePkg/Include/Protocol/SimpleFileSystem.h
	// (edk2.git stable/202408):
	//   #define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
	//     { 0x964e5b22, 0x6459, 0x11d2, \
	//       {0x8e, 0x39, 0x0, 0xa0, 0xc9, 0x69, 0x72, 0x3b } }
	expect := guidFromText(t, "964e5b22-6459-11d2-8e39-00a0c969723b")
	if EFISimpleFileSystemProtocolGUID != expect {
		t.Fatalf("EFISimpleFileSystemProtocolGUID mismatch:\n got    = %+v\n expect = %+v",
			EFISimpleFileSystemProtocolGUID, expect)
	}
}

// TestBlockIOPublishedRevisionConstant pins the Revision value we
// publish — UEFI 2.10 §13.9.1.1 fixes 0x00010000 for the original
// rev1 protocol.
func TestBlockIOPublishedRevisionConstant(t *testing.T) {
	if blockIOPublishedRevision != 0x00010000 {
		t.Errorf("blockIOPublishedRevision = 0x%08x, want 0x00010000", blockIOPublishedRevision)
	}
}

// TestBlockIOLogicalBlockSizeConstant — universal 512.
func TestBlockIOLogicalBlockSizeConstant(t *testing.T) {
	if BlockIOLogicalBlockSize != 512 {
		t.Errorf("BlockIOLogicalBlockSize = %d, want 512", BlockIOLogicalBlockSize)
	}
}

// blockIOInstallTestEntry hand-crafts a registry slot pointing at a
// caller-supplied body. Used by the *Go handler tests below to
// simulate a live install without a live firmware. Returns the
// `this` value (== fake protocol address) the handler will look up.
func blockIOInstallTestEntry(t *testing.T, body []byte) uintptr {
	t.Helper()
	// Use a fake non-zero "protocol" pointer — we don't follow it on
	// the handler path (handlers only key on `this`); the registry's
	// `proto` field is the comparison key.
	fakeProto := uintptr(0xCAFEC0DE0000)
	slot := -1
	for i := range blockIOPublishRegistry {
		if blockIOPublishRegistry[i].proto == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		t.Fatal("blockIOPublishRegistry full — bad test isolation")
	}
	blockIOPublishRegistry[slot] = blockIOPublishEntry{
		proto:         fakeProto,
		body:          uintptr(unsafe.Pointer(&body[0])),
		size:          uintptr(len(body)),
		bodyKeepAlive: body,
	}
	t.Cleanup(func() { blockIOPublishRegistry[slot] = blockIOPublishEntry{} })
	return fakeProto
}

// TestBlockIOResetGo_KnownThisReturnsSuccess — happy path.
func TestBlockIOResetGo_KnownThisReturnsSuccess(t *testing.T) {
	body := make([]byte, 512)
	this := blockIOInstallTestEntry(t, body)
	if got := blockIOResetGo(this, 0); got != blockIOEFISuccess {
		t.Errorf("blockIOResetGo(known) = 0x%x, want EFI_SUCCESS", got)
	}
	if got := blockIOResetGo(this, 1); got != blockIOEFISuccess {
		t.Errorf("blockIOResetGo(known, extended=1) = 0x%x, want EFI_SUCCESS", got)
	}
}

// TestBlockIOResetGo_UnknownThisReturnsNotFound — defensive miss path.
func TestBlockIOResetGo_UnknownThisReturnsNotFound(t *testing.T) {
	if got := blockIOResetGo(0xDEADDEADDEAD, 0); got != blockIOEFINotFound {
		t.Errorf("blockIOResetGo(unknown) = 0x%x, want EFI_NOT_FOUND (0x%x)", got, blockIOEFINotFound)
	}
}

// TestBlockIOFlushBlocksGo_KnownThisReturnsSuccess — happy path.
func TestBlockIOFlushBlocksGo_KnownThisReturnsSuccess(t *testing.T) {
	body := make([]byte, 512)
	this := blockIOInstallTestEntry(t, body)
	if got := blockIOFlushBlocksGo(this); got != blockIOEFISuccess {
		t.Errorf("blockIOFlushBlocksGo(known) = 0x%x, want EFI_SUCCESS", got)
	}
}

// TestBlockIOFlushBlocksGo_UnknownThisReturnsNotFound.
func TestBlockIOFlushBlocksGo_UnknownThisReturnsNotFound(t *testing.T) {
	if got := blockIOFlushBlocksGo(0xDEADDEAD); got != blockIOEFINotFound {
		t.Errorf("blockIOFlushBlocksGo(unknown) = 0x%x, want EFI_NOT_FOUND", got)
	}
}

// TestBlockIOWriteBlocksGo_AlwaysWriteProtected — sprint 1 is RO.
func TestBlockIOWriteBlocksGo_AlwaysWriteProtected(t *testing.T) {
	body := make([]byte, 512)
	this := blockIOInstallTestEntry(t, body)
	dst := make([]byte, 512)
	if got := blockIOWriteBlocksGo(this, 1, 0, 512, uintptr(unsafe.Pointer(&dst[0]))); got != blockIOEFIWriteProtected {
		t.Errorf("blockIOWriteBlocksGo(known, in-bounds) = 0x%x, want EFI_WRITE_PROTECTED (0x%x)",
			got, blockIOEFIWriteProtected)
	}
}

// TestBlockIOWriteBlocksGo_UnknownThisReturnsNotFound — miss takes
// precedence over WRITE_PROTECTED so a stale callback can't be
// confused with a "live but read-only" device.
func TestBlockIOWriteBlocksGo_UnknownThisReturnsNotFound(t *testing.T) {
	dst := make([]byte, 512)
	if got := blockIOWriteBlocksGo(0xDEADDEAD, 1, 0, 512, uintptr(unsafe.Pointer(&dst[0]))); got != blockIOEFINotFound {
		t.Errorf("blockIOWriteBlocksGo(unknown) = 0x%x, want EFI_NOT_FOUND", got)
	}
}

// TestBlockIOReadBlocksGo_RoundTrip — write a recognisable byte
// pattern into the body, read it back through the handler, verify
// the bytes landed where requested.
func TestBlockIOReadBlocksGo_RoundTrip(t *testing.T) {
	// 4 blocks (2 KiB) so we can read block #2 and have plenty of
	// distinct content to compare against.
	const blocks = 4
	body := make([]byte, blocks*int(BlockIOLogicalBlockSize))
	for i := range body {
		body[i] = byte(i & 0xff)
	}
	this := blockIOInstallTestEntry(t, body)

	// Read block 2 (512 bytes starting at offset 1024).
	dst := make([]byte, BlockIOLogicalBlockSize)
	got := blockIOReadBlocksGo(this, 1, 2, uintptr(BlockIOLogicalBlockSize), uintptr(unsafe.Pointer(&dst[0])))
	if got != blockIOEFISuccess {
		t.Fatalf("blockIOReadBlocksGo = 0x%x, want EFI_SUCCESS", got)
	}
	for i := 0; i < int(BlockIOLogicalBlockSize); i++ {
		want := byte((1024 + i) & 0xff)
		if dst[i] != want {
			t.Fatalf("read byte %d = 0x%02x, want 0x%02x", i, dst[i], want)
		}
	}
}

// TestBlockIOReadBlocksGo_ZeroBufferSize is a no-op return success.
func TestBlockIOReadBlocksGo_ZeroBufferSize(t *testing.T) {
	body := make([]byte, 512)
	this := blockIOInstallTestEntry(t, body)
	if got := blockIOReadBlocksGo(this, 1, 0, 0, 0); got != blockIOEFISuccess {
		t.Errorf("blockIOReadBlocksGo(size=0) = 0x%x, want EFI_SUCCESS", got)
	}
}

// TestBlockIOReadBlocksGo_BadBufferSize — must be multiple of block.
func TestBlockIOReadBlocksGo_BadBufferSize(t *testing.T) {
	body := make([]byte, 1024)
	this := blockIOInstallTestEntry(t, body)
	dst := make([]byte, 300)
	got := blockIOReadBlocksGo(this, 1, 0, 300, uintptr(unsafe.Pointer(&dst[0])))
	if got != blockIOEFIBadBufferSize {
		t.Errorf("blockIOReadBlocksGo(size=300) = 0x%x, want EFI_BAD_BUFFER_SIZE (0x%x)",
			got, blockIOEFIBadBufferSize)
	}
}

// TestBlockIOReadBlocksGo_NullBuffer — must be non-NULL when size > 0.
func TestBlockIOReadBlocksGo_NullBuffer(t *testing.T) {
	body := make([]byte, 1024)
	this := blockIOInstallTestEntry(t, body)
	got := blockIOReadBlocksGo(this, 1, 0, uintptr(BlockIOLogicalBlockSize), 0)
	if got != blockIOEFIInvalidParameter {
		t.Errorf("blockIOReadBlocksGo(buf=NULL) = 0x%x, want EFI_INVALID_PARAMETER (0x%x)",
			got, blockIOEFIInvalidParameter)
	}
}

// TestBlockIOReadBlocksGo_OutOfRangeLBA — Lba > LastBlock surfaces
// as EFI_INVALID_PARAMETER (UEFI 2.10 §13.9.3 table 188).
func TestBlockIOReadBlocksGo_OutOfRangeLBA(t *testing.T) {
	body := make([]byte, 1024) // 2 blocks; LastBlock = 1
	this := blockIOInstallTestEntry(t, body)
	dst := make([]byte, BlockIOLogicalBlockSize)
	// Reading block 2 at offset 1024 starts AT end-of-image; the +size
	// extends past, so end > size → EFI_INVALID_PARAMETER.
	got := blockIOReadBlocksGo(this, 1, 2, uintptr(BlockIOLogicalBlockSize), uintptr(unsafe.Pointer(&dst[0])))
	if got != blockIOEFIInvalidParameter {
		t.Errorf("blockIOReadBlocksGo(lba=past-end) = 0x%x, want EFI_INVALID_PARAMETER", got)
	}
}

// TestBlockIOReadBlocksGo_UnknownThisReturnsNotFound.
func TestBlockIOReadBlocksGo_UnknownThisReturnsNotFound(t *testing.T) {
	dst := make([]byte, 512)
	got := blockIOReadBlocksGo(0xDEADBABE, 1, 0, 512, uintptr(unsafe.Pointer(&dst[0])))
	if got != blockIOEFINotFound {
		t.Errorf("blockIOReadBlocksGo(unknown) = 0x%x, want EFI_NOT_FOUND", got)
	}
}

// TestBlockIOLookup_Miss returns the sentinel zero entry + false.
func TestBlockIOLookup_Miss(t *testing.T) {
	_, ok := blockIOLookup(0xFEEDBABE)
	if ok {
		t.Error("blockIOLookup(unregistered) returned ok=true; want false")
	}
}

// TestBlockIOLookup_Hit returns the registered entry.
func TestBlockIOLookup_Hit(t *testing.T) {
	body := make([]byte, 512)
	this := blockIOInstallTestEntry(t, body)
	ent, ok := blockIOLookup(this)
	if !ok {
		t.Fatal("blockIOLookup(known) returned ok=false; want true")
	}
	if ent.proto != this {
		t.Errorf("lookup hit: proto = 0x%x, want 0x%x", ent.proto, this)
	}
	if ent.size != uintptr(len(body)) {
		t.Errorf("lookup hit: size = %d, want %d", ent.size, len(body))
	}
}

// TestBlockIOPublishHostStub_EmptyImage exercises the empty-input
// guard on the host stub path.
func TestBlockIOPublishHostStub_EmptyImage(t *testing.T) {
	_, err := PublishBlockIO(nil)
	if err != ErrEmptyBlockImage {
		t.Errorf("PublishBlockIO(nil) error = %v, want ErrEmptyBlockImage", err)
	}
}

// TestBlockIOPublishHostStub_Unaligned exercises the alignment guard.
func TestBlockIOPublishHostStub_Unaligned(t *testing.T) {
	_, err := PublishBlockIO(make([]byte, 1000)) // not /512
	if err != ErrBlockIOImageNotAligned {
		t.Errorf("PublishBlockIO(unaligned) error = %v, want ErrBlockIOImageNotAligned", err)
	}
}

// TestUnpublishBlockIOHostStub_ZeroHandle exercises the
// nil-handle guard.
func TestUnpublishBlockIOHostStub_ZeroHandle(t *testing.T) {
	if err := UnpublishBlockIO(0); err != ErrBlockIONotPublished {
		t.Errorf("UnpublishBlockIO(0) error = %v, want ErrBlockIONotPublished", err)
	}
}
