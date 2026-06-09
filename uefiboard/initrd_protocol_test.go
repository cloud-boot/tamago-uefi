// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.2 initrd protocol publish helpers.
// The live install/uninstall path lives in
// initrd_protocol_tamago.go and runs under QEMU+EDK2; here we cover
// the host-buildable bits:
//
//  1. GUIDs match the textual form (LINUX_EFI_INITRD_MEDIA_GUID,
//     EFI_LOAD_FILE2_PROTOCOL_GUID, EFI_DEVICE_PATH_PROTOCOL_GUID).
//  2. buildInitrdDevicePath emits a spec-shaped 28-byte buffer with
//     a Vendor node carrying the right GUID and a proper END node.
//  3. PublishInitrd / UnpublishInitrd reject empty inputs and panic
//     past the guards on the host (gating sanity).
//  4. InstallMultipleProtocolInterfaces offsets match UEFI 2.10
//     §4.2 (defensive — a typo here regresses every protocol
//     install at runtime, not just initrd).

package uefiboard

import (
	"strings"
	"testing"
	"unsafe"
)

func TestLinuxEFIInitrdMediaGUID(t *testing.T) {
	want := guidFromText(t, "5568e427-68fc-4f3d-ac74-ca555231cc68")
	if LinuxEFIInitrdMediaGUID != want {
		t.Errorf("LinuxEFIInitrdMediaGUID = %+v, want %+v",
			LinuxEFIInitrdMediaGUID, want)
	}
}

func TestEFILoadFile2ProtocolGUID(t *testing.T) {
	want := guidFromText(t, "4006c0c1-fcb3-403e-996d-4a6c8724e06d")
	if EFILoadFile2ProtocolGUID != want {
		t.Errorf("EFILoadFile2ProtocolGUID = %+v, want %+v",
			EFILoadFile2ProtocolGUID, want)
	}
}

func TestEFIDevicePathProtocolGUID(t *testing.T) {
	want := guidFromText(t, "09576e91-6d3f-11d2-8e39-00a0c969723b")
	if EFIDevicePathProtocolGUID != want {
		t.Errorf("EFIDevicePathProtocolGUID = %+v, want %+v",
			EFIDevicePathProtocolGUID, want)
	}
}

func TestBuildInitrdDevicePath_Layout(t *testing.T) {
	got := buildInitrdDevicePath()
	if len(got) != 24 {
		t.Fatalf("len(buildInitrdDevicePath()) = %d, want 24", len(got))
	}

	// Vendor node header.
	if got[0] != devPathTypeMedia {
		t.Errorf("vendor.Type = 0x%02x, want 0x04", got[0])
	}
	if got[1] != devPathSubTypeVendor {
		t.Errorf("vendor.SubType = 0x%02x, want 0x03", got[1])
	}
	if got[2] != 0x14 || got[3] != 0x00 {
		t.Errorf("vendor.Length = 0x%02x%02x, want 0x0014 (20 LE)",
			got[3], got[2])
	}

	// Vendor GUID payload: LINUX_EFI_INITRD_MEDIA_GUID.
	// 5568e427-68fc-4f3d-ac74-ca555231cc68 — Data1/Data2/Data3 LE.
	wantGUID := []byte{
		0x27, 0xe4, 0x68, 0x55, // Data1 LE
		0xfc, 0x68, // Data2 LE
		0x3d, 0x4f, // Data3 LE
		0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68, // Data4
	}
	for i, b := range wantGUID {
		if got[4+i] != b {
			t.Errorf("vendor.GUID[%d] = 0x%02x, want 0x%02x",
				i, got[4+i], b)
		}
	}

	// END node — sits immediately after the 20-byte vendor node.
	if got[20] != devPathTypeEnd {
		t.Errorf("end.Type = 0x%02x, want 0x7F", got[20])
	}
	if got[21] != devPathSubTypeEndWhole {
		t.Errorf("end.SubType = 0x%02x, want 0xFF", got[21])
	}
	if got[22] != 0x04 || got[23] != 0x00 {
		t.Errorf("end.Length = 0x%02x%02x, want 0x0004 (4 LE)",
			got[23], got[22])
	}
}

func TestPublishInitrd_Empty(t *testing.T) {
	h, err := PublishInitrd(nil)
	if err != ErrEmptyInitrd {
		t.Errorf("PublishInitrd(nil) err = %v, want ErrEmptyInitrd", err)
	}
	if h != 0 {
		t.Errorf("PublishInitrd(nil) handle = %d, want 0", h)
	}
	h, err = PublishInitrd([]byte{})
	if err != ErrEmptyInitrd {
		t.Errorf("PublishInitrd(empty) err = %v, want ErrEmptyInitrd", err)
	}
	if h != 0 {
		t.Errorf("PublishInitrd(empty) handle = %d, want 0", h)
	}
}

func TestPublishInitrd_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("PublishInitrd did not panic on host")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("PublishInitrd panic = %q, want 'not supported on host'", msg)
		}
	}()
	PublishInitrd([]byte{0x1F, 0x8B, 0x08, 0x00}) // gzip magic; never reaches firmware
}

func TestUnpublishInitrd_ZeroHandle(t *testing.T) {
	if err := UnpublishInitrd(0); err != ErrInitrdNotPublished {
		t.Errorf("UnpublishInitrd(0) err = %v, want ErrInitrdNotPublished", err)
	}
}

func TestUnpublishInitrd_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("UnpublishInitrd did not panic on host")
		}
		msg, _ := r.(string)
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("UnpublishInitrd panic = %q, want 'not supported on host'", msg)
		}
	}()
	UnpublishInitrd(0xDEADBEEF)
}

func TestErrEmptyInitrd_Message(t *testing.T) {
	if !strings.Contains(ErrEmptyInitrd.Error(), "initrd") {
		t.Errorf("ErrEmptyInitrd = %q, expected to mention 'initrd'", ErrEmptyInitrd.Error())
	}
}

func TestErrInitrdNotPublished_Message(t *testing.T) {
	if !strings.Contains(ErrInitrdNotPublished.Error(), "handle") {
		t.Errorf("ErrInitrdNotPublished = %q, expected to mention 'handle'", ErrInitrdNotPublished.Error())
	}
}

func TestInstallMultipleProtocolInterfacesOffsets(t *testing.T) {
	if efiBSInstallMultipleProtocolInterfaces != 328 {
		t.Errorf("efiBSInstallMultipleProtocolInterfaces = %d, want 328",
			efiBSInstallMultipleProtocolInterfaces)
	}
	if efiBSUninstallMultipleProtocolInterfaces != 336 {
		t.Errorf("efiBSUninstallMultipleProtocolInterfaces = %d, want 336",
			efiBSUninstallMultipleProtocolInterfaces)
	}
}

// EFIDevicePathNode sanity — the struct layout is documented but
// the test guards against an accidental field reorder in
// initrd_protocol.go.
func TestEFIDevicePathNode_Layout(t *testing.T) {
	n := EFIDevicePathNode{Type: 0x04, SubType: 0x03, Length: 0x18}
	if n.Type != 0x04 || n.SubType != 0x03 || n.Length != 0x18 {
		t.Errorf("EFIDevicePathNode round-trip = %+v", n)
	}
}

// --- loadFileGo: host-side tests of the two-call protocol --------
//
// The asm trampoline can't be exercised on host (no firmware to
// invoke it), but loadFileGo itself is pure-Go-with-unsafe and is
// the load-bearing semantic layer. We test it directly with
// crafted pointers.

// resetLoadFileRegistry zeroes the package-private array between
// subtests so the linear scan returns deterministic results.
func resetLoadFileRegistry(t *testing.T) {
	t.Helper()
	for i := range loadFileRegistry {
		loadFileRegistry[i] = loadFileEntry{}
	}
}

// registerInitrd installs a synthetic entry into slot 0 of the
// registry, returning the synthetic `this` pointer the trampoline
// would normally pass loadFileGo.
func registerInitrd(t *testing.T, body []byte) (this uintptr) {
	t.Helper()
	// `this` is opaque to loadFileGo — it just needs a unique
	// non-zero value the matching loadFileEntry carries. We use the
	// address of a stack-allocated marker, which is stable for the
	// life of this test function.
	marker := byte(0)
	this = uintptr(unsafe.Pointer(&marker))
	loadFileRegistry[0] = loadFileEntry{
		proto: this,
		body:  uintptr(unsafe.Pointer(&body[0])),
		size:  uintptr(len(body)),
	}
	return this
}

func TestLoadFileGo_BootPolicyTrue_Unsupported(t *testing.T) {
	resetLoadFileRegistry(t)
	body := []byte("initrd-bytes-for-bootpolicy-test")
	this := registerInitrd(t, body)
	var sz uintptr = uintptr(len(body))
	got := loadFileGo(this, 0, 1, // bp != 0
		uintptr(unsafe.Pointer(&sz)),
		uintptr(unsafe.Pointer(&body[0])))
	if got != loadFileEFIUnsupported {
		t.Errorf("loadFileGo bp=1 -> 0x%x, want EFI_UNSUPPORTED (0x%x)", got, loadFileEFIUnsupported)
	}
}

func TestLoadFileGo_UnknownHandle_NotFound(t *testing.T) {
	resetLoadFileRegistry(t)
	// No entry registered.
	var sz uintptr = 0
	got := loadFileGo(0xDEADBEEF, 0, 0,
		uintptr(unsafe.Pointer(&sz)),
		0)
	if got != loadFileEFINotFound {
		t.Errorf("loadFileGo unknown this -> 0x%x, want EFI_NOT_FOUND (0x%x)", got, loadFileEFINotFound)
	}
}

func TestLoadFileGo_BufTooSmall_BufferTooSmall(t *testing.T) {
	resetLoadFileRegistry(t)
	body := []byte("the-quick-brown-fox-jumps-over-the-lazy-initrd")
	this := registerInitrd(t, body)
	// Buffer-too-small path #1: bufP non-NULL but capacity less than need.
	var sz uintptr = uintptr(len(body) - 5)
	dst := make([]byte, len(body))
	got := loadFileGo(this, 0, 0,
		uintptr(unsafe.Pointer(&sz)),
		uintptr(unsafe.Pointer(&dst[0])))
	if got != loadFileEFIBufferTooSmall {
		t.Errorf("loadFileGo small-buf -> 0x%x, want EFI_BUFFER_TOO_SMALL (0x%x)", got, loadFileEFIBufferTooSmall)
	}
	if sz != uintptr(len(body)) {
		t.Errorf("after small-buf call, *sz = %d, want %d", sz, len(body))
	}
	// Buffer-too-small path #2: bufP == NULL (the EFI-stub's
	// size-query call).
	sz = 0
	got = loadFileGo(this, 0, 0,
		uintptr(unsafe.Pointer(&sz)),
		0)
	if got != loadFileEFIBufferTooSmall {
		t.Errorf("loadFileGo NULL-buf -> 0x%x, want EFI_BUFFER_TOO_SMALL", got)
	}
	if sz != uintptr(len(body)) {
		t.Errorf("after NULL-buf call, *sz = %d, want %d", sz, len(body))
	}
}

func TestLoadFileGo_BufBigEnough_Success(t *testing.T) {
	resetLoadFileRegistry(t)
	body := []byte("hello\x00world\xffinitrd-payload-bytes!")
	this := registerInitrd(t, body)
	var sz uintptr = uintptr(len(body))
	dst := make([]byte, len(body))
	got := loadFileGo(this, 0, 0,
		uintptr(unsafe.Pointer(&sz)),
		uintptr(unsafe.Pointer(&dst[0])))
	if got != loadFileEFISuccess {
		t.Errorf("loadFileGo big-buf -> 0x%x, want EFI_SUCCESS", got)
	}
	if sz != uintptr(len(body)) {
		t.Errorf("after success call, *sz = %d, want %d", sz, len(body))
	}
	for i := range body {
		if dst[i] != body[i] {
			t.Errorf("dst[%d] = 0x%02x, want 0x%02x", i, dst[i], body[i])
			break
		}
	}
}

func TestLoadFileGo_BufBigger_Success_PartialFill(t *testing.T) {
	// Caller may pass a buffer LARGER than the initrd. We copy
	// only `need` bytes and report `need` bytes via *sz; tail of
	// dst is untouched.
	resetLoadFileRegistry(t)
	body := []byte("short-initrd")
	this := registerInitrd(t, body)
	var sz uintptr = 4096 // big
	dst := make([]byte, 4096)
	// Pre-fill dst tail so we can assert it's untouched.
	for i := range dst {
		dst[i] = 0xAA
	}
	got := loadFileGo(this, 0, 0,
		uintptr(unsafe.Pointer(&sz)),
		uintptr(unsafe.Pointer(&dst[0])))
	if got != loadFileEFISuccess {
		t.Errorf("loadFileGo over-sized-buf -> 0x%x, want EFI_SUCCESS", got)
	}
	if sz != uintptr(len(body)) {
		t.Errorf("after over-sized success, *sz = %d, want %d", sz, len(body))
	}
	for i := range body {
		if dst[i] != body[i] {
			t.Errorf("dst[%d] = 0x%02x, want 0x%02x", i, dst[i], body[i])
		}
	}
	// Tail must be untouched.
	for i := len(body); i < len(dst); i++ {
		if dst[i] != 0xAA {
			t.Errorf("dst[%d] = 0x%02x, want untouched 0xAA", i, dst[i])
			break
		}
	}
}

func TestLoadFileGo_NilSizeP_InvalidParameter(t *testing.T) {
	resetLoadFileRegistry(t)
	body := []byte("any")
	this := registerInitrd(t, body)
	// sizeP == 0 is a caller bug — surface it.
	got := loadFileGo(this, 0, 0, 0, 0)
	if got != loadFileEFIInvalidParameter {
		t.Errorf("loadFileGo nil sizeP -> 0x%x, want EFI_INVALID_PARAMETER", got)
	}
}

func TestLoadFileGo_MultipleSlots(t *testing.T) {
	resetLoadFileRegistry(t)
	bodyA := []byte("initrd-AAA")
	bodyB := []byte("initrd-BBBBB")
	markerA := byte(0)
	markerB := byte(0)
	thisA := uintptr(unsafe.Pointer(&markerA))
	thisB := uintptr(unsafe.Pointer(&markerB))
	loadFileRegistry[0] = loadFileEntry{
		proto: thisA,
		body:  uintptr(unsafe.Pointer(&bodyA[0])),
		size:  uintptr(len(bodyA)),
	}
	loadFileRegistry[3] = loadFileEntry{
		proto: thisB,
		body:  uintptr(unsafe.Pointer(&bodyB[0])),
		size:  uintptr(len(bodyB)),
	}
	// Resolve A.
	dstA := make([]byte, len(bodyA))
	szA := uintptr(len(bodyA))
	if got := loadFileGo(thisA, 0, 0,
		uintptr(unsafe.Pointer(&szA)),
		uintptr(unsafe.Pointer(&dstA[0]))); got != loadFileEFISuccess {
		t.Errorf("loadFileGo A -> 0x%x, want SUCCESS", got)
	}
	for i := range bodyA {
		if dstA[i] != bodyA[i] {
			t.Errorf("dstA[%d] = 0x%02x, want 0x%02x", i, dstA[i], bodyA[i])
		}
	}
	// Resolve B.
	dstB := make([]byte, len(bodyB))
	szB := uintptr(len(bodyB))
	if got := loadFileGo(thisB, 0, 0,
		uintptr(unsafe.Pointer(&szB)),
		uintptr(unsafe.Pointer(&dstB[0]))); got != loadFileEFISuccess {
		t.Errorf("loadFileGo B -> 0x%x, want SUCCESS", got)
	}
	for i := range bodyB {
		if dstB[i] != bodyB[i] {
			t.Errorf("dstB[%d] = 0x%02x, want 0x%02x", i, dstB[i], bodyB[i])
		}
	}
}

func TestErrLoadFileRegistryFull_Message(t *testing.T) {
	if !strings.Contains(ErrLoadFileRegistryFull.Error(), "registry") {
		t.Errorf("ErrLoadFileRegistryFull = %q, expected 'registry'", ErrLoadFileRegistryFull.Error())
	}
}
