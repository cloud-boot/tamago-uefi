// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side unit tests for the RNG
// publisher Go-side semantics (Phase 2, M8.7 — R-M8.6a).

package uefiboard

import (
	"testing"
	"unsafe"
)

// resetRNGRegistry clears the rngRegistry between tests so each
// case starts from a known empty state.
func resetRNGRegistry() {
	for i := range rngRegistry {
		rngRegistry[i] = rngEntry{}
	}
}

func TestEFIRngProtocolGUIDLayout(t *testing.T) {
	g := EFIRngProtocolGUID
	if g.Data1 != 0x3152bca5 || g.Data2 != 0xeade || g.Data3 != 0x433d {
		t.Fatalf("EFIRngProtocolGUID head wrong: %#x %#x %#x", g.Data1, g.Data2, g.Data3)
	}
	want := [8]uint8{0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44}
	if g.Data4 != want {
		t.Fatalf("EFIRngProtocolGUID Data4 wrong: %v != %v", g.Data4, want)
	}
}

func TestRngBSOffsets(t *testing.T) {
	// InstallProtocolInterface is at offset 128 per UEFI 2.10
	// §4.2 + cross-reference in initrd_protocol.go.
	if efiBSInstallProtocolInterface != 128 {
		t.Errorf("efiBSInstallProtocolInterface = %d, want 128", efiBSInstallProtocolInterface)
	}
	// UninstallProtocolInterface is at 144.
	if efiBSUninstallProtocolInterface != 144 {
		t.Errorf("efiBSUninstallProtocolInterface = %d, want 144", efiBSUninstallProtocolInterface)
	}
	if efiNativeInterface != 0 {
		t.Errorf("efiNativeInterface = %d, want 0", efiNativeInterface)
	}
}

func TestRngGetRNGGo_NoLength(t *testing.T) {
	resetRNGRegistry()
	st := rngGetRNGGo(0, 0, 0, 0)
	if st != rngEFIInvalidParameter {
		t.Errorf("expected EFI_INVALID_PARAMETER on zero length, got %#x", st)
	}
}

func TestRngGetRNGGo_NullBuf(t *testing.T) {
	resetRNGRegistry()
	st := rngGetRNGGo(0, 0, 16, 0)
	if st != rngEFIInvalidParameter {
		t.Errorf("expected EFI_INVALID_PARAMETER on NULL bufP, got %#x", st)
	}
}

func TestRngGetRNGGo_NotRegistered(t *testing.T) {
	resetRNGRegistry()
	buf := make([]byte, 16)
	this := uintptr(0xdeadbeef) // not in the registry
	st := rngGetRNGGo(this, 0, 16, uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFINotFound {
		t.Errorf("expected EFI_NOT_FOUND on unregistered this, got %#x", st)
	}
}

func TestRngGetRNGGo_Success(t *testing.T) {
	resetRNGRegistry()
	// Reserve slot 0 with a synthetic `this`.
	this := uintptr(0xcafebabe)
	rngRegistry[0] = rngEntry{proto: this}

	buf := make([]byte, 16)
	st := rngGetRNGGo(this, 0, 16, uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFISuccess {
		t.Fatalf("expected EFI_SUCCESS, got %#x", st)
	}
	// The host stub is deterministic: 0xA0 + i.
	for i, b := range buf {
		want := byte(0xA0) + byte(i)
		if b != want {
			t.Errorf("buf[%d] = %#x, want %#x", i, b, want)
		}
	}
}

func TestRngGetRNGGo_NilEntropy(t *testing.T) {
	resetRNGRegistry()
	this := uintptr(0xabad1dea)
	rngRegistry[0] = rngEntry{proto: this}

	// Swap entropy to nil; restore after.
	saved := rngEntropy
	rngEntropy = nil
	defer func() { rngEntropy = saved }()

	buf := make([]byte, 4)
	st := rngGetRNGGo(this, 0, 4, uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFIDeviceError {
		t.Errorf("expected EFI_DEVICE_ERROR when entropy is nil, got %#x", st)
	}
}

func TestRngGetRNGGo_ShortRead(t *testing.T) {
	resetRNGRegistry()
	this := uintptr(0xfeedface)
	rngRegistry[0] = rngEntry{proto: this}

	saved := rngEntropy
	rngEntropy = func(buf uintptr, n uintptr) uintptr {
		// Pretend we only managed to read half the request.
		for i := uintptr(0); i < n/2; i++ {
			*(*byte)(unsafe.Pointer(buf + i)) = 0x55
		}
		return n / 2
	}
	defer func() { rngEntropy = saved }()

	buf := make([]byte, 16)
	st := rngGetRNGGo(this, 0, 16, uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFIDeviceError {
		t.Errorf("expected EFI_DEVICE_ERROR on short read, got %#x", st)
	}
}

func TestRngGetInfoGo_SizeQuery(t *testing.T) {
	resetRNGRegistry()
	this := uintptr(0x10101010)
	rngRegistry[0] = rngEntry{proto: this}

	// Size-query: listSize = 0, listPtr NULL.
	var size uintptr = 0
	st := rngGetInfoGo(this, uintptr(unsafe.Pointer(&size)), 0)
	const wantStatus uintptr = 0x8000000000000005 // EFI_BUFFER_TOO_SMALL
	if st != wantStatus {
		t.Errorf("expected EFI_BUFFER_TOO_SMALL, got %#x", st)
	}
	if size != 16 {
		t.Errorf("expected size = 16, got %d", size)
	}
}

func TestRngGetInfoGo_Success(t *testing.T) {
	resetRNGRegistry()
	this := uintptr(0x20202020)
	rngRegistry[0] = rngEntry{proto: this}

	buf := make([]byte, 16)
	var size uintptr = 16
	st := rngGetInfoGo(this, uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFISuccess {
		t.Fatalf("expected EFI_SUCCESS, got %#x", st)
	}
	if size != 16 {
		t.Errorf("expected size = 16, got %d", size)
	}
	// First byte should be 0xd7 (Data1 LE byte 0 of
	// e43176d7-... per EFI_RNG_ALGORITHM_RAW).
	if buf[0] != 0xd7 {
		t.Errorf("buf[0] = %#x, want 0xd7 (RAW algorithm GUID first byte)", buf[0])
	}
}

func TestRngGetInfoGo_NullListSize(t *testing.T) {
	resetRNGRegistry()
	st := rngGetInfoGo(0, 0, 0)
	if st != rngEFIInvalidParameter {
		t.Errorf("expected EFI_INVALID_PARAMETER on NULL listSize, got %#x", st)
	}
}

func TestRngGetInfoGo_NotRegistered(t *testing.T) {
	resetRNGRegistry()
	buf := make([]byte, 16)
	var size uintptr = 16
	st := rngGetInfoGo(0xdeadbeef, uintptr(unsafe.Pointer(&size)),
		uintptr(unsafe.Pointer(&buf[0])))
	if st != rngEFINotFound {
		t.Errorf("expected EFI_NOT_FOUND on unregistered this, got %#x", st)
	}
}

func TestRngEntryStorage(t *testing.T) {
	resetRNGRegistry()
	// Fill the registry and confirm the size constant matches.
	for i := 0; i < rngRegistrySize; i++ {
		rngRegistry[i] = rngEntry{proto: uintptr(i + 1)}
	}
	for i := 0; i < rngRegistrySize; i++ {
		if rngRegistry[i].proto != uintptr(i+1) {
			t.Errorf("registry[%d].proto = %d, want %d", i, rngRegistry[i].proto, i+1)
		}
	}
}

func TestRngErrors(t *testing.T) {
	if ErrEmptyRNGRequest.Error() == "" {
		t.Error("ErrEmptyRNGRequest should have a message")
	}
	if ErrRNGNotPublished.Error() == "" {
		t.Error("ErrRNGNotPublished should have a message")
	}
	if ErrRNGRegistryFull.Error() == "" {
		t.Error("ErrRNGRegistryFull should have a message")
	}
}

func TestEFIRngProtocolShape(t *testing.T) {
	// Two function-pointer slots, contiguous, GetInfo first then
	// GetRNG (mirrors the spec struct order).
	var p EFIRngProtocol
	if unsafe.Sizeof(p) != 16 {
		t.Errorf("sizeof(EFIRngProtocol) = %d, want 16", unsafe.Sizeof(p))
	}
	if unsafe.Offsetof(p.GetInfo) != 0 {
		t.Errorf("GetInfo offset = %d, want 0", unsafe.Offsetof(p.GetInfo))
	}
	if unsafe.Offsetof(p.GetRNG) != 8 {
		t.Errorf("GetRNG offset = %d, want 8", unsafe.Offsetof(p.GetRNG))
	}
}
