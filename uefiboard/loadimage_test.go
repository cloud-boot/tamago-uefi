// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.0 image-services wrappers
// (loadimage.go + loadimage_host.go). The live firmware path lives
// in loadimage_tamago.go and is exercised end-to-end by the
// `phase2_efi_handover` probe under QEMU/OVMF; here we only verify
// the host-buildable bits:
//
//  1. LoadImage rejects empty + nil buffers with ErrLoadImageNoSource
//     BEFORE attempting to call into the (non-existent) firmware.
//  2. The image-services offsets match UEFI 2.10 §4.2 (defensive
//     against a future typo regressing the EFI_BOOT_SERVICES layout).
//  3. ErrLoadImageNoSource carries a useful message.
//  4. StartImage / UnloadImage / ExitImage panic with the expected
//     "not supported on host" message — verifies the host-stub
//     gating actually compiles + is reachable.

package uefiboard

import (
	"strings"
	"testing"
)

func TestLoadImage_EmptyBuffer(t *testing.T) {
	h, err := LoadImage(nil)
	if err != ErrLoadImageNoSource {
		t.Errorf("LoadImage(nil) err = %v, want ErrLoadImageNoSource", err)
	}
	if h != 0 {
		t.Errorf("LoadImage(nil) handle = %d, want 0", h)
	}
	h, err = LoadImage([]byte{})
	if err != ErrLoadImageNoSource {
		t.Errorf("LoadImage(empty) err = %v, want ErrLoadImageNoSource", err)
	}
	if h != 0 {
		t.Errorf("LoadImage(empty) handle = %d, want 0", h)
	}
}

func TestErrLoadImageNoSource_Message(t *testing.T) {
	msg := ErrLoadImageNoSource.Error()
	if msg == "" {
		t.Fatal("ErrLoadImageNoSource.Error() is empty")
	}
	if !strings.Contains(msg, "LoadImage") {
		t.Errorf("ErrLoadImageNoSource = %q, expected to mention 'LoadImage'", msg)
	}
	if !strings.Contains(msg, "empty") {
		t.Errorf("ErrLoadImageNoSource = %q, expected to mention 'empty'", msg)
	}
}

// The image-services slot offsets are documented in UEFI 2.10 §4.2
// table 4.2 — assert them so a typo in loadimage.go surfaces here.
func TestImageServiceOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"LoadImage", efiBSLoadImage, 200},
		{"StartImage", efiBSStartImage, 208},
		{"Exit", efiBSExit, 216},
		{"UnloadImage", efiBSUnloadImage, 224},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s offset = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// LoadImage with a non-empty buffer panics on host (no firmware).
// Confirms the host-stub gating actually compiles + is reachable.
func TestLoadImage_NonEmpty_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("LoadImage(non-empty) did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("LoadImage panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("LoadImage panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	LoadImage([]byte{0x4D, 0x5A}) // PE signature; never reaches firmware on host
}

func TestStartImage_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("StartImage did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("StartImage panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("StartImage panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	StartImage(0xDEADBEEF)
}

func TestUnloadImage_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("UnloadImage did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("UnloadImage panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("UnloadImage panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	UnloadImage(0xDEADBEEF)
}

// WireExitToFirmware is a no-op on the host (the goos.Exit slot
// only exists on tamago). Verify it doesn't panic so the host build
// of the chainedhello payload's main can still link + exercise it
// in unit-test contexts.
func TestWireExitToFirmware_NoopOnHost(t *testing.T) {
	before := hostWireExitToFirmwareCalls
	WireExitToFirmware()
	// Calling it twice is idempotent (same semantics as the tamago
	// build's "rewrite the same hook" behaviour).
	WireExitToFirmware()
	if got := hostWireExitToFirmwareCalls - before; got != 2 {
		t.Errorf("WireExitToFirmware calls = %d, want 2", got)
	}
}

func TestExitImage_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("ExitImage did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("ExitImage panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("ExitImage panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	ExitImage(0xDEADBEEF, 0)
}
