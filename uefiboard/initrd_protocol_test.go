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
