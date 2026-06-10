// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.6 InstallConfigurationTable +
// PublishDTB wrappers. The live wrapper lives in
// install_config_table_tamago.go and runs under QEMU+EDK2; here we
// cover the host-buildable bits:
//
//  1. PublishDTB rejects an empty DTB with ErrDTBEmpty BEFORE
//     attempting any firmware call (this is the only host-testable
//     branch — the live AllocatePool / InstallConfigurationTable
//     calls panic on the host stub).
//  2. PublishDTB on a non-empty DTB panics on the host (confirms
//     the host stub is reachable + the gating compiles).
//  3. InstallConfigurationTable + AllocatePool panic on the host
//     with the expected "not supported" message.
//  4. The efiBSInstallConfigurationTable offset matches UEFI 2.10 §4.2.
//  5. DTBGUIDBytes matches the mixed-endian encoding of
//     EFIDTBTableGUID (round-trip sanity — if the encoding ever
//     drifts, the firmware would publish under a GUID Linux doesn't
//     recognise).
//  6. EFI_GUID is a 16-byte type (compile-time + runtime sanity).
//  7. Error message strings carry the relevant keyword.

package uefiboard

import (
	"strings"
	"testing"
	"unsafe"
)

func TestPublishDTB_EmptyBuffer(t *testing.T) {
	err := PublishDTB(nil)
	if err != ErrDTBEmpty {
		t.Errorf("PublishDTB(nil) err = %v, want ErrDTBEmpty", err)
	}
	err = PublishDTB([]byte{})
	if err != ErrDTBEmpty {
		t.Errorf("PublishDTB(empty) err = %v, want ErrDTBEmpty", err)
	}
}

func TestPublishDTB_NonEmpty_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("PublishDTB(non-empty) did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("PublishDTB panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("PublishDTB panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	PublishDTB([]byte{0xd0, 0x0d, 0xfe, 0xed}) // FDT magic; never reaches firmware on host
}

func TestInstallConfigurationTable_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("InstallConfigurationTable did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("InstallConfigurationTable panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("InstallConfigurationTable panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	InstallConfigurationTable(DTBGUIDBytes, unsafe.Pointer(uintptr(0xDEADBEEF)))
}

func TestAllocatePool_PanicsOnHost(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("AllocatePool did not panic on host")
		}
		msg, ok := r.(string)
		if !ok {
			t.Fatalf("AllocatePool panic value type = %T, want string", r)
		}
		if !strings.Contains(msg, "not supported on host") {
			t.Errorf("AllocatePool panic = %q, want substring 'not supported on host'", msg)
		}
	}()
	AllocatePool(EfiBootServicesData, 4096)
}

func TestInstallConfigurationTableOffset(t *testing.T) {
	// UEFI 2.10 §4.2 table 4.2 + edk2 MdePkg/Include/Uefi/UefiSpec.h.
	if efiBSInstallConfigurationTable != 192 {
		t.Errorf("efiBSInstallConfigurationTable = %d, want 192", efiBSInstallConfigurationTable)
	}
}

func TestEFI_GUID_Size(t *testing.T) {
	var g EFI_GUID
	if got, want := unsafe.Sizeof(g), uintptr(16); got != want {
		t.Errorf("sizeof(EFI_GUID) = %d, want %d", got, want)
	}
}

// DTBGUIDBytes must be the byte-array form of EFIDTBTableGUID. If a
// future typo flips a byte here, the firmware would publish under
// the wrong GUID and Linux's EFI-stub would not find the DTB —
// regressing R-M8.5a. Catch any drift at host-test time.
func TestDTBGUIDBytes_MatchesEFIDTBTableGUID(t *testing.T) {
	g := EFIDTBTableGUID
	want := EFI_GUID{
		// Data1 LE.
		byte(g.Data1), byte(g.Data1 >> 8), byte(g.Data1 >> 16), byte(g.Data1 >> 24),
		// Data2 LE.
		byte(g.Data2), byte(g.Data2 >> 8),
		// Data3 LE.
		byte(g.Data3), byte(g.Data3 >> 8),
		// Data4 raw.
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7],
	}
	if DTBGUIDBytes != want {
		t.Errorf("DTBGUIDBytes = %x, want %x (mixed-endian of %s)",
			DTBGUIDBytes, want, "b1b621d5-f19c-41a5-830b-d9152c69aae0")
	}
}

func TestErrDTBEmpty_Message(t *testing.T) {
	if !strings.Contains(ErrDTBEmpty.Error(), "empty") {
		t.Errorf("ErrDTBEmpty = %q, expected to mention 'empty'", ErrDTBEmpty.Error())
	}
	if !strings.Contains(ErrDTBEmpty.Error(), "DTB") {
		t.Errorf("ErrDTBEmpty = %q, expected to mention 'DTB'", ErrDTBEmpty.Error())
	}
}

func TestErrInstallConfigTable_Message(t *testing.T) {
	if !strings.Contains(ErrInstallConfigTable.Error(), "InstallConfigurationTable") {
		t.Errorf("ErrInstallConfigTable = %q, expected to mention 'InstallConfigurationTable'", ErrInstallConfigTable.Error())
	}
}
