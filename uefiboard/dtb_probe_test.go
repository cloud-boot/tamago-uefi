// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.4 DTB ConfigurationTable probe.
// The live walker lives in dtb_probe_tamago.go and runs under
// QEMU+EDK2; here we cover the host-buildable bits:
//
//  1. EFIDTBTableGUID matches the spec-pinned textual form
//     (b1b621d5-f19c-41a5-830b-d9152c69aae0).
//  2. guidsEqual returns true for identical GUIDs and false for any
//     single-bit difference.
//  3. Field offset constants match UEFI 2.10 §4.3.1.

package uefiboard

import "testing"

func TestEFIDTBTableGUID(t *testing.T) {
	want := guidFromText(t, "b1b621d5-f19c-41a5-830b-d9152c69aae0")
	if EFIDTBTableGUID != want {
		t.Errorf("EFIDTBTableGUID = %+v, want %+v", EFIDTBTableGUID, want)
	}
}

func TestGuidsEqual(t *testing.T) {
	g := EFIDTBTableGUID
	if !guidsEqual(&g, &EFIDTBTableGUID) {
		t.Error("guidsEqual on identical GUIDs returned false")
	}
	// Flip one bit in Data1.
	g2 := EFIDTBTableGUID
	g2.Data1 ^= 1
	if guidsEqual(&g2, &EFIDTBTableGUID) {
		t.Error("guidsEqual returned true on Data1-differing GUIDs")
	}
	// Flip one bit in Data4[7].
	g3 := EFIDTBTableGUID
	g3.Data4[7] ^= 1
	if guidsEqual(&g3, &EFIDTBTableGUID) {
		t.Error("guidsEqual returned true on Data4[7]-differing GUIDs")
	}
	// Different family GUID entirely.
	if guidsEqual(&EFIDTBTableGUID, &LinuxEFIInitrdMediaGUID) {
		t.Error("guidsEqual returned true on disjoint GUIDs")
	}
}

func TestSystemTableOffsetsMatchSpec(t *testing.T) {
	// UEFI 2.10 §4.3.1 / EDK2 MdePkg/Include/Uefi/UefiSpec.h.
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"NumberOfTableEntries", efiSTNumberOfTableEntries, 104},
		{"ConfigurationTable", efiSTConfigurationTable, 112},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestConfigurationTableEntrySize(t *testing.T) {
	// 16-byte VendorGuid + 8-byte VendorTable on LP64 UEFI = 24.
	if efiConfigurationTableEntrySize != 24 {
		t.Errorf("efiConfigurationTableEntrySize = %d, want 24",
			efiConfigurationTableEntrySize)
	}
}
