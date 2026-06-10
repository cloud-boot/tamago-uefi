// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side unit tests for the M8.6 fw_cfg DTB fetcher. The live
// MMIO walker lives in dtb_fetch_tamago.go and runs under
// QEMU+EDK2; here we cover the host-buildable bits:
//
//  1. FetchQemuDTB on the host returns ErrNotImplementedOnHost (the
//     host stub fires before any MMIO access).
//  2. fwCfgParseFileDirEntry decodes a known-good entry correctly
//     (size, select, name).
//  3. fwCfgParseFileDirEntry NUL-terminates the name on a padded
//     entry, and on a fully-padded entry returns "".
//  4. fwCfgParseFileDirEntry rejects a short buffer with all zero
//     fields.
//  5. The FW_CFG constants match QEMU's spec-pinned values.
//  6. Error message strings carry the relevant keyword (sanity check
//     against a future typo regressing the surfaced log line).

package uefiboard

import (
	"strings"
	"testing"
)

func TestFetchQemuDTB_HostStub(t *testing.T) {
	dtb, err := FetchQemuDTB()
	if err != ErrNotImplementedOnHost {
		t.Errorf("FetchQemuDTB host: err = %v, want ErrNotImplementedOnHost", err)
	}
	if dtb != nil {
		t.Errorf("FetchQemuDTB host: dtb = %v, want nil", dtb)
	}
}

func TestFwCfgParseFileDirEntry_EtcFdt(t *testing.T) {
	// Synthetic entry: size=0x00002A30 (10800 bytes — typical QEMU
	// virt DTB), select=0x002A, reserved=0, name="etc/fdt".
	var raw [FwCfgFileEntrySize]byte
	// size BE: 00 00 2a 30
	raw[0] = 0x00
	raw[1] = 0x00
	raw[2] = 0x2a
	raw[3] = 0x30
	// select BE: 00 2a
	raw[4] = 0x00
	raw[5] = 0x2a
	// reserved: 00 00 (left as zero).
	// name: "etc/fdt" + NUL padding.
	copy(raw[8:], "etc/fdt")

	size, sel, name := fwCfgParseFileDirEntry(raw[:])
	if size != 0x00002A30 {
		t.Errorf("size = 0x%x, want 0x2A30", size)
	}
	if sel != 0x002A {
		t.Errorf("select = 0x%x, want 0x2A", sel)
	}
	if name != FwCfgFDTName {
		t.Errorf("name = %q, want %q", name, FwCfgFDTName)
	}
}

func TestFwCfgParseFileDirEntry_FullyPaddedName(t *testing.T) {
	// All-zero entry: parser should report empty name (NUL at index 0).
	var raw [FwCfgFileEntrySize]byte
	_, _, name := fwCfgParseFileDirEntry(raw[:])
	if name != "" {
		t.Errorf("all-zero entry: name = %q, want \"\"", name)
	}
}

func TestFwCfgParseFileDirEntry_ShortBuffer(t *testing.T) {
	// 63 bytes is one short — parser must return zero values
	// rather than indexing out of bounds.
	raw := make([]byte, FwCfgFileEntrySize-1)
	size, sel, name := fwCfgParseFileDirEntry(raw)
	if size != 0 || sel != 0 || name != "" {
		t.Errorf("short buffer: got (size=%d, sel=%d, name=%q); want zero values", size, sel, name)
	}
}

func TestFwCfgConstants(t *testing.T) {
	// Pinned against QEMU docs/specs/fw_cfg.rst + hw/arm/virt.c.
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"FwCfgArm64MMIOBase", FwCfgArm64MMIOBase, 0x09020000},
		{"FwCfgDataPort", uint64(FwCfgDataPort), 0x00},
		{"FwCfgSelectorPort", uint64(FwCfgSelectorPort), 0x08},
		{"FwCfgSelectorFileDir", uint64(FwCfgSelectorFileDir), 0x0019},
		{"FwCfgFileEntrySize", uint64(FwCfgFileEntrySize), 64},
		{"FwCfgFileNameSize", uint64(FwCfgFileNameSize), 56},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%x, want 0x%x", c.name, c.got, c.want)
		}
	}
	if FwCfgFDTName != "etc/fdt" {
		t.Errorf("FwCfgFDTName = %q, want %q", FwCfgFDTName, "etc/fdt")
	}
}

func TestFwCfgErrorMessages(t *testing.T) {
	cases := []struct {
		err    error
		needle string
	}{
		{ErrNotImplementedOnHost, "FetchQemuDTB"},
		{ErrFwCfgDTBNotFound, "etc/fdt"},
		{ErrFwCfgDTBTooLarge, "FwCfgMaxFDTSize"},
		{ErrFwCfgEmptyFileDir, "zero entries"},
		{ErrFwCfgUnsupportedArch, "MMIO base"},
	}
	for _, c := range cases {
		if c.err == nil {
			t.Errorf("error is nil; expected to mention %q", c.needle)
			continue
		}
		if !strings.Contains(c.err.Error(), c.needle) {
			t.Errorf("err = %q, expected to contain %q", c.err.Error(), c.needle)
		}
	}
}
