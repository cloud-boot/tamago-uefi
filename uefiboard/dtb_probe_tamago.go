// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — live walker of EFI_SYSTEM_TABLE's
// ConfigurationTable to detect a firmware-published DTB (Phase 2,
// M8.4). Host-side surface + GUID + types live in dtb_probe.go.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// ProbeDTBConfigurationTable scans gST->ConfigurationTable looking
// for an entry whose VendorGuid matches EFIDTBTableGUID. Returns a
// populated DTBProbeResult — never an error: the walk is purely
// in-memory off the captured SystemTable pointer, so the only
// failure mode is "no SystemTable" which is communicated via the
// SystemTablePresent flag.
//
// Called by phase2_oci_kernel_boot.go's MODE C just before
// StartImage on arm64+riscv64 to confirm the kernel's EFI-stub will
// find a DTB without us having to publish one ourselves. On EDK2
// stable202408 + QEMU virt (the M8.4 acceptance target) this returns
// DTBFound=true; on platforms where the firmware doesn't already
// publish a DTB the caller can either (a) accept the consequences
// (the kernel prints "Generating empty DTB" and either panics or
// limps along with no devicetree information) or (b) publish one
// itself via a future PublishDTB helper (M8.5+).
func ProbeDTBConfigurationTable() DTBProbeResult {
	var r DTBProbeResult
	if systemTable == 0 {
		return r
	}
	r.SystemTablePresent = true

	// gST->NumberOfTableEntries (UINTN @ offset 104) and gST->
	// ConfigurationTable (EFI_CONFIGURATION_TABLE* @ offset 112).
	stPtr := uintptr(systemTable)
	n := *(*uintptr)(unsafe.Pointer(stPtr + efiSTNumberOfTableEntries))
	cfgTbl := *(*uintptr)(unsafe.Pointer(stPtr + efiSTConfigurationTable))
	r.NumberOfTableEntries = n
	if n == 0 || cfgTbl == 0 {
		return r
	}

	// Walk n entries of size 24 bytes each (GUID + VOID*). Capture
	// every GUID into r.AllGUIDs as we go — when DTBFound stays
	// false, the dump is the only way to see what the firmware
	// actually exposed (ACPI? SMBIOS? FDT under a different GUID?).
	for i := uintptr(0); i < n; i++ {
		entry := cfgTbl + i*efiConfigurationTableEntrySize
		// VendorGuid is the first 16 bytes; read as an EFIGUID by
		// casting the entry pointer. Safe because EFIGUID has the
		// same on-wire layout as EFI_GUID (verified by the host-side
		// tests in efi_events_test.go).
		g := (*EFIGUID)(unsafe.Pointer(entry))
		r.AllGUIDs = append(r.AllGUIDs, *g)
		if guidsEqual(g, &EFIDTBTableGUID) {
			// VendorTable is the 8 bytes at offset 16.
			vt := *(*uintptr)(unsafe.Pointer(entry + 16))
			r.DTBFound = true
			r.DTBVendorTable = vt
			// Don't return early — continue to capture remaining
			// GUIDs into AllGUIDs for the diagnostic dump.
		}
	}
	return r
}
