// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — Device-Tree-Blob (DTB) ConfigurationTable
// probe (Phase 2, M8.4).
//
// What this is: the read-side query helper that asks the firmware
// "do you already publish a flattened DTB under
// EFI_DTB_TABLE_GUID?". On arm64 + riscv64 QEMU virt with EDK2 OVMF,
// the answer is "yes" — EDK2 picks up the QEMU-provided DTB at
// platform-init and registers it via gBS->InstallConfigurationTable
// so the Linux EFI-stub can find it automatically (per
// Documentation/admin-guide/efi-stub.rst and
// drivers/firmware/efi/libstub/fdt.c::efi_get_fdt() in upstream
// Linux). If we confirm the entry is present, MODE C needs to do
// nothing for DTB — the kernel's EFI-stub already retrieves it
// via gST->ConfigurationTable iteration.
//
// What this is NOT: the publish-side. M8.4 does NOT install a DTB
// itself — that would require either a `-dtb` flag at QEMU launch
// time or carving a DTB from the host's `qemu -machine virt
// dumpdtb=…` output, neither of which is on the M8.4 critical path.
// If a future M8.x needs to publish, it would call
// gBS->InstallConfigurationTable(&EFIDTBTableGUID, &dtbBytes[0])
// with appropriately-typed memory.
//
// References:
//   - UEFI 2.10 §4.6 (Configuration Table Walks).
//   - EDK2 ArmVirtPkg/Library/PlatformBootManagerLib (which calls
//     `gBS->InstallConfigurationTable(&gFdtTableGuid, ...)` after
//     copying QEMU's DTB into firmware-owned pages).
//   - Linux drivers/firmware/efi/libstub/fdt.c::efi_get_fdt() — the
//     consumer side: scans gST->ConfigurationTable for the DTB GUID
//     before falling back to "Generating empty DTB".
//   - The DTB GUID itself (b1b621d5-f19c-41a5-830b-d9152c69aae0) is
//     pinned in MdePkg/Include/Guid/Fdt.h.
//
// This file is host-buildable (no //go:build tamago) so the GUID
// + Go-side table-entry struct can be unit-tested without going
// anywhere near firmware. The live walker lives in
// dtb_probe_tamago.go.

package uefiboard

// EFIDTBTableGUID
//
//	b1b621d5-f19c-41a5-830b-d9152c69aae0
//
// The vendor GUID under which EDK2 (and any other UEFI firmware that
// supports the Linux EFI-stub DTB protocol) registers the flattened
// Device Tree Blob via gBS->InstallConfigurationTable. Linux's
// EFI-stub scans gST->ConfigurationTable for this GUID at startup
// (drivers/firmware/efi/libstub/fdt.c::efi_get_fdt).
//
// Source: MdePkg/Include/Guid/Fdt.h (edk2.git).
var EFIDTBTableGUID = EFIGUID{
	Data1: 0xb1b621d5,
	Data2: 0xf19c,
	Data3: 0x41a5,
	Data4: [8]uint8{0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0},
}

// EFI_SYSTEM_TABLE field offsets used by the DTB walker. The full
// table layout (UEFI 2.10 §4.3.1 + edk2 MdePkg/Include/Uefi/
// UefiSpec.h::EFI_SYSTEM_TABLE) is:
//
//	+000  EFI_TABLE_HEADER Hdr      (24 bytes)
//	+024  CHAR16          *FirmwareVendor
//	+032  UINT32           FirmwareRevision (+4 pad to natural-align next pointer)
//	+040  EFI_HANDLE       ConsoleInHandle
//	+048  EFI_SIMPLE_TEXT_INPUT_PROTOCOL  *ConIn
//	+056  EFI_HANDLE       ConsoleOutHandle
//	+064  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut   <-- already used by board.go
//	+072  EFI_HANDLE       StandardErrorHandle
//	+080  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *StdErr
//	+088  EFI_RUNTIME_SERVICES *RuntimeServices
//	+096  EFI_BOOT_SERVICES    *BootServices         <-- already used by memorymap_tamago.go
//	+104  UINTN                 NumberOfTableEntries
//	+112  EFI_CONFIGURATION_TABLE *ConfigurationTable
//
// (Confirmed against EDK2 stable202408's typedef on arm64 + amd64.)
const (
	efiSTNumberOfTableEntries = 104
	efiSTConfigurationTable   = 112
)

// efiConfigurationTableEntrySize is the on-wire size of one
// EFI_CONFIGURATION_TABLE entry (UEFI 2.10 §4.6, table 4.5):
//
//	typedef struct {
//	    EFI_GUID  VendorGuid;     // 16 bytes
//	    VOID     *VendorTable;    // 8 bytes on every LP64 UEFI arch
//	} EFI_CONFIGURATION_TABLE;
//
// Total 24 bytes. No firmware-private trailing fields are permitted
// in this struct (unlike EFI_MEMORY_DESCRIPTOR), so the stride is
// fixed.
const efiConfigurationTableEntrySize = 24

// DTBProbeResult captures the outcome of ProbeDTBConfigurationTable.
// All fields populated even when the DTB GUID isn't found (so the
// caller can log the total table size as a sanity check on the
// SystemTable walker itself).
type DTBProbeResult struct {
	// SystemTablePresent is true if the captured systemTable global
	// is non-zero — i.e. cpuinit ran and gave us a SystemTable
	// pointer to walk.
	SystemTablePresent bool

	// NumberOfTableEntries is the firmware-reported count of
	// EFI_CONFIGURATION_TABLE entries in gST->ConfigurationTable.
	// Useful as a "did we walk anything at all" sanity check; on
	// EDK2 stable202408 + QEMU virt this is 5..10 typical.
	NumberOfTableEntries uintptr

	// DTBFound is true if at least one entry's VendorGuid matched
	// EFIDTBTableGUID. The kernel EFI-stub will then auto-locate the
	// DTB via this same protocol — MODE C doesn't need to publish.
	DTBFound bool

	// DTBVendorTable is the pointer the matching entry carries —
	// i.e. the physical address of the FDT blob's first byte if
	// the firmware obeyed the protocol. Zero when DTBFound is false.
	// Exposed for diagnostics; consumers (the kernel EFI-stub) walk
	// the ConfigurationTable themselves, they don't take this from us.
	DTBVendorTable uintptr
}

// guidsEqual returns true when two EFIGUIDs encode the same 128-bit
// identity. Inlined-friendly equality, no reflection, no allocations.
//
// Exported package-private (lower-case) so the dtb_probe_tamago.go
// walker — and the host-side unit tests — share the implementation.
func guidsEqual(a, b *EFIGUID) bool {
	if a.Data1 != b.Data1 || a.Data2 != b.Data2 || a.Data3 != b.Data3 {
		return false
	}
	for i := 0; i < 8; i++ {
		if a.Data4[i] != b.Data4[i] {
			return false
		}
	}
	return true
}
