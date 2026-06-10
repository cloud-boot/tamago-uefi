// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — gBS->InstallConfigurationTable wrapper +
// PublishDTB high-level helper (Phase 2, M8.6). Host-buildable surface
// (types + offsets + errors); live wrapper lives in
// install_config_table_tamago.go.
//
// Reference: EDK2 stable/202408
//   MdePkg/Include/Uefi/UefiSpec.h:
//     EFI_STATUS InstallConfigurationTable(
//         IN EFI_GUID  *Guid,
//         IN VOID      *Table );
//   The slot lives at offset 192 of EFI_BOOT_SERVICES (just before
//   LoadImage at 200 — confirmed against MdePkg's struct order and
//   already cross-referenced in initrd_protocol.go's offset comment).
//
// What PublishDTB does:
//
//   1. Allocates EfiBootServicesData pool memory of the DTB's size via
//      gBS->AllocatePool. Pool memory (not pages) is the right
//      lifetime here: the Linux EFI-stub reads the DTB once during
//      its early-init and copies it into kernel-side storage, after
//      which the firmware-side copy is no longer needed. Pool memory
//      is also released automatically at ExitBootServices, so even
//      if a kernel panics before consuming the DTB we don't leak.
//
//   2. Copies the DTB bytes into the firmware-owned pool.
//
//   3. Calls gBS->InstallConfigurationTable(&EFIDTBTableGUID,
//      poolPtr). The firmware adds/updates the
//      EFI_CONFIGURATION_TABLE entry for the DTB GUID; the next
//      ProbeDTBConfigurationTable call will see it, and so will
//      Linux's EFI-stub when it scans the same table during
//      efi_stub_common entry.
//
// Why pool vs pages: pool memory is appropriate for variable-size
// allocations that don't need page alignment. The DTB is ~10 KiB on
// QEMU virt — under one page — and InstallConfigurationTable only
// requires a stable VOID* with no alignment guarantees beyond
// natural-alignment for the DTB's internal u32/u64 fields (which Go's
// `make([]byte, n)` already satisfies, and AllocatePool inherits from
// the underlying ConventionalMemory backing). Pages would over-
// allocate by a factor of ~3 with no benefit.
//
// This file is host-buildable; the actual gBS call lives in
// install_config_table_tamago.go (gated on the tamago build tag).

package uefiboard

import "errors"

// efiBSInstallConfigurationTable is the function-pointer offset of
// InstallConfigurationTable in EFI_BOOT_SERVICES (UEFI 2.10 §4.2
// table 4.2 + edk2 MdePkg/Include/Uefi/UefiSpec.h struct order):
//
//	152 HandleProtocol             (matches efi_events.go)
//	160 Reserved
//	168 RegisterProtocolNotify
//	176 LocateHandle
//	184 LocateDevicePath
//	192 InstallConfigurationTable  <-- here
//	200 LoadImage                  (matches loadimage.go)
//
// (Cross-referenced in initrd_protocol.go's offset comment — single
// source of truth lives there + here.)
const efiBSInstallConfigurationTable = 192

// EFI_GUID is the Go type the M8.6 InstallConfigurationTable wrapper
// accepts. Same on-wire shape as EFIGUID (see http_protocol.go) but
// declared as a fixed-size byte array because that's what callers
// typically have on hand when they want to pass an opaque
// caller-supplied identity (the spec's struct form has the
// mixed-endian field-by-field decomposition that's awkward to build
// programmatically — a raw `[16]byte` is what every other UEFI
// language binding uses too).
//
// We provide DTBGUIDBytes (below) as the byte-array form of
// EFIDTBTableGUID so the PublishDTB helper can hand it straight to
// InstallConfigurationTable without re-encoding.
type EFI_GUID [16]byte

// DTBGUIDBytes is the byte-array form of EFIDTBTableGUID
// (b1b621d5-f19c-41a5-830b-d9152c69aae0) ready to hand to
// InstallConfigurationTable. RFC 4122 mixed-endian:
//   - Data1 (4 bytes) little-endian: d5 21 b6 b1
//   - Data2 (2 bytes) little-endian: 9c f1
//   - Data3 (2 bytes) little-endian: a5 41
//   - Data4 (8 bytes) raw:           83 0b d9 15 2c 69 aa e0
var DTBGUIDBytes = EFI_GUID{
	0xd5, 0x21, 0xb6, 0xb1, // Data1 LE
	0x9c, 0xf1, // Data2 LE
	0xa5, 0x41, // Data3 LE
	0x83, 0x0b, 0xd9, 0x15, 0x2c, 0x69, 0xaa, 0xe0, // Data4 raw
}

// ErrDTBEmpty is returned by PublishDTB when called with an empty
// DTB slice. The firmware would reject the install or the kernel
// would crash dereferencing the published table, so we surface the
// caller-side bug early.
var ErrDTBEmpty = errors.New("uefi: PublishDTB DTB is empty")

// ErrInstallConfigTable is returned when gBS->InstallConfigurationTable
// returns a non-success EFI_STATUS. Wrapped further as *EFIError by
// the live wrapper.
//
// (Currently unused as a sentinel — the live wrapper returns
// &EFIError{Op: "InstallConfigurationTable"} directly so callers see
// the raw status code; kept here for symmetry with the existing
// sentinel-error pattern.)
var ErrInstallConfigTable = errors.New("uefi: InstallConfigurationTable returned non-success")
