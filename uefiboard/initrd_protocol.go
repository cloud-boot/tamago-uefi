// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_LOAD_FILE2_PROTOCOL under the Linux
// initrd vendor GUID (Phase 2, M8.2).
//
// What this is: the publish-side of the Linux EFI initrd handoff
// protocol. Documentation/admin-guide/efi-stub.rst (Linux) describes
// it: the EFI-stub locates a handle that publishes
// EFI_LOAD_FILE2_PROTOCOL under the LINUX_EFI_INITRD_MEDIA_GUID
// device-path, then calls LoadFile2->LoadFile twice — first with a
// NULL Buffer + &BufferSize to learn the size, second with an
// AllocatePages'd Buffer big enough to hold the initrd. We publish
// such a handle backed by an in-memory initrd byte slice.
//
// References:
//   - Documentation/admin-guide/efi-stub.rst (Linux upstream, EFI
//     stub command-line / initrd handoff section).
//   - drivers/firmware/efi/libstub/efi-stub-helper.c (Linux), see
//     efi_load_initrd_dev_path() — the consumer side, including the
//     two-call protocol (size query, then transfer).
//   - https://lore.kernel.org/all/20200818133104.22072-1-ardb@kernel.org/
//     (the patch series that introduced the protocol — canonical
//     reference for the device-path + GUID + call shape).
//
// This file is host-buildable (no //go:build tamago) so the helper
// types, GUID layout, and device-path constructor are unit-testable
// without going anywhere near firmware. The live wrapper that
// actually calls gBS->InstallMultipleProtocolInterfaces lives in
// initrd_protocol_tamago.go.

package uefiboard

import "errors"

// LinuxEFIInitrdMediaGUID
//
//	5568e427-68fc-4f3d-ac74-ca555231cc68
//
// The vendor GUID Linux's EFI-stub looks up to find the initrd
// LoadFile2 publisher. Source: drivers/firmware/efi/libstub/
// efistub.h (LINUX_EFI_INITRD_MEDIA_GUID) and the patch series cited
// in the file header.
var LinuxEFIInitrdMediaGUID = EFIGUID{
	Data1: 0x5568e427,
	Data2: 0x68fc,
	Data3: 0x4f3d,
	Data4: [8]uint8{0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68},
}

// EFI_LOAD_FILE2_PROTOCOL_GUID
//
//	4006c0c1-fcb3-403e-996d-4a6c8724e06d
//
// Source: MdePkg/Include/Protocol/LoadFile2.h (edk2.git).
var EFILoadFile2ProtocolGUID = EFIGUID{
	Data1: 0x4006c0c1,
	Data2: 0xfcb3,
	Data3: 0x403e,
	Data4: [8]uint8{0x99, 0x6d, 0x4a, 0x6c, 0x87, 0x24, 0xe0, 0x6d},
}

// EFI_DEVICE_PATH_PROTOCOL_GUID
//
//	09576e91-6d3f-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Protocol/DevicePath.h (edk2.git). The handle
// we install MUST publish a device path so the EFI-stub can find it
// via LocateDevicePath(LINUX_EFI_INITRD_MEDIA_GUID).
var EFIDevicePathProtocolGUID = EFIGUID{
	Data1: 0x09576e91,
	Data2: 0x6d3f,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_DEVICE_PATH_PROTOCOL Type + SubType constants (UEFI 2.10
// §10.3). We only use:
//   - Type 4  = MEDIA_DEVICE_PATH
//   - SubType 3 = MEDIA_VENDOR_DP (Vendor-Defined Media Device Path)
//   - Type 0x7F = END_DEVICE_PATH_TYPE
//   - SubType 0xFF = END_ENTIRE_DEVICE_PATH_SUBTYPE
const (
	devPathTypeMedia       byte = 0x04
	devPathSubTypeVendor   byte = 0x03
	devPathTypeEnd         byte = 0x7F
	devPathSubTypeEndWhole byte = 0xFF
)

// EFI_BOOT_SERVICES function-pointer offset for
// InstallMultipleProtocolInterfaces. From UEFI 2.10 §4.2 / edk2
// MdePkg/Include/Uefi/UefiSpec.h. The protocol-handler services
// block starts at offset 128 (InstallProtocolInterface) and lays out:
//
//	128 InstallProtocolInterface
//	136 ReinstallProtocolInterface
//	144 UninstallProtocolInterface
//	152 HandleProtocol
//	160 Reserved
//	168 RegisterProtocolNotify
//	176 LocateHandle
//	184 LocateDevicePath
//	192 InstallConfigurationTable
//	200 LoadImage
//	... [image services] ...
//	304 ConnectController
//	312 LocateHandleBuffer    (already in efi_events.go)
//	320 LocateProtocol        (already in efi_events.go)
//	328 InstallMultipleProtocolInterfaces    <-- here
//	336 UninstallMultipleProtocolInterfaces  <-- here
const (
	efiBSInstallMultipleProtocolInterfaces   = 328
	efiBSUninstallMultipleProtocolInterfaces = 336
)

// ErrEmptyInitrd is returned by PublishInitrd when called with no
// initrd bytes — the EFI-stub would refuse to boot off a zero-byte
// initrd anyway, so we surface the caller bug early instead of
// installing a useless protocol instance.
var ErrEmptyInitrd = errors.New("uefi: PublishInitrd initrd is empty")

// ErrInitrdNotPublished is returned by UnpublishInitrd when called
// with a zero handle — i.e. PublishInitrd was never called, or has
// already been undone.
var ErrInitrdNotPublished = errors.New("uefi: initrd handle is zero (not published or already unpublished)")

// EFIDevicePathNode is the spec-aligned head of every device-path
// node (UEFI 2.10 §10.3.1 table 10.5):
//
//	UINT8  Type;
//	UINT8  SubType;
//	UINT8  Length[2]; // little-endian, total bytes of THIS node
//
// — followed by SubType-specific payload bytes. Exposed as a Go
// struct for clarity at the test layer; the live protocol-install
// path serialises directly via the byte builders below.
type EFIDevicePathNode struct {
	Type    byte
	SubType byte
	Length  uint16
}

// buildInitrdDevicePath constructs the 1-node MEDIA_VENDOR device
// path + END node that publishInitrd installs alongside the
// LoadFile2 protocol. The Vendor node carries the
// LINUX_EFI_INITRD_MEDIA_GUID; the END node terminates the path.
//
// Layout (24 bytes total):
//
//	Vendor node (20 bytes):
//	  +00  Type    = 0x04 (MEDIA_DEVICE_PATH)
//	  +01  SubType = 0x03 (MEDIA_VENDOR_DP)
//	  +02  Length  = 0x0014 (20, LE) — header (4) + GUID (16)
//	  +04  Guid    = LINUX_EFI_INITRD_MEDIA_GUID (16 bytes,
//	                 mixed-endian per RFC 4122)
//	End node (4 bytes):
//	  +14  Type    = 0x7F
//	  +15  SubType = 0xFF
//	  +16  Length  = 0x0004 (4, LE)
//
// (Linux's drivers/firmware/efi/libstub/efi-stub-helper.c emits
// exactly this 20+4 byte sequence — confirmed against upstream's
// `static const struct { ... } efi_initrd_dev_path` for v5.10+.)
//
// Returned as a Go byte slice so the caller (the tamago publish
// path) can take &buf[0] and pass it to gBS->Install... directly.
func buildInitrdDevicePath() []byte {
	out := make([]byte, 0, 24)
	// Vendor node header. Length = 4 (header) + 16 (GUID) = 20.
	out = append(out, devPathTypeMedia, devPathSubTypeVendor)
	out = append(out, 0x14, 0x00) // length = 20 LE
	// Vendor GUID payload. EFIGUID is mixed-endian per RFC 4122:
	// Data1/Data2/Data3 are little-endian, Data4 is raw bytes.
	g := LinuxEFIInitrdMediaGUID
	out = append(out,
		byte(g.Data1), byte(g.Data1>>8), byte(g.Data1>>16), byte(g.Data1>>24),
		byte(g.Data2), byte(g.Data2>>8),
		byte(g.Data3), byte(g.Data3>>8),
	)
	out = append(out, g.Data4[:]...)
	// END node.
	out = append(out, devPathTypeEnd, devPathSubTypeEndWhole)
	out = append(out, 0x04, 0x00) // length = 4 LE
	return out
}

// EFILoadFile2Protocol is the Go view of the EFI_LOAD_FILE2_PROTOCOL
// firmware-exposed struct. Per the protocol definition (UEFI 2.10
// §13.5; LoadFile is the same shape as LoadFile, but invoked when
// BootPolicy=FALSE — load by file-path-not-by-boot-manager):
//
//	typedef struct {
//	    EFI_LOAD_FILE LoadFile;
//	} EFI_LOAD_FILE2_PROTOCOL;
//
// Just a single function-pointer slot. We allocate it in package
// memory (a global on tamago) so the firmware can hold a stable
// pointer for the lifetime of the published handle.
type EFILoadFile2Protocol struct {
	LoadFile uint64 // firmware-callable function pointer, MS x64 / AAPCS64 / LP64 ABI
}
