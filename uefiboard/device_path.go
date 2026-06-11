// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — shared device-path constants + protocol GUIDs
// used by multiple publish/filter sites in this package.
//
// History: these symbols originally lived inside initrd_protocol.go
// (M8.2 LoadFile2-publish path). M8.16 (2026-06-11) deleted that whole
// file along with the per-arch asm trampolines once all 4 arches had
// migrated to the cmdline-driven `initrd=<path>` ESP loader
// (uefiboard.InheritParentDeviceHandle, M8.15). The constants below
// survive because block_io_publish_tamago.go + sfs_filter*.go +
// dtb_probe_test.go still need them — they describe firmware-side ABI
// (UEFI 2.10 §10.3 device-path node format, §4.2 BootServices offsets)
// that has nothing inherently to do with the LoadFile2 initrd protocol.
//
// References:
//   - UEFI 2.10 §10.3.1 (device-path node header).
//   - UEFI 2.10 §10.3.5 (MEDIA_DEVICE_PATH; Vendor + End sub-types).
//   - UEFI 2.10 §4.2 (BootServices table layout; protocol-handler
//     offsets).
//   - MdePkg/Include/Protocol/DevicePath.h (edk2.git).
//   - drivers/firmware/efi/libstub/efistub.h (Linux) for
//     LINUX_EFI_INITRD_MEDIA_GUID.

package uefiboard

// LinuxEFIInitrdMediaGUID
//
//	5568e427-68fc-4f3d-ac74-ca555231cc68
//
// The vendor GUID Linux's EFI-stub looks up to find the initrd
// LoadFile2 publisher. cloud-boot no longer publishes such a handle
// (M8.16 deletion) — all 4 arches now hand the initrd over via the
// cmdline `initrd=<path>` token resolved against the inherited parent
// ESP DeviceHandle (M8.15). The GUID constant survives because
// dtb_probe_test.go uses it as a "definitely-not-this-table" sentinel
// when walking gST->ConfigurationTable in the M8.4 probe.
var LinuxEFIInitrdMediaGUID = EFIGUID{
	Data1: 0x5568e427,
	Data2: 0x68fc,
	Data3: 0x4f3d,
	Data4: [8]uint8{0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68},
}

// EFI_DEVICE_PATH_PROTOCOL_GUID
//
//	09576e91-6d3f-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Protocol/DevicePath.h (edk2.git). Used by
// block_io_publish_tamago.go and sfs_filter_tamago.go for
// HandleProtocol + InstallMultipleProtocolInterfaces calls.
var EFIDevicePathProtocolGUID = EFIGUID{
	Data1: 0x09576e91,
	Data2: 0x6d3f,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_DEVICE_PATH_PROTOCOL Type + SubType constants (UEFI 2.10
// §10.3). Used across block_io_publish + sfs_filter:
//   - Type 4    = MEDIA_DEVICE_PATH
//   - SubType 3 = MEDIA_VENDOR_DP (Vendor-Defined Media Device Path)
//   - Type 0x7F = END_DEVICE_PATH_TYPE
//   - SubType 0xFF = END_ENTIRE_DEVICE_PATH_SUBTYPE
//
// devPathSubTypeFilePath (MEDIA_FILEPATH_DP, 0x04) lives in
// loadimage_sfs_tamago.go where it's the only consumer.
const (
	devPathTypeMedia       byte = 0x04
	devPathSubTypeVendor   byte = 0x03
	devPathTypeEnd         byte = 0x7F
	devPathSubTypeEndWhole byte = 0xFF
)

// EFI_BOOT_SERVICES function-pointer offsets for the protocol-handler
// services block. From UEFI 2.10 §4.2 / edk2 MdePkg/Include/Uefi/
// UefiSpec.h:
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
//	312 LocateHandleBuffer    (used by efi_events.go)
//	320 LocateProtocol        (used by efi_events.go)
//	328 InstallMultipleProtocolInterfaces
//	336 UninstallMultipleProtocolInterfaces
const (
	efiBSInstallMultipleProtocolInterfaces   = 328
	efiBSUninstallMultipleProtocolInterfaces = 336
)
