// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// LoadImage via SimpleFileSystem + FilePath — the LoadImage variant
// used by Phase-3 chain-boot.
//
// The existing LoadImage helper in loadimage_tamago.go takes a source
// buffer and passes (BootPolicy=FALSE, ParentImageHandle, DevicePath=
// NULL, SourceBuffer, SourceSize, &outHandle). That shape is fine for
// chain-loading an EFI we already pulled into memory ourselves.
//
// Phase-3 sprint-1 needs the OTHER shape: the firmware reads the EFI
// from a FAT volume via the SimpleFileSystem child handle we just
// discovered with FindSFSChildOf. We construct an EFI_DEVICE_PATH
// that is `<sfs_handle's device path>` ++ FILEPATH(\EFI\BOOT\BOOTX64.EFI)
// ++ END, hand it to gBS->LoadImage with NULL SourceBuffer, and
// firmware-side BdsDxe + LoadImage walk the FS for us.
//
// Why not "read the file into a buffer ourselves and call LoadImage
// with SourceBuffer"? Because the FreeBSD loader.efi keys its
// LoadDevice off the parent-image device path it sees at load time
// (it prints `Load Device: ...` from EFI_LOADED_IMAGE.DeviceHandle and
// then calls fs lookups on that DeviceHandle for kernel/loader.conf).
// If we pre-read the file into RAM, loader.efi's DeviceHandle is
// uninitialised (LoadImage(SourceBuffer != NULL) sets DeviceHandle =
// NULL per UEFI 2.10 §7.4.1) and loader.efi's "Failed to find
// bootable partition" path fires immediately. Going through the
// device-path entry keeps DeviceHandle = our SFS child so loader.efi
// can mount the FAT for its kernel reads.
//
// Reference: UEFI 2.10 §7.4.1, §10.3.5.4 (FILEPATH_DEVICE_PATH),
// MdeModulePkg/Core/Dxe/Image/Image.c CoreLoadImage.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"errors"
	"unsafe"
)

// MEDIA_FILEPATH_DP subtype (UEFI 2.10 §10.3.5.4 table 10.13):
//
//	struct EFI_DEVICE_PATH_PROTOCOL {
//	    UINT8  Type;       // 0x04 MEDIA_DEVICE_PATH
//	    UINT8  SubType;    // 0x04 MEDIA_FILEPATH_DP
//	    UINT8  Length[2];  // total bytes including the trailing UCS-2 \0
//	    CHAR16 PathName[]; // null-terminated UCS-2
//	};
const devPathSubTypeFilePath byte = 0x04

// buildFilePathDevicePath constructs the bytes for a 1-FILEPATH-node
// device path:
//
//	parentBytes (without its END node)
//	  ++ FILEPATH( UCS-2 efiPath ++ "\0" )
//	  ++ END
//
// The caller passes the parent device path *as returned by
// FindSFSChildOf* — i.e. WITH its trailing END node. We trim that
// END internally so the assembled path is well-formed.
//
// efiPath uses backslashes per UEFI fileselects (no leading `/`).
func buildFilePathDevicePath(parent []byte, efiPath string) ([]byte, error) {
	if len(parent) < 4 {
		return nil, errors.New("uefi: parent device path too short")
	}
	endIdx := len(parent) - 4
	if parent[endIdx] != devPathTypeEnd || parent[endIdx+1] != devPathSubTypeEndWhole {
		return nil, errors.New("uefi: parent device path not END-terminated")
	}
	// UCS-2 encode the path with a trailing NUL.
	ucs2 := make([]byte, 0, 2*(len(efiPath)+1))
	for _, r := range efiPath {
		if r > 0xFFFF {
			return nil, errors.New("uefi: filepath contains non-BMP char")
		}
		ucs2 = append(ucs2, byte(r), byte(r>>8))
	}
	ucs2 = append(ucs2, 0x00, 0x00) // NUL terminator
	// FILEPATH node header: type+subtype+length(2) = 4 bytes + UCS-2.
	ln := uint16(4 + len(ucs2))
	node := []byte{devPathTypeMedia, devPathSubTypeFilePath, byte(ln), byte(ln >> 8)}
	node = append(node, ucs2...)
	end := []byte{devPathTypeEnd, devPathSubTypeEndWhole, 0x04, 0x00}
	out := make([]byte, 0, endIdx+int(ln)+4)
	out = append(out, parent[:endIdx]...)
	out = append(out, node...)
	out = append(out, end...)
	return out, nil
}

// LoadImageFromSFS calls gBS->LoadImage with a synthetic device path
// pointing at <efiPath> on the volume whose parent device path is
// `sfsParentDevicePath`. The parent device path is what FindSFSChildOf
// hands us — it already terminates with END, we re-stitch internally.
//
// Returns the new image handle on success. The image is NOT started
// — callers chase up with StartImage(h) when ready.
//
// On EDK2 reference firmware (OVMF used in our live tests) this is
// the call that takes us from "FAT is mounted as an SFS child handle"
// to "the FreeBSD loader.efi is loaded with its DeviceHandle pointing
// at the FAT, ready to walk \boot for the kernel".
func LoadImageFromSFS(sfsParentDevicePath []byte, efiPath string) (uintptr, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	if imageHandle == 0 {
		return 0, ErrNoBootServices
	}
	dp, err := buildFilePathDevicePath(sfsParentDevicePath, efiPath)
	if err != nil {
		return 0, err
	}
	// Keep the DP backing slice alive until LoadImage returns. We
	// declare a local var rather than relying on the temp because
	// efiCall takes uint64s; the GC needs a typed reference.
	dpKA := dp
	var child uint64
	status := efiCall(
		bs+efiBSLoadImage,
		0,                                              // BootPolicy = FALSE
		imageHandle,                                    // ParentImageHandle
		uint64(uintptr(unsafe.Pointer(&dpKA[0]))),      // DevicePath
		0,                                              // SourceBuffer = NULL
		0,                                              // SourceSize   = 0
		uint64(uintptr(unsafe.Pointer(&child))),
	)
	// Defeat the unused-write warning the compiler would otherwise
	// emit for dpKA after the efiCall — we explicitly want to keep the
	// slice live across the call.
	_ = dpKA
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "LoadImage(SFS+FilePath)"}
	}
	return uintptr(child), nil
}
