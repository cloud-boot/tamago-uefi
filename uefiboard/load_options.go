// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_LOADED_IMAGE_PROTOCOL.LoadOptions
// helper (Phase 2, M8.2).
//
// Linux's EFI-stub reads its kernel command line from the
// LoadOptions field of its own image's EFI_LOADED_IMAGE_PROTOCOL
// instance (encoded as a UCS-2 / UTF-16 LE NUL-terminated string).
// This helper installs the bytes there AFTER LoadImage returned the
// child image handle but BEFORE StartImage transfers control to it.
//
// Reference: UEFI 2.10 §9.2 table 9.4 (EFI_LOADED_IMAGE_PROTOCOL):
//
//	typedef struct {
//	    UINT32                    Revision;        // 0
//	    EFI_HANDLE                ParentHandle;    // 8
//	    EFI_SYSTEM_TABLE         *SystemTable;     // 16
//	    EFI_HANDLE                DeviceHandle;    // 24
//	    EFI_DEVICE_PATH_PROTOCOL *FilePath;        // 32
//	    VOID                     *Reserved;        // 40
//	    UINT32                    LoadOptionsSize; // 48 (UINT32)
//	    VOID                     *LoadOptions;     // 56 (VOID*)
//	    VOID                     *ImageBase;       // 64
//	    UINT64                    ImageSize;       // 72
//	    EFI_MEMORY_TYPE           ImageCodeType;   // 80 (UINT32)
//	    EFI_MEMORY_TYPE           ImageDataType;   // 84 (UINT32)
//	    EFI_IMAGE_UNLOAD          Unload;          // 88
//	} EFI_LOADED_IMAGE_PROTOCOL;
//
// LP64-on-64-bit: each pointer is 8 bytes, every UINT32 is 4 bytes
// with C-struct natural alignment — so LoadOptionsSize sits at byte
// offset 48 (UINT32) and LoadOptions at offset 56 (pointer). The
// brief's "56 / 64" numbering assumed LoadOptionsSize was placed at
// offset 56; the canonical edk2 layout (and MdePkg/Include/Protocol/
// LoadedImage.h) places it at 48 (after a UINT32 Revision that
// dual-aligns the following ParentHandle pointer on the natural
// 8-byte boundary). We use the canonical numbers below.

package uefiboard

import "errors"

// EFI_LOADED_IMAGE_PROTOCOL field offsets on every 64-bit UEFI arch
// (UEFI 2.10 §9.2 table 9.4 / edk2 MdePkg/Include/Protocol/
// LoadedImage.h). Annotated above; the two fields the cmdline path
// touches are LoadOptionsSize (UINT32 @ 48) and LoadOptions (VOID* @
// 56). All other fields are read-only from a child-image perspective
// and we do not touch them.
const (
	efiLoadedImageRevision        = 0
	efiLoadedImageParentHandle    = 8
	efiLoadedImageSystemTable     = 16
	efiLoadedImageDeviceHandle    = 24
	efiLoadedImageFilePath        = 32
	efiLoadedImageReserved        = 40
	efiLoadedImageLoadOptionsSize = 48
	efiLoadedImageLoadOptions     = 56
	efiLoadedImageImageBase       = 64
	efiLoadedImageImageSize       = 72
	efiLoadedImageImageCodeType   = 80
	efiLoadedImageImageDataType   = 84
	efiLoadedImageUnload          = 88
)

// EFI_LOADED_IMAGE_PROTOCOL_GUID
//
//	5b1b31a1-9562-11d2-8e3f-00a0c969723b
//
// Source: MdePkg/Include/Protocol/LoadedImage.h (edk2.git). This is
// the GUID HandleProtocol uses to fetch the LoadedImageProtocol view
// of an image handle.
var EFILoadedImageProtocolGUID = EFIGUID{
	Data1: 0x5b1b31a1,
	Data2: 0x9562,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_BOOT_SERVICES function-pointer offset for AllocatePool. Used by
// SetLoadOptions to allocate the firmware-owned buffer the kernel
// EFI-stub will read its cmdline out of. The slot order is:
//
//	56  GetMemoryMap
//	64  AllocatePool      <-- here
//	72  FreePool
//
// (see memorymap.go's comment block).
const (
	efiBSAllocatePool = 64
	efiBSFreePool     = 72
)

// ErrEmptyCmdline is returned by SetLoadOptions when called with an
// empty cmdline. The Linux EFI-stub treats a NUL-terminated empty
// string identically to "no LoadOptions installed" — so the
// host-side guard treats the call as a no-op caller bug instead of
// allocating a 2-byte (NUL only) firmware buffer.
var ErrEmptyCmdline = errors.New("uefi: SetLoadOptions cmdline is empty")

// ErrNilHandle is returned by SetLoadOptions when called with a zero
// image handle. UEFI's HandleProtocol rejects a NULL handle with
// EFI_INVALID_PARAMETER; surfacing it here gives the caller a
// recognisable Go error instead of an opaque EFI_STATUS hex.
var ErrNilHandle = errors.New("uefi: image handle is zero")

// utf16LECmdline encodes a Go string into a UTF-16 LE byte slice
// terminated with a U+0000 NUL code unit (2-byte trailer). The
// returned length is the in-buffer byte count INCLUDING the NUL
// trailer — i.e. exactly what LoadedImage.LoadOptionsSize must be set
// to (UEFI 2.10 §9.2 specifies the size in BYTES, not code units).
//
// Encoding strategy: pure ASCII fast-path (cmdline is typically all
// ASCII — `console=ttyS0 root=...` etc), with a UTF-8 → UCS-2
// fallback that surrogate-pairs anything in the supplementary planes
// (U+10000..U+10FFFF). Non-ASCII Linux cmdlines are exotic but the
// EFI-stub does accept them (per Documentation/admin-guide/efi-stub.rst
// the cmdline is parsed as UTF-16 throughout).
//
// Exposed package-private so the host-side test can verify the
// encoding without going anywhere near firmware.
func utf16LECmdline(s string) []byte {
	// Pre-size: most ASCII strings produce 2*len(s) + 2 bytes.
	// Strings with supplementary-plane runes use 4 bytes for those.
	// Worst case (all U+10000+): 4*len(runes) + 2. The append below
	// grows on demand so the initial capacity is just a hint.
	buf := make([]byte, 0, 2*len(s)+2)
	for _, r := range s {
		switch {
		case r < 0x10000 && (r < 0xD800 || r > 0xDFFF):
			// BMP code unit, not a surrogate half. Direct emit.
			buf = append(buf, byte(r&0xFF), byte((r>>8)&0xFF))
		case r >= 0x10000 && r <= 0x10FFFF:
			// Supplementary plane — emit as a UTF-16 surrogate
			// pair (UAX #15, RFC 2781).
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			buf = append(buf,
				byte(hi&0xFF), byte((hi>>8)&0xFF),
				byte(lo&0xFF), byte((lo>>8)&0xFF),
			)
		default:
			// Invalid rune (lone surrogate, or > U+10FFFF) — emit
			// U+FFFD REPLACEMENT CHARACTER. EFI-stub will treat it
			// as a single unrecognised token; this is preferable to
			// silently dropping the byte.
			buf = append(buf, 0xFD, 0xFF)
		}
	}
	// UTF-16 LE NUL terminator (two zero bytes).
	buf = append(buf, 0x00, 0x00)
	return buf
}
