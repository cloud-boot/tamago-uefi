// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — SetLoadOptions live wrapper (Phase 2,
// M8.2). Installs a UTF-16 LE NUL-terminated cmdline into a loaded
// image's EFI_LOADED_IMAGE_PROTOCOL.LoadOptions field, between
// LoadImage and StartImage. Linux's EFI-stub reads it from there.
//
// Lifetime: the buffer is allocated from EfiLoaderData pool by
// gBS->AllocatePool. The Linux EFI-stub frees the LoadOptions pool
// when it's done with the image (drivers/firmware/efi/libstub does
// the FreePool on cmdline copy). If StartImage rejects the image
// before the stub gets a chance to take ownership we leak the buffer
// for the rest of the Boot Services lifetime — accepted, all
// EfiLoaderData pages go back to the firmware at ExitBootServices
// anyway.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// SetLoadOptions installs `cmdline` (encoded as UTF-16 LE + a U+0000
// terminator) into the LoadedImageProtocol of the image at `handle`.
// Must be called between LoadImage and StartImage. Returns an error
// if HandleProtocol fails, AllocatePool fails, or the encoded buffer
// can't be written.
//
// On success the firmware-allocated buffer is owned by the loaded
// image (typically a Linux EFI-stub) which will FreePool it once
// it has copied the cmdline into its own kernel-side storage.
func SetLoadOptions(handle uintptr, cmdline string) error {
	if handle == 0 {
		return ErrNilHandle
	}
	if cmdline == "" {
		return ErrEmptyCmdline
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}

	// Resolve the LoadedImageProtocol view of `handle`.
	lip, err := HandleProtocol(uint64(handle), &EFILoadedImageProtocolGUID)
	if err != nil {
		return err
	}
	if lip == 0 {
		return &EFIError{Status: efiInvalidParameter, Op: "HandleProtocol(LoadedImage)"}
	}

	// Encode cmdline as UTF-16 LE + NUL terminator.
	enc := utf16LECmdline(cmdline)
	if len(enc) < 2 {
		return ErrEmptyCmdline
	}

	// Allocate a firmware-owned EfiLoaderData buffer the kernel
	// EFI-stub can FreePool later.
	var poolPtr uint64
	status := efiCall(
		bs+efiBSAllocatePool,
		uint64(EfiLoaderData),
		uint64(uintptr(len(enc))),
		uint64(uintptr(unsafe.Pointer(&poolPtr))),
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "AllocatePool(LoadOptions)"}
	}
	if poolPtr == 0 {
		return &EFIError{Status: efiInvalidParameter, Op: "AllocatePool(LoadOptions): NULL"}
	}

	// Copy the encoded bytes into the firmware buffer.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(poolPtr))), len(enc))
	copy(dst, enc)

	// Patch LoadedImageProtocol.LoadOptionsSize (UINT32) and
	// LoadOptions (VOID*). The struct lives in firmware-owned RAM
	// returned by HandleProtocol; the firmware allows boot-time
	// callers to mutate these two fields (UEFI 2.10 §9.2: "After
	// the application has been called by the firmware, the
	// application may update LoadOptionsSize and LoadOptions ...
	// the firmware does not access either field after invoking the
	// application").
	sizeAddr := unsafe.Pointer(uintptr(lip) + uintptr(efiLoadedImageLoadOptionsSize))
	ptrAddr := unsafe.Pointer(uintptr(lip) + uintptr(efiLoadedImageLoadOptions))
	*(*uint32)(sizeAddr) = uint32(len(enc))
	*(*uint64)(ptrAddr) = poolPtr

	return nil
}
