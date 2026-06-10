// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — InheritParentDeviceHandle helper (Phase 2,
// M8.14, R-amd64j closure).
//
// Patches a child loaded image's EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle
// (and .FilePath) so that it points to the SAME ESP volume as the
// parent (us). This lets the Linux EFI-stub's cmdline-driven
// `initrd=<path>` file loader (drivers/firmware/efi/libstub/file.c
// handle_cmdline_files → efi_open_volume) succeed against the ESP we
// already booted from — without us having to expose a synthetic
// SimpleFileSystem protocol.
//
// Why M8.14 needs this (R-amd64j):
//
//   Phase 3 (cloud-boot/docs@14484d3) proved that EDK2 OVMF amd64's
//   LoadFile2 protocol implementation has a quirk where the buffer
//   pointer it passes to our callback is NOT the buffer the kernel
//   later reads from — the kernel reports "Initramfs unpacking failed:
//   invalid magic" even though our callback writes the gzip magic at
//   the address EDK2 hands us. The 3/4 other arches (arm64, riscv64,
//   loong64) work flawlessly with the same LoadFile2 mechanism.
//
//   The Linux EFI-stub's secondary path is `efi_load_initrd_cmdline`
//   (drivers/firmware/efi/libstub/efi-stub-helper.c), which parses
//   `initrd=<path>` tokens from the kernel cmdline and resolves them
//   via handle_cmdline_files → efi_open_device_path → efi_open_volume.
//   The volume fallback uses LoadedImage->DeviceHandle:
//
//       static efi_status_t efi_open_volume(efi_loaded_image_t *image,
//                                           efi_file_protocol_t **fh) {
//           ...
//           status = efi_bs_call(handle_protocol,
//                                efi_table_attr(image, device_handle),
//                                &fs_proto, (void **)&io);
//
//   On EDK2 amd64, when LoadImage is called with SourceBuffer != NULL
//   AND FilePath == NULL, the firmware sets the child's DeviceHandle
//   to NULL (MdeModulePkg/Core/Dxe/Image/Image.c CoreLoadImage). The
//   subsequent handle_protocol(NULL, EFI_FILE_SYSTEM) fails and the
//   initrd= path collapses.
//
//   InheritParentDeviceHandle fixes this: between LoadImage and
//   StartImage we copy the parent's LoadedImage.DeviceHandle and
//   .FilePath into the child's LoadedImage. The kernel EFI-stub then
//   sees a valid ESP DeviceHandle and successfully opens the volume +
//   the cmdline-named initrd file.
//
// arm64 / riscv64 / loong64 don't need this — their EDK2 firmwares
// publish LoadFile2 cleanly and the existing PublishInitrd path works.
// amd64 uses this helper INSTEAD of PublishInitrd.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// InheritParentDeviceHandle copies the parent image's
// EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle (and .FilePath) into the
// child image at `childHandle`. Must be called between LoadImage and
// StartImage. The parent is the image that captured imageHandle in
// cpuinit_<arch>.s — i.e. our own EFI binary.
//
// Effect: the child's `LoadedImage->device_handle` reads, after this
// call, identically to ours — pointing at the ESP volume the firmware
// loaded BOOTX64.EFI from. The Linux EFI-stub then opens the ESP via
// `efi_open_volume(image)` and reads `initrd=<path>` files from it.
//
// Returns an error if HandleProtocol fails on either image, or if
// either LoadedImage pointer is NULL. The (DeviceHandle, FilePath)
// write itself is unchecked — UEFI 2.10 §9.2 permits boot-time
// callers to mutate these fields between LoadImage and StartImage:
// "the firmware does not access either field after invoking the
// application".
func InheritParentDeviceHandle(childHandle uintptr) error {
	if childHandle == 0 {
		return ErrNilHandle
	}
	if imageHandle == 0 {
		return ErrNoBootServices
	}

	parentLIP, err := HandleProtocol(uint64(imageHandle), &EFILoadedImageProtocolGUID)
	if err != nil {
		return err
	}
	if parentLIP == 0 {
		return &EFIError{Status: efiInvalidParameter, Op: "HandleProtocol(LoadedImage, parent)"}
	}

	childLIP, err := HandleProtocol(uint64(childHandle), &EFILoadedImageProtocolGUID)
	if err != nil {
		return err
	}
	if childLIP == 0 {
		return &EFIError{Status: efiInvalidParameter, Op: "HandleProtocol(LoadedImage, child)"}
	}

	parentDH := *(*uint64)(unsafe.Pointer(uintptr(parentLIP) + uintptr(efiLoadedImageDeviceHandle)))
	parentFP := *(*uint64)(unsafe.Pointer(uintptr(parentLIP) + uintptr(efiLoadedImageFilePath)))
	*(*uint64)(unsafe.Pointer(uintptr(childLIP) + uintptr(efiLoadedImageDeviceHandle))) = parentDH
	*(*uint64)(unsafe.Pointer(uintptr(childLIP) + uintptr(efiLoadedImageFilePath))) = parentFP
	return nil
}
