// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — PublishInitrd / UnpublishInitrd live
// wrappers (Phase 2, M8.2 + asm trampoline follow-up).
//
// What's shipped here:
//   - PublishInitrd(initrd) allocates a Go-owned initrd buffer,
//     constructs the MEDIA_VENDOR device path + the LoadFile2
//     protocol struct, wires the LoadFile slot to the per-arch
//     loadFile_trampoline asm symbol, and calls
//     gBS->InstallMultipleProtocolInterfaces(&handle, DPGUID,
//     &devpath[0], LF2GUID, &protocol, NULL) to publish a handle.
//   - UnpublishInitrd(handle) reverses the install via
//     gBS->UninstallMultipleProtocolInterfaces and clears the
//     active-initrd back-pointers.
//
// The asm trampoline (initrd_protocol_<arch>.s) bridges the
// firmware ABI (MS x64 / AAPCS64 / LP64) into Go ABI0 by saving
// the firmware-side callee-saved registers, marshalling the EFI
// args into a Go-ABI0 frame at FP+offsets, calling
// ·loadFileGo(SB), reading the return slot back, and putting the
// EFI_STATUS in the arch's return register.
//
// loadFileGo itself + the package-private loadFileRegistry live in
// initrd_protocol.go (host-buildable) so the host-side unit tests
// can exercise the two-call protocol semantics against crafted
// pointers without going anywhere near firmware.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"
)

// initrdPublishState holds the per-publish backing memory. The
// firmware retains pointers into devicePath and protocol for the
// lifetime of the installed handle, so they MUST outlive the call
// — we keep them in a package-global map keyed by image handle so
// UnpublishInitrd can free them after a successful uninstall.
type initrdPublishState struct {
	devicePath []byte                // the MEDIA_VENDOR + END byte sequence
	protocol   *EFILoadFile2Protocol // the protocol struct with the LoadFile slot pointing at loadFile_trampoline
	body       []byte                // a Go-owned copy of the initrd bytes (kept alive)
	slot       int                   // index into loadFileRegistry (-1 if not stored)
}

// publishedInitrds tracks active PublishInitrd installs so the
// matching UnpublishInitrd can locate the backing buffers and free
// them. The map is package-private — exposed only via
// PublishInitrd / UnpublishInitrd.
var publishedInitrds = map[uintptr]*initrdPublishState{}

// loadFile_trampoline is the per-arch asm symbol that bridges the
// firmware-side ABI into Go ABI0 + ·loadFileGo. Defined in
// initrd_protocol_<arch>.s. The address of this function (taken
// via the funcval indirection below) is what we patch into
// EFILoadFile2Protocol.LoadFile.
func loadFile_trampoline()

// loadFile_trampolineFV is a Go function-value pointing at the asm
// loadFile_trampoline symbol. Taking the address of a Go function
// yields a *funcval whose first word is the entry PC — we use that
// to fish the PC out for patching into EFILoadFile2Protocol.LoadFile.
var loadFile_trampolineFV = loadFile_trampoline

// PublishInitrd installs a Load-File-2 protocol instance backed by
// the given initrd bytes under a fresh handle with the
// LINUX_EFI_INITRD_MEDIA_GUID device path. Returns the handle
// (caller passes to UnpublishInitrd to remove) or an error.
//
// On success the published protocol's LoadFile slot is the
// per-arch loadFile_trampoline, so the EFI-stub's two-call dance
// (size query, then transfer) is fully serviced by Go-side code.
func PublishInitrd(initrd []byte) (uintptr, error) {
	if len(initrd) == 0 {
		return 0, ErrEmptyInitrd
	}
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}

	// Stable Go-owned copies of the inputs the firmware will retain
	// pointers into. The Go GC must not move these for the lifetime
	// of the published handle; package-global slices and the
	// pinned-via-map pattern below ensure that.
	devpath := buildInitrdDevicePath()
	body := make([]byte, len(initrd))
	copy(body, initrd)

	// Resolve the asm trampoline's entry PC. unsafe.Pointer on a
	// Go function value yields a *funcval; the first word is the
	// entry PC.
	trampoline := **(**uintptr)(unsafe.Pointer(&loadFile_trampolineFV))
	protocol := &EFILoadFile2Protocol{
		LoadFile: uint64(trampoline),
	}

	// Reserve a registry slot BEFORE the firmware install so a
	// racing LoadFile call (single-threaded UEFI: only possible
	// from the same call chain, but be defensive) sees a fully
	// populated entry. Slot is reused only after UnpublishInitrd
	// succeeds.
	slot := -1
	for i := range loadFileRegistry {
		if loadFileRegistry[i].proto == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0, ErrLoadFileRegistryFull
	}
	loadFileRegistry[slot] = loadFileEntry{
		proto: uintptr(unsafe.Pointer(protocol)),
		body:  uintptr(unsafe.Pointer(&body[0])),
		size:  uintptr(len(body)),
	}

	// gBS->InstallMultipleProtocolInterfaces signature (UEFI 2.10
	// §7.3.13):
	//
	//   EFI_STATUS InstallMultipleProtocolInterfaces(
	//       IN OUT EFI_HANDLE *Handle,
	//       ... (GUID*, Interface*)* pairs ...,
	//       NULL );
	//
	// The variadic NULL terminator is the firmware's signal that
	// the pair list is complete. With *Handle = NULL on entry the
	// firmware allocates a fresh handle and returns it via Handle.
	var handle uint64
	status := efiCall(
		bs+efiBSInstallMultipleProtocolInterfaces,
		uint64(uintptr(unsafe.Pointer(&handle))),
		uint64(uintptr(unsafe.Pointer(&EFIDevicePathProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(&devpath[0]))),
		uint64(uintptr(unsafe.Pointer(&EFILoadFile2ProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(protocol))),
		0, // NULL terminator
	)
	if status != efiSuccess {
		// Roll back the registry reservation on firmware failure.
		loadFileRegistry[slot] = loadFileEntry{}
		return 0, &EFIError{Status: status, Op: "InstallMultipleProtocolInterfaces(initrd)"}
	}

	// Pin the backing buffers against GC for the lifetime of the
	// install.
	publishedInitrds[uintptr(handle)] = &initrdPublishState{
		devicePath: devpath,
		protocol:   protocol,
		body:       body,
		slot:       slot,
	}
	return uintptr(handle), nil
}

// UnpublishInitrd undoes a previous PublishInitrd by calling
// gBS->UninstallMultipleProtocolInterfaces on the given handle and
// releasing the backing Go-side buffers + clearing the registry
// slot so a stale LoadFile dispatch after this point returns
// EFI_NOT_FOUND.
//
// The (GUID*, Interface*) pairs MUST match what PublishInitrd
// installed exactly (UEFI 2.10 §7.3.14) — same pointers, same NULL
// terminator. We recover them from publishedInitrds; passing an
// unknown handle is a caller bug and is rejected.
func UnpublishInitrd(handle uintptr) error {
	if handle == 0 {
		return ErrInitrdNotPublished
	}
	state, ok := publishedInitrds[handle]
	if !ok {
		return ErrInitrdNotPublished
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}

	status := efiCall(
		bs+efiBSUninstallMultipleProtocolInterfaces,
		uint64(handle),
		uint64(uintptr(unsafe.Pointer(&EFIDevicePathProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(&state.devicePath[0]))),
		uint64(uintptr(unsafe.Pointer(&EFILoadFile2ProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(state.protocol))),
		0, // NULL terminator
	)
	if status != efiSuccess {
		// Leave the entry in publishedInitrds + the registry slot
		// live so a retry can still find the pointers. The
		// firmware-side install is in an indeterminate state;
		// surface the EFI_STATUS so the caller can decide.
		return &EFIError{Status: status, Op: "UninstallMultipleProtocolInterfaces(initrd)"}
	}
	// Firmware confirmed uninstall: drop the registry slot and the
	// Go-side state.
	if state.slot >= 0 && state.slot < loadFileRegistrySize {
		loadFileRegistry[state.slot] = loadFileEntry{}
	}
	delete(publishedInitrds, handle)
	return nil
}
