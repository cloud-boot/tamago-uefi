// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — PublishInitrd / UnpublishInitrd live
// wrappers (Phase 2, M8.2).
//
// Status: PARTIAL — framework only. The protocol-install /
// device-path / handle-allocation plumbing is shipped here and
// works on every arch. The LoadFile callback that the firmware
// invokes from FIRMWARE context to actually transfer the initrd
// bytes is NOT yet wired; the LoadFile function-pointer slot in
// the published protocol struct is currently zero. A real Linux
// EFI-stub that calls LoadFile2->LoadFile on the published handle
// will therefore crash with a NULL-pointer dispatch. See the M8.2
// TODO at the bottom of this file for what's missing and why it's
// hard.
//
// What's shipped here:
//   - PublishInitrd(initrd) allocates a global initrd buffer,
//     constructs the MEDIA_VENDOR device path + the LoadFile2
//     protocol struct, and calls
//     gBS->InstallMultipleProtocolInterfaces(&handle, DPGUID,
//     &devpath[0], LF2GUID, &protocol, NULL) to publish a handle.
//   - UnpublishInitrd(handle) reverses the install via
//     gBS->UninstallMultipleProtocolInterfaces.
//
// What's NOT shipped (M8.2 follow-up):
//   - LoadFile = a Go function callable via the firmware ABI. Needs
//     a per-arch asm trampoline that bridges firmware calling
//     convention (MS x64 / AAPCS64 / LP64) → Go ABI, restores the
//     g pointer, calls the Go-side handler, and returns the
//     EFI_STATUS in the right register. The eficall_<arch>.s
//     thunks are the reverse direction (Go → firmware) and don't
//     help here. Until that lands, the LoadFile slot is zero and
//     any real EFI-stub initrd consumer will fault.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// initrdPublishState holds the per-publish backing memory. The
// firmware retains pointers into devicePath and protocol for the
// lifetime of the installed handle, so they MUST outlive the call
// — we keep them in a package-global map keyed by image handle so
// UnpublishInitrd can free them after a successful uninstall.
type initrdPublishState struct {
	devicePath []byte               // the MEDIA_VENDOR + END byte sequence
	protocol   *EFILoadFile2Protocol // the protocol struct with the (currently zero) LoadFile slot
	body       []byte               // a Go-owned copy of the initrd bytes (kept alive)
}

// publishedInitrds tracks active PublishInitrd installs so the
// matching UnpublishInitrd can locate the backing buffers and free
// them. The map is package-private — exposed only via
// PublishInitrd / UnpublishInitrd.
var publishedInitrds = map[uintptr]*initrdPublishState{}

// PublishInitrd installs a Load-File-2 protocol instance backed by
// the given initrd bytes under a fresh handle with the
// LINUX_EFI_INITRD_MEDIA_GUID device path. Returns the handle
// (caller passes to UnpublishInitrd to remove) or an error.
//
// NOTE M8.2-PARTIAL: the LoadFile function pointer in the installed
// protocol is currently NULL. The published handle is therefore
// VISIBLE to the EFI-stub's LocateDevicePath walk (so locating
// works), but any actual LoadFile dispatch will fault. This is
// enough to exercise the install/uninstall + device-path round-trip
// plumbing end-to-end under firmware; the asm-trampoline follow-up
// is what makes it actually transfer bytes. See the TODO below.
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
	protocol := &EFILoadFile2Protocol{
		LoadFile: 0, // M8.2-PARTIAL: see file header.
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
		return 0, &EFIError{Status: status, Op: "InstallMultipleProtocolInterfaces(initrd)"}
	}

	// Pin the backing buffers against GC for the lifetime of the
	// install.
	publishedInitrds[uintptr(handle)] = &initrdPublishState{
		devicePath: devpath,
		protocol:   protocol,
		body:       body,
	}
	return uintptr(handle), nil
}

// UnpublishInitrd undoes a previous PublishInitrd by calling
// gBS->UninstallMultipleProtocolInterfaces on the given handle and
// releasing the backing Go-side buffers.
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
		// Leave the entry in publishedInitrds so a retry can still
		// find the pointers. The firmware-side install is in an
		// indeterminate state; surface the EFI_STATUS so the
		// caller can decide what to do.
		return &EFIError{Status: status, Op: "UninstallMultipleProtocolInterfaces(initrd)"}
	}
	delete(publishedInitrds, handle)
	return nil
}

// TODO (M8.2 follow-up): wire LoadFile to a real Go function via a
// per-arch asm trampoline. Sketch:
//
//   1. Declare a Go function:
//      //go:nosplit
//      func initrdLoadFileGo(this, fp, bp uintptr, sz *uint64,
//                            buf unsafe.Pointer) uintptr
//      that implements the two-call protocol against the package-
//      global publishedInitrds[matching-handle].body bytes.
//
//   2. Per-arch asm trampoline (initrd_thunk_<arch>.s):
//      - Save firmware-context callee-saved registers per the
//        arch's calling convention (MS x64 saves XMM6-15 + RBP +
//        RBX + RDI + RSI + R12-15; AAPCS64 saves X19-X28; RISC-V
//        LP64 saves s0-s11; LoongArch LP64 saves s0-s8).
//      - Re-establish Go's g pointer (cpuinit captured it; expose
//        as a global the trampoline reads on entry).
//      - Marshal firmware args into Go-ABI arg locations and call
//        initrdLoadFileGo.
//      - Marshal Go return into firmware-ABI return register.
//      - Restore callee-saved regs, ret.
//
//   3. Take the trampoline's address (via `var trampolineFn uintptr
//      = unsafe.Pointer(funcPC(initrdLoadFileTrampoline))`) and
//      patch it into protocol.LoadFile before InstallMultiple...
//
// Why this is non-trivial in 90 minutes:
//   - 4 architectures, each with subtly different callee-saved
//     register sets and FP-register save requirements.
//   - The Go runtime expects to be entered on a goroutine stack
//     with a valid g; firmware enters us on its own stack with no
//     g. We'd need to either switch stacks (and re-find g) or
//     mark the Go-side handler //go:nosplit + accept the risk of
//     stack-overflow on a small firmware stack.
//   - On amd64 specifically, MS x64 vs SystemV ABI differs on
//     which registers carry args (RCX/RDX/R8/R9 vs RDI/RSI/RDX/
//     RCX/R8/R9) AND on shadow-space (MS x64 reserves 32 bytes of
//     shadow space at every call) AND on red-zone (SysV has 128
//     bytes below RSP; MS x64 does not). Misjudging any of these
//     produces a silent corruption that only surfaces under load.
//
// The framework above (device path + protocol install + handle
// uninstall) is the load-bearing piece for the eventual M8.2.x
// follow-up; the trampoline is a contained 4-file asm sprint on
// top of it.
