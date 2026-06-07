// cloud-boot UEFI board — protocol-handler helpers (Phase 2, M1).
//
// Helpers that wrap the protocol-handler subset of EFI_BOOT_SERVICES
// (UEFI 2.10 §7.3) needed by the M1 fetch path:
//
//   - LocateHandleBuffer(ByProtocol, &GUID, NULL, &count, &handles)
//     — walks every controller publishing the given protocol GUID.
//   - HandleProtocol(handle, &GUID, &interface)
//     — opens a known controller's protocol interface.
//   - LocateProtocol(&GUID, NULL, &interface)
//     — convenience for the singleton-style "first match" lookup.
//
// The service-binding pattern (DHCP4 / DNS4 / HTTP all use it) is:
//
//  1. LocateHandleBuffer on the *service-binding* GUID
//     (EFI_DHCP4_SERVICE_BINDING_PROTOCOL_GUID, etc).
//  2. For each handle, HandleProtocol(ServiceBindingGUID) → SBP*.
//  3. SBP.CreateChild(&childHandle) creates a per-instance child.
//  4. HandleProtocol(childHandle, ProtocolGUID) → the live protocol*.
//  5. ... use the protocol ...
//  6. SBP.DestroyChild(childHandle).
//
// Reference:
//   - MdePkg/Include/Uefi/UefiSpec.h (offsets + signatures)
//   - MdePkg/Include/Protocol/ServiceBinding.h
//   - NetworkPkg/HttpBootDxe/HttpBootSupport.c (canonical call shape
//     for the DHCP4 → DNS4 → HTTP service-binding walk)

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// LocateHandleBuffer searches every controller for one publishing the
// given protocol GUID. Returns the handle slice and frees the
// firmware-allocated buffer (the spec hands us a pool-allocated array,
// but we copy into Go memory and ignore the pool — modest leak,
// acceptable for M1).
//
// EFI_LOCATE_SEARCH_TYPE.ByProtocol = 2 (UEFI 2.10 §7.3.11).
func LocateHandleBuffer(guid *EFIGUID) ([]uint64, error) {
	bs := getBootServices()
	if bs == 0 {
		return nil, ErrNoBootServices
	}
	var count uintptr
	var handles uint64 // EFI_HANDLE*
	status := efiCall(
		bs+efiBSLocateHandleBuffer,
		2, // ByProtocol
		uint64(uintptr(unsafe.Pointer(guid))),
		0, // SearchKey
		uint64(uintptr(unsafe.Pointer(&count))),
		uint64(uintptr(unsafe.Pointer(&handles))),
	)
	if status != efiSuccess {
		return nil, &EFIError{Status: status, Op: "LocateHandleBuffer"}
	}
	if count == 0 || handles == 0 {
		return nil, nil
	}
	// Copy the firmware array into a Go slice.
	out := make([]uint64, count)
	src := unsafe.Slice((*uint64)(unsafe.Pointer(uintptr(handles))), int(count))
	copy(out, src)
	return out, nil
}

// HandleProtocol opens an interface on a known controller (UEFI 2.10
// §7.3.5). Returns the protocol-interface pointer (uint64) — caller
// casts to the appropriate protocol struct (DHCP4*/DNS4*/HTTP*).
func HandleProtocol(handle uint64, guid *EFIGUID) (uint64, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	var iface uint64
	status := efiCall(
		bs+efiBSHandleProtocol,
		handle,
		uint64(uintptr(unsafe.Pointer(guid))),
		uint64(uintptr(unsafe.Pointer(&iface))),
		0,
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "HandleProtocol"}
	}
	return iface, nil
}

// LocateProtocol returns the "first match" protocol-interface pointer
// for a given GUID (UEFI 2.10 §7.3.16). Convenience over
// LocateHandleBuffer + HandleProtocol when the caller doesn't care
// which controller publishes it.
func LocateProtocol(guid *EFIGUID) (uint64, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	var iface uint64
	status := efiCall(
		bs+efiBSLocateProtocol,
		uint64(uintptr(unsafe.Pointer(guid))),
		0, // Registration (NULL — return first)
		uint64(uintptr(unsafe.Pointer(&iface))),
		0,
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "LocateProtocol"}
	}
	return iface, nil
}

// EFI_SERVICE_BINDING_PROTOCOL function-pointer offsets:
//
//	struct _EFI_SERVICE_BINDING_PROTOCOL {
//	    EFI_SERVICE_BINDING_CREATE_CHILD     CreateChild;   // 0
//	    EFI_SERVICE_BINDING_DESTROY_CHILD    DestroyChild;  // 8
//	};
const (
	sbpCreateChild  = 0
	sbpDestroyChild = 8
)

// ServiceBindingCreateChild invokes SBP->CreateChild and returns the
// new child handle. The child handle is what HandleProtocol() expects
// when fetching the per-instance protocol interface.
func ServiceBindingCreateChild(sbp uint64) (uint64, error) {
	var child uint64
	status := efiCall(
		sbp+sbpCreateChild,
		sbp,
		uint64(uintptr(unsafe.Pointer(&child))),
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "ServiceBinding.CreateChild"}
	}
	return child, nil
}

// ServiceBindingDestroyChild invokes SBP->DestroyChild on the given
// child handle. Errors are non-fatal during M1 cleanup; callers log
// and proceed.
func ServiceBindingDestroyChild(sbp, child uint64) error {
	status := efiCall(
		sbp+sbpDestroyChild,
		sbp,
		child,
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "ServiceBinding.DestroyChild"}
	}
	return nil
}
