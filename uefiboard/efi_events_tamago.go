// cloud-boot UEFI board — live EFI_EVENT thunks (Phase 2, M1).
//
// Three thin wrappers: CreateEvent / WaitForEvent / CloseEvent. The
// type surface + offsets are in efi_events.go (host-buildable).
//
// gBS->CreateEvent signature (UEFI 2.10 §7.1.2):
//
//	EFI_STATUS CreateEvent(
//	    IN  UINT32             Type,
//	    IN  EFI_TPL            NotifyTpl,
//	    IN  EFI_EVENT_NOTIFY   NotifyFunction OPTIONAL,
//	    IN  VOID              *NotifyContext  OPTIONAL,
//	    OUT EFI_EVENT         *Event );
//
// gBS->WaitForEvent signature (UEFI 2.10 §7.1.5):
//
//	EFI_STATUS WaitForEvent(
//	    IN  UINTN       NumberOfEvents,
//	    IN  EFI_EVENT  *Event,
//	    OUT UINTN      *Index );
//
// gBS->CloseEvent signature (UEFI 2.10 §7.1.6):
//
//	EFI_STATUS CloseEvent(IN EFI_EVENT Event);
//
// All three are well within the 5-arg efiCall envelope.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// CreateEvent registers a new firmware-managed event with no Go-side
// notify callback (NotifyFunction = NULL). The returned EFIEvent is
// what async-completion-token APIs (HTTP.Request/Response,
// DNS4.HostNameToIp) expect in Token.Event.
//
// Type is typically EFIEventNotifySignal | (TPL bits). NotifyTPL is
// TPLCallback in EDK2's reference path (NetworkPkg).
func CreateEvent(eventType, notifyTPL uint32) (EFIEvent, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}
	var ev uint64
	status := efiCall(
		bs+efiBSCreateEvent,
		uint64(eventType),
		uint64(notifyTPL),
		0, // NotifyFunction
		0, // NotifyContext
		uint64(uintptr(unsafe.Pointer(&ev))),
		0,
	)
	if status != efiSuccess {
		return 0, &EFIError{Status: status, Op: "CreateEvent"}
	}
	return EFIEvent(ev), nil
}

// WaitForEvent blocks until any of the given events is signaled.
// Returns the (zero-based) index of the event that fired. The thunk
// passes events as a one-element array on the Go stack — sufficient
// for M1 (always one outstanding token at a time).
func WaitForEvent(ev EFIEvent) error {
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	arr := [1]uint64{uint64(ev)}
	var index uintptr
	status := efiCall(
		bs+efiBSWaitForEvent,
		1, // NumberOfEvents
		uint64(uintptr(unsafe.Pointer(&arr[0]))),
		uint64(uintptr(unsafe.Pointer(&index))),
		0,
		0,
		0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "WaitForEvent"}
	}
	return nil
}

// CloseEvent releases an event handle previously returned by
// CreateEvent. Idempotent on a zero handle.
func CloseEvent(ev EFIEvent) error {
	if ev == 0 {
		return nil
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}
	status := efiCall(
		bs+efiBSCloseEvent,
		uint64(ev),
		0, 0, 0, 0, 0,
	)
	if status != efiSuccess {
		return &EFIError{Status: status, Op: "CloseEvent"}
	}
	return nil
}
