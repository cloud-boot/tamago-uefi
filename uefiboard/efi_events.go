// cloud-boot UEFI board — EFI_EVENT plumbing (Phase 2, M1).
//
// Thin wrappers around gBS->CreateEvent / WaitForEvent / CloseEvent
// (UEFI 2.10 §7.1). The EFI HTTP / DNS4 protocols are async: callers
// register an EFI_EVENT in a "completion token", invoke the operation,
// then either spin on token.Status or block in WaitForEvent until the
// firmware signals.
//
// This file only defines the type-surface + the offsets. The live
// thunk wrappers live in efi_events_tamago.go (gated on `//go:build
// tamago`) so the host build can unit-test the opaque-handle plumbing
// without pulling efiCall in.
//
// Upstream reference (read for the field semantics):
//   - MdePkg/Include/Uefi/UefiSpec.h, §EFI_BOOT_SERVICES Event services
//   - MdeModulePkg/Core/Dxe/Event/Event.c   (EDK2 reference impl)

package uefiboard

// EFI_BOOT_SERVICES function-pointer offsets for the event services.
// Mirrors the canonical struct order from MdePkg/Include/Uefi/UefiSpec.h:
//
//	24  RaiseTPL                       (TPL services)
//	32  RestoreTPL
//	40  AllocatePages                  (Memory services)
//	48  FreePages
//	56  GetMemoryMap
//	64  AllocatePool
//	72  FreePool
//	80  CreateEvent                    (Event/Timer services)  <-- here
//	88  SetTimer
//	96  WaitForEvent                                            <-- here
//	104 SignalEvent
//	112 CloseEvent                                              <-- here
//	120 CheckEvent                                              <-- here
const (
	efiBSCreateEvent  = 80
	efiBSSetTimer     = 88
	efiBSWaitForEvent = 96
	efiBSSignalEvent  = 104
	efiBSCloseEvent   = 112
	efiBSCheckEvent   = 120
)

// EFI_BOOT_SERVICES function-pointer offsets for the protocol-handler
// services (UEFI 2.10 §7.3). Used by M1's DHCP4/DNS4/HTTP path to
// resolve handles for the service-binding protocols.
const (
	efiBSHandleProtocol = 152
	efiBSLocateHandleBuffer = 312
	efiBSLocateProtocol    = 320
)

// EFI_EVENT_TYPE constants (UEFI 2.10 §7.1.1). M1 uses
// EFI_NOTIFY_SIGNAL with a NULL NotifyFunction so the firmware signals
// the event on completion but doesn't run a Go callback at TPL_CALLBACK
// (we can't safely cross the ABI boundary inbound on every arch yet).
const (
	EFIEventTimer          uint32 = 0x80000000
	EFIEventRuntime        uint32 = 0x40000000
	EFIEventNotifyWait     uint32 = 0x00000100
	EFIEventNotifySignal   uint32 = 0x00000200
	EFIEventSignalExitBoot uint32 = 0x00000201
)

// TPL constants (UEFI 2.10 §7.1.7). NotifyTPL for completion-token
// events MUST be <= TPL_CALLBACK (8). M1 uses TPL_NOTIFY (16) — wait,
// the spec actually allows TPL_NOTIFY in CreateEvent; the HTTP and
// DNS protocols' callers in EDK2 (NetworkPkg/HttpDxe/HttpImpl.c
// `HttpResponseWorker`) raise+restore TPL around the read of
// Token.Status. We mirror EDK2's choice: TPL_CALLBACK (8).
const (
	TPLApplication uint32 = 4
	TPLCallback    uint32 = 8
	TPLNotify      uint32 = 16
	TPLHighLevel   uint32 = 31
)

// EFIEvent is the opaque firmware-side EFI_EVENT handle. Treated as a
// scalar token — never dereferenced from Go (firmware-private layout).
type EFIEvent uint64

// IsZero reports whether the event handle is the zero value (i.e.
// never created or already closed). Useful in tests.
func (e EFIEvent) IsZero() bool { return e == 0 }
