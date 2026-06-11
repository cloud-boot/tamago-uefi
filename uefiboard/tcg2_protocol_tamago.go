// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_TCG2_PROTOCOL transport binding
// (Phase 2, measured-boot — gated on `-tags phase2_tpm_measure`).
//
// ADDITIVE + REVERSIBLE: this file only compiles under the
// `phase2_tpm_measure` build tag. With the tag OFF the package builds
// and links exactly as before; nothing in the existing boot flow
// references any symbol defined here unless the tag is set.
//
// What this provides:
//
//   - LocateTCG2() locates the firmware's EFI_TCG2_PROTOCOL via
//     gBS->LocateProtocol(&EFI_TCG2_PROTOCOL_GUID). A clean NOT_FOUND
//     (no firmware TPM) is surfaced as (0, nil) so the caller silently
//     skips measured-boot.
//
//   - tcg2Caller implements github.com/go-tpm2/efitcg2.Caller by
//     invoking the protocol's vtable methods through the existing
//     efiCall thunk (the same MS-x64 / AAPCS64 / LP64 convention every
//     other wrapper in this package uses).
//
//   - NewTCG2 wires a located protocol pointer into an *efitcg2.TCG2,
//     ready to drive go-tpm2/tpm2 commands AND measured-boot
//     extend+log via MeasureToPCR.
//
// VTABLE LAYOUT — this is the validation surface for efitcg2's
// `// INFERRED:` items. The EFI_TCG2_PROTOCOL structure (TCG "EFI
// Protocol Specification, Family 2.0", clause "EFI_TCG2_PROTOCOL") is
// a packed table of pointer-width function pointers in declaration
// order:
//
//	typedef struct tdEFI_TCG2_PROTOCOL {
//	    EFI_TCG2_GET_CAPABILITY                 GetCapability;                  // index 0
//	    EFI_TCG2_GET_EVENT_LOG                  GetEventLog;                    // index 1
//	    EFI_TCG2_HASH_LOG_EXTEND_EVENT          HashLogExtendEvent;             // index 2
//	    EFI_TCG2_SUBMIT_COMMAND                 SubmitCommand;                  // index 3
//	    EFI_TCG2_GET_ACTIVE_PCR_BANKS           GetActivePcrBanks;              // index 4
//	    EFI_TCG2_SET_ACTIVE_PCR_BANKS           SetActivePcrBanks;              // index 5
//	    EFI_TCG2_GET_RESULT_OF_SET_ACTIVE_PCR_BANKS  GetResultOfSetActivePcrBanks; // index 6
//	} EFI_TCG2_PROTOCOL;
//
// So with the located interface pointer `proto`, the function-pointer
// SLOT for method index i is at byte offset i*ptrWidth; on every
// 64-bit UEFI target ptrWidth = 8. efiCall takes the *absolute slot
// address* (proto + i*8) and dereferences it (see eficall_export.go),
// passing `proto` as the `This` first argument. These offsets are what
// efitcg2.MethodHashLogExtendEvent (2) and MethodSubmitCommand (3)
// describe; this file is where they get exercised against real OVMF
// firmware.

//go:build phase2_tpm_measure && tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"

	"github.com/go-tpm2/efitcg2"
)

// EFI_TCG2_PROTOCOL_GUID = 607f766c-7455-42be-930b-e4d76db2720f.
// TCG "EFI Protocol Specification", "#define EFI_TCG2_PROTOCOL_GUID".
// Laid out in the package-local EFIGUID byte order (Data1..Data3
// little-endian, Data4 as-is) so LocateProtocol matches the firmware's
// handle-database entry.
var EFITCG2ProtocolGUID = EFIGUID{
	Data1: 0x607f766c,
	Data2: 0x7455,
	Data3: 0x42be,
	Data4: [8]uint8{0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f},
}

// EFI_TCG2_PROTOCOL vtable method indices (declaration order). Each
// index*8 is the byte offset of that method's function-pointer slot in
// the protocol structure on a 64-bit UEFI target. Mirrors
// efitcg2.Method* — kept local so this file is self-describing and so
// the offsets are asserted (init() below) to agree with the published
// efitcg2 ordinals.
const (
	tcg2MethodGetCapability    = 0
	tcg2MethodGetEventLog      = 1
	tcg2HashLogExtendEventSlot = 2 // efitcg2.MethodHashLogExtendEvent
	tcg2SubmitCommandSlot      = 3 // efitcg2.MethodSubmitCommand
)

// ptrWidth is the EFI pointer width in bytes on every 64-bit UEFI
// target this package supports (amd64/arm64/loong64/riscv64). The
// vtable is a packed array of pointers, so slot i sits at i*ptrWidth.
const ptrWidth = 8

func init() {
	// Compile-time-ish assertion that our local slot indices agree with
	// the published efitcg2 ordinals. If a future efitcg2 release
	// reorders the table this trips loudly at startup rather than
	// measuring into the wrong PCR.
	if tcg2HashLogExtendEventSlot != efitcg2.MethodHashLogExtendEvent ||
		tcg2SubmitCommandSlot != efitcg2.MethodSubmitCommand {
		panic("uefi: efitcg2 vtable ordinals drifted from EFI_TCG2_PROTOCOL declaration order")
	}
}

// tcg2Caller implements efitcg2.Caller over a located
// EFI_TCG2_PROTOCOL pointer + the package efiCall thunk. It holds only
// the interface pointer (`This`); efitcg2 owns all buffer marshaling.
type tcg2Caller struct {
	proto uint64 // EFI_TCG2_PROTOCOL*
}

// slot returns the absolute address of the function-pointer SLOT for
// vtable method index i. efiCall reads the pointer stored there and
// jumps to it (see eficall_export.go).
func (c tcg2Caller) slot(i int) uint64 {
	return c.proto + uint64(i*ptrWidth)
}

// SubmitCommand drives EFI_TCG2_PROTOCOL.SubmitCommand (index 3):
//
//	EFI_STATUS SubmitCommand(
//	    IN EFI_TCG2_PROTOCOL *This,
//	    IN UINTN  InputParameterBlockSize,
//	    IN UINT8 *InputParameterBlock,
//	    IN UINTN  OutputParameterBlockSize,
//	    IN UINT8 *OutputParameterBlock );
//
// TCG "EFI Protocol Specification", "EFI_TCG2_PROTOCOL.SubmitCommand()".
// The firmware writes the TPM response into output in place; efitcg2's
// Send parses the response header out of it.
func (c tcg2Caller) SubmitCommand(inputBlock []byte, output []byte) (uintptr, error) {
	var inPtr, outPtr uint64
	if len(inputBlock) > 0 {
		inPtr = uint64(uintptr(unsafe.Pointer(&inputBlock[0])))
	}
	if len(output) > 0 {
		outPtr = uint64(uintptr(unsafe.Pointer(&output[0])))
	}
	status := efiCall(
		c.slot(tcg2SubmitCommandSlot),
		c.proto, // This
		uint64(len(inputBlock)),
		inPtr,
		uint64(len(output)),
		outPtr,
		0,
	)
	return uintptr(status), nil
}

// HashLogExtendEvent drives EFI_TCG2_PROTOCOL.HashLogExtendEvent
// (index 2):
//
//	EFI_STATUS HashLogExtendEvent(
//	    IN EFI_TCG2_PROTOCOL    *This,
//	    IN UINT64                Flags,
//	    IN EFI_PHYSICAL_ADDRESS  DataToHash,
//	    IN UINT64                DataToHashLen,
//	    IN EFI_TCG2_EVENT       *EfiTcg2Event );
//
// TCG "EFI Protocol Specification",
// "EFI_TCG2_PROTOCOL.HashLogExtendEvent()". This is the measured-boot
// primitive: the firmware hashes DataToHash into the active PCR banks
// for the EFI_TCG2_EVENT's PCRIndex AND appends a TCG event-log record
// — extend + log in one call. `event` is the serialized
// EFI_TCG2_EVENT efitcg2.buildEvent produced (its leading Size field
// states its own length).
func (c tcg2Caller) HashLogExtendEvent(flags uint64, dataToHash []byte, event []byte) (uintptr, error) {
	var dataPtr, eventPtr uint64
	if len(dataToHash) > 0 {
		dataPtr = uint64(uintptr(unsafe.Pointer(&dataToHash[0])))
	}
	if len(event) > 0 {
		eventPtr = uint64(uintptr(unsafe.Pointer(&event[0])))
	}
	status := efiCall(
		c.slot(tcg2HashLogExtendEventSlot),
		c.proto, // This
		flags,
		dataPtr,
		uint64(len(dataToHash)),
		eventPtr,
		0,
	)
	return uintptr(status), nil
}

// EFI_TCG2_BOOT_SERVICE_CAPABILITY layout, as the firmware fills it in
// (TCG "EFI Protocol Specification", "EFI_TCG2_BOOT_SERVICE_CAPABILITY";
// MdePkg/Include/Protocol/Tcg2Protocol.h). The structure has NO #pragma
// pack — it uses natural C alignment — so on a 64-bit target the fields land
// at compiler-computed offsets (verified with cc __builtin_offsetof against
// the edk2 header: sizeof = 36, MaxResponseSize @ 20):
//
//	UINT8            Size;                 // @0  (IN: allocated size; OUT: actual)
//	EFI_TCG2_VERSION StructureVersion;     // @1  (Major,Minor UINT8)
//	EFI_TCG2_VERSION ProtocolVersion;      // @3  (Major,Minor UINT8)
//	UINT32           HashAlgorithmBitmap;  // @8  (3 bytes pad after @5)
//	UINT32           SupportedEventLogs;   // @12
//	BOOLEAN          TPMPresentFlag;       // @16 (UINT8)
//	UINT16           MaxCommandSize;       // @18 (1 byte pad after @17)
//	UINT16           MaxResponseSize;      // @20  <-- the field we need
//	UINT32           ManufacturerID;       // @24 (2 bytes pad after @22)
//	UINT32           NumberOfPCRBanks;     // @28
//	UINT32           ActivePcrBanks;       // @32
const (
	tcg2CapSize              = 36 // sizeof(EFI_TCG2_BOOT_SERVICE_CAPABILITY)
	tcg2CapSizeOffset        = 0  // UINT8 Size (IN OUT)
	tcg2CapMaxResponseOffset = 20 // UINT16 MaxResponseSize
)

// GetCapability drives EFI_TCG2_PROTOCOL.GetCapability (index 0):
//
//	EFI_STATUS GetCapability(
//	    IN EFI_TCG2_PROTOCOL                    *This,
//	    IN OUT EFI_TCG2_BOOT_SERVICE_CAPABILITY *ProtocolCapability );
//
// TCG "EFI Protocol Specification", "EFI_TCG2_PROTOCOL.GetCapability()". The
// ProtocolCapability buffer is IN OUT: the caller sets its leading Size field
// to the allocated length and the firmware fills the rest in place. efitcg2
// type-asserts this method (efitcg2.CapabilityCaller) and uses the returned
// MaxResponseSize to cap SubmitCommand's OutputParameterBlockSize — OVMF's
// CRB-backed EFI_TCG2_PROTOCOL rejects an over-large output block with
// EFI_INVALID_PARAMETER, so this keeps the readback within the firmware's
// advertised ceiling (MaxResponseSize = 0xF80 = 3968 under OVMF + tpm-crb).
//
// A non-success EFI_STATUS is reported to efitcg2 as (0, nil): a zero
// MaxResponseSize tells efitcg2 "not reported, use the requested/default
// size", which is the correct fallback rather than failing the whole
// transport on a capability-query hiccup.
func (c tcg2Caller) GetCapability() (uint32, error) {
	buf := make([]byte, tcg2CapSize)
	buf[tcg2CapSizeOffset] = tcg2CapSize // IN: allocated size

	status := efiCall(
		c.slot(tcg2MethodGetCapability),
		c.proto, // This
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0,
		0,
		0,
		0,
	)
	if status&efiStatusErrorBit != 0 {
		// GetCapability failed (e.g. EFI_BUFFER_TOO_SMALL on a firmware whose
		// struct is larger than ours). Report "not advertised" so efitcg2
		// falls back to its default ceiling rather than erroring the boot.
		return 0, nil
	}

	// MaxResponseSize is a little-endian UINT16 at offset 20.
	maxResp := uint32(buf[tcg2CapMaxResponseOffset]) |
		uint32(buf[tcg2CapMaxResponseOffset+1])<<8
	return maxResp, nil
}

// LocateTCG2 returns the firmware's EFI_TCG2_PROTOCOL interface pointer
// via gBS->LocateProtocol. A NOT_FOUND result (no firmware TPM /
// Tcg2Dxe absent) is surfaced as (0, nil) so the caller can silently
// skip measured-boot; any other failure returns a non-nil error.
func LocateTCG2() (uint64, error) {
	proto, err := LocateProtocol(&EFITCG2ProtocolGUID)
	if err != nil {
		if e, ok := err.(*EFIError); ok && (e.Status&^efiStatusErrorBit) == efiStatusNotFound {
			// No EFI_TCG2_PROTOCOL in the handle database: firmware
			// exposes no TPM. Not an error — measured-boot is skipped.
			return 0, nil
		}
		return 0, err
	}
	return proto, nil
}

// efiStatusErrorBit is the most-significant bit of an EFI_STATUS (the
// native machine word) — set on every EFI_ERROR value. On a 64-bit
// target it is bit 63. UEFI spec, appendix "Status Codes".
const efiStatusErrorBit = uint64(1) << 63

// efiStatusNotFound is the EFI_NOT_FOUND low code (the full status is
// efiStatusErrorBit | efiStatusNotFound). UEFI spec, "Status Codes".
const efiStatusNotFound = 0x0E

// NewTCG2 binds a located EFI_TCG2_PROTOCOL pointer into an
// *efitcg2.TCG2. The returned transport satisfies common.Transport
// (drives go-tpm2/tpm2 commands via SubmitCommand) and exposes
// MeasureToPCR (HashLogExtendEvent). proto MUST be a non-zero pointer
// returned by LocateTCG2.
func NewTCG2(proto uint64) *efitcg2.TCG2 {
	return efitcg2.New(tcg2Caller{proto: proto})
}
