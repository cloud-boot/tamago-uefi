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

//go:build (phase2_tpm_measure || phase2_tpm_eventlog) && tamago && (amd64 || arm64 || loong64 || riscv64)

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

// GetEventLog drives EFI_TCG2_PROTOCOL.GetEventLog (index 1) and assembles
// the firmware's TCG event log into a byte slice. It implements
// efitcg2.EventLogCaller (the optional extension efitcg2 type-asserts), so
// efitcg2.GetEventLog can hand the bytes to attest.ParseEventLog +
// ReplayPCRs.
//
//	EFI_STATUS GetEventLog(
//	    IN  EFI_TCG2_PROTOCOL          *This,
//	    IN  EFI_TCG2_EVENT_LOG_FORMAT   EventLogFormat,      // UINT32
//	    OUT EFI_PHYSICAL_ADDRESS       *EventLogLocation,    // UINT64*
//	    OUT EFI_PHYSICAL_ADDRESS       *EventLogLastEntry,   // UINT64*
//	    OUT BOOLEAN                    *EventLogTruncated );  // UINT8*
//
// TCG "EFI Protocol Specification, Family 2.0",
// "EFI_TCG2_PROTOCOL.GetEventLog()". EFI_PHYSICAL_ADDRESS is a UINT64 (UEFI
// spec, "Common UEFI Data Types"), so the two location out-params are written
// as 8-byte values and BOOLEAN as a single byte (UEFI spec: BOOLEAN is a
// UINT8, 0 = FALSE, 1 = TRUE).
//
// The protocol returns ADDRESSES, not bytes: EventLogLocation is the firmware-
// memory address of the log's FIRST entry and EventLogLastEntry the address of
// its LAST entry (NOT one-past-the-end). To get the full log this method
// computes the byte range
//
//	[location, lastEntry + sizeofEntry(lastEntry))
//
// by parsing the TCG_PCR_EVENT2 header at lastEntry to measure that final
// entry, then reads the range out of identity-mapped firmware memory (this
// loader runs pre-ExitBootServices with firmware memory directly addressable;
// see alloc_pages.go). The empty-log cases — location == 0 (no log), or
// lastEntry == location with only the legacy spec-ID header — are handled:
// the header itself is sized as a legacy TCG_PCR_EVENT so the returned range
// always covers exactly the recorded entries.
//
// A non-success EFI_STATUS is mapped through efitcg2's status handling by
// returning (nil, false, an *EFIError); efitcg2 surfaces it as the call error.
func (c tcg2Caller) GetEventLog(format uint32) (log []byte, truncated bool, err error) {
	var location uint64  // EFI_PHYSICAL_ADDRESS EventLogLocation
	var lastEntry uint64 // EFI_PHYSICAL_ADDRESS EventLogLastEntry
	var truncatedB uint8 // BOOLEAN EventLogTruncated

	status := efiCall(
		c.slot(tcg2MethodGetEventLog),
		c.proto, // This
		uint64(format),
		uint64(uintptr(unsafe.Pointer(&location))),
		uint64(uintptr(unsafe.Pointer(&lastEntry))),
		uint64(uintptr(unsafe.Pointer(&truncatedB))),
		0,
	)
	if status&efiStatusErrorBit != 0 {
		return nil, false, &EFIError{Status: status, Op: "EFI_TCG2_PROTOCOL.GetEventLog"}
	}
	truncated = truncatedB != 0

	// Empty log: firmware reports no event-log area. Return an empty (nil)
	// log; efitcg2 treats that as a valid no-measurements result.
	if location == 0 {
		return nil, truncated, nil
	}

	// Total log byte length = (lastEntry - location) + sizeofEntry(lastEntry).
	// lastEntry points AT the last record, so its own size must be added.
	lastSize, perr := tcg2EntrySize(location, lastEntry)
	if perr != nil {
		return nil, truncated, perr
	}
	total := (lastEntry - location) + lastSize
	log = readFirmwareBytes(location, int(total))
	return log, truncated, nil
}

// tcg2EntrySize returns the on-wire byte size of the event-log entry that
// starts at firmware address entry. The FIRST entry (entry == location) is the
// legacy TCG_PCR_EVENT spec-ID header; every other entry is a crypto-agile
// TCG_PCR_EVENT2. Both layouts are parsed by reading the relevant header fields
// out of firmware memory.
//
//	TCG_PCR_EVENT (legacy header), TCG PFP clause 9.4.5.1 / 10.2.1:
//	    PCRIndex   UINT32
//	    EventType  UINT32
//	    Digest     UINT8[20]   (SHA-1)
//	    EventSize  UINT32
//	    Event      UINT8[EventSize]
//	=> size = 4 + 4 + 20 + 4 + EventSize = 32 + EventSize
//
//	TCG_PCR_EVENT2 (crypto-agile), TCG PFP clause 10.2.1:
//	    PCRIndex   UINT32
//	    EventType  UINT32
//	    Digests    TPML_DIGEST_VALUES { Count UINT32, [Count] TPMT_HA{ AlgId UINT16, Digest UINT8[algSize] } }
//	    EventSize  UINT32
//	    Event      UINT8[EventSize]
//
// The event log on the wire is LITTLE-ENDIAN (TCG PFP, "the event log uses
// little-endian"), unlike the big-endian TPM 2.0 command stream. perr is
// non-nil only on an unknown digest algorithm (a malformed log the firmware
// should never produce), surfaced so the validation walls loudly rather than
// reading a wrong range.
func tcg2EntrySize(location, entry uint64) (uint64, error) {
	if entry == location {
		// Legacy TCG_PCR_EVENT header (PCRIndex 4 + EventType 4 + SHA-1 digest
		// 20 = 28-byte fixed prefix): EventSize is the UINT32 at offset 28, and
		// the entry size is 28 + 4 (EventSize) + EventSize.
		const legacyPrefix = 4 + 4 + 20 // PCRIndex, EventType, SHA-1 digest
		eventSize := readFirmwareU32LE(entry + legacyPrefix)
		return legacyPrefix + 4 + uint64(eventSize), nil
	}
	// Crypto-agile TCG_PCR_EVENT2. Walk the variable-length digest list.
	off := entry + 8 // skip PCRIndex(4) + EventType(4)
	count := readFirmwareU32LE(off)
	off += 4
	for i := uint32(0); i < count; i++ {
		algID := readFirmwareU16LE(off)
		off += 2
		ds, ok := tcg2DigestSize(algID)
		if !ok {
			return 0, &EFIError{Status: efiStatusErrorBit | 0x02, Op: "tcg2EntrySize: unknown digest alg"} // EFI_INVALID_PARAMETER
		}
		off += uint64(ds)
	}
	eventSize := readFirmwareU32LE(off)
	off += 4
	off += uint64(eventSize)
	return off - entry, nil
}

// tcg2DigestSize returns the digest byte width for a TPM_ALG_ID, for the hash
// algorithms a firmware TPM event log uses. TCG "Algorithm Registry",
// TPM_ALG_*; widths per FIPS 180-4 / FIPS 202.
func tcg2DigestSize(algID uint16) (int, bool) {
	switch algID {
	case 0x0004: // TPM_ALG_SHA1
		return 20, true
	case 0x000B: // TPM_ALG_SHA256
		return 32, true
	case 0x000C: // TPM_ALG_SHA384
		return 48, true
	case 0x000D: // TPM_ALG_SHA512
		return 64, true
	case 0x0012: // TPM_ALG_SM3_256
		return 32, true
	default:
		return 0, false
	}
}

// readFirmwareBytes copies n bytes from identity-mapped firmware memory at
// physical address addr into a fresh Go slice. The loader runs pre-
// ExitBootServices where firmware memory is directly addressable on every
// supported 64-bit target (see alloc_pages.go).
func readFirmwareBytes(addr uint64, n int) []byte {
	if n <= 0 {
		return nil
	}
	src := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), n)
	out := make([]byte, n)
	copy(out, src)
	return out
}

// readFirmwareU16LE / readFirmwareU32LE read a little-endian integer from
// firmware memory at physical address addr. The event log is little-endian
// (TCG PFP, "Event Logging").
func readFirmwareU16LE(addr uint64) uint16 {
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), 2)
	return uint16(b[0]) | uint16(b[1])<<8
}

func readFirmwareU32LE(addr uint64) uint32 {
	b := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), 4)
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
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
