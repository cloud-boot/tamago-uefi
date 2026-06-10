// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EFI_RNG_PROTOCOL publisher (Phase 2, M8.7).
//
// What this is: the publish-side of the UEFI random number protocol.
// UEFI 2.10 §37.5 defines EFI_RNG_PROTOCOL with two function slots:
//
//	typedef struct {
//	    EFI_RNG_GET_INFO    GetInfo;
//	    EFI_RNG_GET_RNG     GetRNG;
//	} EFI_RNG_PROTOCOL;
//
//	EFI_STATUS GetInfo (
//	    IN     EFI_RNG_PROTOCOL  *This,
//	    IN OUT UINTN             *RNGAlgorithmListSize,
//	    OUT    EFI_RNG_ALGORITHM *RNGAlgorithmList );
//
//	EFI_STATUS GetRNG (
//	    IN  EFI_RNG_PROTOCOL  *This,
//	    IN  EFI_RNG_ALGORITHM *RNGAlgorithm OPTIONAL,
//	    IN  UINTN             RNGValueLength,
//	    OUT UINT8             *RNGValue );
//
// We publish under the canonical GUID:
//
//	3152bca5-eade-433d-862e-c01cdc291f44
//
// Why we need it (R-M8.6a, 2026-06-10): after M8.6 published a DTB
// and the kernel EFI-stub reached "Loaded initrd from
// LINUX_EFI_INITRD_MEDIA_GUID device path", the next failure was a
// Data Abort INSIDE EDK2's own RngDxe.dll on the kernel's second
// call to `efi_get_random_bytes` (the KASLR / kernel-entropy-seed
// retry path). The first RngDxe call returned EFI_INVALID_PARAMETER
// cleanly; the retry null-deref'd at offset 0x40 inside RngDxe with
// X16 = 0x40 = sizeof(zone state struct) — i.e. RngDxe reads a
// callback table from a still-zero global on retry.
//
// Approach A — kernel cmdline workaround (`nokaslr
// random.trust_bootloader=0 random.trust_cpu=0`) was tried first;
// the kernel STILL re-entered RngDxe and the abort recurred (the
// trust= knobs only affect entropy-pool seeding; KASLR is disabled
// but the EFI-stub's own `efi_get_random_bytes` for `loadrandr=`
// or for the post-StartImage `random_init()` initial seed still
// fires). Therefore: ship our own RNG protocol so the FIRST call
// succeeds and there is no retry.
//
// Implementation: pure-Go callback backed by `crypto/rand`. The asm
// trampoline pattern mirrors initrd_protocol_<arch>.s exactly:
//   - firmware ABI -> Go ABI0 marshal,
//   - call Go-side rngGetRNGGo / rngGetInfoGo,
//   - read EFI_STATUS from the result slot,
//   - restore + return.
//
// The handle is published via gBS->InstallProtocolInterface (single
// protocol — RNG, unlike initrd, does not need a device-path
// companion; the kernel's `efi_get_random_bytes` uses
// LocateProtocol(&EFI_RNG_PROTOCOL_GUID, NULL, &Rng) which finds
// the first matching handle without walking device-path).
//
// This file is host-buildable (no //go:build tamago) so the GUID,
// struct shape, and Go-side callback semantics are unit-testable
// without going anywhere near firmware. The live wrapper is in
// rng_protocol_tamago.go.

package uefiboard

import (
	"errors"
	"unsafe"
)

// EFIRngProtocolGUID
//
//	3152bca5-eade-433d-862e-c01cdc291f44
//
// Source: MdePkg/Include/Protocol/Rng.h (edk2.git) +
// UEFI 2.10 §37.5. Linux's efi_get_random_bytes
// (drivers/firmware/efi/libstub/random.c) uses exactly this GUID.
var EFIRngProtocolGUID = EFIGUID{
	Data1: 0x3152bca5,
	Data2: 0xeade,
	Data3: 0x433d,
	Data4: [8]uint8{0x86, 0x2e, 0xc0, 0x1c, 0xdc, 0x29, 0x1f, 0x44},
}

// EFI_BOOT_SERVICES function-pointer offset for
// InstallProtocolInterface — the single-protocol install used for
// RNG (no device-path companion needed). UEFI 2.10 §7.3.2.
// Cross-referenced in initrd_protocol.go: offset 128 is the start
// of the protocol-handler services block.
const efiBSInstallProtocolInterface = 128

// efiBSUninstallProtocolInterface offset (UEFI 2.10 §7.3.4) —
// immediately after InstallProtocolInterface in the EFI_BOOT_SERVICES
// layout.
const efiBSUninstallProtocolInterface = 144

// EFI_NATIVE_INTERFACE is the InterfaceType the firmware accepts for
// `gBS->InstallProtocolInterface(..., InterfaceType, ...)`. Spec
// defines exactly one value (0) for "native" interface (which is
// what every protocol we publish is). See UEFI 2.10 §7.3.2.
const efiNativeInterface = 0

// ErrEmptyRNGRequest is returned by rngGetRNGGo when the caller
// passes a zero-length request — UEFI spec is silent on the
// behaviour but EDK2 (MdeModulePkg/Universal/Security/RngDxe)
// returns EFI_INVALID_PARAMETER. We mirror that.
var ErrEmptyRNGRequest = errors.New("uefi: GetRNG ValueLength is zero")

// ErrRNGNotPublished is returned by UnpublishRNG when called with a
// zero handle — i.e. PublishRNG was never called, or has already
// been undone.
var ErrRNGNotPublished = errors.New("uefi: RNG handle is zero (not published or already unpublished)")

// ErrRNGRegistryFull is returned by PublishRNG when the fixed-size
// rngRegistry (used by the asm trampoline to look up the active RNG
// publisher by `this` pointer) has no free slot. Hitting this means
// more concurrent PublishRNG calls than the trampoline supports.
var ErrRNGRegistryFull = errors.New("uefi: PublishRNG rng registry full (bump rngRegistrySize)")

// EFIRngProtocol is the Go view of the EFI_RNG_PROTOCOL
// firmware-exposed struct (UEFI 2.10 §37.5):
//
//	typedef struct {
//	    EFI_RNG_GET_INFO  GetInfo;
//	    EFI_RNG_GET_RNG   GetRNG;
//	} EFI_RNG_PROTOCOL;
//
// Two function-pointer slots laid out contiguously. We allocate the
// struct in package memory (a global on tamago) so the firmware can
// hold a stable pointer for the lifetime of the published handle.
type EFIRngProtocol struct {
	GetInfo uint64 // firmware-callable function pointer, MS x64 / AAPCS64 / LP64 ABI
	GetRNG  uint64
}

// rngRegistrySize bounds how many concurrently-published RNG
// publishers the per-arch asm trampoline + Go callbacks can serve.
// UEFI is single-threaded and we publish exactly one at boot; the
// small fixed-size array (no map, no runtime calls) keeps the
// callbacks //go:nosplit-friendly.
const rngRegistrySize = 4

// rngEntry is one slot in the package-private registry of active
// RNG publishers. A non-zero `proto` field marks the slot as live.
// The publisher source is the package-level `rngSource` function
// pointer — we don't store per-entry source because all entries
// share the same crypto/rand-backed source.
type rngEntry struct {
	proto uintptr // address of the published EFI_RNG_PROTOCOL struct (== `this` the firmware passes)
}

// rngRegistry is the package-private array the asm trampoline-driven
// rngGetRNGGo / rngGetInfoGo scan on every firmware callback.
// Static storage — no map, no slice header — so accesses inside the
// nosplit bodies do not pull in runtime helpers.
var rngRegistry [rngRegistrySize]rngEntry

// rngEntropyFn is the package-level entropy source the Go-side
// callbacks pull bytes from. Defaults to a crypto/rand-backed
// reader in rng_protocol_tamago.go; tests in rng_protocol_test.go
// can override with a deterministic source. Signature mirrors
// io.Reader.Read but takes a raw pointer + length so the
// nosplit callback body can avoid constructing a slice header.
type rngEntropyFn func(buf uintptr, n uintptr) uintptr

// rngEntropy is the active source. The tamago build initialises
// it to readCryptoRand; the host build uses a deterministic stub
// (rng_protocol_host.go) so the unit tests are reproducible.
var rngEntropy rngEntropyFn

// EFI_STATUS values used by the rng callbacks. Re-declared as
// untyped consts (the typed ones in memorymap.go are tamago-only)
// so this file remains host-buildable.
const (
	rngEFISuccess          uintptr = 0
	rngEFIInvalidParameter uintptr = 0x8000000000000002
	rngEFIUnsupported      uintptr = 0x8000000000000003
	rngEFIDeviceError      uintptr = 0x8000000000000007
	rngEFINotFound         uintptr = 0x800000000000000E
)

// rngGetRNGGo is the Go-side handler the per-arch asm trampoline
// calls into after marshalling the firmware-ABI args into Go-ABI0
// positions. It implements EFI_RNG_PROTOCOL.GetRNG.
//
// Calling convention (Go ABI0):
//
//	in:  this        = pointer to the published EFI_RNG_PROTOCOL
//	     alg         = pointer to EFI_RNG_ALGORITHM GUID (may be NULL = default)
//	     valueLength = UINTN, number of random bytes requested
//	     valuePtr    = UINT8*, buffer to fill (must be non-NULL when valueLength > 0)
//	out: uintptr EFI_STATUS.
//
// We accept any alg (including NULL); the underlying entropy
// source is the same regardless. The Linux EFI-stub always passes
// a NULL alg pointer + a small length (16 bytes for KASLR seed,
// 32 for the kernel-entropy initial seed). EDK2's RngDxe behaves
// identically (any-alg is a no-op selector).
//
// MUST be //go:nosplit (no stack growth) because the firmware
// entered us on its own stack with no usable Go scheduler state.
// We deliberately avoid calling any runtime helper here: the byte
// fill goes through rngEntropy which is a raw-pointer interface
// (no slice header construction).
//
//go:nosplit
func rngGetRNGGo(this, alg, valueLength, valuePtr uintptr) uintptr {
	_ = alg // any-alg is accepted; semantics are identical for our source.

	if valueLength == 0 {
		return rngEFIInvalidParameter
	}
	if valuePtr == 0 {
		return rngEFIInvalidParameter
	}

	// Look up the published RNG by `this`. Linear scan over a
	// fixed-size array (no map lookups → no runtime helpers). We
	// don't actually USE the entry's contents — all entries share
	// the same global rngEntropy source — but the lookup proves
	// the call is bound to a live publisher (so a stale `this`
	// after UnpublishRNG returns EFI_NOT_FOUND instead of silently
	// servicing the call).
	found := false
	for i := 0; i < rngRegistrySize; i++ {
		if rngRegistry[i].proto == this && rngRegistry[i].proto != 0 {
			found = true
			break
		}
	}
	if !found {
		return rngEFINotFound
	}

	if rngEntropy == nil {
		return rngEFIDeviceError
	}

	// Fill the firmware-provided buffer with random bytes from
	// our source. The source returns the number of bytes actually
	// written; on short reads we report EFI_DEVICE_ERROR per
	// UEFI 2.10 §37.5 GetRNG return values.
	written := rngEntropy(valuePtr, valueLength)
	if written != valueLength {
		return rngEFIDeviceError
	}
	return rngEFISuccess
}

// rngGetInfoGo is the Go-side handler for EFI_RNG_PROTOCOL.GetInfo.
// We advertise a single algorithm (the EFI_RNG_ALGORITHM_RAW GUID)
// — that's the conventional "no preference, give me uniform random
// bytes" identifier UEFI consumers fall back to when GetRNG is
// called with a NULL algorithm pointer.
//
// Calling convention (Go ABI0):
//
//	in:  this       = pointer to the published EFI_RNG_PROTOCOL
//	     listSize   = IN/OUT UINTN*; on entry the buffer capacity,
//	                  on return the required size if BUFFER_TOO_SMALL
//	                  or the bytes written if SUCCESS.
//	     listPtr    = OUT EFI_RNG_ALGORITHM*; the firmware-allocated
//	                  buffer to fill with the algorithm-list. May be
//	                  NULL on the size-query call.
//	out: uintptr EFI_STATUS.
//
// The Linux EFI-stub does NOT call GetInfo — it goes straight to
// GetRNG with a NULL alg pointer. We still implement GetInfo for
// spec-compliance (a strict consumer would refuse to GetRNG against
// a protocol whose GetInfo returns nothing).
//
//go:nosplit
func rngGetInfoGo(this, listSize, listPtr uintptr) uintptr {
	if listSize == 0 {
		return rngEFIInvalidParameter
	}
	// Required size for our single-algorithm list: one EFI_GUID
	// = 16 bytes.
	const need uintptr = 16
	have := *(*uintptr)(unsafe.Pointer(listSize))
	if listPtr == 0 || have < need {
		*(*uintptr)(unsafe.Pointer(listSize)) = need
		return 0x8000000000000005 // EFI_BUFFER_TOO_SMALL
	}

	// Confirm `this` is a live publisher (mirror rngGetRNGGo).
	found := false
	for i := 0; i < rngRegistrySize; i++ {
		if rngRegistry[i].proto == this && rngRegistry[i].proto != 0 {
			found = true
			break
		}
	}
	if !found {
		return rngEFINotFound
	}

	// Write the EFI_RNG_ALGORITHM_RAW GUID into the caller buffer.
	// Source: MdePkg/Include/Protocol/Rng.h —
	//   EFI_RNG_ALGORITHM_RAW = e43176d7-b6e8-4827-b784-7ffdc4b68561
	// Encoded as RFC 4122 mixed-endian (Data1/Data2/Data3 LE,
	// Data4 raw).
	rawGUID := [16]byte{
		0xd7, 0x76, 0x31, 0xe4, // Data1 LE
		0xe8, 0xb6, // Data2 LE
		0x27, 0x48, // Data3 LE
		0xb7, 0x84, 0x7f, 0xfd, 0xc4, 0xb6, 0x85, 0x61, // Data4 raw
	}
	for i := uintptr(0); i < 16; i++ {
		*(*byte)(unsafe.Pointer(listPtr + i)) = rawGUID[i]
	}
	*(*uintptr)(unsafe.Pointer(listSize)) = need
	return rngEFISuccess
}
