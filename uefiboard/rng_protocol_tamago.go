// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — PublishRNG / UnpublishRNG live wrappers
// (Phase 2, M8.7 — closes R-M8.6a).
//
// What's shipped here:
//   - PublishRNG() installs an EFI_RNG_PROTOCOL instance on a fresh
//     handle, wired to the per-arch rngGetRNG_trampoline +
//     rngGetInfo_trampoline asm symbols. The Linux EFI-stub's
//     `efi_get_random_bytes` (drivers/firmware/efi/libstub/random.c)
//     does LocateProtocol(&EFI_RNG_PROTOCOL_GUID, NULL, &Rng) and
//     calls our GetRNG callback on the first matching handle.
//   - UnpublishRNG(handle) reverses the install via
//     gBS->UninstallProtocolInterface and clears the registry.
//
// The asm trampolines (rng_protocol_<arch>.s) mirror the
// initrd_protocol_<arch>.s shape exactly — same Go ABI0 slot
// reservation convention, same callee-saved-register save/restore
// envelope.
//
// The entropy source on tamago is `crypto/rand` (tamago-pie ships a
// working software-only implementation; see
// tamago-pie/src/crypto/rand/rand.go). We seed our own per-call
// buffer fill via `rand.Read` and surface a short-read as
// EFI_DEVICE_ERROR.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"unsafe"
)

// rngPublishState holds the per-publish backing memory. The
// firmware retains pointers into protocol for the lifetime of the
// installed handle; we keep it alive in a package-global map keyed
// by handle so UnpublishRNG can free it after uninstall succeeds.
type rngPublishState struct {
	protocol *EFIRngProtocol
	slot     int // index into rngRegistry (-1 if not stored)
}

// publishedRNGs tracks active PublishRNG installs. The map is
// package-private — exposed only via PublishRNG / UnpublishRNG.
var publishedRNGs = map[uintptr]*rngPublishState{}

// rngGetRNG_trampoline and rngGetInfo_trampoline are the per-arch
// asm symbols that bridge the firmware-side ABI into Go ABI0 +
// rngGetRNGGo / rngGetInfoGo. Defined in rng_protocol_<arch>.s.
func rngGetRNG_trampoline()
func rngGetInfo_trampoline()

// rngTrampolinePCs returns the .abi0 entry PCs of the two RNG
// trampolines. The per-arch implementation lives in
// rng_protocol_trampolinepc_<arch>.go:
//
//   - amd64 keeps the legacy funcval-first-word deref (Sprint 1.2
//     did NOT touch RNG; the RNG path predates the ABIInternal-wrapper
//     diagnosis and has not manifested the symptom under M8.x).
//   - arm64 / riscv64 / loong64 call the per-arch
//     rngGetRNG_trampolinePC / rngGetInfo_trampolinePC asm helpers
//     (Sprint 1.3 R-fbsd1c), which use the assembler's
//     `MOVD $sym(SB),Rn` pseudo (LEAQ-direct equivalent) to resolve
//     directly to the .abi0 entry — bypassing any Go ABIInternal
//     wrapper that might end with FP / g-register clobbers.

func init() {
	rngEntropy = readXorshiftTamago
}

// rngXorshiftState is the package-private state of the xorshift64*
// generator (Marsaglia 2003) we use as the firmware-callback
// entropy source. The initial seed is a non-zero constant; on
// every byte returned the state advances. NOT cryptographically
// strong — the seed is deterministic across boots — but the
// consumer (Linux EFI-stub on a `nokaslr random.trust_*=0`
// cmdline) only uses the bytes to satisfy the EFI_RNG_PROTOCOL
// contract; the actual kernel entropy pool is seeded later
// from CPU + interrupt timing.
//
// Why not crypto/rand: the firmware enters our trampoline on the
// firmware-side stack with substantially less Go-side runtime
// state than a normal goroutine. crypto/rand.Read on tamago calls
// into the Go runtime's GC + sync primitives, which Data Abort
// when re-entered from the firmware-call context (live trace
// 2026-06-10, retry path crashed at offset 0x40 inside our own
// PIE — i.e. inside the runtime's first heap deref under the
// foreign stack). A self-contained xorshift loop touches NO
// runtime helpers and fits cleanly inside the //go:nosplit
// envelope the trampoline established.
var rngXorshiftState uint64 = 0xa3b195354a39b70d

// readXorshiftTamago is the tamago entropy source. Pure xorshift64*
// loop, no runtime helpers, no stack-grow. Returns n on success
// (always).
//
//go:nosplit
func readXorshiftTamago(buf uintptr, n uintptr) uintptr {
	state := rngXorshiftState
	for i := uintptr(0); i < n; i += 8 {
		// xorshift64* core (Marsaglia + Vigna mix constant).
		state ^= state >> 12
		state ^= state << 25
		state ^= state >> 27
		v := state * 0x2545F4914F6CDD1D

		// Spill up to 8 bytes from v into the firmware buffer.
		limit := uintptr(8)
		if n-i < limit {
			limit = n - i
		}
		for j := uintptr(0); j < limit; j++ {
			*(*byte)(unsafe.Pointer(buf + i + j)) = byte(v >> (8 * j))
		}
	}
	rngXorshiftState = state
	return n
}

// UninstallAllRNG yanks EFI_RNG_PROTOCOL from every handle in the
// firmware's handle database without installing our own replacement.
// After it returns, a subsequent
// gBS->LocateProtocol(EFI_RNG_PROTOCOL_GUID, NULL, &iface) returns
// EFI_NOT_FOUND, which lets the Linux EFI-stub's
// `efi_random_get_seed()` short-circuit (see
// drivers/firmware/efi/libstub/random.c — when locate_protocol fails
// the function sets seed_size = 0 and, absent a `RandomSeed` UEFI
// variable, returns early without any further firmware calls).
//
// Returns the count of interfaces yanked (0 = none were present).
//
// Why this rather than PublishRNG (R-M8.8a, 2026-06-10): PublishRNG
// closed R-M8.6a (RngDxe.dll crash on KASLR retry) by replacing the
// firmware's RngDxe handle with our crypto/rand-backed handler. But
// running with M81_LIVE_KEEPRUN=1 + post-EBS log inspection
// uncovered a SECOND pre-ExitBootServices Data Abort downstream of
// our handler — somewhere in `efi_random_get_seed()`'s post-GetRNG
// flow (install_configuration_table + memory-map walk). The
// simplest and most robust workaround is to make
// efi_random_get_seed() take the "no RNG available" early-exit
// path: zero firmware calls instead of (our GetRNG +
// install_configuration_table + free_pool + ...). The kernel's own
// entropy pool is seeded later from CPU + interrupt timing — the
// EFI-stub seed is a defence-in-depth value, not a hard
// requirement for boot.
//
// Idempotency: safe to call multiple times; subsequent calls find
// no interfaces and return 0.
//
// See cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §M8.9 for
// the full diagnosis trace + decision rationale.
func UninstallAllRNG() int {
	bs := getBootServices()
	if bs == 0 {
		return 0
	}
	handles, lerr := LocateHandleBuffer(&EFIRngProtocolGUID)
	if lerr != nil {
		// LocateHandleBuffer returning an error covers both "no
		// such GUID in the handle database" (which is what we
		// want — nothing to do) and "out of resources" (rare on
		// fresh boot). Either way, nothing to yank.
		return 0
	}
	yanked := 0
	for _, h := range handles {
		iface, herr := HandleProtocol(h, &EFIRngProtocolGUID)
		if herr != nil {
			println("phase2-rng: HandleProtocol(existing RNG) skip:", herr.Error())
			continue
		}
		ustatus := efiCall(
			bs+efiBSUninstallProtocolInterface,
			h,
			uint64(uintptr(unsafe.Pointer(&EFIRngProtocolGUID))),
			iface,
			0, 0, 0,
		)
		if ustatus != efiSuccess {
			println("phase2-rng: UninstallProtocolInterface(firmware RNG) non-success:", ustatus)
			continue
		}
		println("phase2-rng: uninstalled firmware RNG interface on handle =", h)
		yanked++
	}
	return yanked
}

// PublishRNG installs an EFI_RNG_PROTOCOL instance on a fresh
// handle. Returns the firmware-assigned handle (caller passes to
// UnpublishRNG to remove) or an error.
//
// On success the published protocol's GetRNG slot is the per-arch
// rngGetRNG_trampoline + GetInfo is rngGetInfo_trampoline, so the
// EFI-stub's call into LocateProtocol(EFI_RNG_PROTOCOL_GUID, ...)
// + GetRNG is fully serviced by Go-side code backed by
// crypto/rand.
//
// Critical detail (R-M8.6a, 2026-06-10): EDK2's `-machine virt`
// arm64 firmware ALREADY publishes its own RngDxe under the same
// GUID, AND that RngDxe.dll Data Aborts on the kernel's RETRY of
// GetRNG (first call returns EFI_INVALID_PARAMETER cleanly; the
// retry null-derefs at offset 0x40). UEFI's
// LocateProtocol(GUID, NULL, &iface) returns the FIRST matching
// handle in the handle database — installation order. To ensure
// the kernel's call lands on OUR safe handler, we must first
// UNINSTALL the firmware's EFI_RNG_PROTOCOL interfaces from every
// pre-existing handle that publishes it. We do not destroy the
// underlying handles (other protocols on the same handle keep
// living) — we just yank the RNG interface so subsequent
// LocateProtocol calls walk past them to ours.
func PublishRNG() (uintptr, error) {
	bs := getBootServices()
	if bs == 0 {
		return 0, ErrNoBootServices
	}

	// Step 1: enumerate every handle currently publishing
	// EFI_RNG_PROTOCOL (the firmware's own RngDxe instance, on
	// arm64-virt). Uninstall the RNG interface from each so the
	// only remaining handle after we install ours is ours.
	if handles, lerr := LocateHandleBuffer(&EFIRngProtocolGUID); lerr == nil {
		for _, h := range handles {
			// Grab the firmware's interface pointer so we can
			// pass it back to UninstallProtocolInterface (UEFI
			// 2.10 §7.3.4 requires the original interface
			// pointer to match the install).
			iface, herr := HandleProtocol(h, &EFIRngProtocolGUID)
			if herr != nil {
				println("phase2-rng: HandleProtocol(existing RNG) skip:", herr.Error())
				continue
			}
			ustatus := efiCall(
				bs+efiBSUninstallProtocolInterface,
				h,
				uint64(uintptr(unsafe.Pointer(&EFIRngProtocolGUID))),
				iface,
				0, 0, 0,
			)
			if ustatus != efiSuccess {
				// Non-fatal: even if we couldn't yank the
				// firmware's interface, our subsequent install
				// still adds a fallback that the kernel's
				// LocateHandleBuffer + iterate path can find.
				println("phase2-rng: UninstallProtocolInterface(firmware RNG) non-success:", ustatus)
			} else {
				println("phase2-rng: uninstalled firmware RNG interface on handle =", h)
			}
		}
	}

	// Resolve the asm trampoline entry PCs. Per-arch helper handles
	// the amd64 funcval-deref vs arm64/riscv64/loong64 LEAQ-direct
	// PC-helper split (see rngTrampolinePCs docstring above).
	getRNGPC, getInfoPC := rngTrampolinePCs()
	protocol := &EFIRngProtocol{
		GetInfo: uint64(getInfoPC),
		GetRNG:  uint64(getRNGPC),
	}

	// Reserve a registry slot BEFORE the firmware install so any
	// later GetRNG call (single-threaded UEFI: only possible from
	// the same call chain, but be defensive) sees a fully
	// populated entry.
	slot := -1
	for i := range rngRegistry {
		if rngRegistry[i].proto == 0 {
			slot = i
			break
		}
	}
	if slot < 0 {
		return 0, ErrRNGRegistryFull
	}
	rngRegistry[slot] = rngEntry{
		proto: uintptr(unsafe.Pointer(protocol)),
	}

	// gBS->InstallProtocolInterface signature (UEFI 2.10 §7.3.2):
	//
	//   EFI_STATUS InstallProtocolInterface(
	//       IN OUT EFI_HANDLE          *Handle,
	//       IN     EFI_GUID            *Protocol,
	//       IN     EFI_INTERFACE_TYPE  InterfaceType,
	//       IN     VOID                *Interface );
	//
	// With *Handle = NULL on entry the firmware allocates a fresh
	// handle and returns it via Handle. InterfaceType MUST be
	// EFI_NATIVE_INTERFACE (0) — the only value the spec defines.
	var handle uint64
	status := efiCall(
		bs+efiBSInstallProtocolInterface,
		uint64(uintptr(unsafe.Pointer(&handle))),
		uint64(uintptr(unsafe.Pointer(&EFIRngProtocolGUID))),
		uint64(efiNativeInterface),
		uint64(uintptr(unsafe.Pointer(protocol))),
		0, 0,
	)
	if status != efiSuccess {
		// Roll back the registry reservation on firmware failure.
		rngRegistry[slot] = rngEntry{}
		return 0, &EFIError{Status: status, Op: "InstallProtocolInterface(rng)"}
	}

	// Pin the protocol struct + registry slot against GC for the
	// lifetime of the install.
	publishedRNGs[uintptr(handle)] = &rngPublishState{
		protocol: protocol,
		slot:     slot,
	}
	return uintptr(handle), nil
}

// UnpublishRNG undoes a previous PublishRNG by calling
// gBS->UninstallProtocolInterface on the given handle and releasing
// the backing Go-side state + clearing the registry slot so a stale
// GetRNG dispatch after this point returns EFI_NOT_FOUND.
func UnpublishRNG(handle uintptr) error {
	if handle == 0 {
		return ErrRNGNotPublished
	}
	state, ok := publishedRNGs[handle]
	if !ok {
		return ErrRNGNotPublished
	}
	bs := getBootServices()
	if bs == 0 {
		return ErrNoBootServices
	}

	// gBS->UninstallProtocolInterface signature (UEFI 2.10 §7.3.4):
	//
	//   EFI_STATUS UninstallProtocolInterface(
	//       IN EFI_HANDLE  Handle,
	//       IN EFI_GUID   *Protocol,
	//       IN VOID       *Interface );
	status := efiCall(
		bs+efiBSUninstallProtocolInterface,
		uint64(handle),
		uint64(uintptr(unsafe.Pointer(&EFIRngProtocolGUID))),
		uint64(uintptr(unsafe.Pointer(state.protocol))),
		0, 0, 0,
	)
	if status != efiSuccess {
		// Leave the registry slot + publishedRNGs entry live so a
		// retry can find the pointers.
		return &EFIError{Status: status, Op: "UninstallProtocolInterface(rng)"}
	}
	if state.slot >= 0 && state.slot < rngRegistrySize {
		rngRegistry[state.slot] = rngEntry{}
	}
	delete(publishedRNGs, handle)
	return nil
}
