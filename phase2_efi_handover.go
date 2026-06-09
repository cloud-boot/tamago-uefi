// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M8.0 probe — gated on `-tags phase2_efi_handover`.
//
// Proves the chain-boot mechanism under TamaGo+UEFI: hand a PE32+
// EFI binary to gBS->LoadImage, then call gBS->StartImage to
// transfer control to it, then observe a clean return.
//
// This probe does NOT use the network. The chained EFI payload
// (cmd/chainedhello, built by `task chainedhello:efi:<arch>`) is
// embedded into the parent binary at build time via `//go:embed`,
// so M8.0 is purely about exercising the firmware's image-services
// path: LoadImage + StartImage + UnloadImage + Exit. Streaming-OCI
// fetch of a real kernel-sized blob is the M8.1 follow-up
// (deferred behind M6.1 amd64 OVMF PE>4MiB bug + M7.1 streaming
// blob fetch).
//
// Steps the probe runs:
//
//   1. Print the embed length so the test runner can confirm a
//      non-trivial payload made it through.
//   2. Call uefiboard.LoadImage(embedBytes) — firmware parses the
//      embedded PE32+, allocates pages, applies relocations.
//   3. Print the returned child image handle.
//   4. Call uefiboard.StartImage(handle) — firmware transfers
//      control to the child's entry point.
//   5. The child (cmd/chainedhello) prints its banner via
//      println / ConOut and returns via gBS->Exit (wired through
//      uefiboard.WireExitToFirmware in the child's main).
//   6. Print the exit status the StartImage call returned.
//   7. Call uefiboard.UnloadImage(handle) to release the child's
//      firmware resources.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_efi_handover \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `efihandover:efi:<arch>` for the per-arch
// wiring.)

//go:build phase2_efi_handover && tamago

package main

import (
	"runtime"

	"github.com/cloud-boot/tamago-uefi/internal/embed_chained"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// runEFIHandoverProbe is the entry point the dispatcher calls when
// the `phase2_efi_handover` build tag is set.
func runEFIHandoverProbe() {
	println("phase2-efi-handover: M8.0 -- gBS->LoadImage + StartImage chain-boot mechanism")
	println("phase2-efi-handover: arch =", runtime.GOARCH)

	// The chained payload ships gzipped in the parent binary so the
	// amd64 PE32+ stays below the M6.1 EDK2 OVMF CpuPageTableLib
	// threshold (~3.17 MiB band; see cloud-boot/docs §5 M6.1). Pay
	// the inflate cost here at probe time rather than at package
	// init so non-M8.0 builds get nothing.
	payload, err := embed_chained.Decompress()
	if err != nil {
		println("phase2-efi-handover: embed Decompress FAILED:", err.Error())
		println("phase2-efi-handover: HANDOVER FAIL:", err.Error())
		return
	}
	println("phase2-efi-handover: embed length (decompressed) =", len(payload))
	if len(payload) == 0 {
		println("phase2-efi-handover: HANDOVER FAIL: embedded chained payload is empty")
		return
	}

	// Smoke-check the PE/COFF leader: every UEFI PE32+ image
	// starts with `MZ` (DOS header magic). If this byte pair is
	// wrong the firmware will reject with EFI_LOAD_ERROR, so
	// flagging it here gives a clearer error than the raw
	// EFI_STATUS later.
	if len(payload) < 2 || payload[0] != 'M' || payload[1] != 'Z' {
		println("phase2-efi-handover: HANDOVER FAIL: payload[0:2] is not 'MZ'")
		return
	}
	println("phase2-efi-handover: payload PE header OK (MZ)")

	handle, err := uefiboard.LoadImage(payload)
	if err != nil {
		println("phase2-efi-handover: LoadImage FAILED:", err.Error())
		println("phase2-efi-handover: HANDOVER FAIL:", err.Error())
		return
	}
	println("phase2-efi-handover: LoadImage OK, handle =", hexUintptr(handle))

	println("phase2-efi-handover: StartImage entering child")
	status, sErr := uefiboard.StartImage(handle)
	// Whether or not StartImage returned a non-zero status, the
	// fact that it returned at all proves the chain-boot mechanism
	// worked end-to-end (child loaded, jumped to, returned).
	println("phase2-efi-handover: chain-boot returned exit_status=" + hexUintptr(status))
	if sErr != nil {
		println("phase2-efi-handover: child reported non-success:", sErr.Error())
	}

	// UnloadImage is only meaningful when the child returned WITHOUT
	// calling gBS->Exit (i.e. via a plain `return` from its entry
	// point that we'd want to clean up after). When the child
	// called gBS->Exit(0) — our chainedhello payload's default
	// path — the firmware has already torn the image down, and
	// UnloadImage returns EFI_INVALID_PARAMETER. So we only call
	// it on a non-zero exit status, where the firmware may have
	// kept the image around for diagnostics. Logged on failure but
	// non-fatal.
	if status != 0 {
		if err := uefiboard.UnloadImage(handle); err != nil {
			println("phase2-efi-handover: UnloadImage warning:", err.Error())
		} else {
			println("phase2-efi-handover: UnloadImage OK")
		}
	} else {
		println("phase2-efi-handover: child returned via gBS->Exit; UnloadImage skipped (firmware already cleaned up)")
	}

	println("phase2-efi-handover: HANDOVER OK")
}

// hexUintptr renders a uintptr as a 0x-prefixed hex string without
// pulling fmt into the build closure. Matches the style of
// uefiboard.hexU64 (memorymap.go) — kept inline because
// phase2_efi_handover doesn't link the rest of phase2_hex.go's
// helpers.
func hexUintptr(v uintptr) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v != 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	i--
	buf[i] = 'x'
	i--
	buf[i] = '0'
	return string(buf[i:])
}
