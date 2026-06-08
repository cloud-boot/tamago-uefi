// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// chainedhello — minimal TamaGo+UEFI payload, designed to be loaded
// into RAM by a parent EFI image via gBS->LoadImage and started via
// gBS->StartImage (Phase 2, M8.0 chain-boot mechanism).
//
// Lifecycle:
//
//   1. UEFI firmware enters cpuinit_<arch>.s with
//      (ImageHandle, EFI_SYSTEM_TABLE*) — same handoff as the parent.
//   2. cpuinit captures ConOut, sets up RamStart, and jumps to
//      runtime.rt0 to bring the Go runtime up.
//   3. main() wires goos.Exit to gBS->Exit (via
//      uefiboard.WireExitToFirmware) so that when main returns the
//      runtime's exit path lands in firmware, not in the TamaGo
//      spin-halt.
//   4. main() prints the distinctive M8.0 banner to ConOut.
//   5. main() returns. runtime.exit calls our goos.Exit, which
//      calls gBS->Exit(0, EFI_SUCCESS), and control resumes in the
//      parent's matching StartImage call.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_<arch>_chainedhello.elf ./cmd/chainedhello
//
// Linked into PE32+/EFI via pectl (see Taskfile chainedhello:efi:*).
package main

import (
	"runtime"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
	// Install the firmware-aware exit hook BEFORE we print anything
	// the parent expects to follow with its "StartImage returned"
	// line — if main() ever returns without this, runtime.exit
	// halts on a `for {}` and the parent's StartImage never
	// resumes.
	uefiboard.WireExitToFirmware()

	// ASCII dash only — ConOut's UTF-16 surface mangles the
	// multi-byte UTF-8 sequence for U+2014 EM DASH into "???".
	// The live runner's grep pattern matches the ASCII form.
	println(">>> M8.0 chained payload -- Hello from " + runtime.GOARCH + " <<<")

	// Returning from main lands in runtime.exit → goos.Exit →
	// uefiboard.ExitImage(parentHandle, 0) → gBS->Exit(0). The
	// parent's StartImage call returns at this point.
}
