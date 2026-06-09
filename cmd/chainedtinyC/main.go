// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// chainedtinyC — M6.2 de-risk variant: minimal main, no Exit hook,
// no println. Entry returns and the TamaGo runtime halts in its
// default spin-loop. The parent's StartImage call will NEVER return
// for this variant — that's by design: tinyC is purely a
// LOADIMAGE-SIZE probe. The PASS signal is just "LoadImage OK" + the
// absence of the CpuDxe.dll #GP block in the QEMU log. If LoadImage
// succeeded without the #GP, the size is under threshold even though
// the parent later wedges waiting for StartImage to return.
//
// To avoid wedging the live runner forever, the parent prints a
// "calling StartImage (no-return expected for tinyC)" marker BEFORE
// the StartImage call, and the runner's wall-clock cap (M8_LIVE_
// TIMEOUT, default 30s) tears QEMU down at the end. PASS detection
// in the runner: "LoadImage OK" present AND no #GP block.
//
// The uefiboard import is required to pull in cpuinit_amd64.s + the
// UEFI-style entry; without it the link would resolve runtime.cpuinit
// to nothing under -tags linkcpuinit. We use a blank import so no
// helper call ends up linked but the cpuinit + ramStart symbols
// (init-only) make it into the binary.
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_amd64_chainedtinyC.elf ./cmd/chainedtinyC
package main

import (
	// Required for cpuinit_amd64.s + ramStart (linkcpuinit/linkramstart).
	_ "github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
}
