// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// chainedtinyA — M6.2 de-risk variant: chainedhello with the shortest
// possible banner. Same shape as cmd/chainedhello (WireExitToFirmware
// + a single println + clean return through gBS->Exit) so we get a
// proper PASS signal (banner + parent's "chain-boot returned"
// line), but trimmed to drop a few hundred bytes versus chainedhello.
//
// The TamaGo runtime + uefiboard + alloc + gc + cpuinit make up the
// hard floor here (~1.4-1.7 MiB on amd64); this variant is the
// "biggest tiny" we test, mostly to validate the test harness works
// end-to-end against a TamaGo-built payload.
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_amd64_chainedtinyA.elf ./cmd/chainedtinyA
//
// Then linked into BOOTX64-CHAINEDTINYA.EFI via pectl link-pie.
package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
	uefiboard.WireExitToFirmware()
	// Shortest distinct banner the live runner can grep for.
	println(">>> M6.2 tinyA <<<")
}
