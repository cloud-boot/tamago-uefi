// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// chainedtinyB — M6.2 de-risk variant: no println body at all. Wires
// the firmware-aware exit hook and returns immediately. Drops the
// fmt/print path from the linker closure, which should chop a few
// tens of KiB versus tinyA.
//
// Detection in the parent: there's no child banner, but the parent's
// uefiboard.StartImage call returns cleanly (because the runtime
// goes through goosExit -> gBS->Exit), so the parent prints
// "phase2-efi-tiny-handover: ... chain-boot returned exit_status=".
// That single line is the PASS signal for tinyB.
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_amd64_chainedtinyB.elf ./cmd/chainedtinyB
package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
	uefiboard.WireExitToFirmware()
}
