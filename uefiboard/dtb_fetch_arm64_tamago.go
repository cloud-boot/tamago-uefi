// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — arm64-specific fw_cfg MMIO base for the
// FetchQemuDTB live walker (Phase 2, M8.6). Shared MMIO walker lives
// in dtb_fetch_tamago.go; host-buildable surface in dtb_fetch.go.

//go:build tamago && arm64

package uefiboard

// fwCfgMMIOBase: arm64 virt — the MMIO base is fixed at 0x09020000
// by QEMU's hw/arm/virt.c::a15memmap[VIRT_FW_CFG].base, stable since
// QEMU v2.10 (the arm64 virt board freeze).
//
// HOWEVER: EDK2's ArmVirtPkg does NOT add the fw_cfg MMIO window
// to the UEFI page tables. A direct MMIO load/store on 0x09020000
// from a UEFI image produces a Synchronous External Abort
// (ESR_EL1 EC=0x25 ISS=0x50 FAR=0x09020008) that ArmCpuDxe's default
// handler asserts on, killing the boot. We learned this the hard
// way during the M8.6 live test (2026-06-10): the very first
// selector-port write inside FetchQemuDTB faulted, before the
// embedded-DTB fallback in MODE C could be reached.
//
// Until a future M8.x adds the gDS->AddMemorySpace + uefi
// MemoryAttribute plumbing to map the fw_cfg window into our
// address space, we return (0, false) here so FetchQemuDTB
// short-circuits with ErrFwCfgUnsupportedArch — never touches MMIO.
// The MODE C caller's embedded-DTB fallback (EmbeddedArm64VirtDTB)
// covers the publish-side need without any MMIO access.
//
// The live MMIO walker (dtb_fetch_tamago.go) is retained as code +
// kept correct against QEMU's docs/specs/fw_cfg.rst — the day EDK2
// (or our own pre-flight mapping) makes 0x09020000 reachable, we
// flip the second return value to true here and the live path
// works transparently.
func fwCfgMMIOBase() (uint64, bool) {
	return 0, false
}
