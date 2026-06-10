// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — fw_cfg MMIO base stub for arches OTHER than
// arm64 (Phase 2, M8.6). Returns (0, false) so FetchQemuDTB short-
// circuits with ErrFwCfgUnsupportedArch on amd64, loong64, riscv64.
//
// Why: M8.6's scope is fixing the arm64 DTB-absence Data Abort
// (R-M8.5a). amd64 firmware (OVMF) hands out ACPI exclusively and the
// EFI-stub doesn't traverse FDT on amd64, so fw_cfg has nothing useful
// for us there. riscv64 virt uses fw_cfg too but at a different MMIO
// base (0x10100000) — a future M8.x extension can flip it to its own
// per-arch file. loong64 virt has no fw_cfg device at all.

//go:build tamago && (amd64 || loong64 || riscv64)

package uefiboard

// fwCfgMMIOBase: not implemented for this arch. The caller (
// FetchQemuDTB) interprets (_, false) as ErrFwCfgUnsupportedArch.
func fwCfgMMIOBase() (uint64, bool) {
	return 0, false
}
