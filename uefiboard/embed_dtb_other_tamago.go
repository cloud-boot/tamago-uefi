// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EmbeddedArm64VirtDTB stub for tamago arches
// other than arm64 (amd64, loong64, riscv64). The embedded DTB is
// arm64-virt-specific; on amd64 the firmware uses ACPI exclusively
// (so no DTB is needed), and loong64/riscv64 use their own
// per-platform DTBs which a future M8.x can embed separately.

//go:build tamago && (amd64 || loong64 || riscv64)

package uefiboard

// EmbeddedArm64VirtDTB returns an empty slice on non-arm64 arches.
// Callers should treat this the same as a host build's empty slice:
// "no embedded DTB available for this platform".
func EmbeddedArm64VirtDTB() []byte {
	return []byte{}
}
