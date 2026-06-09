// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Package embed_chained_tiny holds the per-variant `//go:embed`'d
// chained EFI payloads used by the Phase-2 M6.2 de-risk probe
// (phase2_efi_handover_tiny).
//
// Four variants are staged (amd64 only — M6.2 de-risk targets the
// EDK2 OVMF CpuPageTableLib bug, which only affects amd64):
//
//	A : TamaGo PIE with WireExit + short println banner (~1.7 MiB EFI)
//	B : TamaGo PIE with WireExit only, no println           (~1.7 MiB EFI)
//	C : TamaGo PIE with blank-import uefiboard, empty main  (~1.7 MiB EFI)
//	Z : Hand-rolled minimal PE32+ (xor eax,eax; ret)        (~1 KiB EFI)
//
// All four are staged gzipped (`tiny_<variant>_amd64.efi.gz`) so the
// parent stays well under the M6.1 amd64 LoadImage threshold for the
// PARENT itself (we don't want to fail measurement of the child by
// also tripping the bug on the parent).
//
// On host (`!tamago` build) all four are empty slices so the package
// compiles cleanly for go vet / tests.
//
// The .efi.gz files are NOT checked into git; the Taskfile regenerates
// them every build via the chainedtiny<variant>:efi:amd64 steps + a
// gzip step.
package embed_chained_tiny
