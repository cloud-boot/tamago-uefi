// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Stub for `runEFITinyHandoverProbe` when the
// `phase2_efi_tiny_handover` tag is NOT set, the build is not tamago,
// or the target arch is not amd64 (the M6.2 de-risk experiment is
// amd64-only by design — see phase2_efi_tiny_handover.go header).
//
// Matches the shape of the other phase-2 stubs: a no-op function the
// dispatcher (phase2_dispatch.go) can call unconditionally.

//go:build !phase2_efi_tiny_handover || !tamago || !amd64

package main

// runEFITinyHandoverProbe is a no-op in any build that doesn't have
// the M6.2 de-risk probe tag set, isn't tamago, or isn't amd64.
func runEFITinyHandoverProbe() {}
