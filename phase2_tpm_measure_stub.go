// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 measured boot — no-op stub for builds WITHOUT the
// `phase2_tpm_measure` tag.
//
// This keeps the single call site in phase2_oci_kernel_boot.go
// unconditional (always compiles) while pulling in ZERO TPM/efitcg2
// code and doing nothing when the tag is off. With the tag ON the real
// measurePhase2 in phase2_tpm_measure.go takes over. This is the
// reversibility guarantee: drop the tag ⇒ this no-op is what links.

//go:build !phase2_tpm_measure

package main

// measurePhase2 is a no-op when measured boot is not compiled in. Same
// signature as the real implementation in phase2_tpm_measure.go.
func measurePhase2(vmlinuz []byte, cmdline string) {}
