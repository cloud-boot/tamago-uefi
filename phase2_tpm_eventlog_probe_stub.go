// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// No-op stub for the phase2_tpm_eventlog firmware event-log validation
// probe. When the binary is NOT built with `-tags phase2_tpm_eventlog`,
// runTPMEventLogProbe is a compile-time no-op and pulls in no TPM/attest
// code — main()'s call site stays unconditional but inert, preserving
// behaviour exactly.

//go:build !phase2_tpm_eventlog || !tamago

package main

func runTPMEventLogProbe() {}
