// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 measured boot — PCR readback over the efitcg2 transport.
// Gated on `-tags phase2_tpm_measure`. See phase2_tpm_measure.go.
//
// This reads PCR 4 back through TPM2_PCR_Read, marshaled by
// go-tpm2/tpm2 and carried over the SAME EFI_TCG2_PROTOCOL.SubmitCommand
// transport (efitcg2.TCG2, which satisfies common.Transport). It is
// pure on-device confirmation that the HashLogExtendEvent extend landed
// — printed to the serial log for the run harness to assert on, and the
// value can be cross-checked against a swtpm-side computation of
// SHA-256 over the prior PCR4 value || SHA-256(vmlinuz).

//go:build phase2_tpm_measure && tamago

package main

import (
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/efitcg2"
	"github.com/go-tpm2/tpm2"
)

// readBackPCR4 issues TPM2_PCR_Read for PCR 4 in the SHA-256 bank over
// the efitcg2 transport and prints the digest as hex. Best-effort:
// failures are logged, never fatal.
func readBackPCR4(t *efitcg2.TCG2) {
	dev := tpm2.New(t)
	_, digests, err := dev.PCRRead([]tpm2.PCRSelection{
		{Hash: uint16(common.AlgSHA256), PCRs: []int{int(pcrKernelImage)}},
	})
	if err != nil {
		println("phase2-tpm-measure: PCRRead(PCR4) over efitcg2 FAILED:", err.Error())
		return
	}
	if len(digests) == 0 {
		println("phase2-tpm-measure: PCRRead(PCR4) returned no digest")
		return
	}
	println("phase2-tpm-measure: PCR4 readback (SHA-256) =", hexBytesTPM(digests[0]))
}

// hexBytesTPM renders a byte slice as lowercase hex without importing
// encoding/hex (keeps the dep surface minimal, matching the package's
// hexU64 convention).
func hexBytesTPM(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0x0f])
	}
	return string(out)
}
