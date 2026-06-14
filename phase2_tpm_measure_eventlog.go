// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 measured boot — firmware event-log replay validation.
// Gated on `-tags phase2_tpm_measure`. See phase2_tpm_measure.go.
//
// This closes the full real-firmware attestation loop:
//
//	1. measurePhase2 extended PCR4 (vmlinuz) and PCR8 (cmdline) via
//	   EFI_TCG2_PROTOCOL.HashLogExtendEvent (extend + firmware event-log
//	   record in one call), and read PCR4 back over SubmitCommand.
//	2. validateFirmwareEventLog fetches the FIRMWARE-maintained TCG event
//	   log via efitcg2.GetEventLog (EFI_TCG2_PROTOCOL.GetEventLog, vtable
//	   index 1 + the loader's firmware-memory range read), parses it with
//	   attest.ParseEventLog, replays the SHA-256 bank with attest.ReplayPCRs,
//	   and asserts the replayed PCR4 == the firmware's actual PCR4.
//
// A PASS proves the FIRMWARE log (not a node-built LogBuilder log) replays
// to the real firmware PCRs — the attestation payoff of measured boot and
// the validation target of efitcg2 v0.2.0's GetEventLog + the loader-side
// range computation in tcg2_protocol_tamago.go.

//go:build phase2_tpm_measure && tamago

package main

import (
	"github.com/go-tpm2/attest"
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/efitcg2"
)

// validateFirmwareEventLog fetches + replays the firmware TCG event log and
// asserts the replayed PCR4 matches fwPCR4 (the firmware PCR4 read back over
// the same transport). Best-effort: every failure is logged, never fatal —
// measured boot is additive, not a boot gate. On success it prints the
// canonical PASS line for the run harness to assert on:
//
//	EFITCG2-EVENTLOG: firmware log N bytes, M events; replay PCR4 == firmware PCR4; PASS
func validateFirmwareEventLog(t *efitcg2.TCG2, fwPCR4 []byte) {
	if fwPCR4 == nil {
		println("EFITCG2-EVENTLOG: no firmware PCR4 readback; skipping replay assertion")
		return
	}

	log, err := t.GetEventLog()
	if err != nil {
		// ErrEventLogUnsupported (Caller missing EventLogCaller) or
		// ErrEventLogTruncated (incomplete log) or a firmware call error.
		println("EFITCG2-EVENTLOG: GetEventLog FAILED:", err.Error())
		return
	}
	println("EFITCG2-EVENTLOG: firmware log", len(log), "bytes")

	events, err := attest.ParseEventLog(log)
	if err != nil {
		println("EFITCG2-EVENTLOG: ParseEventLog FAILED:", err.Error())
		return
	}
	println("EFITCG2-EVENTLOG: parsed", len(events), "events")

	pcrs, err := attest.ReplayPCRs(events, uint16(common.AlgSHA256))
	if err != nil {
		println("EFITCG2-EVENTLOG: ReplayPCRs FAILED:", err.Error())
		return
	}
	replayed, ok := pcrs[int(pcrKernelImage)]
	if !ok {
		println("EFITCG2-EVENTLOG: firmware log has no PCR4 events; cannot compare")
		return
	}
	println("EFITCG2-EVENTLOG: replay  PCR4 (SHA-256) =", hexBytesTPM(replayed))
	println("EFITCG2-EVENTLOG: firmware PCR4 (SHA-256) =", hexBytesTPM(fwPCR4))

	if !equalBytesTPM(replayed, fwPCR4) {
		println("EFITCG2-EVENTLOG: replay PCR4 != firmware PCR4; FAIL")
		return
	}

	// Final step: build an attest.EventLogPolicy from the firmware log's own
	// measurements (every event's SHA-256 digest allowlisted) and confirm it
	// ADMITS the firmware PCRs + log. This is the attestation primitive a
	// verifier runs: ParseEventLog + ReplayPCRs (replay == attested PCRs) AND
	// every event on the allowlist. We seed the allowlist FROM the firmware log
	// (a self-consistency / round-trip check on real firmware data), and pin the
	// attested PCR map to the firmware's actual PCR4 read back over SubmitCommand.
	pol := attest.NewEventLogPolicy().RestrictPCRs(int(pcrKernelImage))
	for _, ev := range events {
		d, ok := ev.Digests[uint16(common.AlgSHA256)]
		if ok {
			pol.AllowMeasurement(ev.PCR, d)
		}
	}
	attested := map[int][]byte{int(pcrKernelImage): fwPCR4}
	if perr := pol.Matches(attested, log); perr != nil {
		println("EFITCG2-EVENTLOG: EventLogPolicy.Matches REJECTED:", perr.Error())
		return
	}
	println("EFITCG2-EVENTLOG: EventLogPolicy ADMITS firmware log against firmware PCR4")

	// Canonical PASS line (see the package doc above).
	println("EFITCG2-EVENTLOG: firmware log", len(log), "bytes,", len(events),
		"events; replay==PCRs OK; PASS")
}

// equalBytesTPM reports whether a and b are byte-for-byte equal. Local to keep
// the dependency surface minimal (matching hexBytesTPM's convention rather than
// pulling bytes.Equal into this path).
func equalBytesTPM(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
