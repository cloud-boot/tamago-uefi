// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 firmware event-log validation probe — gated on
// `-tags phase2_tpm_eventlog`.
//
// This is the SELF-CONTAINED real-firmware validation of efitcg2 v0.2.0's
// GetEventLog (EFI_TCG2_PROTOCOL.GetEventLog, vtable index 1) + the
// loader-side event-log byte-range computation in
// uefiboard/tcg2_protocol_tamago.go + the firmware-log↔attest replay
// integration. Unlike the OCI kernel-boot measured-boot path
// (phase2_tpm_measure.go), it needs NO network/registry: it synthesizes a
// measurement so the loop runs under a bare QEMU + OVMF(Tcg2Dxe) + swtpm.
//
// Steps (printed for the run harness to assert on):
//
//	1. Locate EFI_TCG2_PROTOCOL (skip cleanly if no firmware TPM).
//	2. Extend a synthetic blob into PCR4 via MeasureToPCR
//	   (HashLogExtendEvent: extend + firmware event-log record).
//	3. Read PCR4 back over the SAME efitcg2 transport (TPM2_PCR_Read via
//	   SubmitCommand) — the firmware's ACTUAL PCR4.
//	4. Fetch the FIRMWARE event log via efitcg2.GetEventLog.
//	5. attest.ParseEventLog + attest.ReplayPCRs (SHA-256), and assert the
//	   replayed PCR4 == the firmware PCR4 from step 3.
//
// On success it prints the canonical PASS line:
//
//	EFITCG2-EVENTLOG: firmware log N bytes, M events; replay PCR4 == firmware PCR4; PASS

//go:build phase2_tpm_eventlog && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/go-tpm2/attest"
	"github.com/go-tpm2/common"
	"github.com/go-tpm2/efitcg2"
	"github.com/go-tpm2/tpm2"
)

// elPCR4 is the PCR this probe measures into and replays. PCR 4 is the
// firmware-measured-boot home of a loaded boot application image (TCG PC
// Client Platform Firmware Profile, "PCR Usage").
const elPCR4 = 4

// evEFIBootServicesApplicationEL = EV_EFI_BOOT_SERVICES_APPLICATION, the
// event type a loaded UEFI boot application is recorded under (TCG PFP,
// "Event Types").
const evEFIBootServicesApplicationEL uint32 = 0x80000003

func runTPMEventLogProbe() {
	println("phase2-tpm-eventlog: locating EFI_TCG2_PROTOCOL")
	proto, err := uefiboard.LocateTCG2()
	if err != nil {
		println("phase2-tpm-eventlog: LocateTCG2 error:", err.Error())
		return
	}
	if proto == 0 {
		println("phase2-tpm-eventlog: no EFI_TCG2_PROTOCOL (firmware exposes no TPM); skipping")
		return
	}
	println("phase2-tpm-eventlog: EFI_TCG2_PROTOCOL located")

	t := uefiboard.NewTCG2(proto)

	// Synthetic measurement: extend a fixed blob into PCR4 + event-log it.
	blob := []byte("cloud-boot phase2_tpm_eventlog synthetic image")
	if merr := t.MeasureToPCR(elPCR4, evEFIBootServicesApplicationEL, blob, []byte("synthetic")); merr != nil {
		println("phase2-tpm-eventlog: MeasureToPCR(PCR4) FAILED:", merr.Error())
		return
	}
	println("phase2-tpm-eventlog: PCR4 extended +", len(blob), "bytes event-logged")

	// Read the firmware's ACTUAL PCR4 back over the same transport.
	fwPCR4 := elReadPCR4(t)
	if fwPCR4 == nil {
		return
	}

	// Fetch the FIRMWARE event log and replay it.
	log, err := t.GetEventLog()
	if err != nil {
		println("phase2-tpm-eventlog: GetEventLog FAILED:", err.Error())
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
	replayed, ok := pcrs[elPCR4]
	if !ok {
		println("EFITCG2-EVENTLOG: firmware log has no PCR4 events; cannot compare")
		return
	}
	println("EFITCG2-EVENTLOG: replay  PCR4 (SHA-256) =", elHex(replayed))
	println("EFITCG2-EVENTLOG: firmware PCR4 (SHA-256) =", elHex(fwPCR4))

	if !elEqual(replayed, fwPCR4) {
		println("EFITCG2-EVENTLOG: replay PCR4 != firmware PCR4; FAIL")
		return
	}
	println("EFITCG2-EVENTLOG: firmware log", len(log), "bytes,", len(events),
		"events; replay PCR4 == firmware PCR4; PASS")
}

// elReadPCR4 issues TPM2_PCR_Read for PCR 4 (SHA-256) over the efitcg2
// transport and returns the digest (nil on failure).
func elReadPCR4(t *efitcg2.TCG2) []byte {
	dev := tpm2.New(t)
	_, digests, err := dev.PCRRead([]tpm2.PCRSelection{
		{Hash: uint16(common.AlgSHA256), PCRs: []int{elPCR4}},
	})
	if err != nil {
		println("phase2-tpm-eventlog: PCRRead(PCR4) FAILED:", err.Error())
		return nil
	}
	if len(digests) == 0 {
		println("phase2-tpm-eventlog: PCRRead(PCR4) returned no digest")
		return nil
	}
	println("phase2-tpm-eventlog: PCR4 readback (SHA-256) =", elHex(digests[0]))
	return digests[0]
}

// elHex renders bytes as lowercase hex (no encoding/hex import, matching
// the package convention).
func elHex(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, x := range b {
		out = append(out, digits[x>>4], digits[x&0x0f])
	}
	return string(out)
}

// elEqual reports byte-for-byte equality.
func elEqual(a, b []byte) bool {
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
