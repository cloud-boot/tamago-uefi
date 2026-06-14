// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 measured boot — gated on `-tags phase2_tpm_measure`.
//
// ADDITIVE + REVERSIBLE: this file's measurement logic compiles ONLY
// under the `phase2_tpm_measure` build tag. The companion
// phase2_tpm_measure_stub.go provides a no-op measurePhase2 with the
// SAME signature for every build WITHOUT the tag, so the single call
// site in phase2_oci_kernel_boot.go is unconditional but does nothing
// (and pulls in no TPM code) when the tag is off. Removing the tag
// fully reverts the loader to its prior behaviour.
//
// What it does (tag ON): locates the firmware's EFI_TCG2_PROTOCOL,
// and if present measures the just-fetched, already-SHA-256-verified
// kernel image + cmdline into the firmware TPM via
// EFI_TCG2_PROTOCOL.HashLogExtendEvent (extend + event-log in one
// firmware call). No TPM present ⇒ silently skipped.
//
//   - PCR 4: the kernel image (vmlinuz), event type
//     EV_EFI_BOOT_SERVICES_APPLICATION — the firmware-measured-boot
//     home of a loaded boot application image (TCG PC Client Platform
//     Firmware Profile, "PCR Usage").
//   - PCR 8: the kernel command line, event type EV_IPL — the
//     conventional bootloader "config/cmdline" PCR.
//
// The kernel bytes are measured BEFORE LoadImage, mirroring how a
// firmware-measured boot path would record the application image it is
// about to launch, while the bytes are still the exact verified blob.

//go:build phase2_tpm_measure && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// TCG event types (TCG PC Client Platform Firmware Profile, "Event
// Types"). Only the two this path emits are defined here.
const (
	// evEFIBootServicesApplication = EV_EFI_BOOT_SERVICES_APPLICATION:
	// a UEFI boot-services application image was measured/loaded.
	evEFIBootServicesApplication uint32 = 0x80000003
	// evIPL = EV_IPL: an Initial Program Loader event — used here for
	// the kernel command line.
	evIPL uint32 = 0x0000000D
)

// PCR assignments for the measured boot of the OCI-streamed kernel.
const (
	pcrKernelImage uint32 = 4 // boot application image
	pcrKernelCmd   uint32 = 8 // bootloader config / cmdline
)

// measurePhase2 measures the verified kernel image and command line
// into the firmware TPM via EFI_TCG2_PROTOCOL, if one is present. It
// is a best-effort, non-fatal step: any failure is logged and the boot
// continues unchanged (measured boot is additive, not a gate).
//
// Called from phase2_oci_kernel_boot.go right after streamExtractVmlinuz
// (vmlinuz is the exact bytes whose SHA-256 was just verified), before
// LoadImage.
func measurePhase2(vmlinuz []byte, cmdline string) {
	proto, err := uefiboard.LocateTCG2()
	if err != nil {
		println("phase2-tpm-measure: LocateTCG2 error:", err.Error())
		return
	}
	if proto == 0 {
		println("phase2-tpm-measure: no EFI_TCG2_PROTOCOL (firmware exposes no TPM); skipping measured boot")
		return
	}
	println("phase2-tpm-measure: EFI_TCG2_PROTOCOL located; measuring kernel image + cmdline")

	tcg2 := uefiboard.NewTCG2(proto)

	if merr := tcg2.MeasureToPCR(pcrKernelImage, evEFIBootServicesApplication, vmlinuz, []byte("vmlinuz")); merr != nil {
		println("phase2-tpm-measure: MeasureToPCR(PCR4, vmlinuz) FAILED:", merr.Error())
	} else {
		println("phase2-tpm-measure: PCR4 extended with vmlinuz (", len(vmlinuz), "bytes) + event-logged")
	}

	if len(cmdline) > 0 {
		if merr := tcg2.MeasureToPCR(pcrKernelCmd, evIPL, []byte(cmdline), []byte("cmdline")); merr != nil {
			println("phase2-tpm-measure: MeasureToPCR(PCR8, cmdline) FAILED:", merr.Error())
		} else {
			println("phase2-tpm-measure: PCR8 extended with cmdline (", len(cmdline), "bytes) + event-logged")
		}
	}

	// Read PCR4 back over the SAME efitcg2 transport (TPM2_PCR_Read via
	// SubmitCommand) so the run log carries on-device proof the extend
	// landed. This exercises the SubmitCommand vtable slot (index 3) in
	// addition to HashLogExtendEvent (index 2).
	fwPCR4 := readBackPCR4(tcg2)

	// Fetch the FIRMWARE's TCG event log via EFI_TCG2_PROTOCOL.GetEventLog
	// (vtable index 1), replay it with go-tpm2/attest, and assert the
	// replayed PCR4 == the firmware's actual PCR4 just read back. This is
	// the full real-firmware attestation loop: it proves the FIRMWARE log
	// (not a node-built one) reproduces the real PCRs.
	validateFirmwareEventLog(tcg2, fwPCR4)
}
