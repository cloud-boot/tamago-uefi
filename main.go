// cloud-boot — TamaGo UEFI Phase-1 proof of life (multi-arch).
//
// A pure-Go bare-metal UEFI application built on the standard Go runtime
// via TamaGo (GOOS=tamago, GOARCH=amd64/arm64/loong64/riscv64). It uses
// cloud-boot's OWN UEFI board (package uefiboard) — NOT go-boot — for
// the firmware entry, the per-arch service-call thunk, and ConOut
// wiring.
//
// Default build: Phase-1 banner only (prints + goroutine sum + halt).
// Phase 2 milestones add their probes behind build tags:
//
//   - `phase2_probe`  : M0 — GetMemoryMap, print summary, halt.
//
// Build tags compose with the existing `linkcpuinit,linkramstart` set
// the Taskfile pins, e.g.
//
//	GOOS=tamago GOARCH=arm64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_probe \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// Phase 2's design doc lives at
// `cloud-boot/docs/tamago-uefi-phase2-oci-loader.md`.
package main

import (
	"runtime"

	_ "github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
	println("hello from cloud-boot tamago/" + runtime.GOARCH + " UEFI board")
	println("runtime:", runtime.Version(), "GOOS="+runtime.GOOS+" GOARCH="+runtime.GOARCH)

	// goroutine + channel smoke test (proves the real scheduler is up,
	// the whole point of TamaGo over TinyGo).
	done := make(chan int, 1)
	go func() {
		sum := 0
		for i := 0; i < 1000; i++ {
			sum += i
		}
		done <- sum
	}()
	println("goroutine sum:", <-done)

	// Phase-2 M0 probe — opt-in via `-tags phase2_probe`. When NOT
	// built with that tag, runPhase2Probe is the no-op stub in
	// phase2_probe_stub.go and Phase 1 behaviour is preserved exactly.
	runPhase2Probe()

	// Phase-2 firmware event-log validation — opt-in via
	// `-tags phase2_tpm_eventlog`. Self-contained (no OCI/network): it
	// locates EFI_TCG2_PROTOCOL, extends a synthetic measurement into PCR4
	// via HashLogExtendEvent, fetches the FIRMWARE event log via
	// EFI_TCG2_PROTOCOL.GetEventLog, replays it with go-tpm2/attest, and
	// asserts the replay matches the firmware's PCR4. When NOT built with
	// the tag, runTPMEventLogProbe is the no-op stub and behaviour is
	// preserved exactly.
	runTPMEventLogProbe()

	println("DONE — halting")
	for {
		// spin; nothing to exit to yet.
	}
}
