// Phase-2 probe dispatcher (M1.5 onwards).
//
// When EITHER `phase2_pcienum` OR `phase2_snpenum` (or both) is set,
// this file owns the `runPhase2Probe` symbol that main.go calls. It
// invokes each enabled probe in sequence — PCI first, then SNP, since
// SNP wraps the same virtio-net device the PCI walk just identified.
// Each probe's body lives in its own file and is gated on its own
// build tag; when a tag is NOT set, the matching `runXEnumProbe`
// resolves to a no-op stub (phase2_*_stub.go).
//
// The `phase2_probe` (M0) tag is unrelated to this dispatcher — M0's
// GetMemoryMap probe owns its own `runPhase2Probe` in phase2_probe.go
// and is mutually exclusive with the M1/M1.5 tags at build time.

//go:build (phase2_pcienum || phase2_snpenum) && !phase2_probe

package main

// runPhase2Probe is the single entry point main.go calls when any
// Phase-2 probe is enabled. With both M1 + M1.5 tags set it runs the
// PCI walk first, then the SNP walk; with only one of them set, the
// other resolves to a no-op stub.
func runPhase2Probe() {
	runPCIEnumProbe()
	runSNPEnumProbe()
}
