// Phase-2 probe stub — when the binary is NOT built with any of the
// `-tags phase2_*` probe tags, runPhase2Probe is a compile-time no-op.
// Phase 1 banner-only behaviour is preserved bit-for-bit.
//
// Active probe tags (each defines its own runPhase2Probe):
//   - phase2_probe    : M0 — GetMemoryMap probe (phase2_probe.go)
//   - phase2_pcienum  : M1 — PCI IO enumeration + virtio-net identity
//                       probe (phase2_pcienum.go)
//   - phase2_snpenum  : M1.5 — EFI_SIMPLE_NETWORK_PROTOCOL handle
//                       enumeration + MAC peek (phase2_snpenum.go)
//
// At most one probe tag may be set at a time; this stub fires when
// none are set.

//go:build !phase2_probe && !phase2_pcienum && !phase2_snpenum

package main

func runPhase2Probe() {}
