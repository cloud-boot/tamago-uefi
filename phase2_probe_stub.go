// Phase-2 probe stub — when the binary is NOT built with
// `-tags phase2_probe`, runPhase2Probe is a compile-time no-op.
// Phase 1 banner-only behaviour is preserved bit-for-bit.

//go:build !phase2_probe

package main

func runPhase2Probe() {}
