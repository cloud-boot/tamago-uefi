// Phase-2 probe dispatcher (M1.5 onwards).
//
// When EITHER `phase2_pcienum`, `phase2_snpenum`,
// `phase2_blkprintk`, `phase2_virtionet_tx`, OR
// `phase2_netstack_ping` (any combination) is set, this file
// owns the `runPhase2Probe` symbol that main.go calls. It
// invokes each enabled probe in sequence — Block-IO sink setup
// first (so subsequent prints are teed to disk), then PCI walk,
// then SNP walk, then the virtio-net TX/RX probe (M2), then the
// gvisor-netstack ICMP-ping probe (M3), then a final Block-IO
// flush. Each probe's body lives in its own file and is gated
// on its own build tag; when a tag is NOT set, the matching
// `runXProbe` resolves to a no-op stub (phase2_*_stub.go).
//
// Why setup BEFORE the walks: the walks' output is exactly what
// M1.6 wants to capture on Apple VZ. Tee at the print boundary
// means we don't have to duplicate the walks; we just enable the
// sink before they run.
//
// The `phase2_probe` (M0) tag is unrelated to this dispatcher — M0's
// GetMemoryMap probe owns its own `runPhase2Probe` in phase2_probe.go
// and is mutually exclusive with the M1/M1.5/M1.6/M2/M3 tags at build time.

//go:build (phase2_pcienum || phase2_snpenum || phase2_blkprintk || phase2_virtionet_tx || phase2_netstack_ping) && !phase2_probe

package main

// runPhase2Probe is the single entry point main.go calls when any
// Phase-2 probe is enabled. With every M1 + M1.5 + M1.6 + M2 + M3
// tag set it runs the Block-IO sink setup, then the PCI walk,
// then the SNP walk, then the virtio-net TX/RX probe (M2), then
// the gvisor-netstack ICMP-ping probe (M3), then the Block-IO
// sentinel flush. With only a subset of the tags set, the missing
// probes resolve to no-op stubs and only the enabled ones run.
//
// Ordering note: M2 and M3 both bring up the same virtio-net
// device and would step on each other (double init, double
// DRIVER_OK). The Taskfile never sets `phase2_virtionet_tx`
// and `phase2_netstack_ping` simultaneously — M3's binary
// drops the M2 probe — but if someone did, M2 would run first
// and leave the device in DRIVER_OK; M3's `OpenVirtioNet` would
// then re-reset and re-init (idempotent per Virtio 1.1 §3.1.1).
func runPhase2Probe() {
	runBlkPrintkSetup()
	runPCIEnumProbe()
	runSNPEnumProbe()
	runVirtioNetTxProbe()
	runNetstackPingProbe()
	runBlkPrintkTeardown()
}
