// Phase-2 probe stub — when the binary is NOT built with any of the
// `-tags phase2_*` probe tags, runPhase2Probe is a compile-time no-op.
// Phase 1 banner-only behaviour is preserved bit-for-bit.
//
// Active probe tags (the dispatcher in phase2_dispatch.go selects
// which probes run; this file fires only when ALL are off):
//   - phase2_probe           : M0   — GetMemoryMap probe (phase2_probe.go)
//   - phase2_pcienum         : M1   — PCI IO enumeration + virtio-net
//                                     identity probe (phase2_pcienum.go)
//   - phase2_snpenum         : M1.5 — EFI_SIMPLE_NETWORK_PROTOCOL handle
//                                     enumeration + MAC peek (phase2_snpenum.go)
//   - phase2_blkprintk       : M1.6 — Block IO side-channel print sink
//                                     (phase2_blkprintk.go) — composes with
//                                     phase2_pcienum + phase2_snpenum.
//   - phase2_virtionet_tx    : M2   — pure-Go virtio-net TX/RX (one
//                                     ARP request + reply capture)
//                                     (phase2_virtionet_tx.go) —
//                                     composes with phase2_blkprintk.
//   - phase2_ministack_ping  : M3'  — hand-rolled ARP+IPv4+ICMP4 ping
//                                     over ministack (phase2_ministack_ping.go).
//   - phase2_dhcp4_acquire   : M4   — pure-Go DHCPv4 client over
//                                     ministack (phase2_dhcp4_acquire.go).
//
// `phase2_probe` is mutually exclusive with the M1/M1.5/M1.6/M2/M3/M4 dispatcher
// at build time; the M1/M1.5/M1.6/M2/M3/M4 tags compose freely.

//go:build !phase2_probe && !phase2_pcienum && !phase2_snpenum && !phase2_blkprintk && !phase2_virtionet_tx && !phase2_ministack_ping && !phase2_dhcp4_acquire

package main

func runPhase2Probe() {}
