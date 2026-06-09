// Phase-2 probe dispatcher (M1.5 onwards).
//
// When EITHER `phase2_pcienum`, `phase2_snpenum`,
// `phase2_blkprintk`, `phase2_virtionet_tx`,
// `phase2_ministack_ping`, `phase2_dhcp4_acquire`,
// `phase2_http_get`, `phase2_https_get`, `phase2_oci_fetch`, OR
// `phase2_efi_handover` (any combination) is set, this file owns
// the `runPhase2Probe` symbol that main.go calls. It invokes each
// enabled probe in sequence — Block-IO sink setup first (so
// subsequent prints are teed to disk), then PCI walk, then SNP
// walk, then the virtio-net TX/RX probe (M2), then the ministack
// ICMP-ping probe (M3-minimal), then the DHCPv4 acquire probe
// (M4), then the HTTP / HTTPS / OCI probes (M5/M6/M7), then the
// M8.0 EFI chain-boot probe, then a final Block-IO flush. Each
// probe's body lives in its own file and is gated on its own
// build tag; when a tag is NOT set, the matching `runXProbe`
// resolves to a no-op stub (phase2_*_stub.go).
//
// Why setup BEFORE the walks: the walks' output is exactly what
// M1.6 wants to capture on Apple VZ. Tee at the print boundary
// means we don't have to duplicate the walks; we just enable the
// sink before they run.
//
// The `phase2_probe` (M0) tag is unrelated to this dispatcher — M0's
// GetMemoryMap probe owns its own `runPhase2Probe` in phase2_probe.go
// and is mutually exclusive with the M1/M1.5/M1.6/M2/M3/M4 tags at build time.

//go:build (phase2_pcienum || phase2_snpenum || phase2_blkprintk || phase2_virtionet_tx || phase2_ministack_ping || phase2_dhcp4_acquire || phase2_http_get || phase2_https_get || phase2_oci_fetch || phase2_oci_stream_fetch || phase2_oci_cosign_verify || phase2_oci_oras_fetch || phase2_efi_handover || phase2_efi_tiny_handover || phase2_oci_kernel_boot) && !phase2_probe

package main

// runPhase2Probe is the single entry point main.go calls when any
// Phase-2 probe is enabled. With every M1 + M1.5 + M1.6 + M2 + M3 +
// M4 tag set it runs the Block-IO sink setup, then the PCI walk,
// then the SNP walk, then the virtio-net TX/RX probe (M2), then the
// ministack ICMP-ping probe (M3-minimal), then the DHCPv4 acquire
// probe (M4), then the Block-IO sentinel flush. With only a subset
// of the tags set, the missing probes resolve to no-op stubs and
// only the enabled ones run.
//
// Ordering note: M2, M3 and M4 all bring up the same virtio-net
// device and would step on each other (double init, double
// DRIVER_OK). The Taskfile never sets multiple of
// `phase2_virtionet_tx`, `phase2_ministack_ping`, and
// `phase2_dhcp4_acquire` simultaneously — each probe owns its own
// dedicated EFI — but if someone did, they would run in order and
// the second OpenVirtioNet would re-reset and re-init (idempotent
// per Virtio 1.1 §3.1.1).
func runPhase2Probe() {
	runBlkPrintkSetup()
	runPCIEnumProbe()
	runSNPEnumProbe()
	runVirtioNetTxProbe()
	runMinistackPingProbe()
	runDHCP4AcquireProbe()
	runHTTPGetProbe()
	runHTTPSGetProbe()
	runOCIFetchProbe()
	runOCIStreamFetchProbe()
	runOCICosignVerifyProbe()
	runOCIORASFetchProbe()
	runEFIHandoverProbe()
	runEFITinyHandoverProbe()
	runOCIKernelBootProbe()
	runBlkPrintkTeardown()
}
