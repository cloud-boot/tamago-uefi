// Phase-2 M1 PCI-IO enumeration probe — stub for builds without
// the live tamago thunk path. The live implementation in
// phase2_pcienum.go is gated on `phase2_pcienum && tamago`; this
// stub fills in the symbol for:
//
//   - any build with no probe tag at all (Phase-1 banner default);
//   - any host build (`GOOS=darwin`, etc) with `-tags phase2_pcienum`
//     — needed so `go test -tags phase2_pcienum` can compile.
//
// Keeping the stub and the dispatch wrapper host-buildable lets
// `go test` exercise the probe-side host helpers (macHex, struct
// layout) without pulling in efiCall.

//go:build !phase2_pcienum || !tamago

package main

// runPCIEnumProbe is a no-op when the live path is not linked. The
// live implementation lives in phase2_pcienum.go and is only linked
// when `phase2_pcienum && tamago` is set.
func runPCIEnumProbe() {}
