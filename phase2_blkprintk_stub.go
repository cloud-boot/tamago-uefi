// Phase-2 M1.6 Block IO side-channel probe — stub for builds without
// the live tamago thunk path. The live implementation in
// phase2_blkprintk.go is gated on `phase2_blkprintk && tamago`; this
// stub fills in the symbols for:
//
//   - any build with no probe tag at all (Phase-1 banner default);
//   - any build with only phase2_pcienum and/or phase2_snpenum
//     (M1.5 PCI+SNP probe — no Block IO side-channel needed there);
//   - any host build (`GOOS=darwin`, etc) with `-tags phase2_blkprintk`
//     — needed so `go test -tags phase2_blkprintk` can compile.

//go:build !phase2_blkprintk || !tamago

package main

// runBlkPrintkSetup is a no-op when the live path is not linked. The
// live implementation lives in phase2_blkprintk.go and is only linked
// when `phase2_blkprintk && tamago` is set.
func runBlkPrintkSetup() {}

// runBlkPrintkTeardown is a no-op when the live path is not linked.
// Symmetric to runBlkPrintkSetup — same gating.
func runBlkPrintkTeardown() {}
