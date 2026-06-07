// Phase-2 M1.5 SNP enumeration probe — stub for builds without
// the live tamago thunk path. The live implementation in
// phase2_snpenum.go is gated on `phase2_snpenum && tamago`; this
// stub fills in the symbol for:
//
//   - any build with no probe tag at all (Phase-1 banner default);
//   - any host build (`GOOS=darwin`, etc) with `-tags phase2_snpenum`
//     — needed so `go test -tags phase2_snpenum` can compile.

//go:build !phase2_snpenum || !tamago

package main

// runSNPEnumProbe is a no-op when the live path is not linked. The
// live implementation lives in phase2_snpenum.go and is only linked
// when `phase2_snpenum && tamago` is set.
func runSNPEnumProbe() {}
