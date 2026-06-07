// Phase-2 M2-B post-EBS virtio-net probe — stub for builds without
// the live tamago thunk path. The live implementation in
// phase2_virtionet_postebs.go is gated on
// `phase2_virtionet_postebs_tx && tamago`; this stub fills in the
// symbol for:
//
//   - any build with no probe tag at all (Phase-1 banner default);
//   - any build with only phase2_pcienum / phase2_snpenum /
//     phase2_blkprintk / phase2_virtionet_tx and not
//     phase2_virtionet_postebs_tx;
//   - any host build (`GOOS=darwin`, etc) with
//     `-tags phase2_virtionet_postebs_tx` — needed so
//     `go test -tags phase2_virtionet_postebs_tx` can compile.

//go:build !phase2_virtionet_postebs_tx || !tamago

package main

// runVirtioNetPostEBSProbe is a no-op when the live path is not linked.
// The live implementation lives in phase2_virtionet_postebs.go and is
// only linked when `phase2_virtionet_postebs_tx && tamago` is set.
func runVirtioNetPostEBSProbe() {}
