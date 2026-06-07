// cloud-boot UEFI board — post-EBS scratch-store host stub (M2-B).
//
// Mirror of `post_ebs_step_tamago.go`'s `postEBSScratchStore` for
// host builds. The tamago build dereferences `phys` as an
// `unsafe.Pointer` (real MMIO-grade write); the host build is a
// no-op (host tests can't dereference a fabricated physical
// address — they'd fault). The offset-arithmetic and bounds-check
// surface in `PostEBSScratchAppend` is still exercised, which is
// all the host tests care about.

//go:build !tamago

package uefiboard

// postEBSScratchStore is a no-op on host builds. The tamago
// implementation in `post_ebs_step_tamago.go` does the unsafe.Pointer
// dereference. Kept as a function (not a //go:linkname stub) so the
// host build's `go vet` doesn't flag a missing symbol.
func postEBSScratchStore(phys uint64, offset uint32, b byte) {
	// no-op
	_ = phys
	_ = offset
	_ = b
}
