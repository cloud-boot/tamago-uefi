// Host-side tests for the M2-B captured-state shape.
//
// The live `CapturePreEBS` call lives in `post_ebs_capture_tamago.go`
// and needs Boot Services; this file only exercises the pure-data
// surface of `CapturedState` (IsCaptured, field defaults, MAC).

package uefiboard

import (
	"testing"
)

func TestCapturedState_IsCaptured_NilReceiver(t *testing.T) {
	var s *CapturedState
	if s.IsCaptured() {
		t.Errorf("nil receiver IsCaptured() = true, want false")
	}
}

func TestCapturedState_IsCaptured_AllZero(t *testing.T) {
	s := &CapturedState{}
	if s.IsCaptured() {
		t.Errorf("all-zero CapturedState IsCaptured() = true, want false")
	}
}

func TestCapturedState_IsCaptured_MissingMAC(t *testing.T) {
	// All other fields populated, MAC zero.
	s := &CapturedState{
		PCICommonCfgPhys:     0x1000,
		PCINotifyCfgPhys:     0x2000,
		PCIDeviceCfgPhys:     0x3000,
		VQRingsPhys:          [2]uint64{0x4000, 0x5000},
		BlkPrintkScratchPhys: 0x6000,
	}
	if s.IsCaptured() {
		t.Errorf("missing-MAC CapturedState IsCaptured() = true, want false")
	}
}

func TestCapturedState_IsCaptured_HappyPath(t *testing.T) {
	s := &CapturedState{
		PCICommonCfgPhys:     0x1000,
		PCINotifyCfgPhys:     0x2000,
		PCIDeviceCfgPhys:     0x3000,
		VQRingsPhys:          [2]uint64{0x4000, 0x5000},
		BlkPrintkScratchPhys: 0x6000,
		MAC:                  MAC6{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
	}
	if !s.IsCaptured() {
		t.Errorf("happy-path CapturedState IsCaptured() = false, want true")
	}
}

// TestCapturedState_IsCaptured_MissingEachField exercises every
// required-field gate by zeroing one slot at a time from a known-good
// CapturedState and confirming `IsCaptured` reports false.
func TestCapturedState_IsCaptured_MissingEachField(t *testing.T) {
	mkOK := func() *CapturedState {
		return &CapturedState{
			PCICommonCfgPhys:     0x1000,
			PCINotifyCfgPhys:     0x2000,
			PCIDeviceCfgPhys:     0x3000,
			VQRingsPhys:          [2]uint64{0x4000, 0x5000},
			BlkPrintkScratchPhys: 0x6000,
			MAC:                  MAC6{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02},
		}
	}
	cases := []struct {
		name string
		zero func(*CapturedState)
	}{
		{"PCICommonCfgPhys", func(s *CapturedState) { s.PCICommonCfgPhys = 0 }},
		{"PCINotifyCfgPhys", func(s *CapturedState) { s.PCINotifyCfgPhys = 0 }},
		{"PCIDeviceCfgPhys", func(s *CapturedState) { s.PCIDeviceCfgPhys = 0 }},
		{"VQRingsPhys[0]", func(s *CapturedState) { s.VQRingsPhys[0] = 0 }},
		{"VQRingsPhys[1]", func(s *CapturedState) { s.VQRingsPhys[1] = 0 }},
		{"BlkPrintkScratchPhys", func(s *CapturedState) { s.BlkPrintkScratchPhys = 0 }},
		{"MAC", func(s *CapturedState) { s.MAC = MAC6{} }},
	}
	for _, c := range cases {
		s := mkOK()
		c.zero(s)
		if s.IsCaptured() {
			t.Errorf("zeroing %s: IsCaptured() = true, want false", c.name)
		}
	}
}

func TestPostEBSScratchSize(t *testing.T) {
	// Match the captured-state struct documentation: one page.
	if PostEBSScratchSize != 4096 {
		t.Errorf("PostEBSScratchSize = %d, want 4096", PostEBSScratchSize)
	}
}

func TestPostEBSScratchAppend_NilState(t *testing.T) {
	// Nil receiver / nil state should not panic — silently drop the
	// byte. Useful because the post-EBS path runs after EBS, where a
	// nil-deref fault is unrecoverable.
	PostEBSScratchAppend(nil, 'X')
	// no panic == pass
}

func TestPostEBSScratchAppend_NoScratchPhys(t *testing.T) {
	s := &CapturedState{} // BlkPrintkScratchPhys = 0
	PostEBSScratchAppend(s, 'X')
	if s.BlkPrintkScratchOffset != 0 {
		t.Errorf("PostEBSScratchOffset advanced past nil-scratch: %d", s.BlkPrintkScratchOffset)
	}
}

func TestPostEBSScratchAppend_FullBuffer(t *testing.T) {
	// Pre-set the offset to the max — further appends should drop.
	// We can't actually exercise the unsafe.Pointer write under host
	// `go test` (it would fault on a non-mapped phys address), so we
	// use the offset == size guard. The host-buildable code path
	// short-circuits before the write.
	s := &CapturedState{
		BlkPrintkScratchPhys:   0xDEADBEEF, // non-zero so we get past the early-out
		BlkPrintkScratchOffset: PostEBSScratchSize,
	}
	// This MUST short-circuit before postEBSScratchWrite is called.
	// On host build, postEBSScratchWrite has no implementation
	// (it's tamago-only); the host build sees only the offset
	// check above and returns without ever taking the unsafe write
	// path.
	PostEBSScratchAppend(s, 'X')
	if s.BlkPrintkScratchOffset != PostEBSScratchSize {
		t.Errorf("PostEBSScratchOffset advanced past max: %d", s.BlkPrintkScratchOffset)
	}
}
