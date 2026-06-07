// Host-side tests for virtio_pci.go.
//
// The hot path is WalkVirtioPCICaps. M1's probe drives it via
// EFI_PCI_IO_PROTOCOL.Pci.Read callbacks; here we feed it a
// hand-rolled 256-byte config-space buffer and verify the walker
// emits the right capability list. Two synthetic chains:
//
//   1. Modern QEMU virtio-net layout (five caps: common / notify /
//      ISR / device / PCI cfg) — the happy path.
//   2. Malformed: a self-referential cycle and a pointer < 0x40.

package uefiboard

import (
	"encoding/binary"
	"testing"
)

// synthConfigSpace returns a 256-byte config-space buffer with the
// given vendor/device IDs, Status[CapList] set, the CapabilitiesPtr
// set to `firstCap`, and the given raw cap-list bytes pasted in
// starting at offset `firstCap`.
func synthConfigSpace(t *testing.T, vid, did uint16, status uint16, firstCap uint8, capBytes []byte) []byte {
	t.Helper()
	cfg := make([]byte, 256)
	binary.LittleEndian.PutUint16(cfg[0x00:0x02], vid)
	binary.LittleEndian.PutUint16(cfg[0x02:0x04], did)
	binary.LittleEndian.PutUint16(cfg[0x06:0x08], status)
	cfg[0x34] = firstCap
	if int(firstCap)+len(capBytes) > len(cfg) {
		t.Fatalf("synthConfigSpace: cap bytes overflow (cap=%d len=%d)", firstCap, len(capBytes))
	}
	copy(cfg[firstCap:int(firstCap)+len(capBytes)], capBytes)
	return cfg
}

// virtioCapBytes lays out one struct virtio_pci_cap (16 bytes) at the
// canonical offsets per Virtio 1.1 §4.1.4.
func virtioCapBytes(next, clen, cfgType, bar, id uint8, offset, length uint32) [16]byte {
	var b [16]byte
	b[0] = PCICapIDVendorSpecific // cap_vndr
	b[1] = next                   // cap_next
	b[2] = clen                   // cap_len
	b[3] = cfgType                // cfg_type
	b[4] = bar                    // bar
	b[5] = id                     // id
	// b[6..7] padding
	binary.LittleEndian.PutUint32(b[8:12], offset)
	binary.LittleEndian.PutUint32(b[12:16], length)
	return b
}

// readerOver returns read-byte / read-u32 callbacks bound to a config
// buffer. Mirrors what the live probe gets via the
// EFI_PCI_IO_PROTOCOL.Pci.Read width=Uint8/Uint32 paths.
func readerOver(cfg []byte) (ReadU8At, ReadU32At) {
	readU8 := func(off uint8) (uint8, error) {
		if int(off) >= len(cfg) {
			return 0, vpciError("test: read past config-space")
		}
		return cfg[off], nil
	}
	readU32 := func(off uint8) (uint32, error) {
		if int(off)+4 > len(cfg) {
			return 0, vpciError("test: read past config-space (u32)")
		}
		return binary.LittleEndian.Uint32(cfg[off : off+4]), nil
	}
	return readU8, readU32
}

// TestWalkVirtioPCICaps_ModernNet verifies the walker on a QEMU-shaped
// modern virtio-net (DID 0x1041) capability chain.
//
// Layout:
//
//	0x40: CommonCfg  → next 0x50, BAR=4, offset=0,    length=56
//	0x50: NotifyCfg  → next 0x60, BAR=4, offset=0x1000,length=0x1000
//	0x60: ISRCfg     → next 0x70, BAR=4, offset=0x2000,length=0x1000
//	0x70: DeviceCfg  → next 0x80, BAR=4, offset=0x3000,length=12
//	0x80: PCICfg     → next 0x00, BAR=0, offset=0,    length=0
func TestWalkVirtioPCICaps_ModernNet(t *testing.T) {
	var caps []byte
	at := func(b [16]byte) { caps = append(caps, b[:]...) }
	at(virtioCapBytes(0x50, 16, VirtioPCICapCommonCfg, 4, 0, 0x0000, 0x38))
	at(virtioCapBytes(0x60, 16, VirtioPCICapNotifyCfg, 4, 0, 0x1000, 0x1000))
	at(virtioCapBytes(0x70, 16, VirtioPCICapISRCfg, 4, 0, 0x2000, 0x1000))
	at(virtioCapBytes(0x80, 16, VirtioPCICapDeviceCfg, 4, 0, 0x3000, 12))
	at(virtioCapBytes(0x00, 16, VirtioPCICapPCICfg, 0, 0, 0x0000, 0x0000))

	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, caps)
	readU8, readU32 := readerOver(cfg)

	got, err := WalkVirtioPCICaps(0x40, readU8, readU32)
	if err != nil {
		t.Fatalf("WalkVirtioPCICaps: unexpected error: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("WalkVirtioPCICaps: got %d caps, want 5: %+v", len(got), got)
	}

	wantTypes := []uint8{
		VirtioPCICapCommonCfg,
		VirtioPCICapNotifyCfg,
		VirtioPCICapISRCfg,
		VirtioPCICapDeviceCfg,
		VirtioPCICapPCICfg,
	}
	for i, w := range wantTypes {
		if got[i].CfgType != w {
			t.Errorf("cap[%d].CfgType = %d, want %d", i, got[i].CfgType, w)
		}
	}
	if got[0].Offset != 0x0000 || got[0].Length != 0x38 || got[0].BAR != 4 {
		t.Errorf("CommonCfg locator wrong: %+v", got[0])
	}
	if got[3].Offset != 0x3000 || got[3].Length != 12 || got[3].BAR != 4 {
		t.Errorf("DeviceCfg locator wrong: %+v", got[3])
	}
	if got[0].CfgSpaceOffset != 0x40 || got[1].CfgSpaceOffset != 0x50 {
		t.Errorf("CfgSpaceOffset attribution wrong: %+v", got)
	}
}

// TestWalkVirtioPCICaps_SkipsNonVendor verifies that intermixed
// non-vendor capabilities (e.g. MSI-X with cap_id != 0x09) are
// transparently skipped — the walker follows their next pointer
// without emitting them.
func TestWalkVirtioPCICaps_SkipsNonVendor(t *testing.T) {
	var caps []byte
	at := func(b [16]byte) { caps = append(caps, b[:]...) }

	// 0x40 = MSI-X (cap_id 0x11), next 0x50
	msix := [16]byte{}
	msix[0] = 0x11 // MSI-X
	msix[1] = 0x50 // next
	caps = append(caps, msix[:]...)

	// 0x50 = virtio CommonCfg, next 0x00
	at(virtioCapBytes(0x00, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0))

	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, caps)
	readU8, readU32 := readerOver(cfg)

	got, err := WalkVirtioPCICaps(0x40, readU8, readU32)
	if err != nil {
		t.Fatalf("WalkVirtioPCICaps: unexpected error: %v", err)
	}
	if len(got) != 1 || got[0].CfgType != VirtioPCICapCommonCfg {
		t.Fatalf("walker should have emitted one CommonCfg, got %+v", got)
	}
}

// TestWalkVirtioPCICaps_EmptyChain verifies the FirstCap=0 short-circuit.
func TestWalkVirtioPCICaps_EmptyChain(t *testing.T) {
	cfg := make([]byte, 256)
	readU8, readU32 := readerOver(cfg)
	got, err := WalkVirtioPCICaps(0, readU8, readU32)
	if err != nil {
		t.Fatalf("WalkVirtioPCICaps(0): unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("WalkVirtioPCICaps(0): expected nil, got %+v", got)
	}
}

// TestWalkVirtioPCICaps_BadFirstPtr verifies that a cap pointer below
// 0x40 (in the standard header area) is rejected as malformed firmware
// rather than silently iterating into the device-ID/vendor-ID region.
func TestWalkVirtioPCICaps_BadFirstPtr(t *testing.T) {
	cfg := make([]byte, 256)
	readU8, readU32 := readerOver(cfg)
	_, err := WalkVirtioPCICaps(0x10, readU8, readU32)
	if err != ErrVirtioCapChainBadPtr {
		t.Fatalf("expected ErrVirtioCapChainBadPtr, got %v", err)
	}
}

// TestWalkVirtioPCICaps_Cycle verifies the cycle guard. We build a
// self-referential vendor cap at 0x40 whose Next points back at 0x40,
// and check the walker terminates with ErrVirtioCapChainTooLong after
// MaxVirtioCapsToWalk iterations.
func TestWalkVirtioPCICaps_Cycle(t *testing.T) {
	cap := virtioCapBytes(0x40 /* next = self */, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0)
	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, cap[:])
	readU8, readU32 := readerOver(cfg)
	got, err := WalkVirtioPCICaps(0x40, readU8, readU32)
	if err != ErrVirtioCapChainTooLong {
		t.Fatalf("expected ErrVirtioCapChainTooLong, got %v (len=%d)", err, len(got))
	}
	if len(got) != MaxVirtioCapsToWalk {
		t.Errorf("expected %d caps before bailing, got %d", MaxVirtioCapsToWalk, len(got))
	}
}

// TestWalkVirtioPCICaps_ReadError verifies that a read error in the
// middle of the walk is propagated, with whatever caps were collected
// so far. We stub out the reader to fail on the SECOND cap-header
// byte read (the `next` pointer at offset+1 of the second cap), so
// the first cap is emitted, then the walker hits the failure.
func TestWalkVirtioPCICaps_ReadError(t *testing.T) {
	var caps []byte
	at := func(b [16]byte) { caps = append(caps, b[:]...) }
	at(virtioCapBytes(0x50, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0))
	at(virtioCapBytes(0x00, 16, VirtioPCICapNotifyCfg, 0, 0, 0, 0))

	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, caps)
	readU8Underlying, readU32 := readerOver(cfg)
	failAfter := 6 // first cap reads u8 at +0,+1,+2,+3,+4,+5 → 6 calls
	count := 0
	readU8 := func(off uint8) (uint8, error) {
		count++
		if count > failAfter {
			return 0, vpciError("test: injected read failure")
		}
		return readU8Underlying(off)
	}
	got, err := WalkVirtioPCICaps(0x40, readU8, readU32)
	if err == nil {
		t.Fatalf("expected injected read error, got nil (caps=%+v)", got)
	}
	if len(got) != 1 {
		t.Errorf("expected 1 cap collected before the injected failure, got %d (caps=%+v)", len(got), got)
	}
	if got[0].CfgType != VirtioPCICapCommonCfg {
		t.Errorf("first emitted cap should be CommonCfg, got cfgType=%d", got[0].CfgType)
	}
}

// TestWalkVirtioPCICaps_ReadU32Error verifies that a u32-read failure
// (rather than u8) is also propagated. The injected reader fails the
// first u32 access, which happens at offset+8 of the first cap (the
// `offset` field), AFTER the u8 cap header bytes have all read OK.
func TestWalkVirtioPCICaps_ReadU32Error(t *testing.T) {
	cap := virtioCapBytes(0x00, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0)
	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, cap[:])
	readU8, _ := readerOver(cfg)
	failingU32 := func(off uint8) (uint32, error) {
		return 0, vpciError("test: injected u32 read failure")
	}
	got, err := WalkVirtioPCICaps(0x40, readU8, failingU32)
	if err == nil {
		t.Fatalf("expected injected u32 read error, got nil (caps=%+v)", got)
	}
	if len(got) != 0 {
		t.Errorf("expected no caps collected (failure before append), got %d", len(got))
	}
}

// TestWalkVirtioPCICaps_ReadU32OffsetError covers the SECOND u32 read
// in the cap-walker (the `length` field at offset+12). The offset
// field at offset+8 read OK, then length fails.
func TestWalkVirtioPCICaps_ReadU32OffsetError(t *testing.T) {
	cap := virtioCapBytes(0x00, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0)
	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, cap[:])
	readU8, readU32Underlying := readerOver(cfg)
	u32Calls := 0
	failingU32 := func(off uint8) (uint32, error) {
		u32Calls++
		if u32Calls == 2 { // length read at +12
			return 0, vpciError("test: length-read failure")
		}
		return readU32Underlying(off)
	}
	_, err := WalkVirtioPCICaps(0x40, readU8, failingU32)
	if err == nil {
		t.Fatalf("expected length-read failure to propagate, got nil")
	}
}

// TestWalkVirtioPCICaps_PerFieldU8Errors covers every per-field u8
// read in the loop body (clen at +2, cfgType at +3, bar at +4, id
// at +5). For each, we inject a failure exactly at that read
// position and confirm the walker bails with an error.
func TestWalkVirtioPCICaps_PerFieldU8Errors(t *testing.T) {
	cap := virtioCapBytes(0x00, 16, VirtioPCICapCommonCfg, 0, 0, 0, 0)
	cfg := synthConfigSpace(t, VirtioPCIVendorID, VirtioPCIDeviceIDModernNet,
		PCIStatusCapabilityList, 0x40, cap[:])
	_, readU32 := readerOver(cfg)

	// failAt: cap u8 read sequence is capID(+0), next(+1), clen(+2),
	// cfgType(+3), bar(+4), id(+5). Inject failure at each.
	for _, failAt := range []int{3, 4, 5, 6} {
		failAt := failAt
		t.Run("failU8At/"+itoa(failAt), func(t *testing.T) {
			readU8Underlying, _ := readerOver(cfg)
			count := 0
			injecting := func(off uint8) (uint8, error) {
				count++
				if count == failAt {
					return 0, vpciError("test: injected per-field u8 read failure")
				}
				return readU8Underlying(off)
			}
			_, err := WalkVirtioPCICaps(0x40, injecting, readU32)
			if err == nil {
				t.Fatalf("expected injected failure at u8 read #%d, got nil", failAt)
			}
		})
	}
}

// itoa is a host-test helper that avoids pulling strconv in (matching
// the host-test style elsewhere in this file).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestVirtioPCICapsByType(t *testing.T) {
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapCommonCfg, BAR: 1},
		{CfgType: VirtioPCICapDeviceCfg, BAR: 4, Offset: 0x3000},
	}
	got := VirtioPCICapsByType(caps, VirtioPCICapDeviceCfg)
	if got == nil || got.BAR != 4 || got.Offset != 0x3000 {
		t.Fatalf("VirtioPCICapsByType: got %+v, want DeviceCfg with BAR=4 offset=0x3000", got)
	}
	if VirtioPCICapsByType(caps, VirtioPCICapISRCfg) != nil {
		t.Fatalf("VirtioPCICapsByType: expected nil for missing cap type")
	}
}

func TestVirtioPCIDeviceIDHelpers(t *testing.T) {
	cases := []struct {
		did      uint16
		isNet    bool
		isModern bool
	}{
		{0x1000, true, false},  // legacy virtio-net
		{0x1001, false, false}, // legacy virtio-block (not net)
		{0x1040, false, true},  // modern, type 0 (reserved/network-ish)
		{0x1041, true, true},   // modern virtio-net
		{0x1042, false, true},  // modern virtio-block
		{0x107F, false, true},  // top of modern range
		{0x1080, false, false}, // outside both ranges
	}
	for _, c := range cases {
		if got := VirtioPCIDeviceIDIsNet(c.did); got != c.isNet {
			t.Errorf("VirtioPCIDeviceIDIsNet(0x%04x) = %v, want %v", c.did, got, c.isNet)
		}
		if got := VirtioPCIDeviceIDIsModern(c.did); got != c.isModern {
			t.Errorf("VirtioPCIDeviceIDIsModern(0x%04x) = %v, want %v", c.did, got, c.isModern)
		}
	}
}

func TestVirtioConstants(t *testing.T) {
	if VirtioPCIVendorID != 0x1AF4 {
		t.Errorf("VirtioPCIVendorID = 0x%04x, want 0x1AF4", VirtioPCIVendorID)
	}
	if VirtioMACLen != 6 {
		t.Errorf("VirtioMACLen = %d, want 6", VirtioMACLen)
	}
	// Virtio 1.1 §5.1.4 device-config offsets:
	if VirtioNetCfgOffsetMAC != 0 {
		t.Errorf("MAC offset = %d, want 0", VirtioNetCfgOffsetMAC)
	}
	if VirtioNetCfgOffsetStatus != 6 {
		t.Errorf("Status offset = %d, want 6", VirtioNetCfgOffsetStatus)
	}
	if VirtioNetCfgOffsetMaxVirtqueuePairs != 8 {
		t.Errorf("MaxVirtqueuePairs offset = %d, want 8", VirtioNetCfgOffsetMaxVirtqueuePairs)
	}
	if VirtioNetCfgOffsetMTU != 10 {
		t.Errorf("MTU offset = %d, want 10", VirtioNetCfgOffsetMTU)
	}
	// Cap-type constants per Virtio 1.1 §4.1.4:
	cases := []struct {
		name string
		v    uint8
		want uint8
	}{
		{"CommonCfg", VirtioPCICapCommonCfg, 1},
		{"NotifyCfg", VirtioPCICapNotifyCfg, 2},
		{"ISRCfg", VirtioPCICapISRCfg, 3},
		{"DeviceCfg", VirtioPCICapDeviceCfg, 4},
		{"PCICfg", VirtioPCICapPCICfg, 5},
		{"SharedMemCfg", VirtioPCICapSharedMemCfg, 8},
		{"VendorCfg", VirtioPCICapVendorCfg, 9},
	}
	for _, c := range cases {
		if c.v != c.want {
			t.Errorf("VirtioPCICap%s = %d, want %d", c.name, c.v, c.want)
		}
	}
}

// TestVirtioCapErrorTypeString verifies the sentinel-error formatting.
func TestVirtioCapErrorTypeString(t *testing.T) {
	if ErrVirtioCapChainTooLong.Error() == "" {
		t.Error("ErrVirtioCapChainTooLong message is empty")
	}
	if ErrVirtioCapChainBadPtr.Error() == "" {
		t.Error("ErrVirtioCapChainBadPtr message is empty")
	}
}
