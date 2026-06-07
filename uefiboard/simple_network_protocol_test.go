// Host-side tests for simple_network_protocol.go.
//
// Pure type-surface checks: GUID round-trip and field-offset / size
// assertions for EFI_SIMPLE_NETWORK_MODE. The live wrappers (if/when
// a future M-step adds them) will go in a separate
// simple_network_protocol_tamago.go and won't be host-exercisable.
//
// Reference values: MdePkg/Include/Protocol/SimpleNetwork.h (edk2.git
// stable/202408) and MdePkg/Include/Uefi/UefiBaseType.h.

package uefiboard

import (
	"testing"
	"unsafe"
)

func TestEFISimpleNetworkProtocolGUID(t *testing.T) {
	const text = "a19832b9-ac25-11d3-9a2d-0090273fc14d"
	want := guidFromText(t, text)
	if EFISimpleNetworkProtocolGUID != want {
		t.Errorf("EFISimpleNetworkProtocolGUID = %+v\nwant %+v\n(text %q)",
			EFISimpleNetworkProtocolGUID, want, text)
	}
}

// On-the-wire byte pattern for the EFI_SIMPLE_NETWORK_PROTOCOL_GUID,
// independent of the struct field layout above. This catches any
// mixed-endian transposition that the struct comparison would miss if
// guidFromText shared a bug with the GUID constant.
func TestEFISimpleNetworkProtocolGUIDWireBytes(t *testing.T) {
	// a19832b9-ac25-11d3-9a2d-0090273fc14d on-the-wire:
	// b9 32 98 a1  25 ac  d3 11  9a 2d 00 90 27 3f c1 4d
	want := [16]byte{0xb9, 0x32, 0x98, 0xa1, 0x25, 0xac, 0xd3, 0x11,
		0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d}
	got := guidToBytes(EFISimpleNetworkProtocolGUID)
	if got != want {
		t.Errorf("EFISimpleNetworkProtocolGUID wire bytes:\n got %#x\nwant %#x", got, want)
	}
}

// TestSNPProtocolStructOffsets pins the offsets of the
// EFI_SIMPLE_NETWORK_PROTOCOL function-table slots so the snpModeOffset
// constant the live probe relies on stays in sync with the EDK2
// header. We can't `unsafe.Offsetof` on a real Go struct mirror because
// the function pointers are opaque (no Go side), so we just pin the
// arithmetic.
func TestSNPProtocolStructOffsets(t *testing.T) {
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"Revision", snpRevisionOffset, 0},
		{"Start", snpStartOffset, 8},
		{"Stop", snpStopOffset, 16},
		{"Initialize", snpInitializeOffset, 24},
		{"Reset", snpResetOffset, 32},
		{"Shutdown", snpShutdownOffset, 40},
		{"ReceiveFilters", snpReceiveFiltersOffset, 48},
		{"StationAddress", snpStationAddressOffset, 56},
		{"Statistics", snpStatisticsOffset, 64},
		{"MCastIpToMac", snpMCastIpToMacOffset, 72},
		{"NvData", snpNvDataOffset, 80},
		{"GetStatus", snpGetStatusOffset, 88},
		{"Transmit", snpTransmitOffset, 96},
		{"Receive", snpReceiveOffset, 104},
		{"WaitForPacket", snpWaitForPacketOffset, 112},
		{"Mode", snpModeOffset, 120},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("snp%sOffset = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestSNPStateConstants(t *testing.T) {
	// Spec values per UEFI 2.10 §24.1 / SimpleNetwork.h lines 143..148.
	cases := []struct {
		name string
		got  EFISimpleNetworkState
		want EFISimpleNetworkState
	}{
		{"Stopped", EFISimpleNetworkStopped, 0},
		{"Started", EFISimpleNetworkStarted, 1},
		{"Initialized", EFISimpleNetworkInitialized, 2},
		{"MaxState", EFISimpleNetworkMaxState, 3},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("EFISimpleNetwork%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEFIMACAddressSize(t *testing.T) {
	// EFI_MAC_ADDRESS is a 32-byte buffer per UefiBaseType.h.
	if got, want := unsafe.Sizeof(EFIMACAddress{}), uintptr(32); got != want {
		t.Errorf("sizeof(EFIMACAddress) = %d, want %d", got, want)
	}
}

// TestSNPModeLayout pins every field offset of EFI_SIMPLE_NETWORK_MODE.
// A field reordering, a missing field, or a typo'd type would surface
// here rather than silently misalign the MAC-address read in the probe.
func TestSNPModeLayout(t *testing.T) {
	var m EFISimpleNetworkMode
	cases := []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"State", unsafe.Offsetof(m.State), 0},
		{"HwAddressSize", unsafe.Offsetof(m.HwAddressSize), 4},
		{"MediaHeaderSize", unsafe.Offsetof(m.MediaHeaderSize), 8},
		{"MaxPacketSize", unsafe.Offsetof(m.MaxPacketSize), 12},
		{"NvRamSize", unsafe.Offsetof(m.NvRamSize), 16},
		{"NvRamAccessSize", unsafe.Offsetof(m.NvRamAccessSize), 20},
		{"ReceiveFilterMask", unsafe.Offsetof(m.ReceiveFilterMask), 24},
		{"ReceiveFilterSetting", unsafe.Offsetof(m.ReceiveFilterSetting), 28},
		{"MaxMCastFilterCount", unsafe.Offsetof(m.MaxMCastFilterCount), 32},
		{"MCastFilterCount", unsafe.Offsetof(m.MCastFilterCount), 36},
		{"MCastFilter", unsafe.Offsetof(m.MCastFilter), 40},
		{"CurrentAddress", unsafe.Offsetof(m.CurrentAddress), 552},
		{"BroadcastAddress", unsafe.Offsetof(m.BroadcastAddress), 584},
		{"PermanentAddress", unsafe.Offsetof(m.PermanentAddress), 616},
		{"IfType", unsafe.Offsetof(m.IfType), 648},
		{"MacAddressChangeable", unsafe.Offsetof(m.MacAddressChangeable), 649},
		{"MultipleTxSupported", unsafe.Offsetof(m.MultipleTxSupported), 650},
		{"MediaPresentSupported", unsafe.Offsetof(m.MediaPresentSupported), 651},
		{"MediaPresent", unsafe.Offsetof(m.MediaPresent), 652},
	}
	for _, c := range cases {
		if c.off != c.want {
			t.Errorf("%s offset = %d, want %d", c.name, c.off, c.want)
		}
	}
	if got, want := unsafe.Sizeof(m), uintptr(efiSimpleNetworkModeSize); got != want {
		t.Errorf("sizeof(EFISimpleNetworkMode) = %d, want %d", got, want)
	}
}

// TestSNPModeMACReadFromSynthBuffer reproduces the read path the M1.5
// probe uses: cast a raw byte buffer at `&mode.CurrentAddress` and
// pull the first HwAddressSize bytes. Catches alignment / endian
// mistakes in the on-the-wire shape.
func TestSNPModeMACReadFromSynthBuffer(t *testing.T) {
	var m EFISimpleNetworkMode
	m.State = uint32(EFISimpleNetworkStarted)
	m.HwAddressSize = 6
	m.MediaPresent = 1
	// Fake a 52:54:00:12:34:56 MAC at CurrentAddress.
	wantMAC := [6]uint8{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}
	for i, b := range wantMAC {
		m.CurrentAddress.Addr[i] = b
	}
	// Walk the byte view at the well-known offset and confirm we read
	// the MAC back.
	base := (*[efiSimpleNetworkModeSize]byte)(unsafe.Pointer(&m))
	for i, want := range wantMAC {
		got := base[552+i] // CurrentAddress offset = 552
		if got != want {
			t.Errorf("MAC byte %d = 0x%02x, want 0x%02x", i, got, want)
		}
	}
	// The 32-byte slot zero-pads beyond HwAddressSize.
	for i := int(m.HwAddressSize); i < 32; i++ {
		if got := base[552+i]; got != 0 {
			t.Errorf("MAC byte %d (pad) = 0x%02x, want 0x00", i, got)
		}
	}
}
