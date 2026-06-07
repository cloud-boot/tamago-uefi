// Host-side unit tests for memorymap.go.
//
// Skip-gates the actual GetMemoryMap call (it requires running on UEFI
// firmware via TamaGo, which the host test binary cannot do). What we
// CAN test on the host:
//
//  1. The synthetic-buffer parser strides correctly by descriptorSize,
//     including the case where firmware reports a stride > 40 bytes
//     (i.e. it appended private fields).
//  2. Edge cases: empty buffer, zero stride, short stride, partial
//     final entry.
//  3. The hex stringification (no fmt dependency in the EFI path) is
//     correct for a representative set of EFI_STATUS values.
//  4. EFIError.Error() formats as expected.
//
// No //go:build tag: this is a host-only test (Go default) and we want
// `go test ./uefiboard/...` to pick it up from the working dir
// regardless of GOOS/GOARCH.

package uefiboard

import (
	"strings"
	"testing"
)

// makeDescriptorBytes serialises an EFI_MEMORY_DESCRIPTOR plus
// trailing padding to reach descriptorSize. Little-endian throughout.
func makeDescriptorBytes(d MemoryDescriptor, descriptorSize uintptr) []byte {
	if descriptorSize < efiMemoryDescriptorSize {
		panic("descriptorSize must be >= 40")
	}
	out := make([]byte, descriptorSize)
	// Type @ 0, _pad @ 4, PhysicalStart @ 8, VirtualStart @ 16,
	// NumberOfPages @ 24, Attribute @ 32.
	leU32Put(out[0:4], d.Type)
	leU64Put(out[8:16], d.PhysicalStart)
	leU64Put(out[16:24], d.VirtualStart)
	leU64Put(out[24:32], d.NumberOfPages)
	leU64Put(out[32:40], d.Attribute)
	// Trailing bytes left as zero — represent the firmware-private
	// region.
	return out
}

func leU32Put(b []byte, v uint32) {
	_ = b[3]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
}

func leU64Put(b []byte, v uint64) {
	_ = b[7]
	b[0] = byte(v)
	b[1] = byte(v >> 8)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 24)
	b[4] = byte(v >> 32)
	b[5] = byte(v >> 40)
	b[6] = byte(v >> 48)
	b[7] = byte(v >> 56)
}

func TestParseMemoryMap_Empty(t *testing.T) {
	if got := parseMemoryMap(nil, 40); got != nil {
		t.Errorf("parseMemoryMap(nil, 40) = %v, want nil", got)
	}
	if got := parseMemoryMap([]byte{}, 40); got != nil {
		t.Errorf("parseMemoryMap(empty, 40) = %v, want nil", got)
	}
	if got := parseMemoryMap(make([]byte, 100), 0); got != nil {
		t.Errorf("parseMemoryMap(buf, 0) = %v, want nil", got)
	}
	if got := parseMemoryMap(make([]byte, 100), 39); got != nil {
		t.Errorf("parseMemoryMap(buf, 39) = %v, want nil — stride < spec minimum", got)
	}
}

func TestParseMemoryMap_StandardStride(t *testing.T) {
	descs := []MemoryDescriptor{
		{
			Type:          EfiConventionalMemory,
			PhysicalStart: 0x40000000,
			NumberOfPages: 0x10000, // 256 MiB
			Attribute:     0xF,
		},
		{
			Type:          EfiBootServicesData,
			PhysicalStart: 0x50000000,
			NumberOfPages: 0x100,
			Attribute:     0xF,
		},
		{
			Type:          EfiRuntimeServicesCode,
			PhysicalStart: 0x7F000000,
			VirtualStart:  0xFFFFFFFF_7F000000,
			NumberOfPages: 0x10,
			Attribute:     0x800000000000000F,
		},
	}
	var buf []byte
	for _, d := range descs {
		buf = append(buf, makeDescriptorBytes(d, 40)...)
	}
	got := parseMemoryMap(buf, 40)
	if len(got) != len(descs) {
		t.Fatalf("len = %d, want %d", len(got), len(descs))
	}
	for i, want := range descs {
		if got[i].Type != want.Type {
			t.Errorf("[%d].Type = %d, want %d", i, got[i].Type, want.Type)
		}
		if got[i].PhysicalStart != want.PhysicalStart {
			t.Errorf("[%d].PhysicalStart = %#x, want %#x", i, got[i].PhysicalStart, want.PhysicalStart)
		}
		if got[i].VirtualStart != want.VirtualStart {
			t.Errorf("[%d].VirtualStart = %#x, want %#x", i, got[i].VirtualStart, want.VirtualStart)
		}
		if got[i].NumberOfPages != want.NumberOfPages {
			t.Errorf("[%d].NumberOfPages = %d, want %d", i, got[i].NumberOfPages, want.NumberOfPages)
		}
		if got[i].Attribute != want.Attribute {
			t.Errorf("[%d].Attribute = %#x, want %#x", i, got[i].Attribute, want.Attribute)
		}
	}
}

// Firmware MAY append implementation-private fields to each descriptor,
// reporting DescriptorSize > 40. The parser MUST stride by
// DescriptorSize, not by sizeof(spec). This is documented in UEFI 2.10
// §7.2 and is the canonical reason the spec separates DescriptorSize
// from sizeof(EFI_MEMORY_DESCRIPTOR) — see R-M0 in the design doc.
func TestParseMemoryMap_LargerStride(t *testing.T) {
	const stride = uintptr(48) // spec + 8 firmware-private bytes
	descs := []MemoryDescriptor{
		{Type: EfiConventionalMemory, PhysicalStart: 0x1000, NumberOfPages: 1, Attribute: 0xF},
		{Type: EfiACPIReclaimMemory, PhysicalStart: 0x2000, NumberOfPages: 2, Attribute: 0xF},
	}
	var buf []byte
	for i, d := range descs {
		entry := makeDescriptorBytes(d, stride)
		// Stamp a recognisable byte pattern in the trailing private
		// region so we can prove the parser SKIPS it (i.e. the next
		// entry's fields aren't read from these bytes).
		for j := efiMemoryDescriptorSize; j < int(stride); j++ {
			entry[j] = byte(0xC0 | i)
		}
		buf = append(buf, entry...)
	}
	got := parseMemoryMap(buf, stride)
	if len(got) != len(descs) {
		t.Fatalf("len = %d, want %d", len(got), len(descs))
	}
	for i := range descs {
		if got[i].Type != descs[i].Type {
			t.Errorf("[%d].Type = %d, want %d", i, got[i].Type, descs[i].Type)
		}
		if got[i].PhysicalStart != descs[i].PhysicalStart {
			t.Errorf("[%d].PhysicalStart = %#x, want %#x", i, got[i].PhysicalStart, descs[i].PhysicalStart)
		}
		if got[i].NumberOfPages != descs[i].NumberOfPages {
			t.Errorf("[%d].NumberOfPages = %d, want %d", i, got[i].NumberOfPages, descs[i].NumberOfPages)
		}
	}
}

// A buffer whose length is not an exact multiple of the stride: the
// trailing partial entry must be dropped, not parsed from garbage.
func TestParseMemoryMap_PartialFinalEntry(t *testing.T) {
	d := MemoryDescriptor{Type: EfiLoaderData, PhysicalStart: 0x1000, NumberOfPages: 4, Attribute: 0xF}
	buf := makeDescriptorBytes(d, 40)
	// Append 20 bytes of garbage that doesn't fit a full entry.
	buf = append(buf, make([]byte, 20)...)
	got := parseMemoryMap(buf, 40)
	if len(got) != 1 {
		t.Fatalf("len = %d, want 1 (partial second entry must be dropped)", len(got))
	}
	if got[0] != d {
		t.Errorf("got[0] = %+v, want %+v", got[0], d)
	}
}

func TestLeU32_LeU64(t *testing.T) {
	cases32 := []struct {
		in   []byte
		want uint32
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00}, 0},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFF},
		{[]byte{0x78, 0x56, 0x34, 0x12}, 0x12345678},
	}
	for _, c := range cases32 {
		if got := leU32(c.in); got != c.want {
			t.Errorf("leU32(% x) = %#x, want %#x", c.in, got, c.want)
		}
	}

	cases64 := []struct {
		in   []byte
		want uint64
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 0},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFFFFFFFFFF},
		{[]byte{0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12}, 0x123456789ABCDEF0},
	}
	for _, c := range cases64 {
		if got := leU64(c.in); got != c.want {
			t.Errorf("leU64(% x) = %#x, want %#x", c.in, got, c.want)
		}
	}
}

func TestHexU64(t *testing.T) {
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0x0"},
		{1, "0x1"},
		{0xFF, "0xff"},
		{0x100, "0x100"},
		{0xDEADBEEF, "0xdeadbeef"},
		{0x8000000000000005, "0x8000000000000005"},
		{0xFFFFFFFFFFFFFFFF, "0xffffffffffffffff"},
	}
	for _, c := range cases {
		if got := hexU64(c.in); got != c.want {
			t.Errorf("hexU64(%#x) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEFIError_Error(t *testing.T) {
	e := &EFIError{Status: efiBufferTooSmall, Op: "GetMemoryMap"}
	got := e.Error()
	// Must mention the op, the prefix, and the status as hex.
	if !strings.Contains(got, "uefi:") || !strings.Contains(got, "GetMemoryMap") || !strings.Contains(got, "0x8000000000000005") {
		t.Errorf("EFIError.Error() = %q, missing one of the expected substrings", got)
	}
	e2 := &EFIError{Status: 0, Op: "ExitBootServices"}
	if !strings.Contains(e2.Error(), "0x0") {
		t.Errorf("EFIError.Error() with status=0: %q, want '0x0'", e2.Error())
	}
}

// Sentinel errors carry useful messages, not empty strings.
func TestSentinelErrors(t *testing.T) {
	if ErrMapTooSmall.Error() == "" {
		t.Error("ErrMapTooSmall.Error() is empty")
	}
	if ErrNoBootServices.Error() == "" {
		t.Error("ErrNoBootServices.Error() is empty")
	}
}

// Constants for the spec-defined EFI_MEMORY_TYPE values: assert the
// classic enumeration so a typo in memorymap.go would surface here.
func TestMemoryTypeConstants(t *testing.T) {
	cases := []struct {
		got  uint32
		want uint32
		name string
	}{
		{EfiReservedMemoryType, 0, "EfiReservedMemoryType"},
		{EfiLoaderCode, 1, "EfiLoaderCode"},
		{EfiLoaderData, 2, "EfiLoaderData"},
		{EfiBootServicesCode, 3, "EfiBootServicesCode"},
		{EfiBootServicesData, 4, "EfiBootServicesData"},
		{EfiRuntimeServicesCode, 5, "EfiRuntimeServicesCode"},
		{EfiRuntimeServicesData, 6, "EfiRuntimeServicesData"},
		{EfiConventionalMemory, 7, "EfiConventionalMemory"},
		{EfiUnusableMemory, 8, "EfiUnusableMemory"},
		{EfiACPIReclaimMemory, 9, "EfiACPIReclaimMemory"},
		{EfiACPIMemoryNVS, 10, "EfiACPIMemoryNVS"},
		{EfiMemoryMappedIO, 11, "EfiMemoryMappedIO"},
		{EfiMemoryMappedIOPortSpace, 12, "EfiMemoryMappedIOPortSpace"},
		{EfiPalCode, 13, "EfiPalCode"},
		{EfiPersistentMemory, 14, "EfiPersistentMemory"},
		{EfiUnacceptedMemoryType, 15, "EfiUnacceptedMemoryType"},
		{EfiMemoryTypeMax, 16, "EfiMemoryTypeMax"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if EfiPageSize != 4096 {
		t.Errorf("EfiPageSize = %d, want 4096", EfiPageSize)
	}
}

// Live GetMemoryMap is skip-gated: it requires running on UEFI via
// TamaGo. Hosting `go test` builds skip with a clear message.
func TestGetMemoryMap_HostSkip(t *testing.T) {
	// On the host the symbol is not even linked (memorymap_tamago.go
	// is gated on `//go:build tamago`). The smoke test for the live
	// call lives in main.go --phase2-probe and is exercised by
	// running the produced EFI under QEMU.
	t.Skip("GetMemoryMap is exercised end-to-end by the --phase2-probe " +
		"flow under QEMU/OVMF — see Taskfile task probe:memory:<arch>")
}
