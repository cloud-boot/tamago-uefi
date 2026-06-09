// cloud-boot UEFI board — UEFI memory map types + parser (Phase 2, M0).
//
// Exposes a Go view of EFI_MEMORY_DESCRIPTOR (UEFI 2.10 §7.2, table
// 7.10) and a byte-buffer parser. The live wrapper around
// gBS->GetMemoryMap (offset 56 of EFI_BOOT_SERVICES, see
// MdePkg/Include/Uefi/UefiSpec.h) lives in memorymap_tamago.go and is
// gated on `//go:build tamago`; this file is host-buildable so the
// parser can be unit-tested.

package uefiboard

import "errors"

// EFI_BOOT_SERVICES.GetMemoryMap function-pointer offset (UEFI 2.10
// §4.2, table 4.2; corroborated by edk2.git
// MdePkg/Include/Uefi/UefiSpec.h's struct order):
//
//	24  RaiseTPL
//	32  RestoreTPL
//	40  AllocatePages
//	48  FreePages
//	56  GetMemoryMap   <-- here
//	64  AllocatePool
//	72  FreePool
const efiBSGetMemoryMap = 56

// EFI_BOOT_SERVICES.ExitBootServices function-pointer offset (UEFI 2.10
// §4.2, table 4.2; ExitBootServices is the 27th UINTN-sized slot after
// the 24-byte EFI_TABLE_HEADER):
//
//	24  RaiseTPL                  ... (TPL services, 2)
//	40  AllocatePages             ... (Memory services, 5)
//	80  CreateEvent               ... (Event/Timer services, 6)
//	128 InstallProtocolInterface  ... (Protocol services, 9)
//	200 LoadImage                 ... (Image services, 4)
//	232 ExitBootServices          <-- here
const efiBSExitBootServices = 232

// EFI_SYSTEM_TABLE.BootServices offset (UEFI 2.10 §4.3.1). Mirrors the
// value cpuinit_arm64.s already uses (#define EFI_ST_BOOTSERVICES 96).
const efiSTBootServices = 96

// EFI_MEMORY_TYPE values (UEFI 2.10 §7.2, table 7.9). Re-exported as
// typed Go constants so callers can use them in switch statements.
//
// Note: this is the standard set. Some firmwares define
// MemoryTypeMax + N values; we keep them as raw uint32 in
// MemoryDescriptor.Type and let callers handle unknown values.
const (
	EfiReservedMemoryType      uint32 = 0
	EfiLoaderCode              uint32 = 1
	EfiLoaderData              uint32 = 2
	EfiBootServicesCode        uint32 = 3
	EfiBootServicesData        uint32 = 4
	EfiRuntimeServicesCode     uint32 = 5
	EfiRuntimeServicesData     uint32 = 6
	EfiConventionalMemory      uint32 = 7
	EfiUnusableMemory          uint32 = 8
	EfiACPIReclaimMemory       uint32 = 9
	EfiACPIMemoryNVS           uint32 = 10
	EfiMemoryMappedIO          uint32 = 11
	EfiMemoryMappedIOPortSpace uint32 = 12
	EfiPalCode                 uint32 = 13
	EfiPersistentMemory        uint32 = 14
	EfiUnacceptedMemoryType    uint32 = 15
	EfiMemoryTypeMax           uint32 = 16
)

// EfiPageSize is fixed by the UEFI spec at 4 KiB on every architecture
// (UEFI 2.10 §2.3.x and §7.2 — page counts in AllocatePages and the
// NumberOfPages field of EFI_MEMORY_DESCRIPTOR are 4 KiB pages even on
// arches whose MMU supports larger native page sizes).
const EfiPageSize = 4096

// MemoryDescriptor is the Go view of EFI_MEMORY_DESCRIPTOR
// (UEFI 2.10 §7.2, table 7.10):
//
//	typedef struct {
//	    UINT32                Type;
//	    EFI_PHYSICAL_ADDRESS  PhysicalStart;
//	    EFI_VIRTUAL_ADDRESS   VirtualStart;
//	    UINT64                NumberOfPages;
//	    UINT64                Attribute;
//	} EFI_MEMORY_DESCRIPTOR;
//
// On-the-wire layout: 4-byte Type + 4-byte pad to 8-byte align the
// 64-bit PhysicalStart, then three UINT64s. Total 40 bytes. Firmwares
// MAY append implementation-private fields, raising DescriptorSize
// beyond 40; the parser respects that stride.
type MemoryDescriptor struct {
	Type          uint32
	_pad          uint32 // align PhysicalStart on 8 bytes
	PhysicalStart uint64
	VirtualStart  uint64
	NumberOfPages uint64
	Attribute     uint64
}

// efiMemoryDescriptorSize is the on-the-wire byte size of the spec
// shape. The actual firmware-reported DescriptorSize may be larger; the
// parser strides by that. Used here as a sanity floor.
const efiMemoryDescriptorSize = 40

// MemoryMap is the parsed result of a GetMemoryMap call.
type MemoryMap struct {
	// Descriptors is the parsed list, one entry per (DescriptorSize)
	// stride in the raw firmware buffer.
	Descriptors []MemoryDescriptor

	// MapKey is the opaque cookie the firmware tags this snapshot with.
	// Must be passed unchanged to ExitBootServices; if the firmware
	// allocated/freed pages between GetMemoryMap and ExitBootServices,
	// EBS will reject the key and require a refresh.
	MapKey uintptr

	// DescriptorSize is the raw stride reported by firmware. Useful for
	// diagnostics — the parser already consumed it.
	DescriptorSize uintptr

	// DescriptorVersion is the firmware's claimed descriptor schema
	// version (always 1 across UEFI 2.x — EFI_MEMORY_DESCRIPTOR_VERSION
	// is fixed at 1 by edk2.git MdePkg/Include/Uefi/UefiSpec.h). M1
	// captures it for diagnostics; the parser does not branch on it.
	DescriptorVersion uint32
}

// ErrMapTooSmall is returned by GetMemoryMap if firmware kept reporting
// EFI_BUFFER_TOO_SMALL across our retry bound (4 attempts is generous
// — real firmware needs at most 2). Indicates a buggy firmware or a
// runaway allocator.
var ErrMapTooSmall = errors.New("uefi: GetMemoryMap kept reporting EFI_BUFFER_TOO_SMALL across retries")

// ErrNoBootServices is returned by GetMemoryMap / ExitBootServices if
// the SystemTable wasn't captured (cpuinit didn't run) or we're already
// past ExitBootServices (BootServices destroyed).
var ErrNoBootServices = errors.New("uefi: BootServices not available (cpuinit didn't run, or already past ExitBootServices)")

// EFI_STATUS bit-63 set marks an error on a 64-bit UEFI build (UEFI
// 2.10 appendix D — the high bit, *not* bit-31; it's the top bit of a
// UINTN, which is 64-bit on every arch we target).
const (
	efiSuccess          uint64 = 0
	efiInvalidParameter uint64 = 0x8000000000000002
	efiUnsupported      uint64 = 0x8000000000000003
	efiBufferTooSmall   uint64 = 0x8000000000000005
	efiNotFound         uint64 = 0x800000000000000E
)

// parseMemoryMap turns the raw firmware buffer + descriptor-size stride
// into a Go slice. Stride may exceed sizeof(MemoryDescriptor); we copy
// out the spec-defined leading 40 bytes per entry and ignore any
// trailing firmware-private bytes. Returns nil if buf is empty or
// descriptorSize is invalid.
//
// Exposed for unit tests (host build) and used by the tamago
// GetMemoryMap wrapper.
func parseMemoryMap(buf []byte, descriptorSize uintptr) []MemoryDescriptor {
	if len(buf) == 0 || descriptorSize == 0 {
		return nil
	}
	if descriptorSize < efiMemoryDescriptorSize {
		// Firmware violated the spec: descriptors must be at least the
		// spec'd 40 bytes. Refuse to parse; caller treats as empty.
		return nil
	}
	n := uintptr(len(buf)) / descriptorSize
	if n == 0 {
		return nil
	}
	out := make([]MemoryDescriptor, 0, n)
	for i := uintptr(0); i < n; i++ {
		base := i * descriptorSize
		// Bounds-check the spec'd 40-byte head only; trailing
		// firmware-private fields are ignored.
		if base+efiMemoryDescriptorSize > uintptr(len(buf)) {
			break
		}
		// Decode little-endian fields. Every UEFI arch this board
		// targets is little-endian (amd64, arm64-LE, riscv64-LE,
		// loong64-LE).
		var d MemoryDescriptor
		d.Type = leU32(buf[base : base+4])
		d.PhysicalStart = leU64(buf[base+8 : base+16])
		d.VirtualStart = leU64(buf[base+16 : base+24])
		d.NumberOfPages = leU64(buf[base+24 : base+32])
		d.Attribute = leU64(buf[base+32 : base+40])
		out = append(out, d)
	}
	return out
}

func leU32(b []byte) uint32 {
	_ = b[3]
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leU64(b []byte) uint64 {
	_ = b[7]
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}

// EFIError wraps a non-success EFI_STATUS for Go-side handling.
type EFIError struct {
	Status uint64
	Op     string
}

func (e *EFIError) Error() string {
	return "uefi: " + e.Op + ": EFI_STATUS=" + hexU64(e.Status)
}

// hexU64 stringifies without depending on fmt (which TamaGo's runtime
// pulls in only on demand; keeping this dep-light keeps the EFI binary
// small).
func hexU64(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v != 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	i--
	buf[i] = 'x'
	i--
	buf[i] = '0'
	return string(buf[i:])
}
