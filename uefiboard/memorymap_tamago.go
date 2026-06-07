// cloud-boot UEFI board — gBS->GetMemoryMap live wrapper.
//
// This file is gated on `//go:build tamago` because it invokes the
// firmware via uefiboard.efiCall (which only links on the tamago
// target — eficall_<arch>.s has no host build). The parser + types
// it relies on live in memorymap.go (host-buildable).
//
// efiCall is 5-arg as of Phase 2 M1 (see eficall_<arch>.s for the
// incident analysis — M0's 4-arg form caused EDK2 stable202408's
// CoreGetMemoryMap to dereference a stale A4 register on riscv64 and
// fault on a near-NULL store). The 5th arg is the
// `EFI_MEMORY_DESCRIPTOR_VERSION` OUT pointer, which we now pass for
// real so the call is well-defined and the writeback succeeds.
//
// Reference: edk2.git stable/202408
//   - MdeModulePkg/Core/Dxe/Mem/Page.c::CoreGetMemoryMap (lines
//     1881..2090) is the gBS->GetMemoryMap entry. It guards the
//     `*DescriptorVersion` and `*DescriptorSize` writes with NULL
//     checks; the M0 thunk's stale-register issue meant DescriptorVersion
//     was NOT NULL but pointed at a near-NULL address. M1 passes a real
//     stack-allocated UINT32 here.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// getBootServices returns the EFI_BOOT_SERVICES* captured by cpuinit
// from the SystemTable, or 0 if cpuinit didn't run. Exposed at package
// scope so future M-N wrappers can reuse it without re-deriving the
// offset.
//
//go:nosplit
func getBootServices() uint64 {
	if systemTable == 0 {
		return 0
	}
	// SystemTable->BootServices at offset efiSTBootServices (96).
	p := unsafe.Pointer(uintptr(systemTable) + efiSTBootServices)
	return *(*uint64)(p)
}

// GetMemoryMap calls gBS->GetMemoryMap. Two-pass:
//
//  1. Probe with a 0-sized buffer → firmware returns
//     EFI_BUFFER_TOO_SMALL + the required MemoryMapSize.
//  2. Allocate + slop, retry until EFI_SUCCESS (or we give up).
//
// Returns the parsed descriptors + the MapKey (needed by
// ExitBootServices) + the firmware's reported DescriptorSize (used by
// the parser, exposed for diagnostics).
//
// Only usable while still in Boot Services. After ExitBootServices,
// gBS is invalid and this will fault.
func GetMemoryMap() (*MemoryMap, error) {
	bs := getBootServices()
	if bs == 0 {
		return nil, ErrNoBootServices
	}
	fnSlot := bs + efiBSGetMemoryMap

	// Probe call. Firmware MAY require a non-NULL MemoryMap pointer
	// even for the sizing probe; hand it a single-descriptor stack
	// buffer to keep both paths happy.
	var probe MemoryDescriptor
	var size uintptr = 0
	var mapKey uintptr
	var descSize uintptr
	var descVer uint32

	status := efiCall(
		fnSlot,
		uint64(uintptr(unsafe.Pointer(&size))),
		uint64(uintptr(unsafe.Pointer(&probe))),
		uint64(uintptr(unsafe.Pointer(&mapKey))),
		uint64(uintptr(unsafe.Pointer(&descSize))),
		uint64(uintptr(unsafe.Pointer(&descVer))),
		0,
	)
	if status != efiBufferTooSmall && status != efiSuccess {
		return nil, &EFIError{Status: status, Op: "GetMemoryMap (probe)"}
	}
	if size == 0 {
		// Spec-impossible (firmware can't legitimately return SUCCESS
		// with size=0 for a non-empty memory map); treat as empty.
		return &MemoryMap{
			MapKey:            mapKey,
			DescriptorSize:    descSize,
			DescriptorVersion: descVer,
		}, nil
	}
	if descSize == 0 {
		descSize = efiMemoryDescriptorSize
	}

	// Add slop for descriptor-count growth between the sizing probe
	// and the real call: firmware may itself allocate pages while
	// servicing us, which grows the map by one entry. 4 entries is
	// generous.
	bufSize := size + 4*descSize

	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, bufSize)
		size = bufSize
		status = efiCall(
			fnSlot,
			uint64(uintptr(unsafe.Pointer(&size))),
			uint64(uintptr(unsafe.Pointer(&buf[0]))),
			uint64(uintptr(unsafe.Pointer(&mapKey))),
			uint64(uintptr(unsafe.Pointer(&descSize))),
			uint64(uintptr(unsafe.Pointer(&descVer))),
			0,
		)
		switch status {
		case efiSuccess:
			descs := parseMemoryMap(buf[:size], descSize)
			return &MemoryMap{
				Descriptors:       descs,
				MapKey:            mapKey,
				DescriptorSize:    descSize,
				DescriptorVersion: descVer,
			}, nil
		case efiBufferTooSmall:
			bufSize = size + 4*descSize
			continue
		default:
			return nil, &EFIError{Status: status, Op: "GetMemoryMap"}
		}
	}
	return nil, ErrMapTooSmall
}
