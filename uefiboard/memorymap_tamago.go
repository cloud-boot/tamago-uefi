// cloud-boot UEFI board — gBS->GetMemoryMap live wrapper.
//
// This file is gated on `//go:build tamago` because it invokes the
// firmware via uefiboard.efiCall (which only links on the tamago
// target — eficall_<arch>.s has no host build). The parser + types
// it relies on live in memorymap.go (host-buildable).
//
// efiCall is fixed at 4 args (see eficall_<arch>.s). UEFI's
// GetMemoryMap has FIVE OUT parameters (MemoryMapSize, MemoryMap,
// MapKey, DescriptorSize, DescriptorVersion). At M0 we drive the
// 4-arg form, omitting DescriptorVersion: EDK2's
// `MdeModulePkg/Core/Dxe/Mem/Page.c::CoreGetMemoryMap` writes
// `*DescriptorVersion = EFI_MEMORY_DESCRIPTOR_VERSION` only on the
// success path AND only if the pointer is non-NULL; on the probe
// (BUFFER_TOO_SMALL) path the field is not written. So the probe is
// safe with NULL; the real-call writeback we skip — `DescriptorVersion`
// is always 1 in shipping UEFI 2.x firmware, and we expose only
// DescriptorSize for diagnostics.
//
// If a firmware revision were to start rejecting NULL DescriptorVersion
// up-front (EFI_INVALID_PARAMETER), the M0 probe surfaces that as a
// clean error on ConOut and we extend efiCall to 5 args in M1.

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

	status := efiCall(
		fnSlot,
		uint64(uintptr(unsafe.Pointer(&size))),
		uint64(uintptr(unsafe.Pointer(&probe))),
		uint64(uintptr(unsafe.Pointer(&mapKey))),
		uint64(uintptr(unsafe.Pointer(&descSize))),
	)
	if status != efiBufferTooSmall && status != efiSuccess {
		return nil, &EFIError{Status: status, Op: "GetMemoryMap (probe)"}
	}
	if size == 0 {
		// Spec-impossible (firmware can't legitimately return SUCCESS
		// with size=0 for a non-empty memory map); treat as empty.
		return &MemoryMap{
			MapKey:         mapKey,
			DescriptorSize: descSize,
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
		)
		switch status {
		case efiSuccess:
			descs := parseMemoryMap(buf[:size], descSize)
			return &MemoryMap{
				Descriptors:    descs,
				MapKey:         mapKey,
				DescriptorSize: descSize,
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
