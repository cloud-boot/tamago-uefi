// Phase-2 M0 probe — gated on `-tags phase2_probe`.
//
// Calls uefiboard.GetMemoryMap, prints a one-line summary to ConOut
// (descriptor count, per-type RAM totals, the firmware-reported
// DescriptorSize), then returns. Phase 1's caller then prints DONE and
// halts as usual.
//
// This is the M0 smoke test for the Phase-2 design doc (Path X,
// shape A pre-boot loader): proves we can drive a Boot Service from
// pure Go on all four arches end-to-end. NO ExitBootServices is
// performed here — that's M4.

//go:build phase2_probe && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// memoryTypeName maps the spec'd EFI_MEMORY_TYPE values to short labels
// for the probe report. Unknown types are printed numerically.
func memoryTypeName(t uint32) string {
	switch t {
	case uefiboard.EfiReservedMemoryType:
		return "Reserved"
	case uefiboard.EfiLoaderCode:
		return "LoaderCode"
	case uefiboard.EfiLoaderData:
		return "LoaderData"
	case uefiboard.EfiBootServicesCode:
		return "BSCode"
	case uefiboard.EfiBootServicesData:
		return "BSData"
	case uefiboard.EfiRuntimeServicesCode:
		return "RTCode"
	case uefiboard.EfiRuntimeServicesData:
		return "RTData"
	case uefiboard.EfiConventionalMemory:
		return "Conventional"
	case uefiboard.EfiUnusableMemory:
		return "Unusable"
	case uefiboard.EfiACPIReclaimMemory:
		return "ACPIReclaim"
	case uefiboard.EfiACPIMemoryNVS:
		return "ACPINVS"
	case uefiboard.EfiMemoryMappedIO:
		return "MMIO"
	case uefiboard.EfiMemoryMappedIOPortSpace:
		return "MMIOPort"
	case uefiboard.EfiPalCode:
		return "PALCode"
	case uefiboard.EfiPersistentMemory:
		return "Persistent"
	case uefiboard.EfiUnacceptedMemoryType:
		return "Unaccepted"
	}
	return "Type?"
}

func runPhase2Probe() {
	println("phase2-probe: calling gBS->GetMemoryMap")
	mm, err := uefiboard.GetMemoryMap()
	if err != nil {
		println("phase2-probe: GetMemoryMap FAILED:", err.Error())
		println("phase2-probe: this is a Risk-section finding — capture and report")
		return
	}

	// Sum pages per type. The spec defines page count, not byte count;
	// we multiply by EfiPageSize (4 KiB) at print time to give bytes.
	const nTypes = 16 // EfiMemoryTypeMax
	var perType [nTypes]uint64
	var unknownPages uint64
	for _, d := range mm.Descriptors {
		if d.Type < nTypes {
			perType[d.Type] += d.NumberOfPages
		} else {
			unknownPages += d.NumberOfPages
		}
	}

	println("phase2-probe: descriptors=", len(mm.Descriptors),
		"descriptorSize=", uint64(mm.DescriptorSize),
		"mapKey=", uint64(mm.MapKey))

	for t := uint32(0); t < nTypes; t++ {
		pages := perType[t]
		if pages == 0 {
			continue
		}
		// bytes = pages * 4096
		bytes := pages * uefiboard.EfiPageSize
		println("phase2-probe: ", memoryTypeName(t),
			"pages=", pages,
			"bytes=", bytes)
	}
	if unknownPages != 0 {
		println("phase2-probe: <unknown-type> pages=", unknownPages,
			"bytes=", unknownPages*uefiboard.EfiPageSize)
	}
	println("phase2-probe: done")
}
