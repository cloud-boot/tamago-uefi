// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// efipackstub -- M6.2 PR2 self-extracting EFI stub (amd64).
//
// STATUS (2026-06-09, two sprints in): the stub builds, links, loads
// under EDK2 OVMF q35, and main() runs to completion. Section-mapping
// of `.payload` is still NOT working, AND the section-table-ordering
// fix the previous sprint hypothesised was the cause is not sufficient
// on its own. The packer (go-coff/efipack) was switched to insert
// `.payload` BEFORE `.reloc` via peln/appender AppendBefore (clean
// peln addition, 100 % cov), but the live amd64 smoke matrix still
// shows the same fast-exit-to-shell behaviour for the packed HTTP
// binary -- meaning `run()` is hitting one of the early
// `return efiAborted` paths and gBS->Exit is returning control to the
// firmware shell.
//
// Diagnosis re-assessment (post-sprint-2): a read of
// MdePkg/Library/BasePeCoffLib/BasePeCoff.c::PeCoffLoaderLoadImage
// shows the section-load loop iterates the FULL section table (line
// 1391 `for (Index = 0; Index < NumberOfSections; Index++)`) and does
// NOT short-circuit at the relocation directory. The "skips after
// .reloc" theory was therefore wrong. The behavioural symptom (zero
// bytes at ImageBase + .payload.VA) must have a different upstream
// cause -- candidates yet to verify:
//   a. The DxeCore (not BasePeCoffLib) layer applies a security /
//      memory-attribute pass that zero-fills MEM_DISCARDABLE
//      neighbouring data. .reloc has IMAGE_SCN_MEM_DISCARDABLE set;
//      .payload sits next to it in the VA layout.
//   b. SizeOfImage / SizeOfRawData truncation interacts with the
//      InitializedData-only Characteristics flags we set.
//   c. A separate runtime bug (e.g. unsafe.Slice over an address
//      range firmware hasn't mapped) -- TamaGo PIE may treat
//      `imageBytes[:size]` differently than expected.
//
// Live amd64 smoke results with AppendBefore-flip:
//   - HTTP original  : PASS (regression-baseline intact)
//   - HTTP packed    : FAIL (stub runs main, exits via gBS->Exit
//                            with non-success status; child never
//                            reaches HTTP-GET OK)
//   - HTTPS / OCI / EFIHANDOVER not run -- gated on HTTP.
//
// Three follow-up options remain valid; option 2 (re-read file via
// SimpleFileSystem) is now the recommended next move because it
// sidesteps both the EDK2 mapping question AND any
// MEM_DISCARDABLE-neighbour zeroing:
//
//   1. AppendBefore is LANDED in peln + efipack regardless -- it is
//      a structurally cleaner shape and useful for future packers
//      that need to interleave headers around the relocation
//      directory. Test coverage = 100 %.
//   2. Re-read the stub's own file via
//      LOADED_IMAGE_PROTOCOL.DeviceHandle +
//      SimpleFileSystemProtocol -> Open -> Read on the FilePath.
//      Robust against any in-memory section-mapping quirk.
//   3. Inline the compressed payload bytes inside the stub's
//      `.rodata` via a sentinel slot the packer overwrites
//      post-link. Wastes the maximum-payload-size's worth of
//      bytes in every stub.
//
// Lifecycle once the section-mapping issue is fixed:
//
//  1. UEFI firmware enters cpuinit_amd64.s with (ImageHandle,
//     EFI_SYSTEM_TABLE*); the per-arch cpuinit shim captures those
//     into uefiboard.imageHandle / uefiboard.systemTable.
//  2. runtime.rt0 brings the Go runtime up and calls main().
//  3. main() invokes run(), which:
//       a. HandleProtocol(LOADED_IMAGE_PROTOCOL) -> ImageBase/Size.
//       b. Walks the PE section table to find `.payload`.
//       c. Parses the 24-byte CBP0 wire header.
//       d. Decompresses via compress/flate.
//       e. gBS->AllocatePages a buffer of EfiLoaderCode pages.
//       f. gBS->LoadImage(source = decompressed buffer).
//       g. gBS->StartImage on the child handle.
//  4. Whatever EFI_STATUS the child returned is forwarded to
//     gBS->Exit so the parent (e.g. the EDK shell, or
//     phase2-efi-handover's StartImage) sees the same status it
//     would have seen if it had loaded the original (unpacked)
//     payload directly.
//
// Build (TamaGo PIE, amd64):
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_amd64_efipackstub.elf ./cmd/efipackstub
//
// Then linked via pectl link-pie into a PE32+/EFI; the resulting
// PE bytes are what efipack embeds (stub/blobs/amd64.efi.bin) and
// uses as the envelope base PE when packing an input image.
//
// CRITICAL: this stub deliberately mirrors cmd/chainedtinyC's
// runtime shape (no println, no goos.Exit linkname hook). The M6.2
// de-risk sweep on 2026-06-09 found that TamaGo PIEs which install
// the goosExit linkname closure OR print via ConOut before
// chain-booting trigger the EDK2 OVMF CpuPageTableLib #GP at
// CpuDxe.dll +0x110C during a parent's StartImage call -- while a
// structurally identical TamaGo PIE without those two runtime
// behaviours passes. We avoid both here.
package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// EFI_LOADED_IMAGE_PROTOCOL_GUID
//
//	5b1b31a1-9562-11d2-8e3f-00a0c969723b
//
// Source: MdePkg/Include/Protocol/LoadedImage.h (edk2.git).
var loadedImageGUID = uefiboard.EFIGUID{
	Data1: 0x5b1b31a1,
	Data2: 0x9562,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_LOADED_IMAGE_PROTOCOL field offsets on 64-bit UEFI (MdePkg /
// LoadedImage.h with natural 8-byte alignment for pointers/UINT64):
//
//	0  UINT32                    Revision
//	8  EFI_HANDLE                ParentHandle
//	16 EFI_SYSTEM_TABLE          *SystemTable
//	24 EFI_HANDLE                DeviceHandle
//	32 EFI_DEVICE_PATH_PROTOCOL  *FilePath
//	40 VOID                      *Reserved
//	48 UINT32                    LoadOptionsSize
//	56 VOID                      *LoadOptions
//	64 VOID                      *ImageBase
//	72 UINT64                    ImageSize
//	80 EFI_MEMORY_TYPE           ImageCodeType
//	84 EFI_MEMORY_TYPE           ImageDataType
//	88 EFI_IMAGE_UNLOAD          Unload
const (
	liImageBase = 64
	liImageSize = 72
)

// Wire-format constants mirrored from go-coff/efipack:
//
//	[0..4)   "CBP0" magic
//	[4..8)   algo tag ("FLAT" / "LZFS" / "LZ4 ")
//	[8..16)  uncompressed size (LE u64)
//	[16..24) compressed size   (LE u64)
//	[24..)   compressed body
const (
	payloadMagic      = "CBP0"
	payloadHeaderSize = 24
	algoFlat          = "FLAT"
)

// EFI memory types we may pass to AllocatePages. EfiLoaderCode is
// what the firmware itself uses to stage child EFI images.
const (
	efiLoaderCode = 1
	efiPageSize   = 4096
)

// EFI_ABORTED on a 64-bit UEFI.
const efiAborted uintptr = 0x8000000000000015

// main is the stub entry from the firmware's perspective (via
// cpuinit_amd64.s -> runtime.rt0 -> main). We deliberately avoid
// println, fmt, and any goos.Exit linkname hook -- see the package
// comment for why.
func main() {
	status := run()
	_ = uefiboard.ExitImage(myImageHandle(), status)
	for {
	}
}

// run does the actual work, returning an EFI_STATUS to pass to
// gBS->Exit. EFI_SUCCESS (0) for the happy path; EFI_ABORTED for any
// internal failure (the parent firmware logs it but doesn't loop).
func run() uintptr {
	base, size, ok := loadedImageBaseSize()
	if !ok {
		return efiAborted
	}
	imageBytes := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(base))), int(size))

	payload, ok := findPayloadSection(imageBytes)
	if !ok {
		return efiAborted
	}
	if len(payload) < payloadHeaderSize {
		return efiAborted
	}
	if string(payload[0:4]) != payloadMagic {
		return efiAborted
	}
	if string(payload[4:8]) != algoFlat {
		return efiAborted
	}
	uncompressedSize := binary.LittleEndian.Uint64(payload[8:16])
	compressedSize := binary.LittleEndian.Uint64(payload[16:24])
	if uint64(len(payload))-payloadHeaderSize < compressedSize {
		return efiAborted
	}
	if uncompressedSize == 0 {
		return efiAborted
	}
	compressed := payload[payloadHeaderSize : payloadHeaderSize+int(compressedSize)]

	pageCount := (uintptr(uncompressedSize) + efiPageSize - 1) / efiPageSize
	addr, err := uefiboard.AllocatePages(efiLoaderCode, pageCount)
	if err != nil || addr == 0 {
		return efiAborted
	}
	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), int(uncompressedSize))

	if !flateDecode(compressed, dst) {
		return efiAborted
	}

	child, lerr := uefiboard.LoadImage(dst)
	if lerr != nil {
		return efiAborted
	}
	st, _ := uefiboard.StartImage(child)
	return st
}

// loadedImageBaseSize calls gBS->HandleProtocol on our own image
// handle to retrieve EFI_LOADED_IMAGE_PROTOCOL, then reads ImageBase
// and ImageSize. Returns ok=false if either lookup fails.
func loadedImageBaseSize() (base uint64, size uint64, ok bool) {
	iface, err := uefiboard.HandleProtocol(myImageHandleU64(), &loadedImageGUID)
	if err != nil || iface == 0 {
		return 0, 0, false
	}
	basePtr := *(*uint64)(unsafe.Pointer(uintptr(iface) + liImageBase))
	szU64 := *(*uint64)(unsafe.Pointer(uintptr(iface) + liImageSize))
	if basePtr == 0 || szU64 == 0 {
		return 0, 0, false
	}
	return basePtr, szU64, true
}

// myImageHandle returns our PE image handle as a uintptr. cpuinit
// captured it from RCX at entry; uefiboard's imageHandle slot is
// the canonical view -- we go-linkname through it for the
// HandleProtocol + Exit calls.
//
//go:linkname stubImageHandle github.com/cloud-boot/tamago-uefi/uefiboard.imageHandle
var stubImageHandle uint64

func myImageHandle() uintptr   { return uintptr(stubImageHandle) }
func myImageHandleU64() uint64 { return stubImageHandle }

// findPayloadSection walks the PE section table inside pe[] and
// returns the body of the section named ".payload". Tries the
// VirtualAddress view first (firmware-loaded mapping), then the
// PointerToRawData view as a fallback. Validates each candidate
// against the CBP0 magic so a wrong view yields a clean "not
// found" rather than a corrupt body.
func findPayloadSection(pe []byte) ([]byte, bool) {
	if len(pe) < 0x40 || pe[0] != 'M' || pe[1] != 'Z' {
		return nil, false
	}
	elfanew := binary.LittleEndian.Uint32(pe[0x3C:])
	if uint64(elfanew)+4+20 > uint64(len(pe)) {
		return nil, false
	}
	if string(pe[elfanew:elfanew+4]) != "PE\x00\x00" {
		return nil, false
	}
	coffOff := int(elfanew) + 4
	numSections := binary.LittleEndian.Uint16(pe[coffOff+2:])
	sizeOfOpt := binary.LittleEndian.Uint16(pe[coffOff+16:])
	secTableStart := coffOff + 20 + int(sizeOfOpt)
	if secTableStart+int(numSections)*40 > len(pe) {
		return nil, false
	}
	target := ".payload"
	for i := 0; i < int(numSections); i++ {
		off := secTableStart + i*40
		nameBuf := pe[off : off+8]
		name := trimNUL(nameBuf)
		if name != target {
			continue
		}
		vsize := binary.LittleEndian.Uint32(pe[off+8:])
		rsize := binary.LittleEndian.Uint32(pe[off+16:])
		foff := binary.LittleEndian.Uint32(pe[off+20:])
		va := binary.LittleEndian.Uint32(pe[off+12:])
		size := vsize
		if size > rsize {
			size = rsize
		}
		if uint64(va)+uint64(size) <= uint64(len(pe)) {
			if hasPayloadMagic(pe[va:]) {
				return pe[va : va+size], true
			}
		}
		if uint64(foff)+uint64(size) <= uint64(len(pe)) {
			if hasPayloadMagic(pe[foff:]) {
				return pe[foff : foff+size], true
			}
		}
		if uint64(va)+uint64(size) <= uint64(len(pe)) {
			return pe[va : va+size], true
		}
		if uint64(foff)+uint64(size) <= uint64(len(pe)) {
			return pe[foff : foff+size], true
		}
		return nil, false
	}
	return nil, false
}

// hasPayloadMagic returns true iff b starts with the CBP0 wire
// magic.
func hasPayloadMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return b[0] == 'C' && b[1] == 'B' && b[2] == 'P' && b[3] == '0'
}

func trimNUL(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// flateDecode decompresses src (raw flate stream) into dst,
// returning true iff exactly len(dst) bytes were produced.
func flateDecode(src, dst []byte) bool {
	r := flate.NewReader(bytes.NewReader(src))
	defer r.Close()
	n, err := io.ReadFull(r, dst)
	if err != nil && err != io.EOF {
		return false
	}
	if n != len(dst) {
		return false
	}
	var tail [1]byte
	if _, terr := r.Read(tail[:]); terr != io.EOF {
		return false
	}
	return true
}
