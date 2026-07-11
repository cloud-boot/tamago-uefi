//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// efipackstub -- M6.2 PR2 self-extracting EFI stub (amd64).
//
// STATUS (2026-06-09, third sprint -- "option 2"): the previous two
// sprints assumed firmware would map the `.payload` section into RAM
// at its VirtualAddress. Two redesigns (the section-table-ordering
// flip via peln/appender AppendBefore, then the "skip .reloc" theory)
// both failed to produce a runnable packed binary -- on amd64 the
// stub runs to main() but the bytes at ImageBase+payload.VA are zero,
// so the CBP0 magic check fails and we exit via gBS->Exit with
// EFI_ABORTED.
//
// "Option 2" sidesteps the in-RAM mapping question entirely:
//
//   1. HandleProtocol(EFI_LOADED_IMAGE_PROTOCOL) on our own image
//      handle -> LoadedImage.DeviceHandle + LoadedImage.FilePath.
//   2. HandleProtocol(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL) on
//      DeviceHandle -> sfs->OpenVolume(&root).
//   3. Walk the FilePath DevicePath chain, accumulating FilePath
//      (Media/0x04) UTF-16 components into a single path string
//      (e.g. "\EFI\BOOT\BOOTX64.EFI").
//   4. root->Open(path, EFI_FILE_MODE_READ, 0) -> EFI_FILE_PROTOCOL*
//   5. file->GetInfo(EFI_FILE_INFO_GUID, &size, &info) to read the size.
//   6. AllocatePool(size) -> buffer.
//   7. file->Read(&size, buffer) to slurp the whole file into RAM.
//   8. Close file + close root.
//   9. Parse the buffer as a PE32+, find `.payload` at its on-disk
//      offset (PointerToRawData), validate CBP0, decompress, chain
//      via gBS->LoadImage + gBS->StartImage.
//
// Because step 7 reads from disk (the SimpleFileSystem layer
// understands the FAT filesystem on the ESP), we recover the FULL
// on-disk PE bytes -- including the `.payload` section body that the
// firmware refused to map.
//
// What's PRESERVED from the previous sprint:
//   - peln/appender.AppendBefore is LANDED upstream regardless --
//     structurally cleaner shape for any packer that needs to
//     interleave headers around the relocation directory.
//   - The stub's runtime shape mirrors cmd/chainedtinyC: no println,
//     no goos.Exit linkname hook (the M6.2 de-risk sweep showed those
//     two behaviours trigger the EDK2 OVMF CpuPageTableLib #GP at
//     CpuDxe.dll+0x110C during a parent's StartImage call).
//
// Build (TamaGo PIE, amd64):
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_amd64_efipackstub.elf ./cmd/efipackstub
//
// Then linked via pectl link-pie into a PE32+/EFI; the resulting PE
// bytes are what efipack embeds (stub/blobs/amd64.efi.bin) and uses
// as the envelope base PE when packing an input image.
package main

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/go-compressions/lz4"
	"github.com/go-compressions/lzfse"
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

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID
//
//	964e5b22-6459-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Protocol/SimpleFileSystem.h (edk2.git).
var simpleFSGUID = uefiboard.EFIGUID{
	Data1: 0x964e5b22,
	Data2: 0x6459,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_FILE_INFO_GUID
//
//	09576e92-6d3f-11d2-8e39-00a0c969723b
//
// Source: MdePkg/Include/Guid/FileInfo.h (edk2.git).
var fileInfoGUID = uefiboard.EFIGUID{
	Data1: 0x09576e92,
	Data2: 0x6d3f,
	Data3: 0x11d2,
	Data4: [8]uint8{0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b},
}

// EFI_LOADED_IMAGE_PROTOCOL field offsets on 64-bit UEFI:
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
const (
	liDeviceHandle = 24
	liFilePath     = 32
)

// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL function-pointer offsets:
//
//	0  UINT64  Revision
//	8  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_OPEN_VOLUME OpenVolume
const sfsOpenVolume = 8

// EFI_FILE_PROTOCOL function-pointer offsets (UEFI 2.10 §13.5):
//
//	0   UINT64  Revision
//	8   Open
//	16  Close
//	24  Delete
//	32  Read
//	40  Write
//	48  GetPosition
//	56  SetPosition
//	64  GetInfo
//	72  SetInfo
//	80  Flush
const (
	fileOpen    = 8
	fileClose   = 16
	fileRead    = 32
	fileGetInfo = 64
)

// EFI_FILE_MODE_READ (UEFI 2.10 §13.5).
const efiFileModeRead uint64 = 0x0000000000000001

// EFI_DEVICE_PATH_PROTOCOL node header:
//
//	0  UINT8   Type
//	1  UINT8   SubType
//	2  UINT16  Length (total node length including header)
//
// Media type = 0x04, FilePath subtype = 0x04 -- the only node kind we
// extract path components from. Path16[] (UTF-16 LE, NUL-terminated)
// fills bytes 4..Length.
//
// End-of-Hardware node: Type 0x7F, SubType 0xFF (or 0x01 for end-of-
// instance which we treat the same way).
const (
	dpTypeMedia       = 0x04
	dpSubTypeFilePath = 0x04
	dpTypeEnd         = 0x7F
)

// EFI_FILE_INFO header (UEFI 2.10 §13.5.16): the dynamic FileName
// field starts at offset 80. We only care about FileSize at offset 8
// for the buffer-sizing pass.
//
//	0   UINT64  Size           // total size of this struct incl. FileName
//	8   UINT64  FileSize
//	16  UINT64  PhysicalSize
//	24  EFI_TIME CreateTime    // 16 bytes
//	40  EFI_TIME LastAccessTime
//	56  EFI_TIME ModificationTime
//	72  UINT64  Attribute
//	80  CHAR16  FileName[]
const fileInfoFileSize = 8

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
	// Algorithm tags stamped by go-coff/efipack (payloadAlgoTag). Each
	// is exactly four bytes on the wire; LZ4 pads to width with a
	// trailing space. These MUST stay byte-identical to the host-side
	// tags in go-coff/efipack/pack.go.
	algoFlat  = "FLAT"
	algoLZFSE = "LZFS"
	algoLZ4   = "LZ4 "
)

// EFI memory types we may pass to AllocatePages. EfiLoaderCode is
// what the firmware itself uses to stage child EFI images.
const (
	efiLoaderCode = 1
	efiPageSize   = 4096
)

// EFI_ABORTED on a 64-bit UEFI.
const efiAborted uintptr = 0x8000000000000015

// efiSuccess in the raw uint64 status space.
const efiSuccess uint64 = 0

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
// internal failure.
func run() uintptr {
	peBytes, ok := readOwnFile()
	if !ok {
		return efiAborted
	}

	payload, ok := findPayloadOnDisk(peBytes)
	if !ok {
		return efiAborted
	}
	if len(payload) < payloadHeaderSize {
		return efiAborted
	}
	if string(payload[0:4]) != payloadMagic {
		return efiAborted
	}
	algo := string(payload[4:8])
	switch algo {
	case algoFlat, algoLZ4, algoLZFSE:
		// supported
	default:
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

	if !decodePayload(algo, compressed, dst) {
		return efiAborted
	}

	child, lerr := uefiboard.LoadImage(dst)
	if lerr != nil {
		return efiAborted
	}
	st, _ := uefiboard.StartImage(child)
	return st
}

// readOwnFile re-reads our own EFI file off the boot volume via the
// EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle + EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
// pair. Returns the full on-disk PE bytes.
//
// This is the heart of "option 2": rather than trust whatever
// in-memory layout the firmware chose for us, we re-fetch our own
// file from disk so the `.payload` section is recoverable at its
// PointerToRawData offset regardless of what the in-RAM section
// mapping looks like.
func readOwnFile() ([]byte, bool) {
	// Step 1: LOADED_IMAGE_PROTOCOL on our own image handle.
	li, err := uefiboard.HandleProtocol(myImageHandleU64(), &loadedImageGUID)
	if err != nil || li == 0 {
		return nil, false
	}
	devHandle := *(*uint64)(unsafe.Pointer(uintptr(li) + liDeviceHandle))
	filePathPtr := *(*uint64)(unsafe.Pointer(uintptr(li) + liFilePath))
	if devHandle == 0 || filePathPtr == 0 {
		return nil, false
	}

	// Step 2: SimpleFileSystem on the DeviceHandle, then OpenVolume.
	sfs, err := uefiboard.HandleProtocol(devHandle, &simpleFSGUID)
	if err != nil || sfs == 0 {
		return nil, false
	}
	var root uint64
	status := uefiboard.EFICall(
		sfs+sfsOpenVolume,
		sfs,
		uint64(uintptr(unsafe.Pointer(&root))),
		0, 0, 0, 0,
	)
	if status != efiSuccess || root == 0 {
		return nil, false
	}

	// Step 3: walk the DevicePath chain in LoadedImage.FilePath,
	// gathering File-Path nodes into a UTF-16 path.
	path16 := buildPath16(filePathPtr)
	if len(path16) == 0 {
		closeFile(root)
		return nil, false
	}

	// Step 4: root->Open(path).
	var file uint64
	status = uefiboard.EFICall(
		root+fileOpen,
		root,
		uint64(uintptr(unsafe.Pointer(&file))),
		uint64(uintptr(unsafe.Pointer(&path16[0]))),
		efiFileModeRead,
		0,
		0,
	)
	if status != efiSuccess || file == 0 {
		closeFile(root)
		return nil, false
	}

	// Step 5: file->GetInfo(EFI_FILE_INFO_GUID).
	size, ok := getFileSize(file)
	if !ok || size == 0 {
		closeFile(file)
		closeFile(root)
		return nil, false
	}

	// Step 6: allocate buffer (Go-allocated slice; the firmware
	// only needs a pointer + size for Read).
	buf := make([]byte, size)

	// Step 7: file->Read(&size, buf).
	readSize := uintptr(size)
	status = uefiboard.EFICall(
		file+fileRead,
		file,
		uint64(uintptr(unsafe.Pointer(&readSize))),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0, 0, 0,
	)
	closeFile(file)
	closeFile(root)
	if status != efiSuccess {
		return nil, false
	}
	if uint64(readSize) != size {
		// Short read; refuse to proceed with a truncated PE.
		return nil, false
	}
	return buf, true
}

// closeFile invokes the EFI_FILE_PROTOCOL.Close slot. Errors are
// ignored -- there is nothing useful we can do with them at this
// point in the stub's lifetime.
func closeFile(file uint64) {
	if file == 0 {
		return
	}
	_ = uefiboard.EFICall(
		file+fileClose,
		file,
		0, 0, 0, 0, 0,
	)
}

// getFileSize calls file->GetInfo(EFI_FILE_INFO_GUID, ...) twice: once
// with size=0 to get the required buffer size, then once with the
// real buffer. Returns the FileSize field at offset 8 of the returned
// struct.
func getFileSize(file uint64) (uint64, bool) {
	// First call: probe required buffer size.
	var bufSize uintptr
	status := uefiboard.EFICall(
		file+fileGetInfo,
		file,
		uint64(uintptr(unsafe.Pointer(&fileInfoGUID))),
		uint64(uintptr(unsafe.Pointer(&bufSize))),
		0, // Buffer = NULL
		0, 0,
	)
	// Expected: EFI_BUFFER_TOO_SMALL = 0x8000000000000005. bufSize is
	// now the required size. Anything else (including success on a
	// firmware that pre-fills a small buffer for us) we also handle
	// by falling through.
	if bufSize == 0 {
		return 0, false
	}
	buf := make([]byte, bufSize)
	status = uefiboard.EFICall(
		file+fileGetInfo,
		file,
		uint64(uintptr(unsafe.Pointer(&fileInfoGUID))),
		uint64(uintptr(unsafe.Pointer(&bufSize))),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0, 0,
	)
	if status != efiSuccess {
		return 0, false
	}
	if uintptr(len(buf)) < fileInfoFileSize+8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(buf[fileInfoFileSize : fileInfoFileSize+8]), true
}

// buildPath16 walks the EFI_DEVICE_PATH_PROTOCOL chain starting at
// dp, concatenating every Media/FilePath (0x04/0x04) node's Path16
// content into a single NUL-terminated UTF-16 path suitable for
// passing to EFI_FILE_PROTOCOL.Open.
//
// Components from each FilePath node are concatenated as-is. UEFI
// FilePath nodes for individual path components typically already
// include the leading backslash separator (e.g. "\EFI", then
// "\BOOT", then "\BOOTX64.EFI"). For the common case where the
// firmware packs the whole "\EFI\BOOT\BOOTX64.EFI" string into a
// single FilePath node, this also Just Works.
//
// Returns nil if no FilePath nodes were found. Defensively caps the
// walk at a sane node count to avoid wandering off into firmware
// memory if a malformed chain is presented.
func buildPath16(dp uint64) []uint16 {
	if dp == 0 {
		return nil
	}
	const maxNodes = 32
	const maxNodeLen = 4096
	var out []uint16
	cur := uintptr(dp)
	for i := 0; i < maxNodes; i++ {
		t := *(*uint8)(unsafe.Pointer(cur))
		st := *(*uint8)(unsafe.Pointer(cur + 1))
		ln := *(*uint16)(unsafe.Pointer(cur + 2))
		if ln < 4 || ln > maxNodeLen {
			break
		}
		if t == dpTypeEnd {
			break
		}
		if t == dpTypeMedia && st == dpSubTypeFilePath {
			// UTF-16 path data starts at offset 4, runs to ln.
			n16 := (uintptr(ln) - 4) / 2
			if n16 > 0 {
				src := unsafe.Slice((*uint16)(unsafe.Pointer(cur+4)), int(n16))
				// Trim a trailing NUL on this node so the joined
				// result has exactly one terminator at the end.
				if src[len(src)-1] == 0 {
					src = src[:len(src)-1]
				}
				out = append(out, src...)
			}
		}
		cur += uintptr(ln)
	}
	if len(out) == 0 {
		return nil
	}
	// NUL-terminate.
	out = append(out, 0)
	return out
}

// findPayloadOnDisk walks the section table of the PE bytes (read
// from disk) and returns the `.payload` section body using its
// PointerToRawData / SizeOfRawData fields -- not the in-memory
// VirtualAddress view. Validates the CBP0 magic at the head of the
// candidate region.
func findPayloadOnDisk(pe []byte) ([]byte, bool) {
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
		rsize := binary.LittleEndian.Uint32(pe[off+16:])
		foff := binary.LittleEndian.Uint32(pe[off+20:])
		if rsize == 0 {
			return nil, false
		}
		if uint64(foff)+uint64(rsize) > uint64(len(pe)) {
			return nil, false
		}
		body := pe[foff : foff+rsize]
		if !hasPayloadMagic(body) {
			return nil, false
		}
		return body, true
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

// myImageHandle returns our PE image handle as a uintptr. cpuinit
// captured it from RCX at entry; uefiboard's imageHandle slot is
// the canonical view -- we go-linkname through it for the
// HandleProtocol + Exit calls.
//
//go:linkname stubImageHandle github.com/cloud-boot/tamago-uefi/uefiboard.imageHandle
var stubImageHandle uint64

func myImageHandle() uintptr   { return uintptr(stubImageHandle) }
func myImageHandleU64() uint64 { return stubImageHandle }

// decodePayload decompresses the CBP0 body `compressed` into `dst`
// (the AllocatePages EfiLoaderCode buffer, pre-sized to the header's
// uncompressed length) according to the 4-byte wire `algo` tag.
//
//   - FLAT  -> compress/flate, inflated straight into dst.
//   - LZ4   -> github.com/go-compressions/lz4 raw block codec; the
//     CBP0 uncompressed size seeds DecompressBlock's output capacity
//     so it never reallocates, then the result is copied into dst.
//   - LZFS  -> github.com/go-compressions/lzfse (LZFSE); decoded then
//     copied into dst.
//
// Both go-compressions codecs are the SAME pure-Go implementations
// go-coff/efipack proves byte-exact host-side, so a stub decode is
// guaranteed to round-trip whatever the host packer stamped. Returns
// true iff exactly len(dst) bytes were produced.
func decodePayload(algo string, compressed, dst []byte) bool {
	switch algo {
	case algoFlat:
		return flateDecode(compressed, dst)
	case algoLZ4:
		out, err := lz4.DecompressBlock(compressed, len(dst))
		if err != nil || len(out) != len(dst) {
			return false
		}
		copy(dst, out)
		return true
	case algoLZFSE:
		out, err := lzfse.Decompress(compressed)
		if err != nil || len(out) != len(dst) {
			return false
		}
		copy(dst, out)
		return true
	default:
		return false
	}
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
