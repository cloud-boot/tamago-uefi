// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// efipackstub -- M6.2 PR2 self-extracting EFI stub (amd64).
//
// STATUS (2026-06-09, fourth sprint -- "deeper debug"): the first
// three sprints produced (a) "fast-exit via gBS->Exit" then (b) "X64
// Divide Error at RIP=0 mid-stub". ConOut printing trips the very
// CpuPageTableLib #GP that motivated the de-risk in the first place,
// so in-band logging is dead. This sprint wires the M1.6 Block-IO
// side-channel ring buffer directly into the stub so we can drop a
// breadcrumb to a scratch virtio-blk-pci disk at every meaningful
// step. After a crash the host-side `blkprintk-recover` tool reads
// the disk image and prints the last tracepoint that landed -- that's
// the step that crashed.
//
// The runtime shape still mirrors cmd/chainedtinyC: no println, no
// goos.Exit linkname hook. The blkprintk path goes directly via
// uefiboard.BlockIOWriteBlocks + BlockIOFlushBlocks, bypassing
// runtime.printk entirely -- this is the same channel M1.6 used to
// recover output on Apple VZ where ConOut was unavailable.
//
// What "option 2" does (re-read our own file off disk via
// SimpleFileSystem) is preserved unchanged; only the instrumentation
// is new.
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
const (
	dpTypeMedia       = 0x04
	dpSubTypeFilePath = 0x04
	dpTypeEnd         = 0x7F
)

// EFI_FILE_INFO header (UEFI 2.10 §13.5.16): FileSize at offset 8.
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

// efiSuccess in the raw uint64 status space.
const efiSuccess uint64 = 0

// EFI_BUFFER_TOO_SMALL on a 64-bit UEFI -- expected from the
// probe call to file->GetInfo with a NULL buffer.
const efiBufferTooSmall uint64 = 0x8000000000000005

// blkprintk side-channel singleton. Bound (or left nil) by setupBlkprintk
// at the very start of main(). Every tp() call appends to it and
// flushes immediately so a crash leaves the LAST printed step on
// disk -- the host-side blkprintk-recover then reports it.
var blkRing *uefiboard.BlkRingBuffer

// setupBlkprintk walks every EFI_BLOCK_IO_PROTOCOL handle, reads
// LBA 0, and binds blkRing to the first handle whose LBA 0 carries
// uefiboard.BlkPrintkScratchMagic. Failure to find one leaves
// blkRing == nil and tp() degrades to a no-op (stub still runs,
// nothing is observable on the side-channel).
//
// All side-channel setup happens BEFORE we touch the actual stub
// work, so any crash inside the work path is recoverable.
func setupBlkprintk() {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIBlockIOProtocolGUID)
	if err != nil || len(handles) == 0 {
		return
	}
	for _, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIBlockIOProtocolGUID)
		if err != nil || iface == 0 {
			continue
		}
		media, ok := uefiboard.BlockIOMedia(iface)
		if !ok {
			continue
		}
		if media.MediaPresent == 0 || media.ReadOnly != 0 || media.LogicalPartition != 0 {
			continue
		}
		if media.BlockSize == 0 {
			continue
		}
		buf := make([]byte, int(media.BlockSize))
		if err := uefiboard.BlockIOReadBlocks(iface, media.MediaId, 0, buf); err != nil {
			continue
		}
		if !matchesScratchMagic(buf) {
			continue
		}
		ring := uefiboard.NewBlkRingBuffer()
		if err := ring.BindBlockIO(iface, media.MediaId, media.BlockSize, 0); err != nil {
			continue
		}
		blkRing = ring
		return
	}
}

func matchesScratchMagic(buf []byte) bool {
	if len(buf) < len(uefiboard.BlkPrintkScratchMagic) {
		return false
	}
	for i, b := range uefiboard.BlkPrintkScratchMagic {
		if buf[i] != b {
			return false
		}
	}
	return true
}

// tp prints one tracepoint line to the side-channel ring buffer and
// flushes immediately. After a crash the host reads the disk image
// and the last line printed identifies the step that faulted.
//
// Idempotent on nil ring (no scratch disk present -> degrades to
// no-op silently).
func tp(s string) {
	if blkRing == nil {
		return
	}
	blkRing.AppendString(s)
	blkRing.Append('\n')
	_ = blkRing.Flush()
}

// tpHex appends the line "<tag>=0x<hex>" then flushes. Used for
// non-zero pointer / size values worth recovering post-crash.
func tpHex(tag string, v uint64) {
	if blkRing == nil {
		return
	}
	blkRing.AppendString(tag)
	blkRing.AppendString("=0x")
	appendHex(blkRing, v)
	blkRing.Append('\n')
	_ = blkRing.Flush()
}

// tpDec appends the line "<tag>=<decimal>" then flushes. Used for
// human-friendly counts (file size, page count, byte count).
func tpDec(tag string, v uint64) {
	if blkRing == nil {
		return
	}
	blkRing.AppendString(tag)
	blkRing.Append('=')
	appendDec(blkRing, v)
	blkRing.Append('\n')
	_ = blkRing.Flush()
}

// appendHex writes v as exactly 16 lowercase hex chars (no 0x prefix)
// into the ring. Fixed width so the host sees a predictable layout.
func appendHex(r *uefiboard.BlkRingBuffer, v uint64) {
	const digits = "0123456789abcdef"
	var buf [16]byte
	for i := 15; i >= 0; i-- {
		buf[i] = digits[v&0xf]
		v >>= 4
	}
	for i := 0; i < 16; i++ {
		r.Append(buf[i])
	}
}

// appendDec writes v as decimal (no leading zeros) into the ring.
func appendDec(r *uefiboard.BlkRingBuffer, v uint64) {
	if v == 0 {
		r.Append('0')
		return
	}
	var buf [20]byte
	n := 0
	for v > 0 {
		buf[n] = byte('0' + v%10)
		v /= 10
		n++
	}
	for i := n - 1; i >= 0; i-- {
		r.Append(buf[i])
	}
}

// main is the stub entry from the firmware's perspective (via
// cpuinit_amd64.s -> runtime.rt0 -> main). We deliberately avoid
// println, fmt, and any goos.Exit linkname hook -- see the package
// comment for why.
func main() {
	setupBlkprintk()
	tp("efipackstub: entered main")

	status := run()

	tp("efipackstub: run() returned")
	tpHex("status", uint64(status))
	tp("efipackstub: calling gBS->Exit")
	if blkRing != nil {
		blkRing.Append(uefiboard.BlkSentinel)
		_ = blkRing.Flush()
	}
	_ = uefiboard.ExitImage(myImageHandle(), status)
	for {
	}
}

// run does the actual work, returning an EFI_STATUS to pass to
// gBS->Exit. EFI_SUCCESS (0) for the happy path; EFI_ABORTED for any
// internal failure.
func run() uintptr {
	tp("efipackstub: entering run()")

	peBytes, ok := readOwnFile()
	if !ok {
		tp("efipackstub: readOwnFile FAILED")
		return efiAborted
	}
	tpDec("peBytes.len", uint64(len(peBytes)))

	tp("efipackstub: parsing PE for .payload (on-disk)")
	payload, ok := findPayloadOnDisk(peBytes)
	if !ok {
		tp("efipackstub: findPayloadOnDisk FAILED")
		return efiAborted
	}
	tpDec("payload.len", uint64(len(payload)))

	if len(payload) < payloadHeaderSize {
		tp("efipackstub: payload shorter than header")
		return efiAborted
	}
	if string(payload[0:4]) != payloadMagic {
		tp("efipackstub: payload magic mismatch")
		return efiAborted
	}
	if string(payload[4:8]) != algoFlat {
		tp("efipackstub: payload algo != FLAT")
		return efiAborted
	}
	uncompressedSize := binary.LittleEndian.Uint64(payload[8:16])
	compressedSize := binary.LittleEndian.Uint64(payload[16:24])
	tpDec("uncompressedSize", uncompressedSize)
	tpDec("compressedSize", compressedSize)
	if uint64(len(payload))-payloadHeaderSize < compressedSize {
		tp("efipackstub: compressed body underruns payload")
		return efiAborted
	}
	if uncompressedSize == 0 {
		tp("efipackstub: uncompressedSize is zero")
		return efiAborted
	}
	compressed := payload[payloadHeaderSize : payloadHeaderSize+int(compressedSize)]

	tp("efipackstub: AllocatePages for decompressed image")
	pageCount := (uintptr(uncompressedSize) + efiPageSize - 1) / efiPageSize
	tpDec("pageCount", uint64(pageCount))
	addr, err := uefiboard.AllocatePages(efiLoaderCode, pageCount)
	if err != nil || addr == 0 {
		tp("efipackstub: AllocatePages FAILED")
		return efiAborted
	}
	tpHex("pagesAddr", addr)

	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), int(uncompressedSize))

	tp("efipackstub: decompressing flate stream")
	if !flateDecode(compressed, dst) {
		tp("efipackstub: flateDecode FAILED")
		return efiAborted
	}
	tp("efipackstub: decompress OK")

	tp("efipackstub: gBS->LoadImage on decompressed bytes")
	child, lerr := uefiboard.LoadImage(dst)
	if lerr != nil {
		tp("efipackstub: LoadImage FAILED")
		return efiAborted
	}
	tpHex("childHandle", uint64(child))

	tp("efipackstub: gBS->StartImage on child")
	st, _ := uefiboard.StartImage(child)
	tp("efipackstub: StartImage returned")
	tpHex("childStatus", uint64(st))
	return st
}

// readOwnFile re-reads our own EFI file off the boot volume via the
// EFI_LOADED_IMAGE_PROTOCOL.DeviceHandle + EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
// pair. Returns the full on-disk PE bytes.
func readOwnFile() ([]byte, bool) {
	tp("readOwnFile: HandleProtocol(LOADED_IMAGE)")
	li, err := uefiboard.HandleProtocol(myImageHandleU64(), &loadedImageGUID)
	if err != nil || li == 0 {
		tp("readOwnFile: LOADED_IMAGE handle FAILED")
		return nil, false
	}
	tpHex("li", li)

	devHandle := *(*uint64)(unsafe.Pointer(uintptr(li) + liDeviceHandle))
	filePathPtr := *(*uint64)(unsafe.Pointer(uintptr(li) + liFilePath))
	tpHex("devHandle", devHandle)
	tpHex("filePathPtr", filePathPtr)
	if devHandle == 0 || filePathPtr == 0 {
		tp("readOwnFile: NULL devHandle or filePath")
		return nil, false
	}

	tp("readOwnFile: HandleProtocol(SIMPLE_FILE_SYSTEM) on devHandle")
	sfs, err := uefiboard.HandleProtocol(devHandle, &simpleFSGUID)
	if err != nil || sfs == 0 {
		tp("readOwnFile: SIMPLE_FILE_SYSTEM handle FAILED")
		return nil, false
	}
	tpHex("sfs", sfs)

	tp("readOwnFile: sfs->OpenVolume")
	var root uint64
	status := uefiboard.EFICall(
		sfs+sfsOpenVolume,
		sfs,
		uint64(uintptr(unsafe.Pointer(&root))),
		0, 0, 0, 0,
	)
	if status != efiSuccess || root == 0 {
		tp("readOwnFile: OpenVolume FAILED")
		tpHex("openVolumeStatus", status)
		return nil, false
	}
	tpHex("root", root)

	tp("readOwnFile: buildPath16 from FilePath chain")
	path16 := buildPath16(filePathPtr)
	if len(path16) == 0 {
		tp("readOwnFile: buildPath16 produced empty path")
		closeFile(root)
		return nil, false
	}
	tpDec("path16.len", uint64(len(path16)))

	tp("readOwnFile: root->Open(path)")
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
		tp("readOwnFile: Open(path) FAILED")
		tpHex("openStatus", status)
		closeFile(root)
		return nil, false
	}
	tpHex("file", file)

	tp("readOwnFile: getFileSize via GetInfo")
	size, ok := getFileSize(file)
	if !ok || size == 0 {
		tp("readOwnFile: getFileSize FAILED")
		closeFile(file)
		closeFile(root)
		return nil, false
	}
	tpDec("fileSize", size)

	tp("readOwnFile: allocating Go buffer for Read")
	buf := make([]byte, size)

	tp("readOwnFile: file->Read")
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
		tp("readOwnFile: Read FAILED")
		tpHex("readStatus", status)
		return nil, false
	}
	tpDec("readSize", uint64(readSize))
	if uint64(readSize) != size {
		tp("readOwnFile: short Read")
		return nil, false
	}
	tp("readOwnFile: OK")
	return buf, true
}

// closeFile invokes the EFI_FILE_PROTOCOL.Close slot.
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
// with a NULL buffer to get the required size, then once with the real
// buffer.
func getFileSize(file uint64) (uint64, bool) {
	tp("getFileSize: probe (NULL buffer)")
	var bufSize uintptr
	_ = uefiboard.EFICall(
		file+fileGetInfo,
		file,
		uint64(uintptr(unsafe.Pointer(&fileInfoGUID))),
		uint64(uintptr(unsafe.Pointer(&bufSize))),
		0, // Buffer = NULL
		0, 0,
	)
	tpDec("bufSize.probe", uint64(bufSize))
	if bufSize == 0 {
		tp("getFileSize: bufSize stayed zero after probe")
		return 0, false
	}
	tp("getFileSize: allocating + second GetInfo")
	buf := make([]byte, bufSize)
	status := uefiboard.EFICall(
		file+fileGetInfo,
		file,
		uint64(uintptr(unsafe.Pointer(&fileInfoGUID))),
		uint64(uintptr(unsafe.Pointer(&bufSize))),
		uint64(uintptr(unsafe.Pointer(&buf[0]))),
		0, 0,
	)
	if status != efiSuccess {
		tp("getFileSize: second GetInfo FAILED")
		tpHex("getInfoStatus", status)
		return 0, false
	}
	if uintptr(len(buf)) < fileInfoFileSize+8 {
		tp("getFileSize: buffer too small to hold FileSize field")
		return 0, false
	}
	return binary.LittleEndian.Uint64(buf[fileInfoFileSize : fileInfoFileSize+8]), true
}

// buildPath16 walks the EFI_DEVICE_PATH_PROTOCOL chain starting at dp,
// concatenating every Media/FilePath (0x04/0x04) node's Path16 content
// into a single NUL-terminated UTF-16 path.
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
			n16 := (uintptr(ln) - 4) / 2
			if n16 > 0 {
				src := unsafe.Slice((*uint16)(unsafe.Pointer(cur+4)), int(n16))
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
	out = append(out, 0)
	return out
}

// findPayloadOnDisk walks the section table of the PE bytes (read
// from disk) and returns the `.payload` section body using its
// PointerToRawData / SizeOfRawData fields.
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

// efiBufferTooSmall reference kept so the constant doesn't go unused
// when someone re-introduces a buffer-too-small fallback path -- we
// expect that exact status from getFileSize's probe call.
var _ = efiBufferTooSmall
