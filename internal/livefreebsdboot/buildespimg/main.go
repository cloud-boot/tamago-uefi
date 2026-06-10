// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// buildespimg — produce a minimal bootable disk image (PMBR + GPT
// + single FAT16 ESP partition) wrapping an mformat-generated FAT
// blob. The FAT contains exactly one file: \EFI\BOOT\BOOTX64.EFI,
// which on a FreeBSD source ISO is the FreeBSD loader.efi (~660 KiB).
//
// Why a Go helper rather than dd + sgdisk + mformat?
//
//   - macOS dev hosts don't ship sgdisk/gdisk and Homebrew's gptfdisk
//     is a heavyweight install. mformat (mtools) is widely available
//     and we already use it for ESP construction elsewhere in the
//     repo, but mtools alone cannot lay down a GPT.
//   - The Phase-3 sprint-1.1 PoC needs a tiny (<= ~4 MiB) ESP-only
//     image so the bytes.Buffer + Go heap inside tamago can hold it
//     without OOM. The 412 MiB FreeBSD bootonly ISO won't fit in
//     tamago's 256 MiB heap reservation (board_amd64.go), so
//     streaming it via OCI fails closed with "out of memory".
//   - A custom Go helper gives us deterministic, reproducible bytes
//     keyed only on the inner FAT image's content — handy for unit
//     tests of the publish-side block IO path.
//
// Wire layout (sectors are 512 bytes; SectorCount = ceil(FATsize/512)
// + headroom):
//
//	LBA 0      : Protective MBR (single type=0xEE partition spanning
//	             LBA 1..end). bootsig = 0x55 0xAA at byte 510..511.
//	LBA 1      : GPT header (UEFI 2.10 §5.3.2):
//	             - Signature "EFI PART"
//	             - Revision 0x00010000
//	             - HeaderSize 0x5C
//	             - HeaderCRC32 (computed over the header w/ CRC=0)
//	             - MyLBA = 1; AlternateLBA = LastUsableLBA+1
//	             - FirstUsableLBA = 34; LastUsableLBA = totalLBAs-34
//	             - DiskGUID (deterministic from FAT digest)
//	             - PartitionEntryLBA = 2
//	             - NumberOfPartitionEntries = 128
//	             - SizeOfPartitionEntry = 128
//	             - PartitionEntryArrayCRC32
//	LBA 2..33  : 128 partition entries (16 KiB total). Entry 0 is
//	             the EFI System partition:
//	             - PartitionTypeGUID = C12A7328-F81F-11D2-BA4B-00A0C93EC93B
//	             - PartitionGUID (deterministic from FAT digest)
//	             - StartingLBA = 64 (8 KiB aligned)
//	             - EndingLBA = 64 + FATsize/512 - 1
//	             - Attributes = 0
//	             - PartitionName "EFI System" (UTF-16LE)
//	LBA 64..   : The FAT image bytes (built by mformat — caller passes
//	             the path).
//	LastLBA-33..LastLBA-1: Backup partition entry array (128 entries).
//	LastLBA    : Backup GPT header (mirror of LBA 1 with MyLBA/AlternateLBA
//	             swapped and PartitionEntryLBA = LastLBA-32).
//
// CRC32 is the same polynomial as IEEE 802.3 / zlib (`hash/crc32` with
// the IEEE table) — UEFI 2.10 §5.3.1 explicitly mandates this.
//
// Usage:
//
//	buildespimg -fat fat.img -out disk.img
//
// where fat.img is a pre-built FAT image (mformat -i fat.img ::) and
// disk.img will contain a complete GPT-wrapped disk that boots in OVMF.
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
)

const (
	sectorSize         = 512
	gptPartEntrySize   = 128
	gptPartEntryCount  = 128
	gptPartArrayBytes  = gptPartEntrySize * gptPartEntryCount // 16384
	gptPartArraySector = gptPartArrayBytes / sectorSize       // 32
	firstUsableLBA     = 1 + 1 + gptPartArraySector           // 34
	dataStartLBA       = 64                                   // 8 KiB aligned start for the ESP payload
)

// efiSystemPartitionGUID = C12A7328-F81F-11D2-BA4B-00A0C93EC93B
// (UEFI 2.10 §5.3.3 table 5.7). Mixed-endian RFC 4122 — Data1/2/3
// little-endian, Data4 raw.
var efiSystemPartitionGUID = [16]byte{
	0x28, 0x73, 0x2A, 0xC1, // Data1 LE: 0xC12A7328
	0x1F, 0xF8, // Data2 LE: 0xF81F
	0xD2, 0x11, // Data3 LE: 0x11D2
	0xBA, 0x4B, // Data4 [0..1]
	0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B, // Data4 [2..7]
}

func main() {
	fatPath := flag.String("fat", "", "path to pre-built FAT image (mformat)")
	outPath := flag.String("out", "", "path to write the disk image to")
	flag.Parse()
	if *fatPath == "" || *outPath == "" {
		log.Fatalf("usage: buildespimg -fat fat.img -out disk.img")
	}

	fat, err := os.ReadFile(*fatPath)
	if err != nil {
		log.Fatalf("read fat: %v", err)
	}
	if len(fat)%sectorSize != 0 {
		log.Fatalf("FAT image size %d is not a multiple of %d", len(fat), sectorSize)
	}
	fatSectors := uint64(len(fat) / sectorSize)
	if fatSectors == 0 {
		log.Fatalf("FAT image is empty")
	}

	// Deterministic GUIDs derived from FAT digest so two runs produce
	// the same bytes for the same content (useful for testing). We
	// stuff variant/version bits per RFC 4122 §4.4 so EDK2 doesn't
	// reject them.
	dig := sha256.Sum256(fat)
	diskGUID := uuidV4FromBytes(dig[:16])
	partGUID := uuidV4FromBytes(dig[16:])

	dataEndLBA := dataStartLBA + fatSectors - 1
	// Tail: backup partition array (32 sectors) + backup GPT header (1 sector).
	totalLBAs := dataEndLBA + 1 + uint64(gptPartArraySector) + 1
	lastLBA := totalLBAs - 1
	lastUsableLBA := lastLBA - 1 - uint64(gptPartArraySector)
	backupPartArrayLBA := lastLBA - uint64(gptPartArraySector)

	imgSize := int64(totalLBAs) * sectorSize
	img := make([]byte, imgSize)

	// ----- Protective MBR (LBA 0) -----
	// Partition table entry 1: type 0xEE, covers LBA 1..end (capped at 0xFFFFFFFF).
	mbr := img[0:sectorSize]
	mbr[446+0] = 0x00 // boot indicator
	mbr[446+1] = 0x00 // starting CHS h
	mbr[446+2] = 0x02 // starting CHS s
	mbr[446+3] = 0x00 // starting CHS c
	mbr[446+4] = 0xEE // type = GPT protective
	mbr[446+5] = 0xFF // ending CHS h
	mbr[446+6] = 0xFF // ending CHS s
	mbr[446+7] = 0xFF // ending CHS c
	binary.LittleEndian.PutUint32(mbr[446+8:], 1)
	size32 := uint32(totalLBAs - 1)
	if uint64(size32) != totalLBAs-1 {
		size32 = 0xFFFFFFFF
	}
	binary.LittleEndian.PutUint32(mbr[446+12:], size32)
	mbr[510] = 0x55
	mbr[511] = 0xAA

	// ----- Partition entry array (LBA 2..33) -----
	parts := img[2*sectorSize : 2*sectorSize+gptPartArrayBytes]
	// Entry 0:
	copy(parts[0:16], efiSystemPartitionGUID[:])
	copy(parts[16:32], partGUID[:])
	binary.LittleEndian.PutUint64(parts[32:40], dataStartLBA)
	binary.LittleEndian.PutUint64(parts[40:48], dataEndLBA)
	binary.LittleEndian.PutUint64(parts[48:56], 0)
	// PartitionName "EFI System" in UTF-16LE, 72 bytes (36 wchars).
	name := "EFI System"
	for i, r := range name {
		binary.LittleEndian.PutUint16(parts[56+i*2:], uint16(r))
	}
	partArrCRC := crc32.ChecksumIEEE(parts)

	// ----- Primary GPT header (LBA 1) -----
	primary := img[sectorSize : 2*sectorSize]
	writeGPTHeader(primary, gptHeaderArgs{
		myLBA:              1,
		alternateLBA:       lastLBA,
		firstUsableLBA:     firstUsableLBA,
		lastUsableLBA:      lastUsableLBA,
		diskGUID:           diskGUID,
		partitionEntryLBA:  2,
		partitionEntryCRC:  partArrCRC,
	})

	// ----- ESP payload (LBA 64..) -----
	copy(img[dataStartLBA*sectorSize:], fat)

	// ----- Backup partition entry array -----
	backupParts := img[backupPartArrayLBA*sectorSize : backupPartArrayLBA*sectorSize+gptPartArrayBytes]
	copy(backupParts, parts)

	// ----- Backup GPT header (last LBA) -----
	backup := img[lastLBA*sectorSize : (lastLBA+1)*sectorSize]
	writeGPTHeader(backup, gptHeaderArgs{
		myLBA:              lastLBA,
		alternateLBA:       1,
		firstUsableLBA:     firstUsableLBA,
		lastUsableLBA:      lastUsableLBA,
		diskGUID:           diskGUID,
		partitionEntryLBA:  backupPartArrayLBA,
		partitionEntryCRC:  partArrCRC,
	})

	out, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, byteReader(img)); err != nil {
		log.Fatalf("write %s: %v", *outPath, err)
	}
	fmt.Fprintf(os.Stderr, "[buildespimg] wrote %s (%d bytes, %d sectors, FAT %d sectors at LBA %d)\n",
		*outPath, len(img), totalLBAs, fatSectors, dataStartLBA)
}

type gptHeaderArgs struct {
	myLBA             uint64
	alternateLBA      uint64
	firstUsableLBA    uint64
	lastUsableLBA     uint64
	diskGUID          [16]byte
	partitionEntryLBA uint64
	partitionEntryCRC uint32
}

func writeGPTHeader(hdr []byte, a gptHeaderArgs) {
	copy(hdr[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(hdr[8:12], 0x00010000) // Revision
	binary.LittleEndian.PutUint32(hdr[12:16], 92)        // HeaderSize
	// HeaderCRC32 (16..19) left zero for the CRC computation below.
	binary.LittleEndian.PutUint32(hdr[20:24], 0) // Reserved
	binary.LittleEndian.PutUint64(hdr[24:32], a.myLBA)
	binary.LittleEndian.PutUint64(hdr[32:40], a.alternateLBA)
	binary.LittleEndian.PutUint64(hdr[40:48], a.firstUsableLBA)
	binary.LittleEndian.PutUint64(hdr[48:56], a.lastUsableLBA)
	copy(hdr[56:72], a.diskGUID[:])
	binary.LittleEndian.PutUint64(hdr[72:80], a.partitionEntryLBA)
	binary.LittleEndian.PutUint32(hdr[80:84], gptPartEntryCount)
	binary.LittleEndian.PutUint32(hdr[84:88], gptPartEntrySize)
	binary.LittleEndian.PutUint32(hdr[88:92], a.partitionEntryCRC)
	// Zero bytes 92..end of the header sector (already zero in our buffer
	// since we allocate img with make()).

	// HeaderCRC32 over bytes [0..92) with the CRC field zeroed.
	crc := crc32.ChecksumIEEE(hdr[:92])
	binary.LittleEndian.PutUint32(hdr[16:20], crc)
}

// uuidV4FromBytes shapes 16 raw bytes into an RFC 4122 v4 UUID
// (deterministic; not random). EDK2's GPT parsing doesn't validate
// the variant bits, but we set them anyway so tooling doesn't reject
// the image.
func uuidV4FromBytes(b []byte) [16]byte {
	var out [16]byte
	copy(out[:], b)
	out[6] = (out[6] & 0x0F) | 0x40 // version 4
	out[8] = (out[8] & 0x3F) | 0x80 // RFC 4122 variant
	return out
}

// byteReader makes a no-allocation io.Reader over a byte slice without
// pulling in bytes.NewReader (keeps the dependency tree minimal).
func byteReader(b []byte) io.Reader { return &sliceReader{b: b} }

type sliceReader struct {
	b   []byte
	off int
}

func (r *sliceReader) Read(p []byte) (int, error) {
	if r.off >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.off:])
	r.off += n
	return n, nil
}
