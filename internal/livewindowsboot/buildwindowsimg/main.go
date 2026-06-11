// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// buildwindowsimg — produce a bootable Windows disk image for the
// Sprint 4+ live runner. SCAFFOLDING ONLY this sprint — the real
// pipeline is gated on three not-yet-shipped pieces:
//
//   1. A pre-built BCD store extracted from a reference Windows
//      install (Sprint 4.1 — see -bcd flag).
//   2. A real NTFS image carrying the Windows rootfs (Sprint 4 OOS;
//      go-filesystems/ntfs is NTFSIMG1 synthetic format, not real
//      NTFS, so we can't mint a writable rootfs Go-side yet).
//   3. NTFS DXE driver injection into OVMF (Sprint 4.3 — or a Go
//      port via go-filesystems/ntfs once it grows real on-disk
//      support).
//
// What this tool DOES today: lay down the wire layout for a sprint-4.1
// PoC — PMBR + GPT with three Windows-typed partitions, each populated
// only if a corresponding raw bytes file is supplied:
//
//   Partition 1: Microsoft Reserved (MSR), type
//                E3C9E316-0B5C-4DB8-817D-F92DF00215AE.
//                Always present, 16 MiB, zero-filled (Microsoft setup
//                creates this and modern Windows installs expect it).
//
//   Partition 2: EFI System Partition (FAT32, type
//                C12A7328-F81F-11D2-BA4B-00A0C93EC93B), populated from
//                the -fat32 input. Contains \EFI\Microsoft\Boot\
//                bootmgfw.efi + BCD.
//
//   Partition 3: Microsoft Basic Data (MBD, type
//                EBD0A0A2-B9E5-4433-87C0-68B6B72699C7), populated from
//                the -ntfs input bytes (when supplied). This is where
//                the C:\ NTFS volume lives in a real Windows install.
//
// Usage (sprint 4.1 PoC — not yet wired into run.sh):
//
//	# scaffold mode (default): build an MSR-only image for sanity
//	buildwindowsimg -out disk.img
//
//	# ESP populated, no NTFS rootfs (will reach bootmgfw, fail at BCD)
//	buildwindowsimg -fat32 esp.img -out disk.img
//
//	# ESP + NTFS rootfs (sprint 4.3 target — needs real NTFS bytes)
//	buildwindowsimg -fat32 esp.img -ntfs cwin.img -out disk.img
//
// The CRC32 polynomial is IEEE/zlib per UEFI 2.10 §5.3.1.
//
// Sprint 4 ARCHITECTURAL NOTE: every wire-format constant here is
// derived from publicly-documented UEFI 2.10 / Microsoft GPT
// references and the FreeBSD buildespimg sibling. No
// Microsoft-proprietary bytes are embedded.
package main

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"os"
)

const (
	sectorSize         = 512
	gptPartEntrySize   = 128
	gptPartEntryCount  = 128
	gptPartArrayBytes  = gptPartEntrySize * gptPartEntryCount // 16384
	gptPartArraySector = gptPartArrayBytes / sectorSize       // 32
	firstUsableLBA     = 1 + 1 + gptPartArraySector           // 34
	dataStartLBA       = 64                                   // 8 KiB aligned start
	msrSizeMiB         = 16                                   // Microsoft Reserved partition (always 16 MiB)
)

// GPT partition type GUIDs, stored in mixed-endian per RFC 4122 /
// UEFI 2.10 §5.3.3 (Data1/2/3 little-endian, Data4 raw).
//
// MSR:  E3C9E316-0B5C-4DB8-817D-F92DF00215AE
// ESP:  C12A7328-F81F-11D2-BA4B-00A0C93EC93B
// MBD:  EBD0A0A2-B9E5-4433-87C0-68B6B72699C7
var (
	gptTypeMSR = [16]byte{
		0x16, 0xE3, 0xC9, 0xE3,
		0x5C, 0x0B,
		0xB8, 0x4D,
		0x81, 0x7D,
		0xF9, 0x2D, 0xF0, 0x02, 0x15, 0xAE,
	}
	gptTypeESP = [16]byte{
		0x28, 0x73, 0x2A, 0xC1,
		0x1F, 0xF8,
		0xD2, 0x11,
		0xBA, 0x4B,
		0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B,
	}
	gptTypeMBD = [16]byte{
		0xA2, 0xA0, 0xD0, 0xEB,
		0xE5, 0xB9,
		0x33, 0x44,
		0x87, 0xC0,
		0x68, 0xB6, 0xB7, 0x26, 0x99, 0xC7,
	}
)

type partition struct {
	typeGUID [16]byte
	name     [72]byte // UCS-2LE, 36 chars max
	startLBA uint64
	endLBA   uint64
	bytes    []byte // payload (nil = zero-fill)
}

func setPartName(p *partition, name string) {
	// UCS-2LE up to 36 chars.
	for i := 0; i < len(name) && i < 36; i++ {
		p.name[i*2] = name[i]
	}
}

func randGUID() [16]byte {
	var g [16]byte
	if _, err := io.ReadFull(rand.Reader, g[:]); err != nil {
		panic(err)
	}
	// Mark as v4 random per RFC 4122.
	g[7] = (g[7] & 0x0F) | 0x40
	g[8] = (g[8] & 0x3F) | 0x80
	return g
}

func main() {
	var (
		fat32In = flag.String("fat32", "", "Path to a FAT32 image to use as the ESP partition (optional; empty = zero-filled 64 MiB ESP)")
		ntfsIn  = flag.String("ntfs", "", "Path to NTFS bytes for the C: volume (sprint 4.3 — not yet read by anything Go-side)")
		bcdIn   = flag.String("bcd", "", "Path to a pre-built BCD store to inject into the ESP (sprint 4.1 — informational only this revision)")
		outPath = flag.String("out", "", "Path to write the resulting disk image")
		espMiB  = flag.Int("esp-mib", 64, "ESP partition size in MiB when -fat32 is not supplied")
	)
	flag.Parse()
	if *outPath == "" {
		fatal("missing -out")
	}
	if *bcdIn != "" {
		// Sprint 4.1 surface: we accept the flag so the runner script
		// can pass through a path, but we don't yet rewrite the FAT32
		// image to install BCD at the canonical
		// \EFI\Microsoft\Boot\BCD path. That requires either an mtools
		// pre-pass (host) or a FAT32 mutator in Go.
		fmt.Fprintf(os.Stderr, "buildwindowsimg: -bcd accepted for forward-compat (sprint 4.1 will wire FAT32 injection); not modifying ESP this revision\n")
	}

	// Build partitions.
	var parts []partition

	msrSectors := uint64(msrSizeMiB) * 1024 * 1024 / sectorSize
	msr := partition{typeGUID: gptTypeMSR, startLBA: dataStartLBA, endLBA: dataStartLBA + msrSectors - 1}
	setPartName(&msr, "Microsoft reserved partition")
	parts = append(parts, msr)

	var espBytes []byte
	espSectors := uint64(*espMiB) * 1024 * 1024 / sectorSize
	if *fat32In != "" {
		b, err := os.ReadFile(*fat32In)
		if err != nil {
			fatal("read -fat32: %v", err)
		}
		espBytes = b
		// Round up to sector multiple.
		if rem := len(espBytes) % sectorSize; rem != 0 {
			pad := make([]byte, sectorSize-rem)
			espBytes = append(espBytes, pad...)
		}
		espSectors = uint64(len(espBytes)) / sectorSize
	}
	espStart := parts[len(parts)-1].endLBA + 1
	esp := partition{typeGUID: gptTypeESP, startLBA: espStart, endLBA: espStart + espSectors - 1, bytes: espBytes}
	setPartName(&esp, "EFI system partition")
	parts = append(parts, esp)

	if *ntfsIn != "" {
		b, err := os.ReadFile(*ntfsIn)
		if err != nil {
			fatal("read -ntfs: %v", err)
		}
		if rem := len(b) % sectorSize; rem != 0 {
			pad := make([]byte, sectorSize-rem)
			b = append(b, pad...)
		}
		mbdStart := parts[len(parts)-1].endLBA + 1
		mbdSectors := uint64(len(b)) / sectorSize
		mbd := partition{typeGUID: gptTypeMBD, startLBA: mbdStart, endLBA: mbdStart + mbdSectors - 1, bytes: b}
		setPartName(&mbd, "Basic data partition")
		parts = append(parts, mbd)
	}

	if err := writeImage(*outPath, parts); err != nil {
		fatal("write image: %v", err)
	}
	espTag := " + ESP(zero)"
	if *fat32In != "" {
		espTag = " + ESP(populated)"
	}
	mbdTag := ""
	if *ntfsIn != "" {
		mbdTag = " + MBD(NTFS-bytes)"
	}
	fmt.Fprintf(os.Stderr, "buildwindowsimg: wrote %s (%d partitions: MSR%s%s)\n",
		*outPath, len(parts), espTag, mbdTag)
}

func writeImage(outPath string, parts []partition) error {
	if len(parts) == 0 {
		return errors.New("no partitions")
	}
	// Total size = lastPart.endLBA + 1 + GPT-backup region (33 sectors).
	totalSectors := parts[len(parts)-1].endLBA + 1 + 33
	totalBytes := int(totalSectors) * sectorSize

	img := make([]byte, totalBytes)

	// Protective MBR at LBA 0.
	mbr := img[0:sectorSize]
	// type=0xEE partition spanning LBA 1..end.
	mbr[446+0] = 0x00 // boot indicator
	mbr[446+1] = 0x00 // starting head
	mbr[446+2] = 0x02 // starting sector
	mbr[446+3] = 0x00 // starting cylinder
	mbr[446+4] = 0xEE // type GPT-protective
	mbr[446+5] = 0xFF
	mbr[446+6] = 0xFF
	mbr[446+7] = 0xFF
	binary.LittleEndian.PutUint32(mbr[446+8:446+12], 1)
	// size = min(0xFFFFFFFF, totalSectors-1)
	sz := uint64(totalSectors - 1)
	if sz > 0xFFFFFFFF {
		sz = 0xFFFFFFFF
	}
	binary.LittleEndian.PutUint32(mbr[446+12:446+16], uint32(sz))
	mbr[510] = 0x55
	mbr[511] = 0xAA

	// Partition entry array at LBA 2.
	partArrayLBA := uint64(2)
	partArray := img[int(partArrayLBA)*sectorSize : int(partArrayLBA)*sectorSize+gptPartArrayBytes]
	for i, p := range parts {
		entry := partArray[i*gptPartEntrySize : (i+1)*gptPartEntrySize]
		copy(entry[0:16], p.typeGUID[:])
		uniq := randGUID()
		copy(entry[16:32], uniq[:])
		binary.LittleEndian.PutUint64(entry[32:40], p.startLBA)
		binary.LittleEndian.PutUint64(entry[40:48], p.endLBA)
		// attrs left zero
		copy(entry[56:128], p.name[:])
	}
	partArrayCRC := crc32.ChecksumIEEE(partArray)

	// Primary GPT header at LBA 1.
	primaryGPT := img[sectorSize : 2*sectorSize]
	writeGPTHeader(primaryGPT, &gptHeaderParams{
		currentLBA:    1,
		backupLBA:     totalSectors - 1,
		firstUsable:   firstUsableLBA,
		lastUsable:    totalSectors - 1 - 33,
		partEntryLBA:  partArrayLBA,
		partEntryNum:  uint32(len(parts)), // count the populated entries; spare entries are zero-typed so CRC is over the whole 16 KiB array
		partEntrySize: gptPartEntrySize,
		partArrayCRC:  partArrayCRC,
		diskGUID:      randGUID(),
	})
	// Per UEFI 2.10 §5.3.2 NumberOfPartitionEntries is the SIZE of the
	// array (typically 128), and CRC32 is over that whole array. Use
	// 128 here for compatibility with PartitionDxe.
	binary.LittleEndian.PutUint32(primaryGPT[80:84], gptPartEntryCount)
	fixGPTCRC(primaryGPT)

	// Copy partition array + populate partition bytes.
	for _, p := range parts {
		if p.bytes == nil {
			continue
		}
		off := int(p.startLBA) * sectorSize
		copy(img[off:], p.bytes)
	}

	// Backup partition array at totalSectors-33.
	backupPartLBA := totalSectors - 33
	copy(img[int(backupPartLBA)*sectorSize:int(backupPartLBA)*sectorSize+gptPartArrayBytes], partArray)

	// Backup GPT header at last LBA.
	backupGPT := img[(totalSectors-1)*sectorSize : totalSectors*sectorSize]
	writeGPTHeader(backupGPT, &gptHeaderParams{
		currentLBA:    totalSectors - 1,
		backupLBA:     1,
		firstUsable:   firstUsableLBA,
		lastUsable:    totalSectors - 1 - 33,
		partEntryLBA:  backupPartLBA,
		partEntryNum:  gptPartEntryCount,
		partEntrySize: gptPartEntrySize,
		partArrayCRC:  partArrayCRC,
		diskGUID:      [16]byte{}, // copy from primary below
	})
	copy(backupGPT[56:72], primaryGPT[56:72]) // DiskGUID
	fixGPTCRC(backupGPT)

	return os.WriteFile(outPath, img, 0o644)
}

type gptHeaderParams struct {
	currentLBA    uint64
	backupLBA     uint64
	firstUsable   uint64
	lastUsable    uint64
	partEntryLBA  uint64
	partEntryNum  uint32
	partEntrySize uint32
	partArrayCRC  uint32
	diskGUID      [16]byte
}

func writeGPTHeader(buf []byte, p *gptHeaderParams) {
	copy(buf[0:8], []byte("EFI PART"))
	binary.LittleEndian.PutUint32(buf[8:12], 0x00010000) // Revision 1.0
	binary.LittleEndian.PutUint32(buf[12:16], 92)         // HeaderSize
	// HeaderCRC at 16:20 (set later by fixGPTCRC)
	// Reserved 20:24
	binary.LittleEndian.PutUint64(buf[24:32], p.currentLBA)
	binary.LittleEndian.PutUint64(buf[32:40], p.backupLBA)
	binary.LittleEndian.PutUint64(buf[40:48], p.firstUsable)
	binary.LittleEndian.PutUint64(buf[48:56], p.lastUsable)
	copy(buf[56:72], p.diskGUID[:])
	binary.LittleEndian.PutUint64(buf[72:80], p.partEntryLBA)
	binary.LittleEndian.PutUint32(buf[80:84], p.partEntryNum)
	binary.LittleEndian.PutUint32(buf[84:88], p.partEntrySize)
	binary.LittleEndian.PutUint32(buf[88:92], p.partArrayCRC)
}

func fixGPTCRC(buf []byte) {
	// Zero HeaderCRC, compute over first 92 bytes.
	binary.LittleEndian.PutUint32(buf[16:20], 0)
	crc := crc32.ChecksumIEEE(buf[:92])
	binary.LittleEndian.PutUint32(buf[16:20], crc)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "buildwindowsimg: "+format+"\n", args...)
	os.Exit(1)
}
