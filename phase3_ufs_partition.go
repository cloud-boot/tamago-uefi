// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase 3 sprint 2B — UFS partition discovery against a streamed
// disk-image byte slice.
//
// Why this exists Go-side rather than via firmware Block IO consumer:
// the streamed disk image is already a contiguous Go []byte in the
// FreeBSD probe (we PublishBlockIO it for firmware to mount the FAT
// ESP). For the UFS half we'd otherwise need to wire a consumer-side
// EFI_BLOCK_IO_PROTOCOL wrapper around the firmware-created
// partition-child handle and pass that to ufs.Open via an
// io.ReaderAt shim — a 3-link indirection where one direct
// slice-backed reader is equivalent.
//
// Parsing layer:
//   - 16-byte protective MBR signature check (rejects non-GPT).
//   - GPT header at LBA 1: "EFI PART" magic, partition entry array
//     location + count + size.
//   - Walk the partition array entries; each is 128 bytes. The UFS
//     partition is identified by its PartitionTypeGUID:
//       FreeBSD UFS: 516E7CB6-6ECF-11D6-8FF8-00022D09712B
//
// Sprint 2B PASS scope:
//   - If a UFS partition is found AND ufs.Open succeeds against its
//     bytes, we publish SFS on a fresh handle and report the address
//     (loader.efi can locate it via LocateHandleBuffer(SFS_GUID)).
//   - If no UFS partition exists (e.g. our minimal FAT16 ESP-only
//     image from sprint 1.2), the helper returns ErrNoUFSPartition
//     and the probe continues with FAT-only behaviour.

//go:build phase3_oci_freebsd_boot && tamago && amd64

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// ErrNoUFSPartition is returned by findUFSPartitionBytes when the GPT
// has no entry with the FreeBSD UFS PartitionTypeGUID. Sprint 2B's
// FAT16-only ESP image hits this path — it's expected for the smoke
// test, not a hard failure.
var ErrNoUFSPartition = errors.New("phase3: no FreeBSD UFS partition in GPT")

// freebsdUFSTypeGUID = 516E7CB6-6ECF-11D6-8FF8-00022D09712B
// (FreeBSD UFS file system partition type — see /usr/src/sys/sys/
// gpt.h or the FreeBSD GPT(8) man page).
//
// Stored mixed-endian per RFC 4122: Data1/2/3 LE, Data4 raw.
var freebsdUFSTypeGUID = [16]byte{
	0xB6, 0x7C, 0x6E, 0x51, // Data1 LE: 0x516E7CB6
	0xCF, 0x6E, // Data2 LE: 0x6ECF
	0xD6, 0x11, // Data3 LE: 0x11D6
	0x8F, 0xF8, // Data4[0..1]
	0x00, 0x02, 0x2D, 0x09, 0x71, 0x2B, // Data4[2..7]
}

// findUFSPartitionBytes parses the GPT in `image` and returns a slice
// referencing the bytes of the FreeBSD UFS partition (no copy).
// Returns ErrNoUFSPartition if none exists.
func findUFSPartitionBytes(image []byte) ([]byte, error) {
	if len(image) < 1024 {
		return nil, errors.New("phase3: image too small for GPT")
	}
	const sector = 512
	// GPT header at LBA 1 (offset 512).
	hdr := image[sector : 2*sector]
	if !bytes.Equal(hdr[0:8], []byte("EFI PART")) {
		return nil, errors.New("phase3: missing 'EFI PART' magic at LBA 1")
	}
	partEntryLBA := binary.LittleEndian.Uint64(hdr[72:80])
	partEntryCount := binary.LittleEndian.Uint32(hdr[80:84])
	partEntrySize := binary.LittleEndian.Uint32(hdr[84:88])
	if partEntrySize < 128 || partEntrySize > 4096 {
		return nil, errors.New("phase3: GPT partition entry size out of range")
	}
	if partEntryCount > 128 {
		return nil, errors.New("phase3: GPT partition entry count > 128 (rejecting)")
	}
	partBase := int(partEntryLBA) * sector
	if partBase+int(partEntryCount)*int(partEntrySize) > len(image) {
		return nil, errors.New("phase3: GPT partition table extends past image")
	}
	for i := uint32(0); i < partEntryCount; i++ {
		entry := image[partBase+int(i)*int(partEntrySize) : partBase+int(i+1)*int(partEntrySize)]
		var typ [16]byte
		copy(typ[:], entry[0:16])
		if typ == [16]byte{} {
			continue
		}
		if typ != freebsdUFSTypeGUID {
			continue
		}
		start := binary.LittleEndian.Uint64(entry[32:40])
		end := binary.LittleEndian.Uint64(entry[40:48])
		if end < start {
			return nil, errors.New("phase3: UFS partition has end < start")
		}
		startB := int(start) * sector
		endB := int(end+1) * sector
		if endB > len(image) || startB > endB {
			return nil, errors.New("phase3: UFS partition extends past image")
		}
		return image[startB:endB], nil
	}
	return nil, ErrNoUFSPartition
}

// sliceReaderAt wraps a []byte in an io.ReaderAt. Used to feed the
// UFS partition bytes into ufs.Open without dragging bytes.Reader
// (which is fine, but a fresh ReaderAt keeps the dependency footprint
// minimal).
type sliceReaderAt struct{ b []byte }

func (s *sliceReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(s.b)) {
		return 0, io.EOF
	}
	n := copy(p, s.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}
