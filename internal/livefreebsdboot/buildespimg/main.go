// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// buildespimg — produce a bootable disk image (PMBR + GPT + FAT16
// ESP, optionally with a second FreeBSD-UFS partition).
//
// Two modes:
//
//	1. Sprint 1.2: ESP-only — single FAT16 partition containing the
//	   FreeBSD loader.efi at \EFI\BOOT\BOOTX64.EFI.
//
//	2. Sprint 2C-Integration: ESP + UFS — second partition is a
//	   freshly-minted UFS2 filesystem (via go-filesystems/ufs.Mkfs)
//	   populated from a `bootroot.tar` produced by the extractufs
//	   sibling. The bootroot tar carries /boot/kernel/kernel + the
//	   virtio kmod set + a synthetic /boot/loader.conf, ~30 MiB
//	   uncompressed. loader.efi finds the kernel via the EFI SFS that
//	   the publish-side trampoline exposes over this UFS partition.
//
// Wire layout (sectors are 512 bytes):
//
//	LBA 0          : Protective MBR (single type=0xEE partition spanning
//	                 LBA 1..end). bootsig = 0x55 0xAA at byte 510..511.
//	LBA 1          : Primary GPT header (UEFI 2.10 §5.3.2).
//	LBA 2..33      : Primary partition entry array (128 entries × 128 B).
//	LBA 64..       : ESP FAT16 image bytes (built by mformat).
//	LBA ufsStart.. : UFS2 image bytes (optional; built in-memory via
//	                 go-filesystems/ufs.Mkfs).
//	LastLBA-33..   : Backup partition entry array.
//	LastLBA        : Backup GPT header.
//
// CRC32 is the IEEE/zlib polynomial (UEFI 2.10 §5.3.1 mandates this).
//
// Usage:
//
//	# ESP-only (sprint 1.2 compat)
//	buildespimg -fat fat.img -out disk.img
//
//	# ESP + UFS (sprint 2C-Integration)
//	buildespimg -fat fat.img -ufs bootroot.tar -out disk.img
//
// The UFS partition size is the smallest power-of-two MiB that holds
// (tar payload * 4) — a generous 4× headroom for inodes, cg metadata,
// and directory overhead, floored at 64 MiB so newfs defaults work.
package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"os"
	"path"
	"sort"
	"strings"

	ufs "github.com/go-filesystems/ufs"
)

const (
	sectorSize         = 512
	gptPartEntrySize   = 128
	gptPartEntryCount  = 128
	gptPartArrayBytes  = gptPartEntrySize * gptPartEntryCount // 16384
	gptPartArraySector = gptPartArrayBytes / sectorSize       // 32
	firstUsableLBA     = 1 + 1 + gptPartArraySector           // 34
	dataStartLBA       = 64                                   // 8 KiB aligned start for the ESP payload

	// UFS partition sizing knobs. The smoke runner streams the whole
	// disk image into a single Go []byte inside tamago's 256 MiB heap
	// (plus oras's HTTPS working set), so the disk image MUST stay
	// well under ~80 MiB to leave room for the rest of the runtime.
	// With the sprint-2C-A writer cap (single-indirect, bsize=4096)
	// only files ≤ ~2 MiB land in UFS, so the actual payload after
	// the kernel-skip is ~2.5 MiB; an 8 MiB UFS comfortably holds
	// it with metadata overhead, keeping the total disk image at
	// ~25 MiB (16 MiB ESP + 8 MiB UFS + GPT overhead).
	minUFSBytes     = 8 * 1024 * 1024 // 8 MiB floor for sprint-2C-Integration
	ufsHeadroomMult = 2               // 2× tar size for fragmentation slack
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

// freebsdUFSTypeGUID = 516E7CB6-6ECF-11D6-8FF8-00022D09712B
// (FreeBSD UFS file system partition — gpt.h). Mixed-endian per RFC
// 4122; mirrors phase3_ufs_partition.go.
var freebsdUFSTypeGUID = [16]byte{
	0xB6, 0x7C, 0x6E, 0x51, // Data1 LE: 0x516E7CB6
	0xCF, 0x6E, // Data2 LE: 0x6ECF
	0xD6, 0x11, // Data3 LE: 0x11D6
	0x8F, 0xF8, // Data4[0..1]
	0x00, 0x02, 0x2D, 0x09, 0x71, 0x2B, // Data4[2..7]
}

func main() {
	fatPath := flag.String("fat", "", "path to pre-built FAT image (mformat)")
	ufsTar := flag.String("ufs", "", "optional path to bootroot.tar; when set, a 2nd UFS partition is created and populated from the tar")
	ufsSize := flag.Int64("ufs-size", 0, "optional UFS partition size in bytes; 0 = auto (max(64 MiB, 4× tar size, power-of-2 rounded))")
	outPath := flag.String("out", "", "path to write the disk image to")
	flag.Parse()
	if *fatPath == "" || *outPath == "" {
		log.Fatalf("usage: buildespimg -fat fat.img [-ufs bootroot.tar [-ufs-size N]] -out disk.img")
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
	espGUID := uuidV4FromBytes(dig[16:])

	espStartLBA := uint64(dataStartLBA)
	espEndLBA := espStartLBA + fatSectors - 1

	// UFS partition (optional).
	var (
		ufsBytes        []byte
		ufsStartLBA     uint64
		ufsEndLBA       uint64
		ufsPartGUIDVal  [16]byte
		ufsLen          int64
	)
	if *ufsTar != "" {
		// Size the UFS partition.
		tarBytes, err := os.ReadFile(*ufsTar)
		if err != nil {
			log.Fatalf("read ufs tar: %v", err)
		}
		ufsLen = *ufsSize
		if ufsLen == 0 {
			// After the writer-cap skip of the 29 MiB kernel, the
			// actual payload landing in UFS is small (~2.5 MiB of
			// .ko + loader.conf + Lua scripts). 32 MiB is plenty and
			// keeps the total disk image well under tamago's 256 MiB
			// heap reservation for the OCI streaming step.
			ufsLen = minUFSBytes
			// Tar-headroom heuristic kept for the case where the writer
			// cap is lifted in sprint 2D and the kernel actually lands.
			if want := int64(len(tarBytes)) * int64(ufsHeadroomMult); want > ufsLen {
				// Disabled-by-default growth path: only kick in if the
				// per-file cap rises. Today every >2 MiB file is
				// skipped, so this branch stays dormant.
				_ = want
			}
		}
		// Round up to 1 MiB boundary.
		const mib = int64(1024 * 1024)
		if ufsLen%mib != 0 {
			ufsLen += mib - ufsLen%mib
		}

		fmt.Fprintf(os.Stderr, "[buildespimg] sizing UFS partition: tar=%d bytes -> ufs=%d bytes (%d MiB)\n",
			len(tarBytes), ufsLen, ufsLen/(1024*1024))

		ufsBytes, err = buildUFSFromTar(tarBytes, ufsLen)
		if err != nil {
			log.Fatalf("build ufs from tar: %v", err)
		}

		// Align UFS partition start to 1 MiB for legibility.
		const alignSectors = (1 << 20) / sectorSize // 2048
		ufsStartLBA = ((espEndLBA + 1) + alignSectors - 1) / alignSectors * alignSectors
		ufsSectors := uint64(int64(len(ufsBytes)) / sectorSize)
		ufsEndLBA = ufsStartLBA + ufsSectors - 1

		ufsDig := sha256.Sum256(ufsBytes)
		ufsPartGUIDVal = uuidV4FromBytes(ufsDig[:16])
	}

	// Compute total disk size: enough sectors to cover the last
	// partition, plus the backup partition entry array (32 sectors)
	// and backup GPT header (1 sector).
	var dataEndLBA uint64
	if ufsBytes != nil {
		dataEndLBA = ufsEndLBA
	} else {
		dataEndLBA = espEndLBA
	}
	totalLBAs := dataEndLBA + 1 + uint64(gptPartArraySector) + 1
	lastLBA := totalLBAs - 1
	lastUsableLBA := lastLBA - 1 - uint64(gptPartArraySector)
	backupPartArrayLBA := lastLBA - uint64(gptPartArraySector)

	imgSize := int64(totalLBAs) * sectorSize
	img := make([]byte, imgSize)

	// ----- Protective MBR (LBA 0) -----
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
	// Entry 0: ESP.
	copy(parts[0:16], efiSystemPartitionGUID[:])
	copy(parts[16:32], espGUID[:])
	binary.LittleEndian.PutUint64(parts[32:40], espStartLBA)
	binary.LittleEndian.PutUint64(parts[40:48], espEndLBA)
	binary.LittleEndian.PutUint64(parts[48:56], 0)
	writePartName(parts[56:128], "EFI System")
	// Entry 1: UFS (optional).
	if ufsBytes != nil {
		e1 := parts[gptPartEntrySize : gptPartEntrySize*2]
		copy(e1[0:16], freebsdUFSTypeGUID[:])
		copy(e1[16:32], ufsPartGUIDVal[:])
		binary.LittleEndian.PutUint64(e1[32:40], ufsStartLBA)
		binary.LittleEndian.PutUint64(e1[40:48], ufsEndLBA)
		binary.LittleEndian.PutUint64(e1[48:56], 0)
		writePartName(e1[56:128], "FreeBSD-UFS")
	}
	partArrCRC := crc32.ChecksumIEEE(parts)

	// ----- Primary GPT header (LBA 1) -----
	primary := img[sectorSize : 2*sectorSize]
	writeGPTHeader(primary, gptHeaderArgs{
		myLBA:             1,
		alternateLBA:      lastLBA,
		firstUsableLBA:    firstUsableLBA,
		lastUsableLBA:     lastUsableLBA,
		diskGUID:          diskGUID,
		partitionEntryLBA: 2,
		partitionEntryCRC: partArrCRC,
	})

	// ----- ESP payload -----
	copy(img[espStartLBA*sectorSize:], fat)

	// ----- UFS payload -----
	if ufsBytes != nil {
		copy(img[ufsStartLBA*sectorSize:], ufsBytes)
	}

	// ----- Backup partition entry array -----
	backupParts := img[backupPartArrayLBA*sectorSize : backupPartArrayLBA*sectorSize+gptPartArrayBytes]
	copy(backupParts, parts)

	// ----- Backup GPT header (last LBA) -----
	backup := img[lastLBA*sectorSize : (lastLBA+1)*sectorSize]
	writeGPTHeader(backup, gptHeaderArgs{
		myLBA:             lastLBA,
		alternateLBA:      1,
		firstUsableLBA:    firstUsableLBA,
		lastUsableLBA:     lastUsableLBA,
		diskGUID:          diskGUID,
		partitionEntryLBA: backupPartArrayLBA,
		partitionEntryCRC: partArrCRC,
	})

	out, err := os.Create(*outPath)
	if err != nil {
		log.Fatalf("create %s: %v", *outPath, err)
	}
	defer out.Close()
	if _, err := io.Copy(out, byteReader(img)); err != nil {
		log.Fatalf("write %s: %v", *outPath, err)
	}
	if ufsBytes != nil {
		fmt.Fprintf(os.Stderr,
			"[buildespimg] wrote %s (%d bytes total; ESP %d sectors @ LBA %d; UFS %d sectors @ LBA %d)\n",
			*outPath, len(img), fatSectors, espStartLBA, len(ufsBytes)/sectorSize, ufsStartLBA)
	} else {
		fmt.Fprintf(os.Stderr,
			"[buildespimg] wrote %s (%d bytes, %d sectors, FAT %d sectors at LBA %d)\n",
			*outPath, len(img), totalLBAs, fatSectors, espStartLBA)
	}
}

// writePartName encodes name as UTF-16LE into a 72-byte slot.
func writePartName(slot []byte, name string) {
	for i, r := range name {
		if i*2+2 > len(slot) {
			break
		}
		binary.LittleEndian.PutUint16(slot[i*2:], uint16(r))
	}
}

// memWriterAt is an in-memory io.ReaderAt + io.WriterAt over a fixed
// byte slice. ufs.Mkfs uses both halves; we hold the whole partition
// in RAM during construction so we don't need any temp files.
type memWriterAt struct {
	b []byte
}

func newMemWriterAt(size int64) *memWriterAt { return &memWriterAt{b: make([]byte, size)} }

func (m *memWriterAt) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 || off+int64(len(p)) > int64(len(m.b)) {
		return 0, fmt.Errorf("memWriterAt: write at %d len %d exceeds size %d", off, len(p), len(m.b))
	}
	return copy(m.b[off:], p), nil
}

func (m *memWriterAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// buildUFSFromTar mints a fresh UFS2 image of `size` bytes, then walks
// `tarBytes` and copies every entry into the filesystem.
//
// The tar layout produced by extractufs/minimize_fixture.sh nests
// everything under `boot/`. We honour mode bits but cap them to 0o7777.
// Symlinks use the target stored in the tar header.
//
// Entries are sorted by depth (number of slashes) so parents land
// before children — bootroot.tar from `tar c boot/` happens to already
// satisfy this, but sorting makes us robust to tar producers that
// emit children first.
func buildUFSFromTar(tarBytes []byte, size int64) ([]byte, error) {
	w := newMemWriterAt(size)
	fs, err := ufs.Mkfs(w, size)
	if err != nil {
		return nil, fmt.Errorf("ufs.Mkfs(%d): %w", size, err)
	}

	// First pass: collect entries.
	type entry struct {
		hdr  *tar.Header
		body []byte
	}
	var entries []entry
	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar.Next: %w", err)
		}
		var body []byte
		if hdr.Typeflag == tar.TypeReg || hdr.Typeflag == tar.TypeRegA {
			body, err = io.ReadAll(tr)
			if err != nil {
				return nil, fmt.Errorf("read tar body for %s: %w", hdr.Name, err)
			}
		}
		entries = append(entries, entry{hdr: hdr, body: body})
	}

	// Sort by path depth ascending so parent directories land first.
	sort.SliceStable(entries, func(i, j int) bool {
		di := strings.Count(strings.Trim(entries[i].hdr.Name, "/"), "/")
		dj := strings.Count(strings.Trim(entries[j].hdr.Name, "/"), "/")
		return di < dj
	})

	mkdirCache := map[string]bool{"/": true, "": true}
	var ensureParents func(p string) error
	ensureParents = func(p string) error {
		p = "/" + strings.Trim(p, "/")
		if mkdirCache[p] {
			return nil
		}
		parent := path.Dir(p)
		if parent != "/" && parent != "." {
			if err := ensureParents(parent); err != nil {
				return err
			}
		}
		if err := fs.MkDir(p, 0o755); err != nil {
			// Tolerate "already exists" — some tars list parents and we
			// also synthesise them; both call sites converge here.
			if !strings.Contains(err.Error(), "exists") {
				return fmt.Errorf("MkDir %s: %w", p, err)
			}
		}
		mkdirCache[p] = true
		return nil
	}

	// Writer cap (sprint 2C-A): bsize=4096 + single-indirect only =>
	// max file size = (NumDirect + Nindir) * bsize = (12 + 512) * 4096
	// ≈ 2 MiB. Files above this are skipped with a clear diagnostic;
	// sprint 2D extends the writer to bsize=32768 + double-indirect
	// (the kernel is 29 MiB).
	const maxFileBytes = (12 + 512) * 4096

	var nFiles, nDirs, nLinks, nSkipped int
	var skippedLog []string
	for _, e := range entries {
		name := "/" + strings.Trim(e.hdr.Name, "/")
		if name == "/" {
			continue // root already exists
		}
		switch e.hdr.Typeflag {
		case tar.TypeDir:
			if err := ensureParents(name); err != nil {
				return nil, err
			}
			nDirs++
		case tar.TypeReg, tar.TypeRegA:
			parent := path.Dir(name)
			if err := ensureParents(parent); err != nil {
				return nil, err
			}
			perm := os.FileMode(e.hdr.Mode & 0o7777)
			if perm == 0 {
				perm = 0o644
			}
			if len(e.body) > maxFileBytes {
				skippedLog = append(skippedLog,
					fmt.Sprintf("  - %s (%d bytes > %d cap)", name, len(e.body), maxFileBytes))
				nSkipped++
				continue
			}
			if err := fs.WriteFile(name, e.body, perm); err != nil {
				return nil, fmt.Errorf("WriteFile %s (%d bytes): %w", name, len(e.body), err)
			}
			nFiles++
		case tar.TypeSymlink:
			parent := path.Dir(name)
			if err := ensureParents(parent); err != nil {
				return nil, err
			}
			if err := fs.Symlink(e.hdr.Linkname, name); err != nil {
				return nil, fmt.Errorf("Symlink %s -> %s: %w", name, e.hdr.Linkname, err)
			}
			nLinks++
		default:
			// Hardlinks, devices, fifos — skip with a notice. The
			// bootroot tar only contains regular files, dirs, symlinks.
			fmt.Fprintf(os.Stderr, "[buildespimg] skipping tar entry %s (typeflag %d unsupported)\n",
				name, e.hdr.Typeflag)
		}
	}
	fmt.Fprintf(os.Stderr, "[buildespimg] UFS populated: %d dirs, %d files, %d symlinks (%d skipped — see below)\n",
		nDirs, nFiles, nLinks, nSkipped)
	if nSkipped > 0 {
		fmt.Fprintf(os.Stderr, "[buildespimg] files skipped (over sprint-2C-A writer cap of %d bytes):\n", maxFileBytes)
		for _, s := range skippedLog {
			fmt.Fprintln(os.Stderr, s)
		}
		fmt.Fprintln(os.Stderr,
			"[buildespimg] sprint 2D: extend ufs.Mkfs to bsize=32768 + double-indirect to ship the 29 MiB FreeBSD kernel.")
	}
	return w.b, nil
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
