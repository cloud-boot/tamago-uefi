// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// chainedtinyZgen — hand-rolled minimal PE32+/EFI image generator.
// Emits a ~1-section .text PE32+ that EDK2's PeCoffLib.c will accept
// as an EFI_APPLICATION. The entry point is `xor eax,eax; ret` —
// returns EFI_SUCCESS (0) directly through the firmware's
// LoadImage+StartImage path with no runtime, no allocator, nothing.
//
// Used by the M6.2 de-risk experiment to find the smallest possible
// PE32+ amd64 OVMF will load. If even THIS image triggers the
// CpuDxe.dll +0x110C #GP at parent->LoadImage time, the M6.2
// compressor path is a dead end for amd64; if it loads cleanly,
// the threshold is somewhere above this size.
//
// Output: BOOTX64-CHAINEDTINYZ.EFI in the cwd (or via -o).
//
// Build:  go build -o chainedtinyZgen ./cmd/chainedtinyZgen
// Run:    ./chainedtinyZgen -o BOOTX64-CHAINEDTINYZ.EFI
//
// PE32+ layout produced (file alignment 0x200, section alignment
// 0x1000, all per UEFI PI 1.7 / Microsoft PE spec):
//
//	0x000 DOS header (64 B)
//	0x040 PE signature "PE\0\0" (4 B)
//	0x044 IMAGE_FILE_HEADER (20 B)
//	0x058 IMAGE_OPTIONAL_HEADER64 (240 B) — incl. 16 data dirs
//	0x148 IMAGE_SECTION_HEADER for .text (40 B)
//	0x200 .text payload (4 B: 31 C0 C3, padded with 0xCC)
//
// File size: 0x400 (1024 B) — one .text section padded to file
// alignment 0x200, plus a header sector also padded to 0x200.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"os"
)

const (
	fileAlign    = 0x200
	sectionAlign = 0x1000
	imageBase    = uint64(0x140000000)

	// Total image laid out as: header sector (0x200) + .text sector
	// (0x200) = 0x400 file bytes. In-memory it occupies
	// sectionAlign (0x1000) for headers + sectionAlign (0x1000) for
	// .text = 0x2000.
	headersSize = fileAlign      // 0x200
	textOffset  = fileAlign      // .text raw data at file offset 0x200
	textRVA     = sectionAlign   // .text RVA = 0x1000 (one full section align past base)
	sizeOfImage = 2 * sectionAlign // 0x2000

	// PE constants we hard-wire.
	machineAMD64           = 0x8664
	subsystemEFIApplication = 10
	magicPE32Plus          = 0x20b

	// IMAGE_FILE_* characteristics.
	fileCharExecutableImage = 0x0002
	fileCharLargeAddrAware  = 0x0020
	fileCharDebugStripped   = 0x0200

	// IMAGE_SCN_* characteristics for .text.
	scnCntCode      = 0x00000020
	scnMemExecute   = 0x20000000
	scnMemRead      = 0x40000000
)

func main() {
	out := flag.String("o", "BOOTX64-CHAINEDTINYZ.EFI", "output PE32+/EFI file")
	padTo := flag.Int("pad-to", 0, "if >0, pad the .text section so the final file is at least this many bytes (must be a multiple of fileAlign=0x200)")
	flag.Parse()

	// Determine the .text raw size (default = 1 sector = fileAlign).
	// If -pad-to is set, grow .text raw to fill the requested file
	// size minus the header sector. The .text content stays 3 bytes
	// (xor eax,eax; ret) followed by 0xCC pad fill.
	textRaw := fileAlign
	if *padTo > 0 {
		want := *padTo - fileAlign // bytes of .text we need
		if want < fileAlign {
			want = fileAlign
		}
		if want%fileAlign != 0 {
			fmt.Fprintln(os.Stderr, "pad-to must be a multiple of fileAlign=0x200")
			os.Exit(2)
		}
		textRaw = want
	}

	totalFileSize := fileAlign + textRaw
	textVirt := alignUp(textRaw, sectionAlign)
	totalImgSize := sectionAlign + textVirt

	buf := make([]byte, totalFileSize) // zero-filled

	// --- DOS header (64 B) -------------------------------------------------
	// e_magic = "MZ"
	buf[0] = 'M'
	buf[1] = 'Z'
	// e_lfanew @ 0x3C → PE signature offset
	binary.LittleEndian.PutUint32(buf[0x3C:], 0x40)

	// --- PE signature -----------------------------------------------------
	copy(buf[0x40:], []byte{'P', 'E', 0, 0})

	// --- IMAGE_FILE_HEADER @ 0x44 (20 B) ----------------------------------
	off := 0x44
	binary.LittleEndian.PutUint16(buf[off+0:], machineAMD64)         // Machine
	binary.LittleEndian.PutUint16(buf[off+2:], 1)                    // NumberOfSections
	binary.LittleEndian.PutUint32(buf[off+4:], 0)                    // TimeDateStamp
	binary.LittleEndian.PutUint32(buf[off+8:], 0)                    // PointerToSymbolTable
	binary.LittleEndian.PutUint32(buf[off+12:], 0)                   // NumberOfSymbols
	binary.LittleEndian.PutUint16(buf[off+16:], 240)                 // SizeOfOptionalHeader (PE32+ standard)
	binary.LittleEndian.PutUint16(buf[off+18:],
		fileCharExecutableImage|fileCharLargeAddrAware|fileCharDebugStripped) // Characteristics

	// --- IMAGE_OPTIONAL_HEADER64 @ 0x58 (240 B) ---------------------------
	off = 0x58
	binary.LittleEndian.PutUint16(buf[off+0:], magicPE32Plus)        // Magic
	buf[off+2] = 14                                                   // MajorLinkerVersion
	buf[off+3] = 0                                                    // MinorLinkerVersion
	binary.LittleEndian.PutUint32(buf[off+4:], uint32(textRaw))      // SizeOfCode (padded sector(s))
	binary.LittleEndian.PutUint32(buf[off+8:], 0)                    // SizeOfInitializedData
	binary.LittleEndian.PutUint32(buf[off+12:], 0)                   // SizeOfUninitializedData
	binary.LittleEndian.PutUint32(buf[off+16:], textRVA)             // AddressOfEntryPoint (start of .text RVA)
	binary.LittleEndian.PutUint32(buf[off+20:], textRVA)             // BaseOfCode
	binary.LittleEndian.PutUint64(buf[off+24:], imageBase)           // ImageBase
	binary.LittleEndian.PutUint32(buf[off+32:], sectionAlign)        // SectionAlignment
	binary.LittleEndian.PutUint32(buf[off+36:], fileAlign)           // FileAlignment
	binary.LittleEndian.PutUint16(buf[off+40:], 4)                   // MajorOperatingSystemVersion
	binary.LittleEndian.PutUint16(buf[off+42:], 0)                   // MinorOperatingSystemVersion
	binary.LittleEndian.PutUint16(buf[off+44:], 0)                   // MajorImageVersion
	binary.LittleEndian.PutUint16(buf[off+46:], 0)                   // MinorImageVersion
	binary.LittleEndian.PutUint16(buf[off+48:], 4)                   // MajorSubsystemVersion
	binary.LittleEndian.PutUint16(buf[off+50:], 0)                   // MinorSubsystemVersion
	binary.LittleEndian.PutUint32(buf[off+52:], 0)                   // Win32VersionValue
	binary.LittleEndian.PutUint32(buf[off+56:], uint32(totalImgSize)) // SizeOfImage
	binary.LittleEndian.PutUint32(buf[off+60:], headersSize)         // SizeOfHeaders
	binary.LittleEndian.PutUint32(buf[off+64:], 0)                   // CheckSum (firmware doesn't verify)
	binary.LittleEndian.PutUint16(buf[off+68:], subsystemEFIApplication) // Subsystem
	binary.LittleEndian.PutUint16(buf[off+70:], 0)                   // DllCharacteristics
	binary.LittleEndian.PutUint64(buf[off+72:], 0x100000)            // SizeOfStackReserve
	binary.LittleEndian.PutUint64(buf[off+80:], 0x1000)              // SizeOfStackCommit
	binary.LittleEndian.PutUint64(buf[off+88:], 0x100000)            // SizeOfHeapReserve
	binary.LittleEndian.PutUint64(buf[off+96:], 0x1000)              // SizeOfHeapCommit
	binary.LittleEndian.PutUint32(buf[off+104:], 0)                  // LoaderFlags
	binary.LittleEndian.PutUint32(buf[off+108:], 16)                 // NumberOfRvaAndSizes
	// 16 data directory entries (8 B each = 128 B), all zero. They
	// occupy buf[off+112 : off+240] and were already zero-initialized.

	// --- IMAGE_SECTION_HEADER for .text @ 0x148 (40 B) --------------------
	off = 0x148
	copy(buf[off+0:off+8], []byte(".text\x00\x00\x00"))               // Name (8 B, NUL-padded)
	binary.LittleEndian.PutUint32(buf[off+8:], uint32(textRaw))      // VirtualSize (rounded up to sectionAlign in-memory)
	binary.LittleEndian.PutUint32(buf[off+12:], textRVA)             // VirtualAddress
	binary.LittleEndian.PutUint32(buf[off+16:], uint32(textRaw))     // SizeOfRawData
	binary.LittleEndian.PutUint32(buf[off+20:], textOffset)          // PointerToRawData
	binary.LittleEndian.PutUint32(buf[off+24:], 0)                   // PointerToRelocations
	binary.LittleEndian.PutUint32(buf[off+28:], 0)                   // PointerToLinenumbers
	binary.LittleEndian.PutUint16(buf[off+32:], 0)                   // NumberOfRelocations
	binary.LittleEndian.PutUint16(buf[off+34:], 0)                   // NumberOfLinenumbers
	binary.LittleEndian.PutUint32(buf[off+36:], scnCntCode|scnMemExecute|scnMemRead) // Characteristics

	// --- .text payload @ 0x200 -------------------------------------------
	// xor eax, eax     ; 31 C0   (EFI_STATUS rax = EFI_SUCCESS)
	// ret              ; C3      (return to gBS->StartImage caller)
	// Fill the rest of the section with 0xCC (int3) so any stray IP
	// lands in a clean trap, not garbage. For padded variants this
	// is what grows the file — kilobytes / megabytes of 0xCC after a
	// 3-byte entry routine.
	for i := textOffset; i < textOffset+textRaw; i++ {
		buf[i] = 0xCC
	}
	buf[textOffset+0] = 0x31
	buf[textOffset+1] = 0xC0
	buf[textOffset+2] = 0xC3

	if err := os.WriteFile(*out, buf, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "write:", err)
		os.Exit(1)
	}
	fmt.Printf("[chainedtinyZgen] wrote %s (%d bytes)\n", *out, len(buf))
}

func alignUp(n, a int) int {
	if n%a == 0 {
		return n
	}
	return n + (a - n%a)
}
