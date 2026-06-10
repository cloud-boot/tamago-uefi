// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package embed_initramfs

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"
)

func TestEmbedNonEmpty(t *testing.T) {
	if Size() == 0 {
		t.Fatal("embed_initramfs.Size() == 0, want > 0 (go:embed failed?)")
	}
	if Size() != len(RawBytes()) {
		t.Errorf("Size() = %d, len(RawBytes()) = %d, want equal",
			Size(), len(RawBytes()))
	}
	if Size() != len(Bytes()) {
		t.Errorf("Size() = %d, len(Bytes()) = %d, want equal",
			Size(), len(Bytes()))
	}
}

func TestEmbedGzipMagic(t *testing.T) {
	b := RawBytes()
	if len(b) < 3 {
		t.Fatalf("len(RawBytes()) = %d, want >= 3 for gzip magic check", len(b))
	}
	if b[0] != 0x1f || b[1] != 0x8b || b[2] != 0x08 {
		t.Errorf("embedded initramfs magic = %02x %02x %02x, want 1f 8b 08 (gzip)",
			b[0], b[1], b[2])
	}
}

func TestEmbedGzipDecompresses(t *testing.T) {
	r, err := gzip.NewReader(bytes.NewReader(RawBytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader on embedded initramfs: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll(gzip-decoded initramfs): %v", err)
	}
	if len(raw) == 0 {
		t.Fatal("decompressed initramfs is empty")
	}
	// cpio newc magic at offset 0 is "070701".
	const want = "070701"
	if len(raw) < len(want) {
		t.Fatalf("decompressed length %d < cpio magic length %d", len(raw), len(want))
	}
	if string(raw[:len(want)]) != want {
		t.Errorf("decompressed cpio magic = %q, want %q", string(raw[:len(want)]), want)
	}
}

// TestEmbedContainsInitELF verifies the embed is the post-M8.5
// real-binary fixture (a static aarch64 ELF /init), not the legacy
// 260-byte M8.4 shell-script fixture the kernel silently failed to
// exec. Walks the decompressed cpio newc stream looking for an
// "init" entry whose file body starts with the ELF magic
// `\x7fELF`. Fails loudly if we ever regress to a shell-script or
// other interpreted /init the kernel can't actually execve.
func TestEmbedContainsInitELF(t *testing.T) {
	r, err := gzip.NewReader(bytes.NewReader(RawBytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	// cpio newc walker. Each entry is a 110-byte ASCII header
	// followed by name (NUL-terminated, 4-byte aligned) then file
	// body (4-byte aligned). All sizes are 8-char hex strings.
	const headerLen = 110
	off := 0
	for {
		if off+headerLen > len(raw) {
			t.Fatalf("walked off end at %d without finding /init body", off)
		}
		hdr := raw[off : off+headerLen]
		if string(hdr[:6]) != "070701" {
			t.Fatalf("bad cpio magic at off=%d: %q", off, string(hdr[:6]))
		}
		fsize, err := parseCPIOHex8(hdr[54:62])
		if err != nil {
			t.Fatalf("parse filesize: %v", err)
		}
		nsize, err := parseCPIOHex8(hdr[94:102])
		if err != nil {
			t.Fatalf("parse namesize: %v", err)
		}
		nameStart := off + headerLen
		nameEnd := nameStart + int(nsize) - 1 // trim NUL
		if nameEnd > len(raw) || nameStart > nameEnd {
			t.Fatalf("name range OOB: [%d,%d) of %d", nameStart, nameEnd, len(raw))
		}
		name := string(raw[nameStart:nameEnd])
		// File body starts after name, 4-byte aligned from off.
		bodyStart := align4CPIO(nameStart + int(nsize))
		bodyEnd := bodyStart + int(fsize)
		if bodyEnd > len(raw) {
			t.Fatalf("body OOB: [%d,%d) of %d", bodyStart, bodyEnd, len(raw))
		}

		if name == "TRAILER!!!" {
			t.Fatal("walked entire cpio without seeing /init entry")
		}
		if name == "init" || name == "./init" {
			if fsize < 20 {
				t.Fatalf("/init body too small: %d bytes", fsize)
			}
			body := raw[bodyStart:bodyEnd]
			if body[0] != 0x7f || body[1] != 'E' || body[2] != 'L' || body[3] != 'F' {
				t.Fatalf("/init body magic = %02x %02x %02x %02x, want 7f 45 4c 46 (ELF); fixture regressed to script?",
					body[0], body[1], body[2], body[3])
			}
			// EI_CLASS at offset 4: 02 == ELFCLASS64.
			if body[4] != 0x02 {
				t.Errorf("/init EI_CLASS = %02x, want 02 (ELFCLASS64)", body[4])
			}
			// EI_DATA at offset 5: 01 == ELFDATA2LSB (little-endian).
			if body[5] != 0x01 {
				t.Errorf("/init EI_DATA = %02x, want 01 (ELFDATA2LSB)", body[5])
			}
			// e_machine at offset 18 (LSB): 0xB7 == EM_AARCH64.
			if body[18] != 0xB7 || body[19] != 0x00 {
				t.Errorf("/init e_machine = %02x %02x, want B7 00 (EM_AARCH64)",
					body[18], body[19])
			}
			return
		}

		off = align4CPIO(bodyEnd)
	}
}

// parseCPIOHex8 decodes an 8-char ASCII hex field as used by the
// cpio newc header (filesize, namesize, mode, …). Returns an error
// if any character is non-hex, so a corrupt header fails loudly
// rather than silently returning a partial value.
func parseCPIOHex8(b []byte) (uint32, error) {
	if len(b) != 8 {
		return 0, errCPIOLen8
	}
	var v uint32
	for _, c := range b {
		v <<= 4
		switch {
		case c >= '0' && c <= '9':
			v |= uint32(c - '0')
		case c >= 'a' && c <= 'f':
			v |= uint32(c - 'a' + 10)
		case c >= 'A' && c <= 'F':
			v |= uint32(c - 'A' + 10)
		default:
			return 0, errCPIOHex
		}
	}
	return v, nil
}

// align4CPIO rounds up to the next multiple of 4. Cpio newc pads
// both name and file body to a 4-byte boundary measured from the
// start of the archive.
func align4CPIO(n int) int { return (n + 3) &^ 3 }

var (
	errCPIOLen8 = errCPIOString("cpio hex field len != 8")
	errCPIOHex  = errCPIOString("cpio hex field non-hex char")
)

type errCPIOString string

func (e errCPIOString) Error() string { return string(e) }

// TestEmbedInitBannerString verifies the embedded /init ELF
// contains the Phase 2 Path D banner string. The banner is the
// load-bearing identification line a live boot grep matches on;
// if it disappears from the binary we either regressed the Go
// source or the build chain silently re-bottled an older binary.
// Walks the cpio newc archive, locates the /init entry, then does
// a bytes.Contains over its body. We accept any byte position
// because -ldflags='-s -w' may reorder rodata across Go versions.
func TestEmbedInitBannerString(t *testing.T) {
	r, err := gzip.NewReader(bytes.NewReader(RawBytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	body := findCPIOFileBody(t, raw, "init")
	const want = "cloud-boot/openweft Phase 2 Path D"
	if !bytes.Contains(body, []byte(want)) {
		t.Errorf("/init body missing banner substring %q; userspace /init regressed?", want)
	}
}

// TestEmbedInitBinarySizeRange asserts the /init ELF inside the
// cpio.gz is within a sane size envelope. Lower bound rules out
// the legacy ~260-byte shell-script regression; upper bound (5
// MiB) catches accidental import bloat (net/http, crypto/tls, …)
// that would push the embed past the EFI-binary inline budget.
func TestEmbedInitBinarySizeRange(t *testing.T) {
	r, err := gzip.NewReader(bytes.NewReader(RawBytes()))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer r.Close()
	raw, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read all: %v", err)
	}

	body := findCPIOFileBody(t, raw, "init")
	const (
		minBytes = 500 * 1024       // >> any shell-script fixture
		maxBytes = 5 * 1024 * 1024  // EFI-inline budget guardrail
	)
	if len(body) < minBytes || len(body) > maxBytes {
		t.Errorf("/init body size = %d bytes, want in [%d, %d]",
			len(body), minBytes, maxBytes)
	}
}

// findCPIOFileBody walks the decoded cpio newc stream and returns
// the file body for the first entry whose name matches `target`
// (or "./<target>"). Fails the test if the entry is absent. Kept
// alongside TestEmbedContainsInitELF's walker so both tests share
// the same parsing rules.
func findCPIOFileBody(t *testing.T, raw []byte, target string) []byte {
	t.Helper()
	const headerLen = 110
	off := 0
	for {
		if off+headerLen > len(raw) {
			t.Fatalf("walked off end at %d without finding %q", off, target)
		}
		hdr := raw[off : off+headerLen]
		if string(hdr[:6]) != "070701" {
			t.Fatalf("bad cpio magic at off=%d: %q", off, string(hdr[:6]))
		}
		fsize, err := parseCPIOHex8(hdr[54:62])
		if err != nil {
			t.Fatalf("parse filesize: %v", err)
		}
		nsize, err := parseCPIOHex8(hdr[94:102])
		if err != nil {
			t.Fatalf("parse namesize: %v", err)
		}
		nameStart := off + headerLen
		nameEnd := nameStart + int(nsize) - 1
		if nameEnd > len(raw) || nameStart > nameEnd {
			t.Fatalf("name range OOB: [%d,%d) of %d", nameStart, nameEnd, len(raw))
		}
		name := string(raw[nameStart:nameEnd])
		bodyStart := align4CPIO(nameStart + int(nsize))
		bodyEnd := bodyStart + int(fsize)
		if bodyEnd > len(raw) {
			t.Fatalf("body OOB: [%d,%d) of %d", bodyStart, bodyEnd, len(raw))
		}
		if name == "TRAILER!!!" {
			t.Fatalf("cpio archive exhausted without %q", target)
		}
		if name == target || name == "./"+target {
			return raw[bodyStart:bodyEnd]
		}
		off = align4CPIO(bodyEnd)
	}
}

func TestBytesIsDefensiveCopy(t *testing.T) {
	a := Bytes()
	b := Bytes()
	if len(a) == 0 || len(b) == 0 {
		t.Skip("empty embed, can't test copy semantics")
	}
	// Mutate a; b and RawBytes() must be untouched.
	orig := a[0]
	a[0] ^= 0xFF
	if b[0] == a[0] {
		t.Error("Bytes() returned aliased slice; second call mutated")
	}
	if RawBytes()[0] != orig {
		t.Error("Bytes() mutation leaked into RawBytes()")
	}
}
