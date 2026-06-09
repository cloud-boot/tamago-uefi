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
