// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package embed_chained

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// withChainedGz swaps the package-private chainedEFIGz var for the
// duration of one test. The host build (chained_host.go) initialises
// it to nil; tests that need a non-empty embed install one here.
func withChainedGz(t *testing.T, gz []byte) {
	t.Helper()
	prev := chainedEFIGz
	chainedEFIGz = gz
	t.Cleanup(func() { chainedEFIGz = prev })
}

// gzipBytes returns gzip(in). Test helper; failure aborts the test.
func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(in); err != nil {
		t.Fatalf("gzip.Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip.Close: %v", err)
	}
	return buf.Bytes()
}

func TestDecompress_EmptyEmbed(t *testing.T) {
	withChainedGz(t, nil)
	out, err := Decompress()
	if !errors.Is(err, ErrEmptyEmbed) {
		t.Fatalf("err = %v, want ErrEmptyEmbed", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}

func TestDecompress_RoundTrip(t *testing.T) {
	want := []byte("MZ\x90\x00the rest of a PE32+ image goes here, but for the test any bytes work")
	withChainedGz(t, gzipBytes(t, want))
	got, err := Decompress()
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Decompress() = %q, want %q", got, want)
	}
}

func TestDecompress_BadGzipHeader(t *testing.T) {
	// Not a valid gzip stream — the first two bytes are gzip's magic
	// (1f 8b); replacing them with random bytes makes NewReader fail.
	withChainedGz(t, []byte{0xde, 0xad, 0xbe, 0xef})
	out, err := Decompress()
	if err == nil {
		t.Fatalf("err = nil, want gzip header error")
	}
	if errors.Is(err, ErrEmptyEmbed) {
		t.Fatalf("err = ErrEmptyEmbed, want gzip header error")
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}

func TestDecompress_TruncatedGzipBody(t *testing.T) {
	// A valid gzip header but the compressed payload is truncated
	// inside the deflate body: NewReader succeeds, io.ReadAll fails
	// (unexpected EOF or corrupted-data). Truncating only the trailer
	// is NOT enough — Go's gzip.Reader is lenient about a missing
	// CRC32+ISIZE when the deflate stream itself signalled
	// end-of-block cleanly.
	full := gzipBytes(t, []byte("a longer payload that compresses to more than its own length so truncation is obvious"))
	// Keep the 10-byte gzip header, drop most of the deflate body.
	if len(full) < 12 {
		t.Fatalf("gzipped fixture unexpectedly short (%d bytes)", len(full))
	}
	withChainedGz(t, full[:11])
	out, err := Decompress()
	if err == nil {
		t.Fatalf("err = nil, want unexpected-EOF or corrupted-data error")
	}
	if errors.Is(err, ErrEmptyEmbed) {
		t.Fatalf("err = ErrEmptyEmbed, want body error")
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}
