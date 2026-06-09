// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package embed_chained_tiny

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

// withVariantGz swaps one of the package-private *Gz vars for the
// duration of one test. The host build (tiny_host.go) initialises
// all six to nil; tests that need a non-empty embed install one here.
func withVariantGz(t *testing.T, v string, gz []byte) {
	t.Helper()
	switch v {
	case VariantA:
		prev := tinyAGz
		tinyAGz = gz
		t.Cleanup(func() { tinyAGz = prev })
	case VariantB:
		prev := tinyBGz
		tinyBGz = gz
		t.Cleanup(func() { tinyBGz = prev })
	case VariantC:
		prev := tinyCGz
		tinyCGz = gz
		t.Cleanup(func() { tinyCGz = prev })
	case VariantZ:
		prev := tinyZGz
		tinyZGz = gz
		t.Cleanup(func() { tinyZGz = prev })
	case VariantZ64K:
		prev := tinyZ64KGz
		tinyZ64KGz = gz
		t.Cleanup(func() { tinyZ64KGz = prev })
	case VariantZ1M:
		prev := tinyZ1MGz
		tinyZ1MGz = gz
		t.Cleanup(func() { tinyZ1MGz = prev })
	case VariantZ2M:
		prev := tinyZ2MGz
		tinyZ2MGz = gz
		t.Cleanup(func() { tinyZ2MGz = prev })
	default:
		t.Fatalf("withVariantGz: unknown variant %q", v)
	}
}

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

func TestVariants_Ordering(t *testing.T) {
	got := Variants()
	want := []string{VariantA, VariantB, VariantC, VariantZ2M, VariantZ1M, VariantZ64K, VariantZ}
	if len(got) != len(want) {
		t.Fatalf("len(Variants()) = %d, want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("Variants()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestDecompress_UnknownVariant(t *testing.T) {
	out, err := Decompress("nope")
	if !errors.Is(err, ErrUnknownVariant) {
		t.Fatalf("err = %v, want ErrUnknownVariant", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}

func TestDecompress_EveryVariant_EmptyEmbed(t *testing.T) {
	// All six embed slots start nil on host builds; every variant
	// should produce ErrEmptyEmbed without an install.
	for _, v := range Variants() {
		t.Run(v, func(t *testing.T) {
			out, err := Decompress(v)
			if !errors.Is(err, ErrEmptyEmbed) {
				t.Fatalf("err = %v, want ErrEmptyEmbed", err)
			}
			if out != nil {
				t.Fatalf("out = %v, want nil", out)
			}
		})
	}
}

func TestDecompress_EveryVariant_RoundTrip(t *testing.T) {
	// Each variant slot independently round-trips via gzip.
	for _, v := range Variants() {
		t.Run(v, func(t *testing.T) {
			want := []byte("MZ\x90\x00payload for variant " + v)
			withVariantGz(t, v, gzipBytes(t, want))
			got, err := Decompress(v)
			if err != nil {
				t.Fatalf("Decompress(%q): %v", v, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("Decompress(%q) = %q, want %q", v, got, want)
			}
		})
	}
}

func TestDecompress_BadGzipHeader(t *testing.T) {
	withVariantGz(t, VariantZ, []byte{0xde, 0xad, 0xbe, 0xef})
	out, err := Decompress(VariantZ)
	if err == nil {
		t.Fatalf("err = nil, want gzip header error")
	}
	if errors.Is(err, ErrEmptyEmbed) || errors.Is(err, ErrUnknownVariant) {
		t.Fatalf("err = %v, want gzip header error", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}

func TestDecompress_TruncatedGzipBody(t *testing.T) {
	full := gzipBytes(t, []byte("a longer payload that compresses to more than its own length so truncation is obvious"))
	if len(full) < 12 {
		t.Fatalf("gzipped fixture unexpectedly short (%d bytes)", len(full))
	}
	withVariantGz(t, VariantC, full[:11])
	out, err := Decompress(VariantC)
	if err == nil {
		t.Fatalf("err = nil, want unexpected-EOF or corrupted-data error")
	}
	if errors.Is(err, ErrEmptyEmbed) || errors.Is(err, ErrUnknownVariant) {
		t.Fatalf("err = %v, want body error", err)
	}
	if out != nil {
		t.Fatalf("out = %v, want nil", out)
	}
}
