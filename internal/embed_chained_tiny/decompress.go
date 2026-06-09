// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Decompress helpers for the four M6.2 de-risk variants. Mirror of
// internal/embed_chained/decompress.go, but exposes a per-variant
// API since the M6.2 probe iterates through every variant in one
// boot.
//
// The gzip wrapper is the same shape as embed_chained (allocate, copy,
// inflate at call time). Variant Z (the hand-rolled 1-KiB PE32+) is
// also gzipped for symmetry — gzip-of-1KiB is ~50 B overhead, not
// worth a special-case un-gzipped path.

package embed_chained_tiny

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

// Variant names matching the cmd/chainedtiny<V> dirs.
const (
	VariantA    = "A"
	VariantB    = "B"
	VariantC    = "C"
	VariantZ    = "Z"
	VariantZ64K = "Z64K"
	VariantZ1M  = "Z1M"
	VariantZ2M  = "Z2M"
)

// ErrEmptyEmbed is returned when the requested variant slot is empty
// (host build or a missing Taskfile stage).
var ErrEmptyEmbed = errors.New("embed_chained_tiny: variant slot is empty")

// ErrUnknownVariant is returned by Decompress for unknown variant
// keys.
var ErrUnknownVariant = errors.New("embed_chained_tiny: unknown variant")

// Variants returns the list of variant keys in test order. Order is
// largest-to-smallest so the FAIL band (if any) shows up at the top
// and a sequence of consecutive PASSes follows — easy to read.
//
//   C    : TamaGo PIE, ~1.7 MiB
//   Z2M  : hand-rolled PE32+, padded to 2 MiB (largest hand-asm probe)
//   Z1M  : hand-rolled PE32+, padded to 1 MiB
//   Z64K : hand-rolled PE32+, padded to 64 KiB
//   Z    : hand-rolled PE32+, ~1 KiB (the absolute floor)
//   A, B : skipped (not embedded in amd64 build — see tiny_amd64.go)
func Variants() []string {
	return []string{VariantA, VariantB, VariantC, VariantZ2M, VariantZ1M, VariantZ64K, VariantZ}
}

// Decompress returns the raw PE32+ bytes for the named variant. Returns
// ErrEmptyEmbed for empty slots, ErrUnknownVariant for typos.
func Decompress(variant string) ([]byte, error) {
	var gz []byte
	switch variant {
	case VariantA:
		gz = tinyAGz
	case VariantB:
		gz = tinyBGz
	case VariantC:
		gz = tinyCGz
	case VariantZ:
		gz = tinyZGz
	case VariantZ64K:
		gz = tinyZ64KGz
	case VariantZ1M:
		gz = tinyZ1MGz
	case VariantZ2M:
		gz = tinyZ2MGz
	default:
		return nil, ErrUnknownVariant
	}
	if len(gz) == 0 {
		return nil, ErrEmptyEmbed
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return out, nil
}
