// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// SHA-256 content-digest parsing + verification. cloud-boot/init pulls
// `github.com/opencontainers/go-digest` for this; we re-implement it
// in ~30 LOC because:
//
//   - The upstream module's runtime registry of digesters is fine for
//     a Linux init but oversized for a one-arch one-algo TamaGo
//     binary.
//   - crypto/sha256 already builds under tamago (M6 proved this via
//     crypto/x509's transitive dependency).
//   - We never push manifests from the unikernel, only verify; the
//     `FromBytes(b) -> "sha256:HEX"` half of the upstream API is the
//     only part M7 needs.

package oci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

// ErrDigestUnsupported is returned when a digest string names an algo
// other than sha256. The OCI spec lists sha256 + sha512; ministack
// ships sha256 only — sha512 surfaces as ErrDigestUnsupported so the
// fetch fails closed instead of skipping verification.
var ErrDigestUnsupported = errors.New("ministack/oci: only sha256 digests supported")

// ErrDigestBadShape is returned when the digest string lacks the
// expected `<algo>:<hex>` layout or the hex part is the wrong length.
var ErrDigestBadShape = errors.New("ministack/oci: malformed digest string")

// ErrDigestMismatch is returned when a fetched blob's computed
// SHA-256 does not match the descriptor.
var ErrDigestMismatch = errors.New("ministack/oci: digest mismatch on fetched blob")

// digestSHA256HexLen is the length of the hex half of a sha256
// digest — sha256 is 32 bytes → 64 hex chars.
const digestSHA256HexLen = 64

// ParseDigest splits a digest string `<algo>:<hex>` and validates
// shape + algo. Only sha256 is accepted.
func ParseDigest(s string) (algo, hexStr string, err error) {
	i := strings.IndexByte(s, ':')
	if i < 0 {
		return "", "", ErrDigestBadShape
	}
	algo = s[:i]
	hexStr = s[i+1:]
	if algo != "sha256" {
		return "", "", ErrDigestUnsupported
	}
	if len(hexStr) != digestSHA256HexLen {
		return "", "", ErrDigestBadShape
	}
	// Confirm it's actual hex — a non-hex character past the algo
	// separator would otherwise sail through and surface as a
	// digest mismatch much later.
	if _, derr := hex.DecodeString(hexStr); derr != nil {
		return "", "", ErrDigestBadShape
	}
	return algo, hexStr, nil
}

// DigestFromBytes computes the canonical OCI digest string for b
// (`sha256:HEX`). Useful for callers that already have the blob bytes
// in memory and want to assemble a descriptor.
func DigestFromBytes(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// VerifyDigest returns nil if b hashes to want, ErrDigestMismatch
// otherwise. The hex comparison is case-insensitive (OCI registries
// emit lowercase but the spec doesn't forbid mixed-case echoes from
// proxies).
func VerifyDigest(want string, b []byte) error {
	_, wantHex, err := ParseDigest(want)
	if err != nil {
		return err
	}
	gotSum := sha256.Sum256(b)
	gotHex := hex.EncodeToString(gotSum[:])
	if !strings.EqualFold(gotHex, wantHex) {
		return ErrDigestMismatch
	}
	return nil
}
