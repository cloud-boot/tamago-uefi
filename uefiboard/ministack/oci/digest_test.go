// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import (
	"strings"
	"testing"
)

func TestParseDigestValid(t *testing.T) {
	algo, hexStr, err := ParseDigest("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
	if err != nil {
		t.Fatalf("ParseDigest: %v", err)
	}
	if algo != "sha256" {
		t.Errorf("algo=%s", algo)
	}
	if len(hexStr) != digestSHA256HexLen {
		t.Errorf("hex len=%d", len(hexStr))
	}
}

func TestParseDigestRejectsUnsupportedAlgo(t *testing.T) {
	_, _, err := ParseDigest("sha512:" + strings.Repeat("a", 128))
	if err != ErrDigestUnsupported {
		t.Errorf("want ErrDigestUnsupported, got %v", err)
	}
}

func TestParseDigestRejectsMissingColon(t *testing.T) {
	_, _, err := ParseDigest("sha256deadbeef")
	if err != ErrDigestBadShape {
		t.Errorf("want ErrDigestBadShape, got %v", err)
	}
}

func TestParseDigestRejectsBadLength(t *testing.T) {
	_, _, err := ParseDigest("sha256:short")
	if err != ErrDigestBadShape {
		t.Errorf("want ErrDigestBadShape, got %v", err)
	}
}

func TestParseDigestRejectsNonHex(t *testing.T) {
	// 64 chars but with a 'z' in the middle.
	bad := strings.Repeat("a", 30) + "z" + strings.Repeat("a", 33)
	_, _, err := ParseDigest("sha256:" + bad)
	if err != ErrDigestBadShape {
		t.Errorf("want ErrDigestBadShape, got %v", err)
	}
}

func TestDigestFromBytesEmpty(t *testing.T) {
	got := DigestFromBytes(nil)
	// SHA-256 of "" is well-known.
	want := "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestVerifyDigestOK(t *testing.T) {
	body := []byte("hello, world\n")
	d := DigestFromBytes(body)
	if err := VerifyDigest(d, body); err != nil {
		t.Errorf("VerifyDigest: %v", err)
	}
}

func TestVerifyDigestMismatch(t *testing.T) {
	d := DigestFromBytes([]byte("a"))
	if err := VerifyDigest(d, []byte("b")); err != ErrDigestMismatch {
		t.Errorf("want ErrDigestMismatch, got %v", err)
	}
}

func TestVerifyDigestRejectsBadDigest(t *testing.T) {
	if err := VerifyDigest("bogus", []byte("x")); err != ErrDigestBadShape {
		t.Errorf("want ErrDigestBadShape, got %v", err)
	}
}

func TestVerifyDigestCaseInsensitiveHex(t *testing.T) {
	body := []byte("test")
	d := DigestFromBytes(body)
	// Upper-case the hex half — should still verify.
	colon := strings.IndexByte(d, ':')
	upper := d[:colon+1] + strings.ToUpper(d[colon+1:])
	if err := VerifyDigest(upper, body); err != nil {
		t.Errorf("VerifyDigest with upper-case hex: %v", err)
	}
}
