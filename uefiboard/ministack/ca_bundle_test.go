// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// TestEmbeddedCABundleParses asserts the in-tree PEM file parses
// into a non-empty *x509.CertPool. If this fails, ca_bundle.pem has
// been corrupted or the embed directive is mis-wired.
func TestEmbeddedCABundleParses(t *testing.T) {
	pool, err := NewRootCAs()
	if err != nil {
		t.Fatalf("NewRootCAs: %v", err)
	}
	if pool == nil {
		t.Fatal("NewRootCAs returned a nil pool with nil error")
	}
	// Subjects() is deprecated but stable across Go versions and the
	// only public knob for inspecting a CertPool's contents. The
	// returned slice has one entry per cert we added.
	subjects := pool.Subjects() //nolint:staticcheck // deprecation noted; intentional for inspection.
	if len(subjects) == 0 {
		t.Fatal("CertPool has zero subjects — embed failed")
	}
}

// TestEmbeddedRootCount cross-checks the cert count we report.
func TestEmbeddedRootCount(t *testing.T) {
	// Force the cache to populate.
	if _, err := NewRootCAs(); err != nil {
		t.Fatalf("NewRootCAs: %v", err)
	}
	if EmbeddedRootCount() < 1 {
		t.Errorf("EmbeddedRootCount: got %d, want >=1", EmbeddedRootCount())
	}
}

// TestEmbeddedRootsCoverExpectedCAs scans the embedded bundle and
// asserts that every root we hand-picked for example.com + the
// "big four" CAs is present. If this fails the bundle has drifted
// and the M6 live probe might stop verifying.
func TestEmbeddedRootsCoverExpectedCAs(t *testing.T) {
	wantCNs := []string{
		"ISRG Root X1",
		"ISRG Root X2",
		"DigiCert Global Root G2",
		"DigiCert Global Root CA",
		"GTS Root R1",
		"SSL.com TLS ECC Root CA 2022",
		"SSL.com TLS RSA Root CA 2022",
		// USERTrust RSA Certification Authority — Sectigo CA chain
		// used by ghcr.io (the M7 smoke target).
		"USERTrust RSA Certification Authority",
	}
	got := map[string]bool{}
	rest := embeddedCABundlePEM
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			rest = remainder
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("ParseCertificate: %v", err)
			rest = remainder
			continue
		}
		got[cert.Subject.CommonName] = true
		rest = remainder
	}
	for _, want := range wantCNs {
		if !got[want] {
			t.Errorf("missing expected root CN in bundle: %q", want)
		}
	}
}

// TestNewRootCAsCached confirms repeated calls return the same
// pointer — Loose CAs[] hits a sync.Once, so successive calls must
// not re-build the pool.
func TestNewRootCAsCached(t *testing.T) {
	p1, err := NewRootCAs()
	if err != nil {
		t.Fatalf("first NewRootCAs: %v", err)
	}
	p2, err := NewRootCAs()
	if err != nil {
		t.Fatalf("second NewRootCAs: %v", err)
	}
	if p1 != p2 {
		t.Errorf("pool not cached: p1=%p p2=%p", p1, p2)
	}
}

// TestCountPEMCertificatesEmpty verifies the counter on an empty blob.
func TestCountPEMCertificatesEmpty(t *testing.T) {
	if got := countPEMCertificates(nil); got != 0 {
		t.Errorf("countPEMCertificates(nil) = %d, want 0", got)
	}
	if got := countPEMCertificates([]byte("nope no certificates here")); got != 0 {
		t.Errorf("count on garbage = %d, want 0", got)
	}
}

// TestCountPEMCertificatesMatches asserts countPEMCertificates
// equals the number of pem.Decode blocks of type CERTIFICATE.
func TestCountPEMCertificatesMatches(t *testing.T) {
	count := 0
	rest := embeddedCABundlePEM
	for {
		block, remainder := pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			count++
		}
		rest = remainder
	}
	if got := countPEMCertificates(embeddedCABundlePEM); got != count {
		t.Errorf("countPEMCertificates = %d, pem.Decode count = %d", got, count)
	}
}

// TestEqualBytesCABundle covers the manual byte-compare helper.
func TestEqualBytesCABundle(t *testing.T) {
	cases := []struct {
		a, b []byte
		want bool
	}{
		{nil, nil, true},
		{[]byte{}, []byte{}, true},
		{[]byte("abc"), []byte("abc"), true},
		{[]byte("abc"), []byte("abd"), false},
		{[]byte("abc"), []byte("ab"), false},
		{[]byte("ab"), []byte("abc"), false},
	}
	for _, c := range cases {
		if got := equalBytesCABundle(c.a, c.b); got != c.want {
			t.Errorf("equalBytesCABundle(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// TestEmbeddedBundleHasPEMHeader is a defensive shape check — the
// first 27 bytes must be the BEGIN CERTIFICATE marker. Catches a
// regression where the file gets wrapped in some other framing.
func TestEmbeddedBundleHasPEMHeader(t *testing.T) {
	marker := []byte("-----BEGIN CERTIFICATE-----")
	if !bytes.HasPrefix(embeddedCABundlePEM, marker) {
		t.Errorf("embedded bundle does not start with %q (got first 40 bytes: %q)",
			marker, embeddedCABundlePEM[:40])
	}
}
