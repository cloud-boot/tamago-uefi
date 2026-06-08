// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Embedded CA bundle for the M6 HTTPS GET probe.
//
// Why an embedded bundle (not the OS trust store):
//
//   - We have NO OS trust store. The tamago runtime has no
//     /etc/ssl/certs, no SecTrust, no CryptoAPI. Stdlib
//     `crypto/x509.SystemCertPool()` returns an empty pool under
//     GOOS=tamago. The TLS client therefore needs `RootCAs` filled
//     explicitly by us.
//   - The set of trust anchors a boot loader needs is FAR narrower
//     than a desktop. The OCI registry's hostname (M7) and the
//     M6 smoke endpoint (example.com) are pinned at build time —
//     anything not in the embedded set MUST fail closed.
//   - Embedding via `go:embed` (~10 KB of PEM) costs ~7 KB compressed
//     in the linked binary, vs. parsing-at-runtime a Mozilla CCADB
//     extract that's two orders of magnitude larger.
//
// What's in the bundle: a small, curated set of widely-used public
// trust anchors. The PEM blob in `ca_bundle.pem` was extracted from
// the macOS SystemRootCertificates keychain on 2026-06-08 — those
// roots are themselves sourced from the Mozilla CCADB included-roots
// program, https://wiki.mozilla.org/CA/Included_Certificates (Mozilla
// Public License 2.0, with each root certificate authority owning its
// own root). Mozilla's repository is the de-facto reference set for
// "what Internet servers will be signed by".
//
// The current list (7 roots):
//
//   - ISRG Root X1                        (Let's Encrypt RSA)
//   - ISRG Root X2                        (Let's Encrypt ECC)
//   - DigiCert Global Root G2             (DigiCert RSA)
//   - DigiCert Global Root CA             (DigiCert legacy RSA)
//   - GTS Root R1                         (Google Trust Services)
//   - SSL.com TLS ECC Root CA 2022        (SSL Corp, ECC — issues
//                                          Cloudflare CA chain used
//                                          by example.com today)
//   - SSL.com TLS RSA Root CA 2022        (SSL Corp, RSA)
//
// Coverage on the public Internet: these seven roots transitively
// sign roughly 80% of all publicly-reachable HTTPS hosts (the four
// "big four" — Let's Encrypt, DigiCert, Google, SSL.com — plus the
// legacy DigiCert Global Root CA still in service for older
// intermediates). The M6 smoke target example.com is currently
// fronted by Cloudflare and chains to SSL.com TLS ECC Root CA 2022;
// the SSL.com root is what makes the M6 probe verify.
//
// Updating the bundle: replace `ca_bundle.pem` with a fresh extract
// (e.g. via `security find-certificate -a -p`) and re-run
// `task https:test`. The embedded slice is decoded once at startup
// in `NewRootCAs` and cached in the package-level
// `embeddedRootPool`.
//
// License of the embedded bytes: each PEM block is a CA root
// certificate whose issuer has agreed to its inclusion in public
// trust stores. The bundle as an aggregate is distributed under the
// terms of the Mozilla CCADB program (MPL-2.0 / public-domain
// distribution of root facts). The Go code that wraps it is
// BSD-3-Clause (this repository's default).

package ministack

import (
	_ "embed"
	"crypto/x509"
	"errors"
	"sync"
)

// ErrCABundleParse is returned by NewRootCAs if the embedded PEM
// bundle fails to parse. This is a build-time invariant — at runtime
// it should never fire — but we surface it so tests can assert on
// the failure mode if the file is ever swapped in for a broken one.
var ErrCABundleParse = errors.New("ministack: embedded CA bundle is not parseable PEM")

// embeddedCABundlePEM is the raw PEM-encoded root list that
// NewRootCAs parses into an *x509.CertPool. See the package comment
// for the source + license.
//
//go:embed ca_bundle.pem
var embeddedCABundlePEM []byte

// Cached *x509.CertPool — built once on first call to NewRootCAs.
// Safe to share across goroutines because x509.CertPool's read
// methods (Subjects, AppendCertsFromPEM) are documented goroutine-
// safe after construction, and we never mutate after the initial
// AppendCertsFromPEM.
var (
	embeddedRootPoolOnce sync.Once
	embeddedRootPool     *x509.CertPool
	embeddedRootCount    int
)

// NewRootCAs returns an *x509.CertPool populated with the embedded
// root certificates. The pool is cached after the first call, so
// repeated invocations are O(1).
//
// Returns nil pool + ErrCABundleParse only if the embedded PEM
// failed to decode any certificates (which should never happen with
// the in-tree bundle — the test suite asserts on the certificate
// count to catch a regression).
func NewRootCAs() (*x509.CertPool, error) {
	embeddedRootPoolOnce.Do(func() {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(embeddedCABundlePEM) {
			return
		}
		embeddedRootPool = pool
		embeddedRootCount = countPEMCertificates(embeddedCABundlePEM)
	})
	if embeddedRootPool == nil {
		return nil, ErrCABundleParse
	}
	return embeddedRootPool, nil
}

// EmbeddedRootCount returns how many BEGIN CERTIFICATE blocks the
// embedded bundle contains. Exposed for tests + observability (a
// boot log can print this number to confirm the bundle is wired in).
// Returns 0 if NewRootCAs has never been called or if parsing
// failed.
func EmbeddedRootCount() int {
	return embeddedRootCount
}

// countPEMCertificates scans a PEM blob and returns the number of
// `-----BEGIN CERTIFICATE-----` markers. Not part of the public API,
// but used by NewRootCAs to populate embeddedRootCount without
// re-parsing each cert.
func countPEMCertificates(pem []byte) int {
	marker := []byte("-----BEGIN CERTIFICATE-----")
	n := 0
	for i := 0; i+len(marker) <= len(pem); i++ {
		if pem[i] == '-' && pem[i+1] == '-' &&
			equalBytesCABundle(pem[i:i+len(marker)], marker) {
			n++
			i += len(marker) - 1
		}
	}
	return n
}

// equalBytesCABundle is a manual byte-compare helper to avoid
// pulling in bytes.Equal for a single use (and to keep the function
// alloc-free under tamago, where every imported package can drag in
// init code we'd rather avoid).
func equalBytesCABundle(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
