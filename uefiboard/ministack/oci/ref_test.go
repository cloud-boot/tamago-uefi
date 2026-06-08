// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import "testing"

func TestParseRef(t *testing.T) {
	cases := []struct {
		in, scheme, host, repo, ref string
	}{
		{"ghcr.io/owner/repo:tag", "https", "ghcr.io", "owner/repo", "tag"},
		{"https://ghcr.io/owner/repo:tag", "https", "ghcr.io", "owner/repo", "tag"},
		{"http://example.com/r:t", "http", "example.com", "r", "t"},
		{"127.0.0.1:5000/r:t", "http", "127.0.0.1:5000", "r", "t"},
		{"localhost:5000/r:t", "http", "localhost:5000", "r", "t"},
		{"ghcr.io/owner/repo@sha256:deadbeef", "https", "ghcr.io", "owner/repo", "sha256:deadbeef"},
		{"ghcr.io/repo", "https", "ghcr.io", "repo", "latest"},
	}
	for _, c := range cases {
		r, err := ParseRef(c.in)
		if err != nil {
			t.Fatalf("ParseRef(%q): %v", c.in, err)
		}
		if r.Scheme != c.scheme || r.Host != c.host || r.Repo != c.repo || r.Reference != c.ref {
			t.Errorf("ParseRef(%q) = %+v; want scheme=%s host=%s repo=%s ref=%s",
				c.in, r, c.scheme, c.host, c.repo, c.ref)
		}
	}
}

func TestParseRefLocalhostExplicitHTTPSDowngraded(t *testing.T) {
	// Documented quirk: explicit https:// against localhost falls back to
	// http (local registries serve plaintext). Matches cloud-boot/init.
	r, err := ParseRef("https://localhost:5000/r:t")
	if err != nil {
		t.Fatal(err)
	}
	if r.Scheme != "http" {
		t.Errorf("scheme=%s; want http (localhost downgrade)", r.Scheme)
	}
}

func TestParseRefRejectsMissingSlash(t *testing.T) {
	if _, err := ParseRef("noslash"); err != ErrRefNoRepo {
		t.Errorf("want ErrRefNoRepo, got %v", err)
	}
}

func TestParseRefRejectsEmptyRepo(t *testing.T) {
	if _, err := ParseRef("ghcr.io/:tag"); err != ErrRefNoRepo {
		t.Errorf("want ErrRefNoRepo, got %v", err)
	}
}

func TestRefURLs(t *testing.T) {
	r := &Ref{Scheme: "https", Host: "ghcr.io", Repo: "owner/repo", Reference: "tag"}
	if got := r.baseURL(); got != "https://ghcr.io/v2/owner/repo" {
		t.Errorf("baseURL = %s", got)
	}
	if got := r.manifestURL("latest"); got != "https://ghcr.io/v2/owner/repo/manifests/latest" {
		t.Errorf("manifestURL = %s", got)
	}
	if got := r.blobURL("sha256:abc"); got != "https://ghcr.io/v2/owner/repo/blobs/sha256:abc" {
		t.Errorf("blobURL = %s", got)
	}
}
