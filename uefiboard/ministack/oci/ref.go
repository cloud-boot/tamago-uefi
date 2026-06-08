// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// OCI reference parsing — a slim adaptation of cloud-boot/init's
// pkg/oci.ParseRef. The shape is intentionally identical so M7→M8
// plumbing can re-use the same `Ref{Scheme, Host, Repo, Reference}`
// view. The only ministack-specific change is that we hand the parsed
// pieces back as a struct directly addressable by the higher-level
// fetch loop rather than holding them on a Client value (ministack's
// transport is the Stack, not a heap-allocated `*Client`).
//
// Accepted shapes:
//
//	ghcr.io/owner/repo:tag
//	ghcr.io/owner/repo@sha256:HEX
//	https://ghcr.io/owner/repo:tag
//	http://localhost:5000/repo:tag
//
// Localhost / 127.0.0.1 default to http:// per the upstream rule (it's
// what local test registries serve over). Everything else defaults to
// https://.

package oci

import (
	"errors"
	"strings"
)

// ErrRefNoRepo is returned when the reference string lacks a `/` to
// separate host from repository.
var ErrRefNoRepo = errors.New("ministack/oci: missing repository in reference")

// Ref is a parsed OCI image reference.
type Ref struct {
	Scheme    string // "http" or "https"
	Host      string // "ghcr.io" or "localhost:5000"
	Repo      string // "owner/repo" — slashes preserved
	Reference string // tag (e.g. "latest") or digest ("sha256:abc...")
}

// ParseRef parses an OCI reference string into a Ref. See the package
// doc for the accepted shapes. The default reference (when neither
// `:tag` nor `@digest` is given) is `latest`.
func ParseRef(s string) (*Ref, error) {
	scheme := "https"
	if i := strings.Index(s, "://"); i >= 0 {
		scheme = s[:i]
		s = s[i+3:]
	}
	slash := strings.Index(s, "/")
	if slash < 0 {
		return nil, ErrRefNoRepo
	}
	host, rest := s[:slash], s[slash+1:]
	// Localhost overrides — local test registries don't have certs.
	if strings.HasPrefix(host, "localhost") || strings.HasPrefix(host, "127.0.0.1") {
		// Explicit https:// stays https; only the implicit default flips.
		if scheme == "https" {
			scheme = "http"
		}
	}

	repo := rest
	ref := "latest"
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		repo, ref = rest[:i], rest[i+1:]
	} else if i := strings.LastIndex(rest, ":"); i >= 0 {
		repo, ref = rest[:i], rest[i+1:]
	}
	if repo == "" {
		return nil, ErrRefNoRepo
	}
	return &Ref{Scheme: scheme, Host: host, Repo: repo, Reference: ref}, nil
}

// baseURL is the OCI distribution v2 base URL for this reference,
// e.g. "https://ghcr.io/v2/owner/repo".
func (r *Ref) baseURL() string {
	return r.Scheme + "://" + r.Host + "/v2/" + r.Repo
}

// manifestURL returns the URL for `/manifests/<ref-or-digest>`.
func (r *Ref) manifestURL(reference string) string {
	return r.baseURL() + "/manifests/" + reference
}

// blobURL returns the URL for `/blobs/<digest>`.
func (r *Ref) blobURL(d string) string {
	return r.baseURL() + "/blobs/" + d
}
