// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// OCI manifest + index JSON shapes — the minimum subset the
// ministack OCI client needs to walk an artifact.
//
// We don't depend on `github.com/opencontainers/image-spec` (cloud-boot/init
// does) for three reasons:
//
//   - It pulls a transitive dep on go-digest, which we replace with
//     digest.go in this package.
//   - We only need read-side JSON parsing (no marshal). The structs
//     below are a hand-trimmed subset of `specs-go/v1.Manifest` and
//     `specs-go/v1.Index`.
//   - Stable struct tags + zero validation logic in upstream's read
//     path means there's nothing to lose by inlining.
//
// Media types we handle:
//
//   - OCI image index v1:        application/vnd.oci.image.index.v1+json
//   - Docker manifest list v2:   application/vnd.docker.distribution.manifest.list.v2+json
//   - OCI image manifest v1:     application/vnd.oci.image.manifest.v1+json
//   - Docker manifest v2:        application/vnd.docker.distribution.manifest.v2+json
//
// The two "list" variants are dereferenced by walking the `manifests`
// array and matching on platform.os == "linux" + platform.architecture
// (passed by the caller, typically `runtime.GOARCH`).

package oci

import (
	"encoding/json"
	"errors"
)

// Media-type constants the M7 client recognises.
const (
	MediaTypeOCIIndex          = "application/vnd.oci.image.index.v1+json"
	MediaTypeOCIManifest       = "application/vnd.oci.image.manifest.v1+json"
	MediaTypeDockerIndex       = "application/vnd.docker.distribution.manifest.list.v2+json"
	MediaTypeDockerManifest    = "application/vnd.docker.distribution.manifest.v2+json"
	MediaTypeOCIImageConfig    = "application/vnd.oci.image.config.v1+json"
	MediaTypeOCIImageLayer     = "application/vnd.oci.image.layer.v1.tar+gzip"
	MediaTypeDockerImageConfig = "application/vnd.docker.container.image.v1+json"
	MediaTypeDockerImageLayer  = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

// ManifestAcceptHeader is the Accept value the client sends on
// `/manifests/<ref>` — both OCI + Docker shapes, both index + image.
const ManifestAcceptHeader = MediaTypeOCIIndex + ", " +
	MediaTypeDockerIndex + ", " +
	MediaTypeOCIManifest + ", " +
	MediaTypeDockerManifest

// Platform mirrors `ocispec.Platform` — just what we need to pick a
// manifest out of an index.
type Platform struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Variant      string `json:"variant,omitempty"`
}

// Descriptor mirrors `ocispec.Descriptor` — every blob/manifest
// reference in an index or manifest has this shape.
type Descriptor struct {
	MediaType string    `json:"mediaType"`
	Digest    string    `json:"digest"`
	Size      int64     `json:"size"`
	Platform  *Platform `json:"platform,omitempty"`
}

// Index mirrors `ocispec.Index` — multi-arch / multi-platform manifest
// list.
type Index struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Manifests     []Descriptor `json:"manifests"`
}

// Manifest mirrors `ocispec.Manifest` — single-arch image manifest.
type Manifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// ErrIndexNoMatch is returned when no manifest in the index matches
// the requested (os, arch).
var ErrIndexNoMatch = errors.New("ministack/oci: no manifest in index matches requested platform")

// ErrManifestEmpty is returned when an empty body is handed to
// ParseManifest / ParseIndex. Surfaces as a clear message instead of
// the cryptic "unexpected end of JSON input".
var ErrManifestEmpty = errors.New("ministack/oci: empty manifest body")

// ParseIndex decodes raw JSON bytes into an Index.
func ParseIndex(raw []byte) (*Index, error) {
	if len(raw) == 0 {
		return nil, ErrManifestEmpty
	}
	var idx Index
	if err := json.Unmarshal(raw, &idx); err != nil {
		return nil, err
	}
	return &idx, nil
}

// ParseManifest decodes raw JSON bytes into a Manifest.
func ParseManifest(raw []byte) (*Manifest, error) {
	if len(raw) == 0 {
		return nil, ErrManifestEmpty
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// IsIndex reports whether the raw JSON body / content-type names a
// multi-arch index (vs an image manifest).
func IsIndex(raw []byte, contentType string) bool {
	switch contentType {
	case MediaTypeOCIIndex, MediaTypeDockerIndex:
		return true
	}
	// Body sniff — registries occasionally drop the Content-Type or
	// hand us the "wrong" one when caching across vendors.
	var probe struct {
		MediaType string       `json:"mediaType"`
		Manifests []Descriptor `json:"manifests"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	if probe.MediaType == MediaTypeOCIIndex || probe.MediaType == MediaTypeDockerIndex {
		return true
	}
	return len(probe.Manifests) > 0
}

// PickPlatform returns the descriptor in idx matching the requested
// (osName, arch), or ErrIndexNoMatch if none. Variants are not
// considered — M7 doesn't need ARMv7-vs-ARMv8 disambiguation; arm64 +
// linux is enough.
func PickPlatform(idx *Index, osName, arch string) (Descriptor, error) {
	for _, m := range idx.Manifests {
		if m.Platform == nil {
			continue
		}
		if m.Platform.OS == osName && m.Platform.Architecture == arch {
			return m, nil
		}
	}
	return Descriptor{}, ErrIndexNoMatch
}
