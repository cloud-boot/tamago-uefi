// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Top-level OCI artifact fetch — the entry point the M7 probe (and,
// later, the M8 EBS+kexec sequence) calls.
//
// Sequence:
//
//  1. ParseRef(refStr)        — split scheme/host/repo/reference.
//  2. NewRegistry(...)        — bind to ministack Stack + DNS.
//  3. Authenticate()          — observe 401, fetch anonymous bearer.
//  4. FetchManifestRaw(ref)   — get the bytes at /manifests/<ref>.
//  5. If index, PickPlatform + FetchManifestRaw(<picked-digest>).
//  6. ParseManifest(raw)      — decode to descriptors.
//  7. For each descriptor caller asks for, FetchBlob().
//
// We return both the raw bytes AND a structured Artifact so the M7
// probe can print descriptor sizes/digests without having to re-parse,
// and so the future M8 probe can hand layer bytes straight to the
// kexec setup without re-fetching.
//
// The default policy is "fetch config + every layer". Callers wanting
// to skip large layers (e.g. when probing without M7.1 streaming
// support) can pass a non-nil FetchOptions.LayerFilter to drop layers
// by descriptor.

package oci

import (
	"fmt"
)

// Artifact is the in-RAM materialised view of one OCI image manifest:
// the resolved manifest bytes/digest, the config blob bytes, and zero
// or more layer blob bytes — all SHA-256-verified.
type Artifact struct {
	// Reference is the resolved manifest reference (the digest after
	// dereferencing the index, or the tag if there was no index).
	Reference string
	// ManifestRaw is the raw JSON bytes of the resolved image
	// manifest (NOT the index). The digest is verifiable via
	// DigestFromBytes(ManifestRaw).
	ManifestRaw []byte
	// ManifestDigest is `sha256:` + the hex digest of ManifestRaw.
	ManifestDigest string
	// IndexRaw is the raw bytes of the index, if the reference
	// resolved through one. Nil if the registry returned an image
	// manifest directly.
	IndexRaw []byte
	// IndexDigest mirrors ManifestDigest for IndexRaw. Empty when
	// IndexRaw is nil.
	IndexDigest string
	// Manifest is the parsed view of ManifestRaw.
	Manifest *Manifest
	// ConfigBlob is the bytes of the config descriptor's blob.
	ConfigBlob []byte
	// LayerBlobs is the bytes of each layer descriptor's blob, in
	// the order they appear in Manifest.Layers. Indexes match
	// 1:1 with Manifest.Layers.
	LayerBlobs [][]byte
}

// FetchOptions tunes a FetchArtifact call.
type FetchOptions struct {
	// OS is the target operating system for index resolution
	// (default: "linux"). M7 only ever wants linux.
	OS string
	// Arch is the target architecture (default: caller-supplied —
	// typically runtime.GOARCH).
	Arch string
	// LayerFilter, if non-nil, decides whether to fetch each layer
	// descriptor. Returning false skips the layer (and the
	// corresponding LayerBlobs entry is left nil). Useful for the
	// M7 smoke test which has a 1 MiB response cap and wants to
	// skip multi-MiB tar.gz layers.
	LayerFilter func(Descriptor) bool
	// SkipConfig, if true, skips the config blob fetch. Useful for
	// pure-layout smoke tests.
	SkipConfig bool
}

// FetchArtifact runs the full OCI walk for refStr against the
// supplied Registry. The caller owns the Registry (so the same
// ministack Stack + DNS can be re-used across fetches).
func FetchArtifact(reg *Registry, opts FetchOptions) (*Artifact, error) {
	osName := opts.OS
	if osName == "" {
		osName = "linux"
	}
	arch := opts.Arch
	if arch == "" {
		return nil, fmt.Errorf("ministack/oci: FetchArtifact requires opts.Arch")
	}

	if err := reg.Authenticate(); err != nil {
		return nil, fmt.Errorf("authenticate: %w", err)
	}

	manifestRaw, contentType, err := reg.FetchManifestRaw(reg.Ref.Reference)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", reg.Ref.Reference, err)
	}

	art := &Artifact{}
	if IsIndex(manifestRaw, contentType) {
		idx, perr := ParseIndex(manifestRaw)
		if perr != nil {
			return nil, fmt.Errorf("parse index: %w", perr)
		}
		art.IndexRaw = manifestRaw
		art.IndexDigest = DigestFromBytes(manifestRaw)
		picked, perr := PickPlatform(idx, osName, arch)
		if perr != nil {
			return nil, perr
		}
		// Recurse: fetch the picked manifest by digest.
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			return nil, fmt.Errorf("fetch picked %s: %w", picked.Digest, ferr)
		}
		// Verify the picked manifest's digest against the index
		// claim — protects against a tampered intermediary swapping
		// manifests at the second hop.
		if verr := VerifyDigest(picked.Digest, mraw); verr != nil {
			return nil, fmt.Errorf("verify picked manifest: %w", verr)
		}
		art.Reference = picked.Digest
		manifestRaw = mraw
	} else {
		art.Reference = reg.Ref.Reference
	}

	art.ManifestRaw = manifestRaw
	art.ManifestDigest = DigestFromBytes(manifestRaw)
	m, err := ParseManifest(manifestRaw)
	if err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	art.Manifest = m

	if !opts.SkipConfig {
		cfg, err := reg.FetchBlob(m.Config)
		if err != nil {
			return nil, fmt.Errorf("fetch config %s: %w", m.Config.Digest, err)
		}
		art.ConfigBlob = cfg
	}

	art.LayerBlobs = make([][]byte, len(m.Layers))
	for i, layer := range m.Layers {
		if opts.LayerFilter != nil && !opts.LayerFilter(layer) {
			continue
		}
		bytes, err := reg.FetchBlob(layer)
		if err != nil {
			return nil, fmt.Errorf("fetch layer[%d] %s: %w", i, layer.Digest, err)
		}
		art.LayerBlobs[i] = bytes
	}

	return art, nil
}
