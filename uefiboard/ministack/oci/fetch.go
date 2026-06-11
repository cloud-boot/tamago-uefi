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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
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

// FetchBlobStream fetches a single blob descriptor through the
// Registry's streaming transport and writes it to `dst`. The fetched
// bytes are tee'd through a SHA-256 hasher while they flow; on EOF
// the computed digest is checked against desc.Digest. On any mismatch
// ErrDigestMismatch is returned (the caller is expected to discard
// whatever made it into `dst`).
//
// Returns the number of bytes successfully written to `dst`.
//
// Unlike FetchBlob, this method does NOT cap the response size — the
// caller bounds `dst` if they want a ceiling. This is what makes the
// streaming path the unlock for multi-MiB kernel-sized blobs that
// the buffered path's 1 MiB cap rejects.
//
// The Registry's Transport must implement StreamTransport. Following
// redirects (3xx → Location) mirrors FetchBlob: up to maxBlobRedirects
// hops, bearer dropped after the first hop so S3-style pre-signed
// URLs don't get a conflicting Authorization header.
func (reg *Registry) FetchBlobStream(desc Descriptor, dst io.Writer) (int64, error) {
	if _, _, err := ParseDigest(desc.Digest); err != nil {
		return 0, err
	}
	st, ok := reg.Transport.(StreamTransport)
	if !ok {
		return 0, ErrTransportNotStreaming
	}

	url := reg.Ref.blobURL(desc.Digest)
	bearer := reg.bearer
	for hop := 0; hop <= maxBlobRedirects; hop++ {
		h := sha256.New()
		mw := io.MultiWriter(dst, h)

		opts := ministack.HTTPGetOptions{
			DNSServer:      reg.DNS,
			DialTimeout:    reg.DialTimeout,
			RequestTimeout: reg.RequestTimeout,
		}
		if bearer != "" {
			opts.ExtraHeaders = append(opts.ExtraHeaders, "Authorization: Bearer "+bearer)
		}

		status, n, headers, herr := st.GetStream(url, mw, opts)
		if herr != nil {
			return n, herr
		}
		if isRedirect(status) {
			loc := headers["location"]
			if loc == "" {
				return 0, &ErrRegistryStatus{URL: url, Status: status}
			}
			url = loc
			bearer = ""
			continue
		}
		if status != 200 {
			return n, &ErrRegistryStatus{URL: url, Status: status}
		}
		if desc.Size > 0 && n != desc.Size {
			return n, fmt.Errorf("ministack/oci: blob size mismatch: got %d want %d", n, desc.Size)
		}
		_, wantHex, _ := ParseDigest(desc.Digest)
		gotHex := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(gotHex, wantHex) {
			return n, ErrDigestMismatch
		}
		return n, nil
	}
	return 0, fmt.Errorf("ministack/oci: too many redirects (>%d) for %s", maxBlobRedirects, desc.Digest)
}

// ErrBlobBufferTooSmall is returned by FetchBlobToBuffer when the
// caller-supplied slice is shorter than desc.Size.
var ErrBlobBufferTooSmall = errors.New("ministack/oci: caller buffer shorter than descriptor size")

// ErrBlobBufferOverflow is returned by FetchBlobToBuffer if the
// transport delivers more bytes than the caller-supplied slice can
// hold. This protects against a registry returning a body larger than
// the descriptor's declared Size.
var ErrBlobBufferOverflow = errors.New("ministack/oci: blob exceeds caller buffer")

// fixedSliceWriter is an io.Writer that fills a caller-owned []byte at
// a running offset. It does NOT allocate. Writing past the slice end
// returns ErrBlobBufferOverflow. Used by FetchBlobToBuffer to stream
// chunks directly into the final destination — no bytes.Buffer
// transient, no growth, no copy.
type fixedSliceWriter struct {
	buf []byte
	off int
}

// Write implements io.Writer. Returns the number of bytes copied. If
// the input would exceed the slice it copies as much as fits, then
// returns ErrBlobBufferOverflow so the streaming-transport loop fails
// closed.
func (w *fixedSliceWriter) Write(p []byte) (int, error) {
	if w.off >= len(w.buf) {
		if len(p) == 0 {
			return 0, nil
		}
		return 0, ErrBlobBufferOverflow
	}
	n := copy(w.buf[w.off:], p)
	w.off += n
	if n < len(p) {
		return n, ErrBlobBufferOverflow
	}
	return n, nil
}

// FetchBlobToBuffer streams a single blob descriptor through the
// Registry's streaming transport, writing directly into the caller-
// supplied []byte at offset 0. The slice MUST be at least desc.Size
// bytes long. As bytes arrive they are tee'd through a SHA-256 hasher
// and copied into `dst`; on EOF the computed digest is verified
// against desc.Digest. On mismatch ErrDigestMismatch is returned and
// the caller is expected to discard whatever is in `dst`.
//
// Why this exists alongside FetchBlobStream:
//
// FetchBlobStream takes an io.Writer, which the natural callers back
// with bytes.Buffer{}.Grow(N). bytes.Buffer reserves N bytes for
// growth, but when the caller then calls .Bytes() the underlying
// slice is shared with the buffer's internal cursor — and any further
// padding/growth performed by the caller (e.g. tail-pad to a 512-byte
// LBA multiple via append) may allocate a SECOND N-byte slice if
// capacity isn't sufficient. On tamago's 256 MiB heap with a 64 MiB
// disk image, that doubling forces an OOM.
//
// FetchBlobToBuffer avoids this entirely: the caller allocates exactly
// one slice of `target.Size`, hands it in, and the stream fills it in
// place. The publish-side BlockIO then references that same slice via
// bodyKeepAlive (R-amd64j Phase 1 pattern), so the entire image
// pipeline lives in ONE 64 MiB allocation.
//
// Returns the number of bytes successfully written. On error the
// returned count is the bytes already deposited into `dst` — caller
// owns the slice and is responsible for discarding it on error.
//
// Unlike FetchBlob, this method does NOT cap the response size at the
// registry-side limit; the cap is the slice length itself. A registry
// returning more bytes than `dst` can hold fails closed with
// ErrBlobBufferOverflow.
func (reg *Registry) FetchBlobToBuffer(desc Descriptor, dst []byte) (int64, error) {
	if _, _, err := ParseDigest(desc.Digest); err != nil {
		return 0, err
	}
	if desc.Size > 0 && int64(len(dst)) < desc.Size {
		return 0, ErrBlobBufferTooSmall
	}
	st, ok := reg.Transport.(StreamTransport)
	if !ok {
		return 0, ErrTransportNotStreaming
	}

	url := reg.Ref.blobURL(desc.Digest)
	bearer := reg.bearer
	for hop := 0; hop <= maxBlobRedirects; hop++ {
		h := sha256.New()
		w := &fixedSliceWriter{buf: dst}
		mw := io.MultiWriter(w, h)

		opts := ministack.HTTPGetOptions{
			DNSServer:      reg.DNS,
			DialTimeout:    reg.DialTimeout,
			RequestTimeout: reg.RequestTimeout,
		}
		if bearer != "" {
			opts.ExtraHeaders = append(opts.ExtraHeaders, "Authorization: Bearer "+bearer)
		}

		status, n, headers, herr := st.GetStream(url, mw, opts)
		if herr != nil {
			return n, herr
		}
		if isRedirect(status) {
			loc := headers["location"]
			if loc == "" {
				return 0, &ErrRegistryStatus{URL: url, Status: status}
			}
			url = loc
			bearer = ""
			continue
		}
		if status != 200 {
			return n, &ErrRegistryStatus{URL: url, Status: status}
		}
		if desc.Size > 0 && n != desc.Size {
			return n, fmt.Errorf("ministack/oci: blob size mismatch: got %d want %d", n, desc.Size)
		}
		_, wantHex, _ := ParseDigest(desc.Digest)
		gotHex := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(gotHex, wantHex) {
			return n, ErrDigestMismatch
		}
		return n, nil
	}
	return 0, fmt.Errorf("ministack/oci: too many redirects (>%d) for %s", maxBlobRedirects, desc.Digest)
}
