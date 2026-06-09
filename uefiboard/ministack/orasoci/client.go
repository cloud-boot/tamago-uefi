// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Thin wrapper around oras.land/oras-go/v2/registry/remote.Repository
// pre-wired with the MinistackRoundTripper transport.
//
// The M7.alt evaluation exercises this from phase2_oci_oras_fetch:
//
//  1. NewRepository(stack, dns, "ghcr.io/linuxcontainers/alpine:latest")
//  2. FetchToMemory copies the manifest+config into an in-RAM store
//  3. Verify digest + bytes (probe-side)
//
// Everything past step 1 lives in the probe; this file just owns the
// "how do I get an oras.Repository that uses ministack's L2/L3/L4"
// detail so the probe stays a thin glue layer.

package orasoci

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	oras "oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
)

// Repository pairs a configured *remote.Repository with the
// MinistackRoundTripper it routes through.
type Repository struct {
	// Repo is the oras-go remote.Repository wired up with the
	// ministack-backed Transport.
	Repo *remote.Repository
	// Transport is the underlying RoundTripper. Exposed for
	// observability + so callers can swap timeouts post-construction.
	Transport *MinistackRoundTripper
}

// FetchResult captures the outcome of FetchToMemory: the descriptor
// of the resolved root (manifest, after dereferencing index when
// applicable) and the destination memory store the bytes landed in.
type FetchResult struct {
	Root  ocispec.Descriptor
	Store *memory.Store
}

// NewRepository constructs an oras-go remote.Repository bound to the
// supplied ministack Stack + DNS resolver. `ref` is the canonical
// reference string (e.g. "ghcr.io/linuxcontainers/alpine:latest").
//
// The resulting Repository is configured for anonymous-pull; the
// auth.Client handles the 401 + Bearer dance against ghcr.io's token
// endpoint automatically.
func NewRepository(stack *ministack.Stack, dns net.IP, ref string) (*Repository, error) {
	repo, err := remote.NewRepository(ref)
	if err != nil {
		return nil, err
	}
	rt := New(stack, dns)
	httpClient := &http.Client{
		Transport: rt,
		Timeout:   90 * time.Second,
	}
	authClient := &auth.Client{
		Client: httpClient,
		Credential: auth.StaticCredential(repo.Reference.Registry, auth.Credential{
			// Anonymous-pull; nothing to set.
		}),
	}
	repo.Client = authClient
	repo.PlainHTTP = false
	return &Repository{Repo: repo, Transport: rt}, nil
}

// FetchToMemory runs oras.Copy from the bound remote Repository into
// a fresh in-memory store, returning the root descriptor (the
// manifest's digest) and the destination store (so the probe can
// inspect the fetched bytes).
//
// `ref` defaults to the Repository's configured reference when empty.
func (r *Repository) FetchToMemory(ctx context.Context, ref string) (*FetchResult, error) {
	if ref == "" {
		ref = r.Repo.Reference.Reference
	}
	store := memory.New()
	desc, err := oras.Copy(ctx, r.Repo, ref, store, "", oras.DefaultCopyOptions)
	if err != nil {
		return nil, err
	}
	return &FetchResult{Root: desc, Store: store}, nil
}
