// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// jsonMarshal is a thin wrapper around encoding/json.Marshal so tests
// can keep the import list close to the helpers that use it.
func jsonMarshal(v interface{}) ([]byte, error) { return json.Marshal(v) }

// buildFetchHarness wires a mockTransport with a full
// auth-challenge → token → index → manifest → blob walk that
// FetchArtifact can drive.
func buildFetchHarness(t *testing.T, configBody, layerBody []byte) (*mockTransport, *Ref, Descriptor, Descriptor) {
	t.Helper()
	mt := newMockTransport(t)

	configDesc := Descriptor{
		MediaType: MediaTypeOCIImageConfig,
		Digest:    DigestFromBytes(configBody),
		Size:      int64(len(configBody)),
	}
	layerDesc := Descriptor{
		MediaType: MediaTypeOCIImageLayer,
		Digest:    DigestFromBytes(layerBody),
		Size:      int64(len(layerBody)),
	}
	manifest := &Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        configDesc,
		Layers:        []Descriptor{layerDesc},
	}
	manifestBody := mustMarshal(t, manifest)
	manifestDigest := DigestFromBytes(manifestBody)

	idx := &Index{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []Descriptor{
			{
				MediaType: MediaTypeOCIManifest,
				Digest:    manifestDigest,
				Size:      int64(len(manifestBody)),
				Platform:  &Platform{OS: "linux", Architecture: "amd64"},
			},
		},
	}
	indexBody := mustMarshal(t, idx)

	// 1. Auth probe → 401 with challenge.
	probeURL := "https://reg.example.com/v2/r/manifests/latest"
	mt.On(probeURL, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Bearer realm="https://auth.example.com/token",service="reg",scope="repository:r:pull"`,
		}, nil)
	})
	// 2. Token endpoint.
	mt.OnPrefix("https://auth.example.com/token", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, []byte(`{"token":"unit-test-bearer"}`))
	})
	// 3. After auth, /manifests/latest returns the index.
	// We override the original handler now that auth has happened.
	// Use a stateful handler that tells the second call from the first.
	authCalled := 0
	mt.On(probeURL, func(req mockRequest) *ministack.HTTPResponse {
		authCalled++
		switch authCalled {
		case 1:
			return fakeResponse(401, map[string]string{
				"www-authenticate": `Bearer realm="https://auth.example.com/token",service="reg",scope="repository:r:pull"`,
			}, nil)
		default:
			return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIIndex}, indexBody)
		}
	})
	// 4. /manifests/<digest> returns the image manifest.
	mt.On("https://reg.example.com/v2/r/manifests/"+manifestDigest, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIManifest}, manifestBody)
	})
	// 5. /blobs/<config>
	mt.On("https://reg.example.com/v2/r/blobs/"+configDesc.Digest, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, configBody)
	})
	// 6. /blobs/<layer>
	mt.On("https://reg.example.com/v2/r/blobs/"+layerDesc.Digest, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, layerBody)
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	return mt, ref, configDesc, layerDesc
}

func mustMarshal(t *testing.T, v interface{}) []byte {
	t.Helper()
	// Tiny helper using encoding/json — the test isn't perf-critical.
	b, err := jsonMarshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// FetchArtifact happy path through index → manifest → blobs.
func TestFetchArtifact(t *testing.T) {
	cfg := []byte(`{"architecture":"amd64","os":"linux"}`)
	layer := []byte("layer-bytes")
	mt, ref, configDesc, layerDesc := buildFetchHarness(t, cfg, layer)
	reg := NewRegistryWithTransport(mt, nil, ref)

	art, err := FetchArtifact(reg, FetchOptions{Arch: "amd64"})
	if err != nil {
		t.Fatalf("FetchArtifact: %v", err)
	}
	if art.IndexRaw == nil {
		t.Errorf("expected IndexRaw set")
	}
	if string(art.ConfigBlob) != string(cfg) {
		t.Errorf("config mismatch")
	}
	if len(art.LayerBlobs) != 1 || string(art.LayerBlobs[0]) != string(layer) {
		t.Errorf("layer mismatch: %v", art.LayerBlobs)
	}
	if art.Manifest.Config.Digest != configDesc.Digest {
		t.Errorf("manifest.config.digest mismatch")
	}
	if art.Manifest.Layers[0].Digest != layerDesc.Digest {
		t.Errorf("manifest.layers[0].digest mismatch")
	}
}

// FetchArtifact rejects opts.Arch == "".
func TestFetchArtifactRequiresArch(t *testing.T) {
	mt := newMockTransport(t)
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if _, err := FetchArtifact(reg, FetchOptions{}); err == nil ||
		!strings.Contains(err.Error(), "Arch") {
		t.Errorf("want Arch-required error, got %v", err)
	}
}

// FetchArtifact when reference returns an image manifest directly (no index).
func TestFetchArtifactDirectManifest(t *testing.T) {
	cfg := []byte(`{"os":"linux"}`)
	layer := []byte("L")
	configDesc := Descriptor{MediaType: MediaTypeOCIImageConfig, Digest: DigestFromBytes(cfg), Size: int64(len(cfg))}
	layerDesc := Descriptor{MediaType: MediaTypeOCIImageLayer, Digest: DigestFromBytes(layer), Size: int64(len(layer))}
	manifest := &Manifest{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIManifest,
		Config:        configDesc,
		Layers:        []Descriptor{layerDesc},
	}
	manifestBody := mustMarshal(t, manifest)

	mt := newMockTransport(t)
	mt.On("https://reg.example.com/v2/r/manifests/latest", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIManifest}, manifestBody)
	})
	mt.On("https://reg.example.com/v2/r/blobs/"+configDesc.Digest, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, cfg)
	})
	mt.On("https://reg.example.com/v2/r/blobs/"+layerDesc.Digest, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, layer)
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	art, err := FetchArtifact(reg, FetchOptions{Arch: "amd64"})
	if err != nil {
		t.Fatalf("FetchArtifact: %v", err)
	}
	if art.IndexRaw != nil {
		t.Errorf("expected no IndexRaw on direct manifest")
	}
	if art.Reference != "latest" {
		t.Errorf("reference=%s", art.Reference)
	}
}

func TestFetchArtifactLayerFilter(t *testing.T) {
	cfg := []byte(`{}`)
	layer := []byte("LL")
	mt, ref, _, _ := buildFetchHarness(t, cfg, layer)
	reg := NewRegistryWithTransport(mt, nil, ref)
	art, err := FetchArtifact(reg, FetchOptions{
		Arch:        "amd64",
		LayerFilter: func(d Descriptor) bool { return false },
	})
	if err != nil {
		t.Fatalf("FetchArtifact: %v", err)
	}
	if art.LayerBlobs[0] != nil {
		t.Errorf("expected layer skipped, got %d bytes", len(art.LayerBlobs[0]))
	}
}

func TestFetchArtifactSkipConfig(t *testing.T) {
	cfg := []byte(`{}`)
	layer := []byte("L")
	mt, ref, _, _ := buildFetchHarness(t, cfg, layer)
	reg := NewRegistryWithTransport(mt, nil, ref)
	art, err := FetchArtifact(reg, FetchOptions{Arch: "amd64", SkipConfig: true})
	if err != nil {
		t.Fatalf("FetchArtifact: %v", err)
	}
	if art.ConfigBlob != nil {
		t.Errorf("expected config skipped")
	}
}

func TestFetchArtifactIndexNoMatch(t *testing.T) {
	cfg := []byte(`{}`)
	layer := []byte("L")
	mt, ref, _, _ := buildFetchHarness(t, cfg, layer)
	reg := NewRegistryWithTransport(mt, nil, ref)
	// Request riscv64 — fixture only has amd64.
	_, err := FetchArtifact(reg, FetchOptions{Arch: "riscv64"})
	if err != ErrIndexNoMatch {
		t.Errorf("want ErrIndexNoMatch, got %v", err)
	}
}

func TestFetchArtifactPickedManifestDigestMismatch(t *testing.T) {
	cfg := []byte(`{}`)
	layer := []byte("L")
	configDesc := Descriptor{MediaType: MediaTypeOCIImageConfig, Digest: DigestFromBytes(cfg), Size: int64(len(cfg))}
	layerDesc := Descriptor{MediaType: MediaTypeOCIImageLayer, Digest: DigestFromBytes(layer), Size: int64(len(layer))}
	manifest := &Manifest{SchemaVersion: 2, Config: configDesc, Layers: []Descriptor{layerDesc}}
	manifestBody := mustMarshal(t, manifest)
	// LIE about the picked digest in the index.
	fakeDigest := DigestFromBytes([]byte("lying-about-this"))
	idx := &Index{
		SchemaVersion: 2,
		MediaType:     MediaTypeOCIIndex,
		Manifests: []Descriptor{{
			MediaType: MediaTypeOCIManifest,
			Digest:    fakeDigest,
			Platform:  &Platform{OS: "linux", Architecture: "amd64"},
		}},
	}
	indexBody := mustMarshal(t, idx)

	mt := newMockTransport(t)
	mt.On("https://reg.example.com/v2/r/manifests/latest", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIIndex}, indexBody)
	})
	mt.On("https://reg.example.com/v2/r/manifests/"+fakeDigest, func(req mockRequest) *ministack.HTTPResponse {
		// Return a manifest whose digest != fakeDigest.
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIManifest}, manifestBody)
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := FetchArtifact(reg, FetchOptions{Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "verify picked manifest") {
		t.Errorf("want verify-picked error, got %v", err)
	}
}

func TestFetchArtifactAuthenticateFailure(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(403, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := FetchArtifact(reg, FetchOptions{Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "authenticate") {
		t.Errorf("want authenticate error, got %v", err)
	}
}

func TestFetchArtifactBadIndexJSON(t *testing.T) {
	mt := newMockTransport(t)
	mt.On("https://reg.example.com/v2/r/manifests/latest", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIIndex}, []byte("not-json-but-ct-says-index"))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := FetchArtifact(reg, FetchOptions{Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "parse index") {
		t.Errorf("want parse-index error, got %v", err)
	}
}
