// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import "testing"

const sampleIndex = `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:aaaa",
      "size": 670,
      "platform": { "architecture": "amd64", "os": "linux" }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:bbbb",
      "size": 670,
      "platform": { "architecture": "arm64", "os": "linux" }
    }
  ]
}`

const sampleManifest = `{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:cfgcfg",
    "size": 1744
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:l1l1",
      "size": 100
    }
  ]
}`

func TestParseIndex(t *testing.T) {
	idx, err := ParseIndex([]byte(sampleIndex))
	if err != nil {
		t.Fatalf("ParseIndex: %v", err)
	}
	if len(idx.Manifests) != 2 {
		t.Errorf("manifests=%d", len(idx.Manifests))
	}
	if idx.Manifests[1].Platform.Architecture != "arm64" {
		t.Errorf("arm64 not at idx[1]")
	}
}

func TestParseIndexRejectsEmpty(t *testing.T) {
	if _, err := ParseIndex(nil); err != ErrManifestEmpty {
		t.Errorf("want ErrManifestEmpty, got %v", err)
	}
}

func TestParseIndexRejectsBadJSON(t *testing.T) {
	if _, err := ParseIndex([]byte("not-json")); err == nil {
		t.Errorf("expected JSON error")
	}
}

func TestParseManifest(t *testing.T) {
	m, err := ParseManifest([]byte(sampleManifest))
	if err != nil {
		t.Fatalf("ParseManifest: %v", err)
	}
	if m.Config.Digest != "sha256:cfgcfg" {
		t.Errorf("config digest=%s", m.Config.Digest)
	}
	if len(m.Layers) != 1 || m.Layers[0].Digest != "sha256:l1l1" {
		t.Errorf("layers=%+v", m.Layers)
	}
}

func TestParseManifestRejectsEmpty(t *testing.T) {
	if _, err := ParseManifest(nil); err != ErrManifestEmpty {
		t.Errorf("want ErrManifestEmpty, got %v", err)
	}
}

func TestParseManifestRejectsBadJSON(t *testing.T) {
	if _, err := ParseManifest([]byte("{")); err == nil {
		t.Errorf("expected JSON error")
	}
}

func TestIsIndexByContentType(t *testing.T) {
	if !IsIndex(nil, MediaTypeOCIIndex) {
		t.Errorf("OCI index ct should be index")
	}
	if !IsIndex(nil, MediaTypeDockerIndex) {
		t.Errorf("Docker index ct should be index")
	}
	if IsIndex(nil, MediaTypeOCIManifest) {
		t.Errorf("OCI manifest ct should NOT be index")
	}
}

func TestIsIndexByBodySniff(t *testing.T) {
	// Index body without Content-Type → must sniff.
	if !IsIndex([]byte(sampleIndex), "") {
		t.Errorf("body sniff missed index")
	}
	if IsIndex([]byte(sampleManifest), "") {
		t.Errorf("body sniff false-positive on manifest")
	}
}

func TestIsIndexRejectsBadJSON(t *testing.T) {
	if IsIndex([]byte("nope"), "") {
		t.Errorf("bad JSON should not be index")
	}
}

func TestPickPlatform(t *testing.T) {
	idx, err := ParseIndex([]byte(sampleIndex))
	if err != nil {
		t.Fatal(err)
	}
	d, err := PickPlatform(idx, "linux", "arm64")
	if err != nil {
		t.Fatalf("PickPlatform: %v", err)
	}
	if d.Digest != "sha256:bbbb" {
		t.Errorf("picked = %s", d.Digest)
	}
}

func TestPickPlatformNoMatch(t *testing.T) {
	idx, err := ParseIndex([]byte(sampleIndex))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PickPlatform(idx, "linux", "riscv64"); err != ErrIndexNoMatch {
		t.Errorf("want ErrIndexNoMatch, got %v", err)
	}
}

func TestPickPlatformSkipsMissingPlatform(t *testing.T) {
	idx := &Index{Manifests: []Descriptor{
		{Digest: "sha256:no-platform"},
		{Digest: "sha256:has-platform", Platform: &Platform{OS: "linux", Architecture: "amd64"}},
	}}
	d, err := PickPlatform(idx, "linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	if d.Digest != "sha256:has-platform" {
		t.Errorf("picked wrong: %s", d.Digest)
	}
}
