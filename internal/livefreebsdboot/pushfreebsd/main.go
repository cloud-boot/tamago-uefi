// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// pushfreebsd — push a single FreeBSD disk-image artifact to an OCI
// Distribution v2 registry as a single-layer image.
//
// Used by internal/livefreebsdboot/run.sh to publish the per-run
// FreeBSD bootable disk image (downloaded from download.freebsd.org)
// to ttl.sh so the Phase 3 sprint 1 live runner has a real public
// OCI ref to stream from.
//
// Wire shape:
//
//   manifest
//     mediaType:    application/vnd.oci.image.manifest.v1+json
//     artifactType: application/vnd.cloud-boot.diskimage.v1
//     config:       application/vnd.oci.empty.v1+json   ({} — 2 bytes)
//     layers[0]:    application/vnd.cloud-boot.diskimage.raw.v1
//                   (raw disk image bytes, NOT gzipped — the probe
//                   reads them directly into a Block IO publisher)
//
// Usage:
//   pushfreebsd -src FreeBSD-14.3-RELEASE-amd64-bootonly.iso -dst ttl.sh/cloudboot-freebsd-XXXX:24h
//
// Anonymous push only — ttl.sh accepts any tag without auth. Mirrors
// internal/livedhcpocimenu/pushbootmenu/main.go for the registry
// upload semantics.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	specsgo "github.com/opencontainers/image-spec/specs-go"
)

const (
	diskImageArtifactType   = "application/vnd.cloud-boot.diskimage.v1"
	diskImageLayerMediaType = "application/vnd.cloud-boot.diskimage.raw.v1"
)

func main() {
	src := flag.String("src", "", "path to the FreeBSD disk image (.iso or .img) to publish")
	dst := flag.String("dst", "", "OCI ref to push to (e.g. ttl.sh/cloudboot-freebsd-XXXX:24h)")
	flag.Parse()
	if *src == "" || *dst == "" {
		log.Fatalf("usage: pushfreebsd -src <file.iso> -dst <host/repo:tag>")
	}
	img, err := os.ReadFile(*src)
	if err != nil {
		log.Fatalf("read %s: %v", *src, err)
	}
	if len(img) == 0 {
		log.Fatalf("source %s is empty", *src)
	}

	// Sanity checks: protective MBR signature + GPT magic at LBA 1.
	if len(img) < 520 ||
		img[510] != 0x55 || img[511] != 0xAA {
		log.Fatalf("source %s missing MBR signature at offset 510..511 (not a bootable disk image)", *src)
	}
	if string(img[512:520]) != "EFI PART" {
		log.Fatalf("source %s missing 'EFI PART' GPT magic at LBA 1 (not a GPT image)", *src)
	}

	layerDig := digest.FromBytes(img)
	configJSON := []byte(`{}`)
	configDig := digest.FromBytes(configJSON)

	manifest := ocispec.Manifest{
		Versioned:    specsgo.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: diskImageArtifactType,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    configDig,
			Size:      int64(len(configJSON)),
			Data:      configJSON,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: diskImageLayerMediaType,
			Digest:    layerDig,
			Size:      int64(len(img)),
			Annotations: map[string]string{
				"org.opencontainers.image.title": "diskimage.raw",
			},
		}},
		Annotations: map[string]string{
			"org.opencontainers.image.description": "cloud-boot Phase 3 sprint 1 FreeBSD disk image (raw GPT+ESP)",
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		log.Fatalf("manifest marshal: %v", err)
	}

	log.Printf("publishing %d-byte disk image -> %s", len(img), *dst)
	if err := pushOCI(*dst, configJSON, configDig, img, layerDig, manifestJSON); err != nil {
		log.Fatalf("push: %v", err)
	}
	fmt.Printf("PUSHED %s\n", *dst)
	fmt.Printf("  layer digest: %s\n", layerDig)
	fmt.Printf("  manifest:     %d bytes\n", len(manifestJSON))
}

func hostOf(ref string) string {
	if i := strings.Index(ref, "/"); i >= 0 {
		return ref[:i]
	}
	return ref
}

func repoOf(ref string) string {
	rest := ref
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		return rest[:i]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		return rest[:i]
	}
	return rest
}

func tagOf(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 {
		return ref[i+1:]
	}
	rest := ref
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		return rest[i+1:]
	}
	return "latest"
}

// pushOCI is trimmed-down anonymous-only single-layer push. Identical
// shape to internal/livedhcpocimenu/pushbootmenu/main.go.
func pushOCI(ref string, configJSON []byte, configDig digest.Digest, layer []byte, layerDig digest.Digest, manifestJSON []byte) error {
	host := hostOf(ref)
	repo := repoOf(ref)
	tag := tagOf(ref)
	scheme := "https"

	uploadBlob := func(blob []byte, dig digest.Digest) error {
		postURL := fmt.Sprintf("%s://%s/v2/%s/blobs/uploads/", scheme, host, repo)
		req, _ := http.NewRequest("POST", postURL, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("POST uploads: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != 202 && resp.StatusCode != 201 {
			return fmt.Errorf("POST uploads: status %d body=%q", resp.StatusCode, string(body))
		}
		loc := resp.Header.Get("Location")
		if loc == "" {
			return fmt.Errorf("POST uploads: missing Location header")
		}
		if strings.HasPrefix(loc, "/") {
			loc = fmt.Sprintf("%s://%s%s", scheme, host, loc)
		}
		sep := "?"
		if strings.Contains(loc, "?") {
			sep = "&"
		}
		putURL := loc + sep + "digest=" + string(dig)
		req2, _ := http.NewRequest("PUT", putURL, bytes.NewReader(blob))
		req2.Header.Set("Content-Type", "application/octet-stream")
		req2.ContentLength = int64(len(blob))
		resp2, err := http.DefaultClient.Do(req2)
		if err != nil {
			return fmt.Errorf("PUT blob: %w", err)
		}
		body2, _ := io.ReadAll(resp2.Body)
		resp2.Body.Close()
		if resp2.StatusCode != 201 && resp2.StatusCode != 202 && resp2.StatusCode != 204 {
			return fmt.Errorf("PUT blob: status %d body=%q", resp2.StatusCode, string(body2))
		}
		log.Printf("           uploaded blob %s (%d bytes) status=%d", dig, len(blob), resp2.StatusCode)
		return nil
	}

	if err := uploadBlob(configJSON, configDig); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := uploadBlob(layer, layerDig); err != nil {
		return fmt.Errorf("layer: %w", err)
	}

	manifestURL := fmt.Sprintf("%s://%s/v2/%s/manifests/%s", scheme, host, repo, tag)
	req, _ := http.NewRequest("PUT", manifestURL, bytes.NewReader(manifestJSON))
	req.Header.Set("Content-Type", ocispec.MediaTypeImageManifest)
	req.ContentLength = int64(len(manifestJSON))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("PUT manifest: %w", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 202 {
		return fmt.Errorf("PUT manifest: status %d body=%q", resp.StatusCode, string(body))
	}
	log.Printf("           uploaded manifest -> %s status=%d", manifestURL, resp.StatusCode)
	return nil
}
