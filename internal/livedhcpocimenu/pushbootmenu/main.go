// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// pushbootmenu — push a single HCL boot-menu artifact to an OCI
// Distribution v2 registry as a single-layer, single-blob image.
//
// Used by internal/livedhcpocimenu/run.sh to publish the per-run
// sample HCL config to ttl.sh so the M9.0 live runner has a real
// public OCI ref to advertise via DHCP option 67.
//
// Wire shape (matches what the M9.0 probe expects):
//
//   manifest
//     mediaType:    application/vnd.oci.image.manifest.v1+json
//     artifactType: application/vnd.cloud-boot.bootmenu.v1
//     config:       application/vnd.oci.empty.v1+json   ({} — 2 bytes)
//     layers[0]:    application/vnd.cloud-boot.bootmenu.hcl.v1
//                   (raw HCL bytes, NOT gzipped, NOT tar-wrapped)
//
// Usage:
//   pushbootmenu -src bootconfig.hcl -dst ttl.sh/cloudboot-m90-XXXX:24h
//
// Anonymous push only — ttl.sh accepts any tag without auth, and
// that's the only destination M9.0 live testing needs. (ghcr.io would
// need a separate bearer-auth leg; not in scope.)
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
	bootmenuArtifactType   = "application/vnd.cloud-boot.bootmenu.v1"
	bootmenuLayerMediaType = "application/vnd.cloud-boot.bootmenu.hcl.v1"
)

func main() {
	src := flag.String("src", "", "path to the HCL boot-menu file to publish")
	dst := flag.String("dst", "", "OCI ref to push to (e.g. ttl.sh/cloudboot-m90-XXXX:24h)")
	flag.Parse()
	if *src == "" || *dst == "" {
		log.Fatalf("usage: pushbootmenu -src <file.hcl> -dst <host/repo:tag>")
	}
	hcl, err := os.ReadFile(*src)
	if err != nil {
		log.Fatalf("read %s: %v", *src, err)
	}
	if len(hcl) == 0 {
		log.Fatalf("source %s is empty", *src)
	}

	layerDig := digest.FromBytes(hcl)
	configJSON := []byte(`{}`)
	configDig := digest.FromBytes(configJSON)

	manifest := ocispec.Manifest{
		Versioned:    specsgo.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: bootmenuArtifactType,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    configDig,
			Size:      int64(len(configJSON)),
			Data:      configJSON,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: bootmenuLayerMediaType,
			Digest:    layerDig,
			Size:      int64(len(hcl)),
			Annotations: map[string]string{
				"org.opencontainers.image.title": "bootconfig.hcl",
			},
		}},
		Annotations: map[string]string{
			"org.opencontainers.image.description": "cloud-boot M9 DHCP-discovered OCI boot menu (HCL)",
		},
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		log.Fatalf("manifest marshal: %v", err)
	}

	log.Printf("publishing %d-byte HCL -> %s", len(hcl), *dst)
	if err := pushOCI(*dst, configJSON, configDig, hcl, layerDig, manifestJSON); err != nil {
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
	// ref includes host/repo:tag — take the LAST ":" but only on the
	// repo portion (host:port is OK as long as a "/" follows it).
	rest := ref
	if i := strings.Index(rest, "/"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		return rest[i+1:]
	}
	return "latest"
}

// pushOCI is a trimmed-down version of cmd/cloudboot-oci-extract's
// pushOCI: anonymous-only (ttl.sh), single layer, single config blob.
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
