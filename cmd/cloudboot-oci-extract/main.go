// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloudboot-oci-extract — extract a vmlinuz (EFI-stub PE32+) kernel
// from a published source and republish it as a single-blob OCI
// artifact.
//
// Why this exists (M8.4 rv64+loong64 dormant gap, 2026-06-10): the
// public OCI registry landscape doesn't ship standalone EFI-stub
// kernel artifacts for riscv64 or loongarch64. The kernels DO exist —
// they sit inside per-distro packages (Debian .deb under
// pool/main/l/linux/) — but no upstream publishes them as
// `application/vnd.cloud-boot.efistub-kernel.v1` OCI blobs that the
// tamago-uefi MODE C OCI loader can stream.
//
// This tool closes the gap by:
//
//   1. Downloading a known kernel-bearing source (.deb today; rootfs
//      OCI layer tomorrow once one ships /boot/vmlinuz).
//   2. Walking the archive, locating the vmlinuz / vmlinux matching
//      the requested arch.
//   3. Validating the bytes are a PE32+ EFI application with the
//      correct COFF Machine field (0x5064 riscv64, 0x6264 loongarch64,
//      0xaa64 arm64, 0x8664 amd64).
//   4. Re-packaging as a single-blob OCI artifact and pushing to the
//      destination ref using the OCI Distribution v2 push protocol.
//
// Pure Go, no CGO, stdlib only (plus opencontainers/image-spec for
// the manifest type — already a tamago-uefi dependency — plus
// github.com/ulikunitz/xz for the .deb data.tar.xz inner archive).
//
// Sources supported today:
//
//   deb:<url>
//       Plain Debian .deb URL (ar archive containing data.tar.xz).
//       Used for riscv64 + loong64 since those arches have no
//       kernel-bearing OCI rootfs yet (verified 2026-06-10 against
//       riscv64/debian:sid, ghcr.io/loong64/openeuler:*-{default,
//       init,base,toolbox,minimal,micro}).
//
//   oci:<ref>
//       Public anonymous OCI rootfs ref whose first layer's tar.gz
//       contains /boot/vmlinuz-*. (Reserved for the day a rootfs
//       ships a kernel for these arches.)
//
// Destinations supported:
//
//   <host>/<repo>:<tag>
//       OCI Distribution v2 anonymous-push endpoint. Validated
//       against ttl.sh; future ghcr.io/cloud-boot/* with bearer
//       token is a straight Authorization-header addition.
//
// Why ttl.sh: it accepts anonymous PUTs (validated 2026-06-10 with
// `curl -XPOST https://ttl.sh/v2/<any-repo>/blobs/uploads/` → 202)
// and lives 24h. Long enough to populate the per-arch consts and
// run a live test. Permanent re-publish lives in the nightly
// workflow `.github/workflows/vmlinuz-nightly.yml` (cron 04:00 UTC).
//
// Permanence path (M8.4 follow-up, 2026-06-10): pass
// `-push-to-ghcr ghcr.io/<owner>/<repo>:<tag>` and set env-var
// `GHCR_TOKEN` to a `write:packages` PAT. The tool then performs a
// SECOND push leg with `Authorization: Bearer $GHCR_TOKEN` on every
// POST/PUT, after the first (anonymous) ttl.sh leg succeeds. The two
// pushes are independent — ttl.sh failing does NOT skip ghcr.io and
// vice versa; both errors are reported, and exit-code is non-zero if
// either fails. If `-push-to-ghcr` is empty OR `GHCR_TOKEN` is unset
// the secondary leg is skipped silently with a single-line notice.

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	digest "github.com/opencontainers/go-digest"
	specsgo "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"

	"github.com/ulikunitz/xz"
)

// efistubKernelMediaType: cloud-boot semantic media-type for the
// single-blob raw-kernel layer (not what the in-tree MODE C loader
// uses today — it expects a tar.gz containing boot/vmlinuz, see
// kernelLayerMediaType).
const efistubKernelMediaType = "application/vnd.cloud-boot.efistub-kernel.v1"

// kernelLayerMediaType: docker rootfs tar.gz, matching the wire shape
// the in-tree streamExtractVmlinuz reader expects (gunzip+tar walk
// for boot/vmlinuz). Using the standard docker media-type keeps the
// arm64 → riscv64/loong64 wiring uniform.
const kernelLayerMediaType = "application/vnd.docker.image.rootfs.diff.tar.gzip"

// COFF Machine constants per PE32+ spec.
const (
	coffMachineAMD64   = 0x8664
	coffMachineARM64   = 0xaa64
	coffMachineRISCV64 = 0x5064
	coffMachineLOONG64 = 0x6264
)

func coffMachineFor(arch string) (uint16, error) {
	switch arch {
	case "amd64", "x86_64":
		return coffMachineAMD64, nil
	case "arm64", "aarch64":
		return coffMachineARM64, nil
	case "riscv64":
		return coffMachineRISCV64, nil
	case "loong64", "loongarch64":
		return coffMachineLOONG64, nil
	}
	return 0, fmt.Errorf("unknown arch %q", arch)
}

func main() {
	src := flag.String("src", "", "source URL: deb:https://... or oci:host/repo:tag")
	arch := flag.String("arch", "", "target arch: riscv64 | loong64 | loongarch64 | arm64 | amd64")
	dst := flag.String("dst", "", "destination OCI ref: host/repo:tag (e.g. ttl.sh/foo:24h)")
	pushToGHCR := flag.String("push-to-ghcr", "", "optional secondary destination on ghcr.io (e.g. ghcr.io/cloud-boot/vmlinuz-riscv64:latest); reads PAT from env GHCR_TOKEN (scope: write:packages); skipped silently if empty or GHCR_TOKEN unset")
	cmdlineHint := flag.String("cmdline-hint", "", "optional kernel cmdline to embed as manifest annotation")
	flag.Parse()

	if *src == "" || *arch == "" || *dst == "" {
		flag.Usage()
		os.Exit(2)
	}

	wantMachine, err := coffMachineFor(*arch)
	if err != nil {
		log.Fatalf("arch: %v", err)
	}

	log.Printf("step 1/4: fetch source %s", *src)
	kernel, kernelName, err := fetchKernel(*src, *arch)
	if err != nil {
		log.Fatalf("fetch: %v", err)
	}
	log.Printf("           %s extracted (%d bytes)", kernelName, len(kernel))

	log.Printf("step 2/4: PE32+ validation (arch=%s machine=0x%04x)", *arch, wantMachine)
	if err := validateEFIStub(kernel, wantMachine); err != nil {
		log.Fatalf("validate: %v", err)
	}
	log.Printf("           MZ + PE\\0\\0 + COFF Machine ok")

	log.Printf("step 3/4: package as OCI artifact (tar.gz containing boot/vmlinuz)")
	layer, err := packageAsTarGz(kernel, "boot/vmlinuz")
	if err != nil {
		log.Fatalf("package tar.gz: %v", err)
	}
	layerDig, layerSize := digestOf(layer)
	log.Printf("           layer: %d bytes (raw %d → gzip %d, ratio %.1f%%)",
		len(layer), len(kernel), len(layer), 100.0*float64(len(layer))/float64(len(kernel)))
	configJSON := []byte(`{}`)
	configDig, configSize := digestOf(configJSON)
	manifest := ocispec.Manifest{
		Versioned:    specsgo.Versioned{SchemaVersion: 2},
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: efistubKernelMediaType,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    configDig,
			Size:      configSize,
			Data:      configJSON,
		},
		Layers: []ocispec.Descriptor{{
			MediaType: kernelLayerMediaType,
			Digest:    layerDig,
			Size:      layerSize,
			Annotations: map[string]string{
				"org.opencontainers.image.title":  kernelName,
				"cloud-boot.efistub.arch":         *arch,
				"cloud-boot.efistub.coff-machine": fmt.Sprintf("0x%04x", wantMachine),
				"cloud-boot.efistub.raw-size":     fmt.Sprintf("%d", len(kernel)),
			},
		}},
		Annotations: map[string]string{
			"org.opencontainers.image.description": "cloud-boot EFI-stub kernel (extracted by cloudboot-oci-extract)",
			"cloud-boot.efistub.source":            *src,
		},
	}
	if *cmdlineHint != "" {
		manifest.Annotations["cloud-boot.kernel.cmdline-hint"] = *cmdlineHint
	}
	manifestJSON, err := json.Marshal(manifest)
	if err != nil {
		log.Fatalf("manifest marshal: %v", err)
	}

	log.Printf("step 4/4: push to %s (anonymous)", *dst)
	primaryErr := pushOCI(*dst, "", configJSON, configDig, layer, layerDig, manifestJSON)
	if primaryErr != nil {
		log.Printf("           PRIMARY push FAILED: %v", primaryErr)
	} else {
		fmt.Printf("\nPUSHED %s\n", *dst)
		fmt.Printf("  kernel:   %s (raw %d bytes, layer tar.gz %d bytes, %s)\n", kernelName, len(kernel), len(layer), layerDig)
		fmt.Printf("  manifest: %d bytes\n", len(manifestJSON))
		fmt.Printf("  pull via: curl -L https://%s/v2/%s/blobs/%s\n",
			hostOf(*dst), repoOf(*dst), layerDig)
	}

	// Secondary leg: ghcr.io permanent push (bearer-auth).
	var secondaryErr error
	switch {
	case *pushToGHCR == "":
		log.Printf("ghcr.io push skipped: -push-to-ghcr flag empty")
	case os.Getenv("GHCR_TOKEN") == "":
		log.Printf("ghcr.io push skipped: no GHCR_TOKEN secret")
	default:
		log.Printf("step 4b: push to %s (bearer-auth ghcr.io)", *pushToGHCR)
		token := os.Getenv("GHCR_TOKEN")
		secondaryErr = pushOCI(*pushToGHCR, token, configJSON, configDig, layer, layerDig, manifestJSON)
		if secondaryErr != nil {
			log.Printf("           GHCR push FAILED: %v", secondaryErr)
		} else {
			fmt.Printf("\nPUSHED %s\n", *pushToGHCR)
			fmt.Printf("  pull via: docker pull %s\n", *pushToGHCR)
		}
	}

	if primaryErr != nil || secondaryErr != nil {
		os.Exit(1)
	}
}

// packageAsTarGz wraps `data` inside a tar.gz with a single entry
// at `name` (mode 0644, uid/gid 0). Matches the wire shape that
// tamago-uefi's streamExtractVmlinuz expects (gunzip+tar walk for
// boot/vmlinuz).
func packageAsTarGz(data []byte, name string) ([]byte, error) {
	var buf bytes.Buffer
	gz, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name:     name,
		Mode:     0644,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
		Uid:      0,
		Gid:      0,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return nil, err
	}
	if _, err := tw.Write(data); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// validateEFIStub checks that b starts with "MZ", has a valid
// pe_offset at 0x3C, "PE\0\0" at that offset, and the COFF Machine
// field at pe_offset+4 matches want.
func validateEFIStub(b []byte, want uint16) error {
	if len(b) < 0x40 {
		return fmt.Errorf("too short (%d bytes)", len(b))
	}
	if b[0] != 'M' || b[1] != 'Z' {
		return fmt.Errorf("missing MZ magic at byte 0")
	}
	peOff := int(uint32(b[0x3c]) | uint32(b[0x3d])<<8 | uint32(b[0x3e])<<16 | uint32(b[0x3f])<<24)
	if peOff < 0 || peOff+6 > len(b) {
		return fmt.Errorf("pe_offset 0x%x out of range", peOff)
	}
	if string(b[peOff:peOff+4]) != "PE\x00\x00" {
		return fmt.Errorf("missing PE\\0\\0 at offset 0x%x", peOff)
	}
	got := uint16(b[peOff+4]) | uint16(b[peOff+5])<<8
	if got != want {
		return fmt.Errorf("COFF Machine 0x%04x != want 0x%04x", got, want)
	}
	return nil
}

func digestOf(b []byte) (digest.Digest, int64) {
	h := sha256.Sum256(b)
	return digest.Digest("sha256:" + hex.EncodeToString(h[:])), int64(len(b))
}

// ----------------- fetch + extract -----------------

func fetchKernel(src, arch string) ([]byte, string, error) {
	switch {
	case strings.HasPrefix(src, "deb:"):
		return fetchKernelDeb(strings.TrimPrefix(src, "deb:"), arch)
	case strings.HasPrefix(src, "oci:"):
		return fetchKernelOCI(strings.TrimPrefix(src, "oci:"), arch)
	}
	return nil, "", fmt.Errorf("unknown source scheme: %s", src)
}

func fetchKernelDeb(url, arch string) ([]byte, string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	debBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	log.Printf("           downloaded %d bytes from %s", len(debBytes), url)

	dataBytes, dataName, err := arFindMember(debBytes, "data.tar.")
	if err != nil {
		return nil, "", fmt.Errorf("ar: %w", err)
	}
	log.Printf("           ar member: %s (%d bytes)", dataName, len(dataBytes))

	var tarReader io.Reader
	switch {
	case strings.HasSuffix(dataName, ".xz"):
		xr, err := xz.NewReader(bytes.NewReader(dataBytes))
		if err != nil {
			return nil, "", fmt.Errorf("xz: %w", err)
		}
		tarReader = xr
	case strings.HasSuffix(dataName, ".gz"):
		gr, err := gzip.NewReader(bytes.NewReader(dataBytes))
		if err != nil {
			return nil, "", fmt.Errorf("gzip: %w", err)
		}
		defer gr.Close()
		tarReader = gr
	default:
		tarReader = bytes.NewReader(dataBytes)
	}

	return findKernelInTar(tarReader, arch)
}

func fetchKernelOCI(ref, arch string) ([]byte, string, error) {
	return nil, "", fmt.Errorf("oci: source not implemented for this arch (no rootfs ships /boot/vmlinuz for riscv64/loong64 as of 2026-06-10; use deb: scheme)")
}

func findKernelInTar(r io.Reader, arch string) ([]byte, string, error) {
	archAliases := map[string][]string{
		"riscv64":     {"riscv64"},
		"loong64":     {"loong64", "loongarch64"},
		"loongarch64": {"loong64", "loongarch64"},
		"arm64":       {"arm64", "aarch64"},
		"amd64":       {"amd64", "x86_64"},
	}
	aliases := archAliases[arch]
	if aliases == nil {
		aliases = []string{arch}
	}

	type candidate struct {
		name string
		data []byte
	}
	var vmlinuz, vmlinux *candidate

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name := hdr.Name
		base := name
		if i := strings.LastIndex(name, "/"); i >= 0 {
			base = name[i+1:]
		}
		if !strings.HasPrefix(base, "vmlinuz") && !strings.HasPrefix(base, "vmlinux") && !strings.HasPrefix(base, "Image") {
			continue
		}
		matched := false
		for _, a := range aliases {
			if strings.Contains(base, a) {
				matched = true
				break
			}
		}
		// Many .debs put the kernel under arch-naked name (single-arch
		// pool). Accept those.
		if !matched {
			matched = true
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return nil, "", err
		}
		c := &candidate{name: base, data: data}
		switch {
		case strings.HasPrefix(base, "vmlinuz"):
			if vmlinuz == nil {
				vmlinuz = c
			}
		case strings.HasPrefix(base, "vmlinux"):
			if vmlinux == nil {
				vmlinux = c
			}
		case strings.HasPrefix(base, "Image"):
			if vmlinuz == nil {
				vmlinuz = c
			}
		}
	}
	if vmlinuz != nil {
		return vmlinuz.data, vmlinuz.name, nil
	}
	if vmlinux != nil {
		return vmlinux.data, vmlinux.name, nil
	}
	return nil, "", fmt.Errorf("no /boot/vmlinuz nor /boot/vmlinux found in archive (arch=%s)", arch)
}

// ----------------- AR (GNU ar / .deb) -----------------

func arFindMember(b []byte, prefix string) ([]byte, string, error) {
	if len(b) < 8 || string(b[:8]) != "!<arch>\n" {
		return nil, "", fmt.Errorf("not an ar archive")
	}
	off := 8
	for off+60 <= len(b) {
		nameField := strings.TrimRight(string(b[off:off+16]), " /")
		sizeStr := strings.TrimSpace(string(b[off+48 : off+58]))
		fmagic := string(b[off+58 : off+60])
		if fmagic != "`\n" {
			return nil, "", fmt.Errorf("bad ar magic at offset %d", off)
		}
		var size int
		if _, err := fmt.Sscanf(sizeStr, "%d", &size); err != nil {
			return nil, "", fmt.Errorf("bad size %q: %w", sizeStr, err)
		}
		dataStart := off + 60
		if dataStart+size > len(b) {
			return nil, "", fmt.Errorf("ar member %q truncated", nameField)
		}
		if strings.HasPrefix(nameField, prefix) {
			return b[dataStart : dataStart+size], nameField, nil
		}
		off = dataStart + size
		if off%2 == 1 {
			off++
		}
	}
	return nil, "", fmt.Errorf("ar member %s* not found", prefix)
}

// ----------------- OCI Distribution v2 push -----------------

func hostOf(ref string) string {
	if i := strings.Index(ref, "/"); i >= 0 {
		return ref[:i]
	}
	return ref
}

func repoOf(ref string) string {
	r := ref
	if i := strings.Index(r, "/"); i >= 0 {
		r = r[i+1:]
	}
	if i := strings.LastIndex(r, ":"); i >= 0 {
		r = r[:i]
	}
	return r
}

func tagOf(ref string) string {
	r := ref
	slash := strings.Index(r, "/")
	if i := strings.LastIndex(r, ":"); i > slash {
		return r[i+1:]
	}
	return "latest"
}

// pushOCI performs OCI Distribution v2 anonymous push when
// bearerToken == "", or bearer-auth push (used for ghcr.io) when
// bearerToken is non-empty. The bearer token is attached to every
// POST and PUT in the upload sequence.
func pushOCI(ref, bearerToken string, configJSON []byte, configDig digest.Digest, layer []byte, layerDig digest.Digest, manifestJSON []byte) error {
	host := hostOf(ref)
	repo := repoOf(ref)
	tag := tagOf(ref)
	scheme := "https"

	authReq := func(req *http.Request) {
		if bearerToken != "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}
	}

	uploadBlob := func(blob []byte, dig digest.Digest) error {
		postURL := fmt.Sprintf("%s://%s/v2/%s/blobs/uploads/", scheme, host, repo)
		req, _ := http.NewRequest("POST", postURL, nil)
		authReq(req)
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
		authReq(req2)
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
	authReq(req)
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
