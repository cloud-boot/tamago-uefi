// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M7.1b probe — gated on `-tags phase2_oci_cosign_verify`.
//
// Cosign keyed-signature verification on an OCI image manifest. The
// last security gate before M8.1 (real-kernel boot) can ship trusting
// a signed image.
//
// MODE A — REAL IMAGE (default):
//
//   - bring up virtio-net → DHCP → ministack roots (same setup as M7).
//   - parse the embedded cosignTargetRef.
//   - fetch the index, pick the per-arch manifest, capture its
//     digest (`sha256:` + sha256(rawManifest)).
//   - reg.FetchManifestRaw(`sha256-<hex>.sig`) → cosign sig artifact.
//   - CosignVerifier.Verify(reg, ref, manifestDigest) → ECDSA verify
//     each layer's `dev.sigstore.cosign/v1/signature` annotation
//     against the canonical payload.
//
// MODE B — SELF-TEST (auto-fallback):
//
//   - if the configured target image has no embedded pubkey OR the
//     cosignTargetRef is empty, we fall back to a fully-offline
//     self-test that proves the verifier path end-to-end:
//       1. Generate an ephemeral P-256 keypair in-VM.
//       2. Sign the canonical cosign payload locally.
//       3. Walk a hand-built in-RAM .sig manifest blob.
//       4. CosignVerifier.Verify() against the in-RAM transport.
//     This mode does NOT require the network — DHCP/roots are still
//     brought up to mirror the live-network path, but the verifier
//     itself works against a mock Transport.
//
// The current build defaults to MODE B (no static cosign pubkey
// shipped yet). Wiring MODE A against a real signed image is the
// follow-up.

//go:build phase2_oci_cosign_verify && tamago

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// cosignTargetRef is the public OCI artifact the M7.1b real-image
// probe targets. Empty = self-test only (no network leg).
//
// When non-empty, the probe walks the index → picks the per-arch
// manifest → fetches the .sig tag → ECDSA-verifies the signature
// annotation against cosignEmbeddedPubKey.
//
// Leaving this empty is the current default because we don't yet ship
// the matching pinned pubkey for a public cosign-signed image. The
// canonical M7.1b candidate (`ghcr.io/sigstore/cosign/cosign:v2.4.0`)
// is signed KEYLESSLY (Fulcio + Rekor), which is out of scope for
// M7.1b. The self-test path proves the verifier end-to-end; wiring
// against a real keyed-cosign image is queued as a follow-up.
const cosignTargetRef = ""

// cosignEmbeddedPubKey is the PEM-encoded ECDSA P-256 public key the
// real-image path verifies against. Empty in this build because the
// real-image path is gated behind cosignTargetRef being set.
const cosignEmbeddedPubKey = ""

// runOCICosignVerifyProbe is the entry point the dispatcher calls
// when the `phase2_oci_cosign_verify` build tag is set.
func runOCICosignVerifyProbe() {
	println("phase2-oci-cosign: M7.1b - keyed cosign signature verification")
	println("phase2-oci-cosign: arch =", runtime.GOARCH)

	if cosignTargetRef == "" || cosignEmbeddedPubKey == "" {
		println("phase2-oci-cosign: MODE = self-test (no cosignTargetRef / cosignEmbeddedPubKey configured)")
		runCosignSelfTest()
		return
	}

	println("phase2-oci-cosign: MODE = real-image")
	println("phase2-oci-cosign: target =", cosignTargetRef)
	runCosignRealImage()
}

// runCosignSelfTest exercises the verifier end-to-end without the
// network: generate a keypair in-VM, sign the canonical cosign
// payload, mock the .sig manifest, and ECDSA-verify. Also exercises
// a tampered-sig negative case so we exit knowing both directions
// work in this build.
func runCosignSelfTest() {
	println("phase2-oci-cosign: generating ephemeral P-256 keypair")
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: ecdsa.GenerateKey:", err.Error())
		return
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: MarshalPKIXPublicKey:", err.Error())
		return
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	println("phase2-oci-cosign: parsing PEM pubkey into CosignVerifier")
	v, err := oci.NewCosignVerifier(pemBytes)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: NewCosignVerifier:", err.Error())
		return
	}
	println("phase2-oci-cosign: pubkey parsed - curve P-256 OK")

	ref, err := oci.ParseRef("ghcr.io/cloud-boot/m7-1b-selftest:latest")
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: ParseRef:", err.Error())
		return
	}
	manifestDigest := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	println("phase2-oci-cosign: building canonical payload")
	payload := oci.CanonicalPayload(ref.Host+"/"+ref.Repo, manifestDigest)
	println("phase2-oci-cosign: canonical payload size =", len(payload))

	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: ecdsa.SignASN1:", err.Error())
		return
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	println("phase2-oci-cosign: signed payload - b64 sig len =", len(sigB64))

	tag, err := oci.SigTag(manifestDigest)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: SigTag:", err.Error())
		return
	}
	println("phase2-oci-cosign: derived .sig tag =", tag)

	sigManifest := buildCosignSelfTestSigManifest(sigB64)

	mt := newCosignSelfTestTransport(ref, tag, sigManifest)
	reg := oci.NewRegistryWithTransport(mt, nil, ref)

	println("phase2-oci-cosign: running Verify (HAPPY path)")
	if verr := v.Verify(reg, *ref, manifestDigest); verr != nil {
		println("phase2-oci-cosign: COSIGN FAIL: happy path Verify:", verr.Error())
		return
	}
	println("phase2-oci-cosign: happy path Verify OK")

	// Negative case: flip a bit in the signature and re-verify.
	rawSig, _ := base64.StdEncoding.DecodeString(sigB64)
	rawSig[len(rawSig)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(rawSig)
	mtT := newCosignSelfTestTransport(ref, tag, buildCosignSelfTestSigManifest(tampered))
	regT := oci.NewRegistryWithTransport(mtT, nil, ref)
	println("phase2-oci-cosign: running Verify (TAMPERED signature - expect FAIL)")
	if terr := v.Verify(regT, *ref, manifestDigest); terr == nil {
		println("phase2-oci-cosign: COSIGN FAIL: tampered Verify unexpectedly passed")
		return
	}
	println("phase2-oci-cosign: tampered Verify rejected (as expected)")

	// Also exercise the network legs (DHCP + roots) so the probe
	// matches the shape of the other M7 probes and a live runner can
	// match on the same anchor lines.
	exerciseNetworkSetupForCosign()

	println("phase2-oci-cosign: COSIGN OK")
}

// runCosignRealImage walks a real signed image. Disabled in this
// build (cosignTargetRef + cosignEmbeddedPubKey are empty). Kept as
// a placeholder so the symbol exists and the call-site stays single-
// branch when the constants are later populated.
func runCosignRealImage() {
	pciIO := locateVirtioNetForCosign()
	if pciIO == 0 {
		println("phase2-oci-cosign: no modern virtio-net device found")
		println("phase2-oci-cosign: COSIGN FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase2-oci-cosign: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-oci-cosign: lease acquired")
	println("phase2-oci-cosign:   IP =", lease.IP.String())
	if len(lease.DNS) == 0 {
		println("phase2-oci-cosign: COSIGN FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-oci-cosign: COSIGN FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci-cosign: COSIGN FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-oci-cosign: embedded roots =", ministack.EmbeddedRootCount())

	ref, err := oci.ParseRef(cosignTargetRef)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: ParseRef:", err.Error())
		return
	}
	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 60 * time.Second

	if err := reg.Authenticate(); err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: FetchManifestRaw(index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-oci-cosign: COSIGN FAIL: ParseIndex:", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-oci-cosign: COSIGN FAIL: PickPlatform:", perr.Error())
			return
		}
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-oci-cosign: COSIGN FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}
	manifestDigest := oci.DigestFromBytes(rawManifest)
	println("phase2-oci-cosign: manifest digest =", manifestDigest)

	v, err := oci.NewCosignVerifier([]byte(cosignEmbeddedPubKey))
	if err != nil {
		println("phase2-oci-cosign: COSIGN FAIL: NewCosignVerifier:", err.Error())
		return
	}
	if verr := v.Verify(reg, *ref, manifestDigest); verr != nil {
		println("phase2-oci-cosign: COSIGN FAIL:", verr.Error())
		return
	}
	println("phase2-oci-cosign: COSIGN OK")
}

// exerciseNetworkSetupForCosign brings up the same network setup the
// real-image path uses so the self-test mode emits the anchor lines
// the live runner matches on (DHCP lease, embedded roots). The
// network is brought up only enough to prove DHCP+roots work — no
// fetch is performed.
func exerciseNetworkSetupForCosign() {
	pciIO := locateVirtioNetForCosign()
	if pciIO == 0 {
		println("phase2-oci-cosign: skipping network setup - no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-oci-cosign: OpenVirtioNet FAILED:", err.Error())
		return
	}
	println("phase2-oci-cosign: device UP. MAC =", vn.MAC.String())
	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()
	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-oci-cosign: DHCP4Acquire FAILED:", err.Error())
		return
	}
	println("phase2-oci-cosign: lease acquired")
	println("phase2-oci-cosign:   IP =", lease.IP.String())
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-oci-cosign: NewRootCAs FAILED:", perr.Error())
		return
	}
	println("phase2-oci-cosign: embedded roots =", ministack.EmbeddedRootCount())
}

// locateVirtioNetForCosign walks the EFI_PCI_IO_PROTOCOL handle space
// looking for the first 1AF4:1041 (modern virtio-net). Returns 0 if
// none. Same shape as the M7 / M7.1a helpers.
func locateVirtioNetForCosign() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		return 0
	}
	for _, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIPciIOProtocolGUID)
		if err != nil {
			continue
		}
		vid, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgVendorID)
		if err != nil {
			continue
		}
		did, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgDeviceID)
		if err != nil {
			continue
		}
		if vid == uefiboard.VirtioPCIVendorID && did == uefiboard.VirtioPCIDeviceIDModernNet {
			return iface
		}
	}
	return 0
}

// buildCosignSelfTestSigManifest emits a minimal cosign-shaped .sig
// manifest body carrying the supplied base64 signature on one layer.
func buildCosignSelfTestSigManifest(sigB64 string) []byte {
	return []byte(`{"schemaVersion":2,"mediaType":"` + oci.MediaTypeOCIManifest +
		`","layers":[{"mediaType":"` + oci.CosignSimpleSigningMediaType +
		`","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":42,"annotations":{"` +
		oci.CosignSignatureAnnotation + `":"` + sigB64 + `"}}]}`)
}

// cosignSelfTestTransport is an in-process oci.Transport that serves
// the cosign .sig manifest body for the expected URL. Any other URL
// surfaces as a clear error so a misrouted request can't silently
// pass.
type cosignSelfTestTransport struct {
	tagURL string
	body   []byte
}

func newCosignSelfTestTransport(ref *oci.Ref, tag string, body []byte) *cosignSelfTestTransport {
	return &cosignSelfTestTransport{
		tagURL: ref.Scheme + "://" + ref.Host + "/v2/" + ref.Repo + "/manifests/" + tag,
		body:   body,
	}
}

func (t *cosignSelfTestTransport) Get(url string, _ ministack.HTTPGetOptions) (*ministack.HTTPResponse, error) {
	if url != t.tagURL {
		return &ministack.HTTPResponse{
			StatusCode: 404,
			StatusLine: "HTTP/1.1 404 Not Found (selftest)",
			Headers:    map[string]string{},
			Body:       []byte("selftest: unknown url"),
		}, nil
	}
	return &ministack.HTTPResponse{
		StatusCode: 200,
		StatusLine: "HTTP/1.1 200 OK (selftest)",
		Headers:    map[string]string{"content-type": oci.MediaTypeOCIManifest},
		Body:       t.body,
	}, nil
}
