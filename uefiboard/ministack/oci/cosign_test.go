// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// ----- helpers ----------------------------------------------------

// genTestKey generates an ephemeral P-256 keypair for one test and
// returns the priv key plus the PEM-encoded public half (cosign on-
// disk shape).
func genTestKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return priv, pemBytes
}

// signPayloadB64 signs `payload` with priv and returns the base64-
// encoded ASN.1-DER ECDSA signature (cosign's on-disk shape).
func signPayloadB64(t *testing.T, priv *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// buildSigManifestOne returns the JSON bytes of a cosign-style .sig
// manifest with a single layer carrying the supplied base64 sig
// annotation (empty → annotation key omitted).
func buildSigManifestOne(sigB64 string) []byte {
	if sigB64 == "" {
		return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` +
			`{"mediaType":"` + CosignSimpleSigningMediaType + `","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":42,"annotations":{}}` +
			`]}`)
	}
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` +
		`{"mediaType":"` + CosignSimpleSigningMediaType + `","digest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","size":42,"annotations":{"` +
		CosignSignatureAnnotation + `":"` + sigB64 + `"}}` +
		`]}`)
}

// buildSigManifestTwo returns a .sig manifest with two layers carrying
// the supplied annotations (empty → drop annotation on that layer).
func buildSigManifestTwo(firstSigB64, secondSigB64 string) []byte {
	layer := func(sig string) string {
		if sig == "" {
			return `{"mediaType":"` + CosignSimpleSigningMediaType + `","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":42,"annotations":{}}`
		}
		return `{"mediaType":"` + CosignSimpleSigningMediaType + `","digest":"sha256:2222222222222222222222222222222222222222222222222222222222222222","size":42,"annotations":{"` + CosignSignatureAnnotation + `":"` + sig + `"}}`
	}
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` +
		layer(firstSigB64) + `,` + layer(secondSigB64) + `]}`)
}

// emptyLayersSigManifest is a .sig manifest body with zero layers.
var emptyLayersSigManifest = []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[]}`)

// sigHandler returns a mockHandler that always replies (status, body)
// for the .sig manifest URL.
func sigHandler(status int, body []byte) mockHandler {
	return func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(status, map[string]string{"content-type": MediaTypeOCIManifest}, body)
	}
}

// mustSigReg wires a Registry whose mock transport serves (status,
// body) at the cosign .sig tag URL.
func mustSigReg(t *testing.T, env *sigVerifyEnv, status int, body []byte) *Registry {
	t.Helper()
	mt := newMockTransport(t)
	mt.On(env.tagURL, sigHandler(status, body))
	return NewRegistryWithTransport(mt, nil, env.ref)
}

// sigVerifyEnv bundles the moving parts for a Verify-call test.
type sigVerifyEnv struct {
	priv           *ecdsa.PrivateKey
	verifier       *CosignVerifier
	ref            *Ref
	manifestDigest string
	payload        []byte
	tagURL         string
}

func newSigVerifyEnv(t *testing.T) *sigVerifyEnv {
	t.Helper()
	priv, pemBytes := genTestKey(t)
	v, err := NewCosignVerifier(pemBytes)
	if err != nil {
		t.Fatalf("NewCosignVerifier: %v", err)
	}
	ref, err := ParseRef("ghcr.io/cloud-boot/test:latest")
	if err != nil {
		t.Fatalf("ParseRef: %v", err)
	}
	digest := "sha256:" + strings.Repeat("c", 64)
	payload := CanonicalPayload(ref.Host+"/"+ref.Repo, digest)
	tag, _ := SigTag(digest)
	return &sigVerifyEnv{
		priv:           priv,
		verifier:       v,
		ref:            ref,
		manifestDigest: digest,
		payload:        payload,
		tagURL:         ref.manifestURL(tag),
	}
}

// ----- NewCosignVerifier ------------------------------------------

func TestNewCosignVerifierP256OK(t *testing.T) {
	_, pemBytes := genTestKey(t)
	v, err := NewCosignVerifier(pemBytes)
	if err != nil {
		t.Fatalf("NewCosignVerifier: %v", err)
	}
	if v.PubKey == nil {
		t.Fatal("PubKey nil")
	}
}

func TestNewCosignVerifierBadPEM(t *testing.T) {
	if _, err := NewCosignVerifier([]byte("not a pem")); err != ErrCosignPEMBad {
		t.Errorf("want ErrCosignPEMBad, got %v", err)
	}
}

func TestNewCosignVerifierBadDER(t *testing.T) {
	bogus := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not der")})
	if _, err := NewCosignVerifier(bogus); err == nil {
		t.Fatal("want parse error, got nil")
	}
}

func TestNewCosignVerifierRejectsRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := NewCosignVerifier(pemBytes); err != ErrCosignKeyNotECDSA {
		t.Errorf("want ErrCosignKeyNotECDSA, got %v", err)
	}
}

func TestNewCosignVerifierRejectsNonP256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if _, err := NewCosignVerifier(pemBytes); err != ErrCosignCurveNotP256 {
		t.Errorf("want ErrCosignCurveNotP256, got %v", err)
	}
}

// ----- SigTag + CanonicalPayload ----------------------------------

func TestSigTagOK(t *testing.T) {
	d := "sha256:" + strings.Repeat("a", 64)
	tag, err := SigTag(d)
	if err != nil {
		t.Fatal(err)
	}
	want := "sha256-" + strings.Repeat("a", 64) + ".sig"
	if tag != want {
		t.Errorf("tag=%s want=%s", tag, want)
	}
}

func TestSigTagRejectsBadDigest(t *testing.T) {
	if _, err := SigTag("md5:abc"); err == nil {
		t.Fatal("want err for non-sha256, got nil")
	}
}

func TestCanonicalPayloadShape(t *testing.T) {
	got := string(CanonicalPayload("ghcr.io/foo/bar", "sha256:deadbeef"))
	want := `{"critical":{"identity":{"docker-reference":"ghcr.io/foo/bar"},"image":{"docker-manifest-digest":"sha256:deadbeef"},"type":"cosign container image signature"},"optional":null}`
	if got != want {
		t.Errorf("payload mismatch:\n got=%s\nwant=%s", got, want)
	}
}

func TestCanonicalPayloadEscapes(t *testing.T) {
	// Defensive escaping - exercise every branch of jsonEscape.
	got := string(CanonicalPayload("x\"y\\z\n\t\r"+string(byte(0x01)), "sha256:00"))
	wants := []string{
		`x\"`,    // dq -> escaped
		`y\\`,    // bs -> escaped
		`z\n`,    // LF -> n
		`\t`,     // HT -> t
		`\r`,     // CR -> r
		`\u0001`, // control -> uXXXX
	}
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("missing escape %q in %q", want, got)
		}
	}
}

// ----- Verify happy + negative paths ------------------------------

func TestVerifyHappyPath(t *testing.T) {
	env := newSigVerifyEnv(t)
	sigB64 := signPayloadB64(t, env.priv, env.payload)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(sigB64))

	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestVerifySecondLayerOK(t *testing.T) {
	env := newSigVerifyEnv(t)
	good := signPayloadB64(t, env.priv, env.payload)
	bad := signPayloadB64(t, env.priv, []byte("nope"))
	reg := mustSigReg(t, env, 200, buildSigManifestTwo(bad, good))
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify (two-layer): %v", err)
	}
}

func TestVerifyTamperedSignature(t *testing.T) {
	env := newSigVerifyEnv(t)
	sigB64 := signPayloadB64(t, env.priv, env.payload)
	raw, _ := base64.StdEncoding.DecodeString(sigB64)
	raw[len(raw)-1] ^= 0x01 // flip a bit
	tampered := base64.StdEncoding.EncodeToString(raw)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(tampered))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestVerifyWrongManifestDigest(t *testing.T) {
	env := newSigVerifyEnv(t)
	// Signed payload references env.manifestDigest. Calling Verify with
	// a different digest reconstructs a different payload → ECDSA fails.
	sigB64 := signPayloadB64(t, env.priv, env.payload)
	wrong := "sha256:" + strings.Repeat("d", 64)
	wrongTag, _ := SigTag(wrong)
	wrongURL := env.ref.manifestURL(wrongTag)

	mt := newMockTransport(t)
	mt.On(wrongURL, sigHandler(200, buildSigManifestOne(sigB64)))
	reg := NewRegistryWithTransport(mt, nil, env.ref)

	err := env.verifier.Verify(reg, *env.ref, wrong)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestVerifyWrongPubKey(t *testing.T) {
	env := newSigVerifyEnv(t)
	// Signature made under env.priv but verifier holds a different key.
	otherPriv, _ := genTestKey(t)
	sigB64 := signPayloadB64(t, otherPriv, env.payload)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(sigB64))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestVerifyBadManifestDigestArg(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(""))
	if err := env.verifier.Verify(reg, *env.ref, "not-a-digest"); err != ErrCosignBadManifestDigest {
		t.Errorf("want ErrCosignBadManifestDigest, got %v", err)
	}
}

func TestVerifyMissingSigTag404(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 404, []byte(`{"errors":["MANIFEST_UNKNOWN"]}`))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if err == nil || !strings.Contains(err.Error(), "fetch .sig manifest") {
		t.Errorf("want fetch error wrapping 404, got %v", err)
	}
	var statusErr *ErrRegistryStatus
	if !errors.As(err, &statusErr) || statusErr.Status != 404 {
		t.Errorf("want wrapped 404 ErrRegistryStatus, got %v", err)
	}
}

func TestVerifyEmptyLayers(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, emptyLayersSigManifest)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != ErrCosignSigManifestEmpty {
		t.Errorf("want ErrCosignSigManifestEmpty, got %v", err)
	}
}

func TestVerifyMissingAnnotation(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(""))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
	if !strings.Contains(err.Error(), "missing") {
		t.Errorf("error message should mention missing annotation: %v", err)
	}
}

func TestVerifyMalformedBase64(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, buildSigManifestOne("@@not-base64@@"))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
	if !strings.Contains(err.Error(), "base64") {
		t.Errorf("error message should mention base64: %v", err)
	}
}

func TestVerifyMalformedSigManifestJSON(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, []byte(`{`))
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if err == nil || !strings.Contains(err.Error(), "parse .sig manifest") {
		t.Errorf("want parse error, got %v", err)
	}
}

func TestVerifyEmptySigManifestBody(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, nil)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if err == nil || !errors.Is(err, ErrManifestEmpty) {
		t.Errorf("want ErrManifestEmpty wrap, got %v", err)
	}
}

func TestVerifyNilVerifier(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(""))
	var v *CosignVerifier
	if err := v.Verify(reg, *env.ref, env.manifestDigest); err != ErrCosignKeyNotECDSA {
		t.Errorf("want ErrCosignKeyNotECDSA, got %v", err)
	}
}

func TestVerifyZeroPubKey(t *testing.T) {
	env := newSigVerifyEnv(t)
	reg := mustSigReg(t, env, 200, buildSigManifestOne(""))
	v := &CosignVerifier{}
	if err := v.Verify(reg, *env.ref, env.manifestDigest); err != ErrCosignKeyNotECDSA {
		t.Errorf("want ErrCosignKeyNotECDSA, got %v", err)
	}
}

// ----- internal helpers exercise ----------------------------------

func TestParseSigManifestEmptyBody(t *testing.T) {
	if _, err := parseSigManifest(nil); err != ErrManifestEmpty {
		t.Errorf("want ErrManifestEmpty, got %v", err)
	}
}
