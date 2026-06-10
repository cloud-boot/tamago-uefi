// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	if !strings.Contains(err.Error(), CosignSignatureAnnotation) {
		t.Errorf("error message should mention the cosign annotation key: %v", err)
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

// ----- v3 sigstore-bundle helpers + tests -------------------------

// buildSigstoreBundleV3 returns the JSON body of a v0.3 sigstore
// bundle carrying the supplied keyed ECDSA(P-256, SHA-256) signature
// for the SHA-256 of `payload`. Mirrors the on-wire shape cosign v3
// produces for `--key`-mode signing.
func buildSigstoreBundleV3(t *testing.T, priv *ecdsa.PrivateKey, payload []byte) []byte {
	t.Helper()
	h := sha256.Sum256(payload)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	body := `{` +
		`"mediaType":"` + SigstoreBundleMediaTypeV03 + `",` +
		`"verificationMaterial":{"publicKey":{"hint":"test-key"},"tlogEntries":[]},` +
		`"messageSignature":{` +
		`"messageDigest":{"algorithm":"SHA2_256","digest":"` + base64.StdEncoding.EncodeToString(h[:]) + `"},` +
		`"signature":"` + base64.StdEncoding.EncodeToString(sig) + `"` +
		`}}`
	return []byte(body)
}

// buildSigstoreBundleV3WithDigest returns a v3 bundle whose
// messageDigest references an ARBITRARY digest (not necessarily the
// digest of the canonical payload). Used to exercise the
// "bundle-for-different-payload" rejection path.
func buildSigstoreBundleV3WithDigest(t *testing.T, priv *ecdsa.PrivateKey, digestBytes []byte) []byte {
	t.Helper()
	if len(digestBytes) != sha256.Size {
		t.Fatalf("digestBytes must be 32 bytes, got %d", len(digestBytes))
	}
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digestBytes)
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	body := `{` +
		`"mediaType":"` + SigstoreBundleMediaTypeV03 + `",` +
		`"messageSignature":{` +
		`"messageDigest":{"algorithm":"SHA2_256","digest":"` + base64.StdEncoding.EncodeToString(digestBytes) + `"},` +
		`"signature":"` + base64.StdEncoding.EncodeToString(sig) + `"` +
		`}}`
	return []byte(body)
}

// buildSigManifestBundleV3 wraps `bundleBody` in a single-layer .sig
// manifest with the v3 media-type. `mediaType` overrides v0.3 if set
// (useful to test v0.2 acceptance).
func buildSigManifestBundleV3(bundleBody []byte, mediaType string) []byte {
	if mediaType == "" {
		mediaType = SigstoreBundleMediaTypeV03
	}
	digest := DigestFromBytes(bundleBody)
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` +
		`{"mediaType":"` + mediaType + `","digest":"` + digest + `","size":` + itoa(len(bundleBody)) + `,"annotations":{}}` +
		`]}`)
}

// buildSigManifestMixed returns a .sig manifest carrying two layers
// in `order`-controlled positions: one legacy-annotation, one v3
// bundle. order=="legacyFirst" puts the legacy layer first.
func buildSigManifestMixed(legacySigB64 string, bundleBody []byte, order string) []byte {
	bDigest := DigestFromBytes(bundleBody)
	legacyLayer := `{"mediaType":"` + CosignSimpleSigningMediaType + `","digest":"sha256:3333333333333333333333333333333333333333333333333333333333333333","size":42,"annotations":{"` + CosignSignatureAnnotation + `":"` + legacySigB64 + `"}}`
	bundleLayer := `{"mediaType":"` + SigstoreBundleMediaTypeV03 + `","digest":"` + bDigest + `","size":` + itoa(len(bundleBody)) + `,"annotations":{}}`
	first, second := legacyLayer, bundleLayer
	if order == "bundleFirst" {
		first, second = bundleLayer, legacyLayer
	}
	return []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","layers":[` + first + `,` + second + `]}`)
}

func itoa(n int) string {
	// Tiny utility; we avoid strconv import churn since this file
	// already pulls a handful of crypto packages.
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// mustBundleReg wires a Registry whose mock transport serves the .sig
// manifest body on the .sig tag URL AND the bundle JSON on every blob
// URL. The .sig manifest must reference the bundle layer by its
// SHA-256 (use DigestFromBytes(bundleBody)).
func mustBundleReg(t *testing.T, env *sigVerifyEnv, manifestBody, bundleBody []byte) *Registry {
	t.Helper()
	mt := newMockTransport(t)
	mt.On(env.tagURL, sigHandler(200, manifestBody))
	mt.OnPrefix(env.ref.Scheme+"://"+env.ref.Host+"/v2/"+env.ref.Repo+"/blobs/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, bundleBody)
	})
	return NewRegistryWithTransport(mt, nil, env.ref)
}

// ----- parseSigstoreBundle unit coverage --------------------------

func TestParseSigstoreBundleRoundTrip(t *testing.T) {
	priv, _ := genTestKey(t)
	payload := []byte(`{"any":"payload"}`)
	body := buildSigstoreBundleV3(t, priv, payload)
	got, err := parseSigstoreBundle(body)
	if err != nil {
		t.Fatalf("parseSigstoreBundle: %v", err)
	}
	if got.format != sigFormatBundleV3 {
		t.Errorf("format=%d want sigFormatBundleV3", got.format)
	}
	h := sha256.Sum256(payload)
	if !bytes.Equal(got.messageDigest, h[:]) {
		t.Errorf("messageDigest mismatches sha256(payload)")
	}
	// And the signature really verifies against the digest.
	if !ecdsa.VerifyASN1(&priv.PublicKey, h[:], got.bytes) {
		t.Errorf("round-tripped signature failed to verify")
	}
}

func TestParseSigstoreBundleRejectsEmpty(t *testing.T) {
	if _, err := parseSigstoreBundle(nil); err != ErrCosignBundleMalformed {
		t.Errorf("want ErrCosignBundleMalformed, got %v", err)
	}
}

func TestParseSigstoreBundleRejectsBadJSON(t *testing.T) {
	if _, err := parseSigstoreBundle([]byte(`{`)); !errors.Is(err, ErrCosignBundleMalformed) {
		t.Errorf("want ErrCosignBundleMalformed wrap, got %v", err)
	}
}

func TestParseSigstoreBundleRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"no sig", `{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"AAAA"}}}`},
		{"no digest", `{"messageSignature":{"signature":"AAAA","messageDigest":{"algorithm":"SHA2_256"}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSigstoreBundle([]byte(tc.body)); !errors.Is(err, ErrCosignBundleMalformed) {
				t.Errorf("want ErrCosignBundleMalformed wrap, got %v", err)
			}
		})
	}
}

func TestParseSigstoreBundleRejectsBadAlgo(t *testing.T) {
	body := `{"messageSignature":{"signature":"AA==","messageDigest":{"algorithm":"SHA2_512","digest":"AA=="}}}`
	if _, err := parseSigstoreBundle([]byte(body)); !errors.Is(err, ErrCosignBundleAlgo) {
		t.Errorf("want ErrCosignBundleAlgo wrap, got %v", err)
	}
}

func TestParseSigstoreBundleRejectsBadBase64(t *testing.T) {
	body := `{"messageSignature":{"signature":"@@@","messageDigest":{"algorithm":"SHA2_256","digest":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}}}`
	if _, err := parseSigstoreBundle([]byte(body)); !errors.Is(err, ErrCosignBundleMalformed) {
		t.Errorf("want ErrCosignBundleMalformed wrap (sig b64), got %v", err)
	}
	body = `{"messageSignature":{"signature":"AA==","messageDigest":{"algorithm":"SHA2_256","digest":"@@@"}}}`
	if _, err := parseSigstoreBundle([]byte(body)); !errors.Is(err, ErrCosignBundleMalformed) {
		t.Errorf("want ErrCosignBundleMalformed wrap (digest b64), got %v", err)
	}
}

func TestParseSigstoreBundleRejectsShortDigest(t *testing.T) {
	body := `{"messageSignature":{"signature":"AA==","messageDigest":{"algorithm":"SHA2_256","digest":"` + base64.StdEncoding.EncodeToString([]byte("short")) + `"}}}`
	if _, err := parseSigstoreBundle([]byte(body)); !errors.Is(err, ErrCosignBundleMalformed) {
		t.Errorf("want ErrCosignBundleMalformed wrap (short digest), got %v", err)
	}
}

// ----- Verify v3 happy + negative paths ---------------------------

func TestVerifyV3BundleHappyPath(t *testing.T) {
	env := newSigVerifyEnv(t)
	bundle := buildSigstoreBundleV3(t, env.priv, env.payload)
	manifest := buildSigManifestBundleV3(bundle, "")
	reg := mustBundleReg(t, env, manifest, bundle)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify v3 bundle: %v", err)
	}
}

func TestVerifyV3BundleV02MediaType(t *testing.T) {
	// cosign v3-beta used the v0.2 media-type — accept it too.
	env := newSigVerifyEnv(t)
	bundle := buildSigstoreBundleV3(t, env.priv, env.payload)
	manifest := buildSigManifestBundleV3(bundle, SigstoreBundleMediaTypeV02)
	reg := mustBundleReg(t, env, manifest, bundle)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify v0.2 bundle: %v", err)
	}
}

func TestVerifyV3BundleWrongMessageDigest(t *testing.T) {
	// Bundle's messageDigest doesn't match sha256(CanonicalPayload).
	// MUST be rejected even though the signature is valid for that
	// digest — guards against bundle-substitution.
	env := newSigVerifyEnv(t)
	wrong := sha256.Sum256([]byte("not the canonical payload"))
	bundle := buildSigstoreBundleV3WithDigest(t, env.priv, wrong[:])
	manifest := buildSigManifestBundleV3(bundle, "")
	reg := mustBundleReg(t, env, manifest, bundle)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Fatalf("want ErrCosignNoMatchingSignature, got %v", err)
	}
	if !strings.Contains(err.Error(), "messageDigest mismatches") {
		t.Errorf("error should mention messageDigest mismatch: %v", err)
	}
}

func TestVerifyV3BundleTamperedSignature(t *testing.T) {
	env := newSigVerifyEnv(t)
	bundle := buildSigstoreBundleV3(t, env.priv, env.payload)
	// Flip one byte inside the base64 sig field — re-encode the whole
	// bundle.
	var parsed sigstoreBundle
	if err := json.Unmarshal(bundle, &parsed); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(parsed.MessageSignature.Signature)
	raw[len(raw)-1] ^= 0x01
	parsed.MessageSignature.Signature = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := json.Marshal(parsed)
	manifest := buildSigManifestBundleV3(tampered, "")
	reg := mustBundleReg(t, env, manifest, tampered)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestVerifyV3BundleMalformedBody(t *testing.T) {
	env := newSigVerifyEnv(t)
	bad := []byte(`{this is not valid json`)
	manifest := buildSigManifestBundleV3(bad, "")
	reg := mustBundleReg(t, env, manifest, bad)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature wrap, got %v", err)
	}
}

func TestVerifyV3BundleFetchFails(t *testing.T) {
	env := newSigVerifyEnv(t)
	bundle := buildSigstoreBundleV3(t, env.priv, env.payload)
	manifest := buildSigManifestBundleV3(bundle, "")
	mt := newMockTransport(t)
	mt.On(env.tagURL, sigHandler(200, manifest))
	// Blob URL: serve a 500 to exercise the fetch-error branch.
	mt.OnPrefix(env.ref.Scheme+"://"+env.ref.Host+"/v2/"+env.ref.Repo+"/blobs/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(500, nil, []byte("boom"))
	})
	reg := NewRegistryWithTransport(mt, nil, env.ref)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature wrap, got %v", err)
	}
	if !strings.Contains(err.Error(), "fetch bundle blob") {
		t.Errorf("error should mention fetch failure: %v", err)
	}
}

// ----- mixed legacy + v3 ordering ---------------------------------

func TestVerifyMixedLegacyFirstOK(t *testing.T) {
	env := newSigVerifyEnv(t)
	// Legacy carries the matching signature; bundle carries an
	// unrelated digest (would FAIL alone) — Verify must still PASS via
	// the legacy layer.
	legacy := signPayloadB64(t, env.priv, env.payload)
	wrong := sha256.Sum256([]byte("other"))
	bundle := buildSigstoreBundleV3WithDigest(t, env.priv, wrong[:])
	manifest := buildSigManifestMixed(legacy, bundle, "legacyFirst")
	reg := mustBundleReg(t, env, manifest, bundle)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify (legacy-first mixed): %v", err)
	}
}

func TestVerifyMixedBundleFirstOK(t *testing.T) {
	env := newSigVerifyEnv(t)
	// Bundle carries the matching signature; legacy carries garbage.
	bundle := buildSigstoreBundleV3(t, env.priv, env.payload)
	badLegacy := signPayloadB64(t, env.priv, []byte("not the payload"))
	manifest := buildSigManifestMixed(badLegacy, bundle, "bundleFirst")
	reg := mustBundleReg(t, env, manifest, bundle)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify (bundle-first mixed): %v", err)
	}
}

// ----- v3 DSSE envelope tests (matches what cosign v3 sign emits
// today with --registry-referrers-mode=oci-1-1) ------------------

// buildDSSEStatement encodes an in-toto v1 Statement whose single
// subject names `hexDigest` under sha256.
func buildDSSEStatement(hexDigest string) []byte {
	stmt := `{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"sha256":"` + hexDigest + `"},"annotations":{}}],"predicateType":"https://sigstore.dev/cosign/sign/v1","predicate":{}}`
	return []byte(stmt)
}

// buildSigstoreBundleV3DSSE returns a v3 bundle wrapping the supplied
// in-toto Statement payload, signed with priv over DSSE-PAE.
func buildSigstoreBundleV3DSSE(t *testing.T, priv *ecdsa.PrivateKey, payload []byte, payloadType string) []byte {
	t.Helper()
	pae := dssePAE(payloadType, payload)
	h := sha256.Sum256(pae)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}
	body := `{` +
		`"mediaType":"` + SigstoreBundleMediaTypeV03 + `",` +
		`"dsseEnvelope":{` +
		`"payload":"` + base64.StdEncoding.EncodeToString(payload) + `",` +
		`"payloadType":"` + payloadType + `",` +
		`"signatures":[{"sig":"` + base64.StdEncoding.EncodeToString(sig) + `"}]` +
		`}}`
	return []byte(body)
}

func TestVerifyV3DSSEHappyPath(t *testing.T) {
	env := newSigVerifyEnv(t)
	_, hexDigest, _ := ParseDigest(env.manifestDigest)
	stmt := buildDSSEStatement(hexDigest)
	bundle := buildSigstoreBundleV3DSSE(t, env.priv, stmt, "application/vnd.in-toto+json")
	manifest := buildSigManifestBundleV3(bundle, "")
	reg := mustBundleReg(t, env, manifest, bundle)
	if err := env.verifier.Verify(reg, *env.ref, env.manifestDigest); err != nil {
		t.Fatalf("Verify v3 DSSE: %v", err)
	}
}

func TestVerifyV3DSSEWrongSubject(t *testing.T) {
	// Statement names a different manifest digest — must be rejected
	// even though the DSSE signature itself is valid.
	env := newSigVerifyEnv(t)
	stmt := buildDSSEStatement(strings.Repeat("0", 64))
	bundle := buildSigstoreBundleV3DSSE(t, env.priv, stmt, "application/vnd.in-toto+json")
	manifest := buildSigManifestBundleV3(bundle, "")
	reg := mustBundleReg(t, env, manifest, bundle)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Fatalf("want ErrCosignNoMatchingSignature, got %v", err)
	}
	if !strings.Contains(err.Error(), "in-toto subject digest") {
		t.Errorf("error should mention subject digest mismatch: %v", err)
	}
}

func TestVerifyV3DSSETamperedSignature(t *testing.T) {
	env := newSigVerifyEnv(t)
	_, hexDigest, _ := ParseDigest(env.manifestDigest)
	stmt := buildDSSEStatement(hexDigest)
	bundle := buildSigstoreBundleV3DSSE(t, env.priv, stmt, "application/vnd.in-toto+json")
	// Flip one byte inside the DSSE signature.
	var b sigstoreBundle
	if err := json.Unmarshal(bundle, &b); err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(b.DsseEnvelope.Signatures[0].Sig)
	raw[len(raw)-1] ^= 0x01
	b.DsseEnvelope.Signatures[0].Sig = base64.StdEncoding.EncodeToString(raw)
	tampered, _ := json.Marshal(b)
	manifest := buildSigManifestBundleV3(tampered, "")
	reg := mustBundleReg(t, env, manifest, tampered)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestVerifyV3DSSEPayloadTypeMismatch(t *testing.T) {
	// Sign with payloadType="X", then mutate to "Y" before verify —
	// DSSE PAE binds the type so the signature must fail.
	env := newSigVerifyEnv(t)
	_, hexDigest, _ := ParseDigest(env.manifestDigest)
	stmt := buildDSSEStatement(hexDigest)
	bundle := buildSigstoreBundleV3DSSE(t, env.priv, stmt, "application/vnd.in-toto+json")
	mutated := bytes.ReplaceAll(bundle, []byte(`"application/vnd.in-toto+json"`), []byte(`"application/vnd.other+json"`))
	manifest := buildSigManifestBundleV3(mutated, "")
	reg := mustBundleReg(t, env, manifest, mutated)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

func TestParseSigstoreBundleDSSERejectsMissing(t *testing.T) {
	cases := []struct {
		name, body string
	}{
		{"no payload", `{"dsseEnvelope":{"payloadType":"x","signatures":[{"sig":"AA=="}]}}`},
		{"no payloadType", `{"dsseEnvelope":{"payload":"AA==","signatures":[{"sig":"AA=="}]}}`},
		{"no sigs", `{"dsseEnvelope":{"payload":"AA==","payloadType":"x"}}`},
		{"empty sig", `{"dsseEnvelope":{"payload":"AA==","payloadType":"x","signatures":[{"sig":""}]}}`},
		{"bad payload b64", `{"dsseEnvelope":{"payload":"@@@","payloadType":"x","signatures":[{"sig":"AA=="}]}}`},
		{"bad sig b64", `{"dsseEnvelope":{"payload":"AA==","payloadType":"x","signatures":[{"sig":"@@@"}]}}`},
		{"payload not a Statement", `{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte("{not json")) + `","payloadType":"x","signatures":[{"sig":"AA=="}]}}`},
		{"no subjects", `{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"s","subject":[]}`)) + `","payloadType":"x","signatures":[{"sig":"AA=="}]}}`},
		{"no sha256", `{"dsseEnvelope":{"payload":"` + base64.StdEncoding.EncodeToString([]byte(`{"_type":"s","subject":[{"digest":{"sha512":"abc"}}]}`)) + `","payloadType":"x","signatures":[{"sig":"AA=="}]}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseSigstoreBundle([]byte(tc.body)); !errors.Is(err, ErrCosignBundleMalformed) {
				t.Errorf("want ErrCosignBundleMalformed wrap, got %v", err)
			}
		})
	}
}

func TestParseSigstoreBundleNoSubtree(t *testing.T) {
	// A bundle JSON that's syntactically valid but has neither shape.
	body := `{"mediaType":"` + SigstoreBundleMediaTypeV03 + `","verificationMaterial":{}}`
	if _, err := parseSigstoreBundle([]byte(body)); !errors.Is(err, ErrCosignBundleMalformed) {
		t.Errorf("want ErrCosignBundleMalformed, got %v", err)
	}
}

func TestDSSEPAE(t *testing.T) {
	// Reference DSSEv1 PAE example: type="x", payload="hello" →
	// "DSSEv1 1 x 5 hello".
	got := dssePAE("x", []byte("hello"))
	want := []byte("DSSEv1 1 x 5 hello")
	if !bytes.Equal(got, want) {
		t.Errorf("PAE mismatch:\n got=%q\nwant=%q", got, want)
	}
	// Zero-length type + zero-length payload edges.
	got = dssePAE("", []byte{})
	if string(got) != "DSSEv1 0  0 " {
		t.Errorf("PAE zero edge: %q", got)
	}
}

// ----- live wire-format test ---------------------------------------
//
// Real bytes captured 2026-06-09 from a cosign v3 sign session against
// ttl.sh — wired straight into the parser to exercise the full DSSE
// path against bytes a real cosign-v3 signer emitted (not a fixture
// the test itself synthesised).

const liveCosignV3BundleJSON = `{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial":{"publicKey":{"hint":"h162TZsIBy5Y8U9qYWcmpVAp5dKpXhR7gnz8sNfZjV4="}}, "dsseEnvelope":{"payload":"eyJfdHlwZSI6Imh0dHBzOi8vaW4tdG90by5pby9TdGF0ZW1lbnQvdjEiLCAic3ViamVjdCI6W3siZGlnZXN0Ijp7InNoYTI1NiI6IjUwOTliODlkNzY2NmNjMjE4NmNhZDc2OWRkYzI2MmRkYzdjMzM1YjMzZjVmZTc5ZjlmZmU1MGEwMTI4MmIyM2UifSwgImFubm90YXRpb25zIjp7fX1dLCAicHJlZGljYXRlVHlwZSI6Imh0dHBzOi8vc2lnc3RvcmUuZGV2L2Nvc2lnbi9zaWduL3YxIiwgInByZWRpY2F0ZSI6e319", "payloadType":"application/vnd.in-toto+json", "signatures":[{"sig":"MEUCIBs2jKDupMmrqsjzI3W2oiID2y0P7n4UKT/RZHFeUOuhAiEA4SWsNDZXQBFqaA1/npF+HOGAaG2iuA52mxgPFCpgQog="}]}}`

const liveCosignV3PubKeyPEM = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoJmXprHRCRJdqHnRaPDkVssbQNO1
is6XUr+/ApqnDi8HvBCRPbwU2P8jgkgtOOggNUf03tvJe0/9eZOb04aDbQ==
-----END PUBLIC KEY-----
`

// liveCosignV3ManifestDigest is the digest the live bundle was signed
// over — the in-toto Statement names it as the sole sha256 subject.
const liveCosignV3ManifestDigest = "sha256:5099b89d7666cc2186cad769ddc262ddc7c335b33f5fe79f9ffe50a01282b23e"

func TestLiveCosignV3DSSEBundleParseAndVerify(t *testing.T) {
	// Step 1: parse the bundle.
	sig, err := parseSigstoreBundle([]byte(liveCosignV3BundleJSON))
	if err != nil {
		t.Fatalf("parseSigstoreBundle (live): %v", err)
	}
	if sig.format != sigFormatBundleV3DSSE {
		t.Fatalf("format=%d want sigFormatBundleV3DSSE", sig.format)
	}

	// Step 2: subject must match the manifest digest cosign signed.
	_, wantHex, _ := ParseDigest(liveCosignV3ManifestDigest)
	if sig.subjectDigest != wantHex {
		t.Fatalf("subjectDigest=%s want=%s", sig.subjectDigest, wantHex)
	}

	// Step 3: ECDSA verify against the real cosign-generated pubkey.
	block, _ := pem.Decode([]byte(liveCosignV3PubKeyPEM))
	if block == nil {
		t.Fatal("pem.Decode live pubkey returned nil")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	pub := pubAny.(*ecdsa.PublicKey)
	paeDigest := sha256.Sum256(dssePAE(sig.dssePayloadTy, sig.dssePayload))
	if !ecdsa.VerifyASN1(pub, paeDigest[:], sig.bytes) {
		t.Fatal("ECDSA verify failed on the real captured cosign v3 bundle")
	}
}

func TestVerifyMixedBothFailReports(t *testing.T) {
	env := newSigVerifyEnv(t)
	// Both layers fail — legacy with wrong payload, bundle with wrong
	// digest. Verify must return ErrCosignNoMatchingSignature with a
	// per-layer error in the wrapper.
	badLegacy := signPayloadB64(t, env.priv, []byte("nope"))
	wrong := sha256.Sum256([]byte("other"))
	bundle := buildSigstoreBundleV3WithDigest(t, env.priv, wrong[:])
	manifest := buildSigManifestMixed(badLegacy, bundle, "legacyFirst")
	reg := mustBundleReg(t, env, manifest, bundle)
	err := env.verifier.Verify(reg, *env.ref, env.manifestDigest)
	if !errors.Is(err, ErrCosignNoMatchingSignature) {
		t.Errorf("want ErrCosignNoMatchingSignature, got %v", err)
	}
}

// ----- cosign v3 OCI-1.1 sig-tag fallback (sha256-<hex> no .sig) ----

func TestSigTagOCI11(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	got, err := SigTagOCI11(digest)
	if err != nil {
		t.Fatalf("SigTagOCI11: %v", err)
	}
	want := "sha256-1111111111111111111111111111111111111111111111111111111111111111"
	if got != want {
		t.Fatalf("SigTagOCI11(%q) = %q, want %q", digest, got, want)
	}
}

func TestSigTagOCI11BadDigest(t *testing.T) {
	if _, err := SigTagOCI11("not-a-digest"); err == nil {
		t.Fatal("SigTagOCI11 with bad digest: want err, got nil")
	}
}

func TestCandidateSigTagsBadDigest(t *testing.T) {
	if _, err := candidateSigTags("not-a-digest"); err == nil {
		t.Fatal("candidateSigTags with bad digest: want err, got nil")
	}
}

func TestCandidateSigTagsBothForms(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	tags, err := candidateSigTags(digest)
	if err != nil {
		t.Fatalf("candidateSigTags: %v", err)
	}
	if len(tags) != 2 {
		t.Fatalf("len(tags) = %d, want 2", len(tags))
	}
	if !strings.HasSuffix(tags[0], ".sig") {
		t.Errorf("tags[0] = %q, want trailing `.sig`", tags[0])
	}
	if strings.HasSuffix(tags[1], ".sig") {
		t.Errorf("tags[1] = %q, want NO trailing `.sig`", tags[1])
	}
}
