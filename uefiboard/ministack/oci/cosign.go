// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Keyed cosign signature verification — M7.1b.
//
// Scope: KEYED ONLY (= ECDSA-P256 against a pinned public key the
// caller already trusts). Keyless mode (Rekor + Fulcio + OIDC) is
// explicitly OUT of scope — we control which images we boot and
// embed the signer's public key.
//
// Cosign signature shape (per
// https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md):
//
//   - Signatures for an image manifest are stored as a SEPARATE OCI
//     artifact, tagged `sha256-<digest>.sig` on the same repo (where
//     `<digest>` is the hex-only half of the manifest's sha256).
//   - The .sig artifact is itself an OCI manifest. Each signature is
//     one layer; the ECDSA signature is carried on the layer
//     descriptor as the annotation
//     `dev.cosignproject.cosign/signature` (base64-encoded raw
//     ECDSA(P-256, SHA-256) signature, ASN.1-DER encoded).
//   - The signed payload is the canonical JSON
//
//       {"critical":{"identity":{"docker-reference":"REF"},
//                    "image":{"docker-manifest-digest":"sha256:HEX"},
//                    "type":"cosign container image signature"},
//        "optional":null}
//
//     (no whitespace, exact field order).
//
// What this file does NOT do:
//
//   - Fetch transparency-log inclusion proofs (Rekor) — keyless-only.
//   - Verify Fulcio-issued ephemeral cert chains — keyless-only.
//   - Validate annotation-based identity claims (subject / issuer) —
//     keyed mode doesn't bind to an OIDC subject.

package oci

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Cosign annotation key carrying the base64-encoded ECDSA signature
// on a .sig manifest layer descriptor. Per the cosign SIGNATURE_SPEC
// (https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md),
// the canonical annotation is `dev.cosignproject.cosign/signature`
// — this is what real cosign-keyed-signed images carry.
const CosignSignatureAnnotation = "dev.cosignproject.cosign/signature"

// CosignSimpleSigningMediaType is the layer media-type cosign assigns
// to the simple-signing payload blob. We don't strictly require it
// (the annotation is what matters) but we sniff it as a sanity check.
const CosignSimpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

// CosignPayloadType is the literal `type` field in the canonical
// payload — cosign stamps this string verbatim.
const CosignPayloadType = "cosign container image signature"

// Errors surfaced by CosignVerifier — fail-closed on every shape
// mismatch.
var (
	// ErrCosignPEMBad is returned when the supplied PEM bytes don't
	// decode to a valid PEM block.
	ErrCosignPEMBad = errors.New("ministack/oci/cosign: invalid PEM-encoded public key")
	// ErrCosignKeyNotECDSA is returned when the parsed public key is
	// not *ecdsa.PublicKey (e.g. RSA, Ed25519).
	ErrCosignKeyNotECDSA = errors.New("ministack/oci/cosign: public key is not ECDSA")
	// ErrCosignCurveNotP256 is returned when the ECDSA key is on a
	// curve other than P-256.
	ErrCosignCurveNotP256 = errors.New("ministack/oci/cosign: ECDSA key is not on the P-256 curve")
	// ErrCosignSigManifestEmpty is returned when the .sig manifest
	// has zero layers (= zero signatures).
	ErrCosignSigManifestEmpty = errors.New("ministack/oci/cosign: .sig manifest has zero layer signatures")
	// ErrCosignNoMatchingSignature is returned when none of the
	// signatures on the .sig manifest verify against the configured
	// pubkey + payload.
	ErrCosignNoMatchingSignature = errors.New("ministack/oci/cosign: no matching signature found on .sig manifest")
	// ErrCosignBadManifestDigest is returned when manifestDigest isn't
	// a valid sha256 digest string.
	ErrCosignBadManifestDigest = errors.New("ministack/oci/cosign: manifest digest must be a sha256:HEX string")
)

// CosignVerifier verifies cosign keyed signatures against a pinned
// ECDSA P-256 public key.
//
// Construct via NewCosignVerifier; the zero value is unusable.
type CosignVerifier struct {
	// PubKey is the trusted ECDSA P-256 public key. Signatures that
	// don't verify under this key are rejected.
	PubKey *ecdsa.PublicKey
}

// NewCosignVerifier parses a PEM-encoded ECDSA P-256 public key and
// returns a ready-to-use verifier. Accepts both PKIX
// "PUBLIC KEY" and the rare "ECDSA PUBLIC KEY" blocks (cosign emits
// the former).
func NewCosignVerifier(pemPubKey []byte) (*CosignVerifier, error) {
	block, _ := pem.Decode(pemPubKey)
	if block == nil {
		return nil, ErrCosignPEMBad
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ministack/oci/cosign: ParsePKIXPublicKey: %w", err)
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, ErrCosignKeyNotECDSA
	}
	if ec.Curve == nil || ec.Curve.Params() == nil || ec.Curve.Params().Name != "P-256" {
		return nil, ErrCosignCurveNotP256
	}
	return &CosignVerifier{PubKey: ec}, nil
}

// SigTag returns the cosign tag (`sha256-<hex>.sig`) for the given
// manifest digest (`sha256:<hex>`). Exposed so the M7.1b probe + tests
// can pre-compute the expected tag for logging.
func SigTag(manifestDigest string) (string, error) {
	algo, hexStr, err := ParseDigest(manifestDigest)
	if err != nil {
		return "", err
	}
	return algo + "-" + hexStr + ".sig", nil
}

// CanonicalPayload returns the exact byte sequence the cosign signer
// signs for a given (docker-reference, manifest-digest) pair. No
// whitespace, exact field order — matches the cosign reference
// implementation's `payload.Cosign{}.MarshalJSON`.
//
// Exposed so tests + the M7.1b probe self-test can sign the same bytes
// the verifier will reconstruct.
func CanonicalPayload(dockerReference, manifestDigest string) []byte {
	// Hand-formatted (no encoding/json roundtrip) so we're certain of
	// byte-for-byte stability across Go versions and reflection
	// ordering quirks. The cosign spec is explicit that the payload
	// must be exactly this layout.
	var sb strings.Builder
	sb.WriteString(`{"critical":{"identity":{"docker-reference":"`)
	sb.WriteString(jsonEscape(dockerReference))
	sb.WriteString(`"},"image":{"docker-manifest-digest":"`)
	sb.WriteString(jsonEscape(manifestDigest))
	sb.WriteString(`"},"type":"`)
	sb.WriteString(CosignPayloadType)
	sb.WriteString(`"},"optional":null}`)
	return []byte(sb.String())
}

// jsonEscape escapes the minimum set of characters needed for the
// cosign payload — `"` and `\` plus control chars. The expected inputs
// (an OCI reference + a sha256 digest string) only contain ASCII
// printables in practice; we still escape defensively because a
// malicious operator-supplied reference shouldn't be able to forge a
// different canonical payload via injection.
func jsonEscape(s string) string {
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '"':
			sb.WriteString(`\"`)
		case '\\':
			sb.WriteString(`\\`)
		case '\n':
			sb.WriteString(`\n`)
		case '\r':
			sb.WriteString(`\r`)
		case '\t':
			sb.WriteString(`\t`)
		default:
			if c < 0x20 {
				const hex = "0123456789abcdef"
				sb.WriteString(`\u00`)
				sb.WriteByte(hex[c>>4])
				sb.WriteByte(hex[c&0x0F])
			} else {
				sb.WriteByte(c)
			}
		}
	}
	return sb.String()
}

// sigManifest is the trimmed shape of a cosign .sig manifest — same as
// an OCI image manifest but the layers carry annotations.
type sigManifest struct {
	SchemaVersion int             `json:"schemaVersion"`
	MediaType     string          `json:"mediaType"`
	Layers        []sigLayerDescr `json:"layers"`
}

// sigLayerDescr is a layer descriptor with the cosign annotations map
// surfaced. We don't share Descriptor here because Descriptor doesn't
// expose annotations (it's the trimmed-for-manifest-walk subset).
type sigLayerDescr struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations"`
}

// parseSigManifest decodes a cosign .sig manifest body.
func parseSigManifest(raw []byte) (*sigManifest, error) {
	if len(raw) == 0 {
		return nil, ErrManifestEmpty
	}
	var m sigManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Verify fetches the cosign .sig artifact for the supplied
// manifestDigest, walks each layer, and ECDSA-verifies the
// `dev.cosignproject.cosign/signature` annotation against the canonical
// payload constructed from (reg.Ref.Repo + manifestDigest).
//
// Returns nil on first successful signature; an error describing the
// failure mode otherwise.
//
// Notes on docker-reference: cosign signs the docker reference STRING
// (typically `<host>/<repo>`, without tag or digest). We reconstruct
// it as `ref.Host + "/" + ref.Repo` — matching cosign CLI's
// `crane.ParseReference(...).Context().Name()` output for the same
// image.
func (v *CosignVerifier) Verify(reg *Registry, ref Ref, manifestDigest string) error {
	if v == nil || v.PubKey == nil {
		return ErrCosignKeyNotECDSA
	}
	if _, _, err := ParseDigest(manifestDigest); err != nil {
		return ErrCosignBadManifestDigest
	}

	tag, err := SigTag(manifestDigest)
	if err != nil {
		return err
	}

	raw, _, err := reg.FetchManifestRaw(tag)
	if err != nil {
		return fmt.Errorf("ministack/oci/cosign: fetch .sig manifest %s: %w", tag, err)
	}

	m, err := parseSigManifest(raw)
	if err != nil {
		return fmt.Errorf("ministack/oci/cosign: parse .sig manifest: %w", err)
	}
	if len(m.Layers) == 0 {
		return ErrCosignSigManifestEmpty
	}

	dockerRef := ref.Host + "/" + ref.Repo
	payload := CanonicalPayload(dockerRef, manifestDigest)
	digest := sha256.Sum256(payload)

	var lastErr error
	for i, l := range m.Layers {
		sigB64, ok := l.Annotations[CosignSignatureAnnotation]
		if !ok || sigB64 == "" {
			lastErr = fmt.Errorf("layer[%d]: missing %s annotation", i, CosignSignatureAnnotation)
			continue
		}
		sig, derr := base64.StdEncoding.DecodeString(sigB64)
		if derr != nil {
			lastErr = fmt.Errorf("layer[%d]: malformed base64 signature: %w", i, derr)
			continue
		}
		if ecdsa.VerifyASN1(v.PubKey, digest[:], sig) {
			return nil
		}
		lastErr = fmt.Errorf("layer[%d]: ECDSA verify failed", i)
	}
	if lastErr != nil {
		return fmt.Errorf("%w: %v", ErrCosignNoMatchingSignature, lastErr)
	}
	return ErrCosignNoMatchingSignature
}

