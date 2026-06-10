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
	"bytes"
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

// SigstoreBundleMediaTypeV02 / V03 are the OCI layer media-types
// cosign v3 (and the sigstore-go library it consumes) uses when
// storing the signing material as a sigstore protobuf bundle, JSON-
// encoded. We support both the v0.2 beta and the v0.3 release-shape;
// the keyed-signing subset we care about is byte-identical between
// the two versions for our verification path.
//
// Spec sources:
//   - protobuf:    https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto
//   - cosign spec: https://github.com/sigstore/cosign/blob/main/specs/SIGNATURE_SPEC.md
const (
	SigstoreBundleMediaTypeV02 = "application/vnd.dev.sigstore.bundle.v0.2+json"
	SigstoreBundleMediaTypeV03 = "application/vnd.dev.sigstore.bundle.v0.3+json"
)

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
	// ErrCosignBundleMalformed is returned when a sigstore-bundle
	// layer body doesn't parse as the expected JSON shape (missing
	// messageSignature, mismatched algorithm, etc.).
	ErrCosignBundleMalformed = errors.New("ministack/oci/cosign: malformed sigstore bundle layer body")
	// ErrCosignBundleAlgo is returned when a sigstore-bundle layer
	// declares a digest algorithm other than SHA2_256 — out of scope
	// for the keyed-ECDSA-P256 verifier.
	ErrCosignBundleAlgo = errors.New("ministack/oci/cosign: sigstore bundle uses unsupported digest algorithm (want SHA2_256)")
)

// sigFormat names which on-wire shape a parsed signature came from.
// Two formats co-exist in the wild as of cosign v3:
//
//   - sigFormatLegacy:    cosign <= v2 — base64 signature on the layer
//     descriptor annotation `dev.cosignproject.cosign/signature`.
//   - sigFormatBundleV3:  cosign >= v3 — JSON-encoded sigstore bundle
//     served as the layer body (media-type
//     `application/vnd.dev.sigstore.bundle.v0.{2,3}+json`).
type sigFormat int

const (
	sigFormatLegacy sigFormat = iota + 1
	sigFormatBundleV3
	sigFormatBundleV3DSSE
)

// parsedSignature is the verifier-side intermediate that abstracts
// over the legacy-annotation, v3-messageSignature, and v3-dsseEnvelope
// shapes. All three formats yield ECDSA(P-256, SHA-256) signature
// bytes; the metadata determines how the verifier reconstructs the
// signed bytes:
//
//   - sigFormatLegacy:        signed bytes = sha256(CanonicalPayload).
//   - sigFormatBundleV3:      messageDigest must equal sha256(CanonicalPayload),
//     then signed bytes = messageDigest.
//   - sigFormatBundleV3DSSE:  signed bytes = sha256(DSSE-PAE(payloadType, payload));
//     subjectDigest is the in-toto Statement's sole sha256 subject
//     and MUST equal the hex of the manifest digest we're verifying.
type parsedSignature struct {
	format        sigFormat
	bytes         []byte // raw ASN.1-DER ECDSA signature
	messageDigest []byte // populated only for sigFormatBundleV3 (32-byte sha256)
	dssePayload   []byte // populated only for sigFormatBundleV3DSSE
	dssePayloadTy string // populated only for sigFormatBundleV3DSSE
	subjectDigest string // populated only for sigFormatBundleV3DSSE (hex sha256)
}

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

// SigTag returns the cosign legacy tag (`sha256-<hex>.sig`) for the
// given manifest digest (`sha256:<hex>`). Cosign v2 + cosign v3 with
// the legacy publish layout (the default until cosign v3.x switched to
// OCI-1.1 mode) use this form. Exposed so the M7.1b probe + tests can
// pre-compute the expected tag for logging.
func SigTag(manifestDigest string) (string, error) {
	algo, hexStr, err := ParseDigest(manifestDigest)
	if err != nil {
		return "", err
	}
	return algo + "-" + hexStr + ".sig", nil
}

// SigTagOCI11 returns the cosign OCI-1.1 tag (`sha256-<hex>`, no
// `.sig` suffix) for the given manifest digest. Cosign v3 with the
// OCI-1.1 publish mode (`cosign sign --registry-referrers-mode=oci-1-1`
// or the v3.x default) emits the bundle at this tag. Returned for
// callers that need the precise form; Verify tries both forms
// automatically, so most code paths don't need to call this directly.
func SigTagOCI11(manifestDigest string) (string, error) {
	algo, hexStr, err := ParseDigest(manifestDigest)
	if err != nil {
		return "", err
	}
	return algo + "-" + hexStr, nil
}

// candidateSigTags returns the cosign tag forms Verify will try in
// order: legacy `.sig`-suffixed first (cosign v2 + legacy v3), then
// OCI-1.1 unsuffixed (cosign v3 default). Verify uses whichever
// produces a fetchable manifest with non-zero layers.
func candidateSigTags(manifestDigest string) ([]string, error) {
	legacy, err := SigTag(manifestDigest)
	if err != nil {
		return nil, err
	}
	oci11, err := SigTagOCI11(manifestDigest)
	if err != nil {
		return nil, err
	}
	return []string{legacy, oci11}, nil
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

// sigstoreBundle is the trimmed JSON shape of a sigstore protobuf
// bundle as cosign v3 emits it on the wire. We only consume the
// fields needed for keyed verification; verificationMaterial.tlogEntries
// / publicKey are intentionally ignored — we control the trust root
// via the embedded pubkey, not via the bundle's own claims.
//
// Two payload shapes coexist in cosign v3 on the wire:
//
//   - messageSignature: raw ECDSA signature over a pre-computed
//     SHA-256 of the cosign canonical payload. Used by `sign-blob`
//     and `--key`-mode signing without DSSE.
//   - dsseEnvelope: DSSE-PAE-encoded in-toto Statement whose subject
//     digest is the manifest digest being signed. This is what
//     `cosign sign --registry-referrers-mode=oci-1-1` emits today.
type sigstoreBundle struct {
	MediaType        string                  `json:"mediaType"`
	MessageSignature *bundleMessageSignature `json:"messageSignature,omitempty"`
	DsseEnvelope     *bundleDsseEnvelope     `json:"dsseEnvelope,omitempty"`
}

type bundleMessageSignature struct {
	MessageDigest struct {
		Algorithm string `json:"algorithm"`
		Digest    string `json:"digest"`
	} `json:"messageDigest"`
	Signature string `json:"signature"`
}

type bundleDsseEnvelope struct {
	// Base64-standard-encoded payload bytes — for cosign v3 keyed,
	// this is an in-toto Statement JSON document.
	Payload     string `json:"payload"`
	PayloadType string `json:"payloadType"`
	Signatures  []struct {
		// Base64-standard-encoded raw ASN.1-DER ECDSA signature over
		// DSSE-PAE("application/vnd.in-toto+json", payloadBytes).
		Sig string `json:"sig"`
	} `json:"signatures"`
}

// inTotoStatement is the trimmed shape of the in-toto v1 Statement
// the DSSE envelope wraps. Only `subject[].digest.sha256` is consumed.
type inTotoStatement struct {
	Type    string `json:"_type"`
	Subject []struct {
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// isSigstoreBundleMediaType reports whether mt is one of the keyed-
// signing-capable sigstore bundle media-types we accept.
func isSigstoreBundleMediaType(mt string) bool {
	return mt == SigstoreBundleMediaTypeV02 || mt == SigstoreBundleMediaTypeV03
}

// parseSigstoreBundle decodes the JSON body of a sigstore-bundle .sig
// layer. Dispatches between the messageSignature shape (raw signature
// over pre-computed SHA-256) and the dsseEnvelope shape (DSSE-PAE
// over in-toto Statement). For messageSignature the algorithm must be
// SHA2_256; for DSSE we verify by computing sha256(DSSE-PAE(...)) and
// extracting the subject digest from the embedded in-toto Statement.
func parseSigstoreBundle(raw []byte) (*parsedSignature, error) {
	if len(raw) == 0 {
		return nil, ErrCosignBundleMalformed
	}
	var b sigstoreBundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCosignBundleMalformed, err)
	}
	if b.MessageSignature != nil {
		return parseSigstoreBundleMessageSignature(b.MessageSignature)
	}
	if b.DsseEnvelope != nil {
		return parseSigstoreBundleDSSE(b.DsseEnvelope)
	}
	return nil, fmt.Errorf("%w: bundle has neither messageSignature nor dsseEnvelope", ErrCosignBundleMalformed)
}

func parseSigstoreBundleMessageSignature(ms *bundleMessageSignature) (*parsedSignature, error) {
	if ms.Signature == "" {
		return nil, fmt.Errorf("%w: missing messageSignature.signature", ErrCosignBundleMalformed)
	}
	if ms.MessageDigest.Digest == "" {
		return nil, fmt.Errorf("%w: missing messageSignature.messageDigest.digest", ErrCosignBundleMalformed)
	}
	if ms.MessageDigest.Algorithm != "SHA2_256" {
		return nil, fmt.Errorf("%w: got %q", ErrCosignBundleAlgo, ms.MessageDigest.Algorithm)
	}
	sig, err := base64.StdEncoding.DecodeString(ms.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: signature base64: %v", ErrCosignBundleMalformed, err)
	}
	digest, err := base64.StdEncoding.DecodeString(ms.MessageDigest.Digest)
	if err != nil {
		return nil, fmt.Errorf("%w: messageDigest base64: %v", ErrCosignBundleMalformed, err)
	}
	if len(digest) != sha256.Size {
		return nil, fmt.Errorf("%w: SHA2_256 digest must be %d bytes, got %d", ErrCosignBundleMalformed, sha256.Size, len(digest))
	}
	return &parsedSignature{
		format:        sigFormatBundleV3,
		bytes:         sig,
		messageDigest: digest,
	}, nil
}

func parseSigstoreBundleDSSE(env *bundleDsseEnvelope) (*parsedSignature, error) {
	if env.Payload == "" {
		return nil, fmt.Errorf("%w: missing dsseEnvelope.payload", ErrCosignBundleMalformed)
	}
	if env.PayloadType == "" {
		return nil, fmt.Errorf("%w: missing dsseEnvelope.payloadType", ErrCosignBundleMalformed)
	}
	if len(env.Signatures) == 0 || env.Signatures[0].Sig == "" {
		return nil, fmt.Errorf("%w: missing dsseEnvelope.signatures[0].sig", ErrCosignBundleMalformed)
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("%w: dsseEnvelope.payload base64: %v", ErrCosignBundleMalformed, err)
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
	if err != nil {
		return nil, fmt.Errorf("%w: dsseEnvelope.signatures[0].sig base64: %v", ErrCosignBundleMalformed, err)
	}
	var stmt inTotoStatement
	if jerr := json.Unmarshal(payload, &stmt); jerr != nil {
		return nil, fmt.Errorf("%w: in-toto Statement parse: %v", ErrCosignBundleMalformed, jerr)
	}
	if len(stmt.Subject) == 0 {
		return nil, fmt.Errorf("%w: in-toto Statement has no subjects", ErrCosignBundleMalformed)
	}
	subj := stmt.Subject[0].Digest["sha256"]
	if subj == "" {
		return nil, fmt.Errorf("%w: in-toto Statement subject[0] has no sha256 digest", ErrCosignBundleMalformed)
	}
	return &parsedSignature{
		format:        sigFormatBundleV3DSSE,
		bytes:         sig,
		dssePayload:   payload,
		dssePayloadTy: env.PayloadType,
		subjectDigest: subj,
	}, nil
}

// dssePAE returns the DSSE Pre-Authentication Encoding for
// (payloadType, payload), per https://github.com/secure-systems-lab/dsse:
//
//	"DSSEv1 " + len(type) + " " + type + " " + len(payload) + " " + payload
//
// The verifier signs sha256(PAE(...)) — NOT the bare payload — which
// is what binds (payload-type, payload) into one byte-string so a
// signer can't be tricked into re-using a signature across types.
func dssePAE(payloadType string, payload []byte) []byte {
	var sb bytes.Buffer
	sb.WriteString("DSSEv1 ")
	sb.WriteString(itoaInt(len(payloadType)))
	sb.WriteByte(' ')
	sb.WriteString(payloadType)
	sb.WriteByte(' ')
	sb.WriteString(itoaInt(len(payload)))
	sb.WriteByte(' ')
	sb.Write(payload)
	return sb.Bytes()
}

// itoaInt is a tiny ASCII-decimal stringifier we use to avoid pulling
// strconv into the cosign verifier surface (everything else here is
// pure crypto + encoding/json + bytes).
func itoaInt(n int) string {
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

// collectSignatures walks every layer of a .sig manifest and emits
// one parsedSignature per layer that carries either a legacy
// annotation signature OR a sigstore bundle body. Layers we don't
// recognise are silently skipped — the .sig manifest may interleave
// in-toto attestations / SBOMs that the verifier should ignore.
//
// The Registry is needed for v3-bundle layers (we have to fetch the
// blob body). Legacy annotation-only layers don't touch the registry.
//
// `perLayerErr` collects the first parse error seen on any layer that
// LOOKED like a signature carrier but failed to decode; callers
// surface it as the "no matching signature found" explanation if
// none of the layers verify.
func collectSignatures(reg *Registry, m *sigManifest) (sigs []parsedSignature, perLayerErr error) {
	for i, l := range m.Layers {
		// Legacy v2 annotation path — present even on layers whose
		// mediaType is not simple-signing (some old signers emit no
		// mediaType at all).
		if sigB64, ok := l.Annotations[CosignSignatureAnnotation]; ok && sigB64 != "" {
			sig, derr := base64.StdEncoding.DecodeString(sigB64)
			if derr != nil {
				if perLayerErr == nil {
					perLayerErr = fmt.Errorf("layer[%d]: malformed base64 signature: %w", i, derr)
				}
				continue
			}
			sigs = append(sigs, parsedSignature{format: sigFormatLegacy, bytes: sig})
			continue
		}
		// v3 sigstore-bundle path — must fetch the layer body.
		if isSigstoreBundleMediaType(l.MediaType) {
			body, ferr := reg.FetchBlob(Descriptor{MediaType: l.MediaType, Digest: l.Digest, Size: l.Size})
			if ferr != nil {
				if perLayerErr == nil {
					perLayerErr = fmt.Errorf("layer[%d]: fetch bundle blob %s: %w", i, l.Digest, ferr)
				}
				continue
			}
			sig, perr := parseSigstoreBundle(body)
			if perr != nil {
				if perLayerErr == nil {
					perLayerErr = fmt.Errorf("layer[%d]: %w", i, perr)
				}
				continue
			}
			sigs = append(sigs, *sig)
			continue
		}
		// Layer with neither annotation nor bundle media-type — note
		// it as the candidate error so empty-signature .sig manifests
		// surface a useful message.
		if perLayerErr == nil {
			perLayerErr = fmt.Errorf("layer[%d]: no %s annotation and mediaType %q is not a sigstore bundle", i, CosignSignatureAnnotation, l.MediaType)
		}
	}
	return sigs, perLayerErr
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

	// candidateSigTags is infallible here — ParseDigest above guarantees
	// the hex/algo are well-formed. Try legacy `.sig` first (cosign v2 +
	// legacy v3); fall back to OCI-1.1 unsuffixed (cosign v3 oci-1-1
	// publish mode) only if the legacy fetch errors out. A successful
	// response with an empty body is NOT a fall-back trigger — the
	// registry confirmed the tag exists but says "no signatures here",
	// which parseSigManifest surfaces as ErrManifestEmpty downstream.
	tags, _ := candidateSigTags(manifestDigest)
	var (
		raw      []byte
		usedTag  string
		fetchErr error
	)
	for _, t := range tags {
		r, _, ferr := reg.FetchManifestRaw(t)
		if ferr != nil {
			if fetchErr == nil {
				fetchErr = ferr
			}
			continue
		}
		raw = r
		usedTag = t
		break
	}
	if usedTag == "" {
		return fmt.Errorf("ministack/oci/cosign: fetch .sig manifest (tried %v): %w", tags, fetchErr)
	}

	m, err := parseSigManifest(raw)
	if err != nil {
		return fmt.Errorf("ministack/oci/cosign: parse .sig manifest %s: %w", usedTag, err)
	}
	if len(m.Layers) == 0 {
		return ErrCosignSigManifestEmpty
	}

	dockerRef := ref.Host + "/" + ref.Repo
	payload := CanonicalPayload(dockerRef, manifestDigest)
	digest := sha256.Sum256(payload)

	sigs, collectErr := collectSignatures(reg, m)
	if len(sigs) == 0 {
		// collectErr is always non-nil when sigs is empty: every layer
		// of a non-empty .sig manifest either yields a parsedSignature
		// or contributes a parse/fetch error to collectErr.
		return fmt.Errorf("%w: %v", ErrCosignNoMatchingSignature, collectErr)
	}

	// hexDigest is the hex-only half of manifestDigest, used to
	// cross-check the in-toto subject of dsseEnvelope bundles.
	_, hexDigest, _ := ParseDigest(manifestDigest)

	lastErr := collectErr
	for i, sig := range sigs {
		switch sig.format {
		case sigFormatLegacy:
			if ecdsa.VerifyASN1(v.PubKey, digest[:], sig.bytes) {
				return nil
			}
			lastErr = fmt.Errorf("signature[%d] (legacy): ECDSA verify failed", i)
		case sigFormatBundleV3:
			// The v3 bundle pre-digests the canonical payload; we
			// re-derive our own digest from CanonicalPayload and
			// require an exact match before trusting the bundle. A
			// bundle whose messageDigest references a DIFFERENT
			// payload (e.g. an old image substituted by a MITM) must
			// be rejected even if the signature itself is valid.
			if !bytes.Equal(sig.messageDigest, digest[:]) {
				lastErr = fmt.Errorf("signature[%d] (v3 bundle): messageDigest mismatches canonical payload digest", i)
				continue
			}
			if ecdsa.VerifyASN1(v.PubKey, digest[:], sig.bytes) {
				return nil
			}
			lastErr = fmt.Errorf("signature[%d] (v3 bundle): ECDSA verify failed", i)
		case sigFormatBundleV3DSSE:
			// The DSSE envelope binds (payloadType, payload) into the
			// signed message via Pre-Authentication Encoding. We:
			//   1. confirm the in-toto Statement names OUR manifest
			//      digest as its (sole) subject, and
			//   2. verify ECDSA(sha256(DSSE-PAE(...))).
			if !strings.EqualFold(sig.subjectDigest, hexDigest) {
				lastErr = fmt.Errorf("signature[%d] (v3 dsse): in-toto subject digest %s mismatches manifest digest %s", i, sig.subjectDigest, hexDigest)
				continue
			}
			paeDigest := sha256.Sum256(dssePAE(sig.dssePayloadTy, sig.dssePayload))
			if ecdsa.VerifyASN1(v.PubKey, paeDigest[:], sig.bytes) {
				return nil
			}
			lastErr = fmt.Errorf("signature[%d] (v3 dsse): ECDSA verify failed", i)
		}
	}
	if lastErr == nil {
		// Defensive: collectSignatures only returns >0 sigs when each
		// of them was successfully parsed AND each loop iteration sets
		// lastErr on every non-success path. Should never trigger.
		return ErrCosignNoMatchingSignature
	}
	return fmt.Errorf("%w: %v", ErrCosignNoMatchingSignature, lastErr)
}

