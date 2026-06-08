// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// HTTP-level operations against an OCI Distribution v2 registry,
// running over the ministack HTTPS (M6) / HTTP (M5) clients.
//
// What's here:
//
//   - Registry struct — bundles the ministack Stack + DNS server with
//     the parsed Ref so call sites stay short.
//   - fetchAuthChallenge: send the initial /v2/<repo>/manifests/<ref>
//     request, observe the 401, parse `Www-Authenticate: Bearer
//     realm=..., service=..., scope=...`.
//   - fetchBearerToken: GET the realm with the service+scope params,
//     decode the `{ "token": "..." }` JSON response.
//   - fetchManifestRaw / fetchBlob: authenticated GETs with the
//     bearer token in `Authorization: Bearer ...`.
//
// What's intentionally NOT here:
//
//   - HTTP redirects. ghcr.io serves manifests + small blobs (config,
//     index, small layers) inline with `200 OK`; only large layers
//     redirect to S3. The M7 smoke test targets the inline path; the
//     redirect path is an M7.1 follow-up because it costs another
//     parseURL + dial round per blob.
//   - Basic auth / operator-supplied bearer. Public-read access is
//     enough for shape A. Anonymous-pull is the common case for
//     ghcr.io/cloud-boot/* (which we control) and ghcr.io/library/*.
//   - HEAD / PUT. The unikernel never pushes; manifest-existence
//     probing is unneeded because we're always fetching.
//
// Design choices vs cloud-boot/init's pkg/oci:
//
//   - No SRV resolution — DHCP-learned DNS already handed us a single
//     resolver; the registry host is treated as opaque and resolved
//     once by ministack's DNS path.
//   - No per-host token cache — under shape A the M7 probe makes one
//     end-to-end fetch and halts; cache invalidation is trivially
//     "the process exited".
//   - No `net/http` — ministack's HTTPSGet returns headers + body
//     already, which is all we need.

package oci

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// ErrChallengeMissing is returned when the registry's 401 reply lacks
// the Www-Authenticate header.
var ErrChallengeMissing = errors.New("ministack/oci: registry 401 missing Www-Authenticate header")

// ErrChallengeUnsupported is returned when the challenge uses a
// scheme other than `Bearer`.
var ErrChallengeUnsupported = errors.New("ministack/oci: only Bearer auth challenges supported")

// ErrChallengeMissingRealm is returned when the parsed challenge
// lacks a realm parameter.
var ErrChallengeMissingRealm = errors.New("ministack/oci: bearer challenge missing realm")

// ErrTokenEmpty is returned when the realm endpoint replies with an
// empty `{ "token": "" }` body.
var ErrTokenEmpty = errors.New("ministack/oci: token endpoint returned empty token")

// ErrRegistryStatus wraps an unexpected non-200 status from the
// registry.
type ErrRegistryStatus struct {
	URL    string
	Status int
}

func (e *ErrRegistryStatus) Error() string {
	return fmt.Sprintf("ministack/oci: %s: unexpected status %d", e.URL, e.Status)
}

// Transport is the abstraction Registry uses to send a single HTTP
// GET. The default implementation (NewMinistackTransport) routes
// through the Stack's HTTPSGet / HTTPGet; tests inject a mock that
// services requests in-process without standing up TLS.
//
// Implementations MUST honour the Authorization / Accept extra
// headers if provided.
type Transport interface {
	Get(url string, opts ministack.HTTPGetOptions) (*ministack.HTTPResponse, error)
}

// stackTransport routes requests through a ministack Stack — HTTPS by
// default, falling back to HTTP for http:// URLs (local test
// registries).
type stackTransport struct {
	stack *ministack.Stack
}

// NewMinistackTransport wraps a ministack Stack in a Transport. The
// scheme is inferred per-request from the URL prefix.
func NewMinistackTransport(s *ministack.Stack) Transport {
	return &stackTransport{stack: s}
}

func (t *stackTransport) Get(url string, opts ministack.HTTPGetOptions) (*ministack.HTTPResponse, error) {
	if strings.HasPrefix(url, "http://") {
		return t.stack.HTTPGet(url, opts)
	}
	return t.stack.HTTPSGet(url, opts)
}

// Registry binds a Transport + DHCP-learned DNS server to a parsed
// Ref. The zero value is unusable; construct via NewRegistry.
type Registry struct {
	Transport Transport
	DNS       net.IP
	Ref       *Ref

	// DialTimeout caps the TCP+TLS handshake per request. Zero =
	// ministack's defaultDialTimeout.
	DialTimeout time.Duration
	// RequestTimeout caps the request lifetime once connected. Zero
	// = ministack's defaultRequestTimeout.
	RequestTimeout time.Duration

	// bearer is the cached negotiated bearer token (per-fetch, not
	// per-host; see file header comment).
	bearer string
}

// NewRegistry constructs a Registry from a parsed Ref + ministack
// Stack. The default Transport is the ministack-backed one.
func NewRegistry(stack *ministack.Stack, dns net.IP, ref *Ref) *Registry {
	return &Registry{Transport: NewMinistackTransport(stack), DNS: dns, Ref: ref}
}

// NewRegistryWithTransport is the test/dep-injection constructor. The
// supplied Transport is invoked for every HTTP request.
func NewRegistryWithTransport(t Transport, dns net.IP, ref *Ref) *Registry {
	return &Registry{Transport: t, DNS: dns, Ref: ref}
}

// httpGet routes through the configured Transport. Adds Accept +
// Authorization headers when non-empty.
func (r *Registry) httpGet(url string, accept string, bearer string) (*ministack.HTTPResponse, error) {
	opts := ministack.HTTPGetOptions{
		DNSServer:      r.DNS,
		DialTimeout:    r.DialTimeout,
		RequestTimeout: r.RequestTimeout,
	}
	if accept != "" {
		opts.ExtraHeaders = append(opts.ExtraHeaders, "Accept: "+accept)
	}
	if bearer != "" {
		opts.ExtraHeaders = append(opts.ExtraHeaders, "Authorization: Bearer "+bearer)
	}
	return r.Transport.Get(url, opts)
}

// Authenticate observes the registry's 401 challenge on the
// `/manifests/<ref>` endpoint, parses the Bearer params, fetches the
// anonymous token, and caches it on r. Subsequent calls re-use the
// cached token.
//
// Re-running Authenticate explicitly (e.g. after a token expiry) is
// supported — it overwrites the cache.
func (r *Registry) Authenticate() error {
	probeURL := r.Ref.manifestURL(r.Ref.Reference)
	resp, err := r.httpGet(probeURL, ManifestAcceptHeader, "")
	if err != nil {
		return fmt.Errorf("auth probe: %w", err)
	}
	if resp.StatusCode == 200 {
		// Public registry with no auth requirement (rare but legal).
		r.bearer = ""
		return nil
	}
	if resp.StatusCode != 401 {
		return &ErrRegistryStatus{URL: probeURL, Status: resp.StatusCode}
	}
	chal := resp.Headers["www-authenticate"]
	if chal == "" {
		return ErrChallengeMissing
	}
	params, err := parseBearerChallenge(chal)
	if err != nil {
		return err
	}
	realm := params["realm"]
	if realm == "" {
		return ErrChallengeMissingRealm
	}
	tokenURL := buildTokenURL(realm, params["service"], params["scope"])
	tokResp, err := r.httpGet(tokenURL, "", "")
	if err != nil {
		return fmt.Errorf("token fetch: %w", err)
	}
	if tokResp.StatusCode != 200 {
		return &ErrRegistryStatus{URL: tokenURL, Status: tokResp.StatusCode}
	}
	tok, err := parseTokenBody(tokResp.Body)
	if err != nil {
		return err
	}
	if tok == "" {
		return ErrTokenEmpty
	}
	r.bearer = tok
	return nil
}

// FetchManifestRaw returns the raw bytes + content type for the named
// reference. Authenticate() must have run first if the registry
// requires auth.
func (r *Registry) FetchManifestRaw(reference string) ([]byte, string, error) {
	url := r.Ref.manifestURL(reference)
	resp, err := r.httpGet(url, ManifestAcceptHeader, r.bearer)
	if err != nil {
		return nil, "", err
	}
	if resp.StatusCode != 200 {
		return nil, "", &ErrRegistryStatus{URL: url, Status: resp.StatusCode}
	}
	return resp.Body, resp.Headers["content-type"], nil
}

// maxBlobRedirects caps how many 3xx Location hops we'll follow for a
// blob fetch. ghcr.io routes blobs straight from `ghcr.io` (200 OK)
// for small artifacts and via a 307 to S3 / cloudfront for larger
// ones. One hop is enough in practice; two leaves headroom for
// vendors that bounce through a CDN before reaching their object
// store.
const maxBlobRedirects = 2

// FetchBlob returns the bytes for a blob digest, verifying SHA-256
// against the descriptor before returning. ErrDigestMismatch is
// surfaced if the body doesn't match.
//
// Follows up to maxBlobRedirects 3xx responses (302, 307). The
// Authorization header is intentionally NOT forwarded across the
// hop — registries that redirect to S3 expect the pre-signed URL to
// authenticate the request, and forwarding the bearer would surface
// as a "auth header AWS doesn't recognise" 400 from S3.
func (r *Registry) FetchBlob(desc Descriptor) ([]byte, error) {
	url := r.Ref.blobURL(desc.Digest)
	bearer := r.bearer
	for hop := 0; hop <= maxBlobRedirects; hop++ {
		resp, err := r.httpGet(url, "", bearer)
		if err != nil {
			return nil, err
		}
		if isRedirect(resp.StatusCode) {
			loc := resp.Headers["location"]
			if loc == "" {
				return nil, &ErrRegistryStatus{URL: url, Status: resp.StatusCode}
			}
			url = loc
			// Drop the bearer on the next hop — see method doc.
			bearer = ""
			continue
		}
		if resp.StatusCode != 200 {
			return nil, &ErrRegistryStatus{URL: url, Status: resp.StatusCode}
		}
		if err := VerifyDigest(desc.Digest, resp.Body); err != nil {
			return nil, err
		}
		if desc.Size > 0 && int64(len(resp.Body)) != desc.Size {
			// Spec says the size field is advisory but mismatches are
			// almost always either truncation or an active MITM; fail
			// closed.
			return nil, fmt.Errorf("ministack/oci: blob size mismatch: got %d want %d", len(resp.Body), desc.Size)
		}
		return resp.Body, nil
	}
	return nil, fmt.Errorf("ministack/oci: too many redirects (>%d) for %s", maxBlobRedirects, desc.Digest)
}

// isRedirect reports whether status names a follow-the-Location
// response that we should chase. We treat 301/302/307/308 the same
// way — a one-shot blob fetch doesn't preserve method semantics
// (everything is GET) so the distinction between "permanent" /
// "temporary" / "method-preserving" is academic for our use case.
func isRedirect(status int) bool {
	switch status {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

// parseBearerChallenge splits a `Www-Authenticate: Bearer realm=...,service=...,scope=...`
// value into its key=value pairs (quoted values are unquoted).
//
// Adapted verbatim in shape from cloud-boot/init's splitChallenge +
// the inline key=value loop in fetchBearer. Renamed for readability
// and merged into one entry point because the unikernel never wants
// to look at the raw `Bearer ...` prefix separately.
func parseBearerChallenge(chal string) (map[string]string, error) {
	low := strings.ToLower(chal)
	if !strings.HasPrefix(low, "bearer ") {
		return nil, ErrChallengeUnsupported
	}
	rest := chal[len("Bearer "):]
	params := map[string]string{}
	for _, p := range splitQuoted(rest) {
		i := strings.Index(p, "=")
		if i < 0 {
			continue
		}
		k := strings.TrimSpace(p[:i])
		v := strings.Trim(p[i+1:], `" `)
		params[strings.ToLower(k)] = v
	}
	return params, nil
}

// splitQuoted splits a comma-separated string but respects pairs of
// double quotes (so `realm="https://a/?x=y,z"` stays one element).
func splitQuoted(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch == '"':
			inQuote = !inQuote
			cur.WriteByte(ch)
		case ch == ',' && !inQuote:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// buildTokenURL stamps `realm?service=<svc>&scope=<scope>`, merging
// with whatever query realm already carries. Empty service / scope
// values are dropped (RFC 6750 §3 leaves them optional).
func buildTokenURL(realm, service, scope string) string {
	if service == "" && scope == "" {
		return realm
	}
	sep := "?"
	if strings.Contains(realm, "?") {
		sep = "&"
	}
	var sb strings.Builder
	sb.WriteString(realm)
	sb.WriteString(sep)
	first := true
	if service != "" {
		sb.WriteString("service=")
		sb.WriteString(urlEscape(service))
		first = false
	}
	if scope != "" {
		if !first {
			sb.WriteString("&")
		}
		sb.WriteString("scope=")
		sb.WriteString(urlEscape(scope))
	}
	return sb.String()
}

// urlEscape is a minimal application/x-www-form-urlencoded escaper —
// just enough for the chars the OCI auth dance can throw at us
// (`:` `/` `,` `+` ` `). We don't need full RFC 3986 coverage; the
// realm + service + scope alphabet is restrictive.
func urlEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z',
			'a' <= c && c <= 'z',
			'0' <= c && c <= '9',
			c == '-' || c == '_' || c == '.' || c == '~':
			sb.WriteByte(c)
		default:
			sb.WriteByte('%')
			sb.WriteByte(hex[c>>4])
			sb.WriteByte(hex[c&0x0F])
		}
	}
	return sb.String()
}

// parseTokenBody extracts a token from a registry's
// `/token` response body. Accepts both `{ "token": "..." }` (Docker
// canonical) and `{ "access_token": "..." }` (OAuth2 / GHCR).
func parseTokenBody(body []byte) (string, error) {
	// We deliberately don't pull in encoding/json for this single
	// field — a tiny manual scan keeps the dependency closure tight
	// and matches the M5 hand-rolled-HTTP ethos. The body is always
	// trustworthy JSON from the realm endpoint we just authenticated
	// against; we just need to find one string value.
	if tok := extractStringField(body, "token"); tok != "" {
		return tok, nil
	}
	if tok := extractStringField(body, "access_token"); tok != "" {
		return tok, nil
	}
	return "", nil
}

// extractStringField scans body for `"key" : "value"` and returns
// value. Returns "" if not found. Quote escapes inside the value are
// not supported — registry tokens are URL-safe alphanumerics + a few
// punctuation chars; if a registry ever returns a backslash-escaped
// token we'll wire encoding/json instead.
func extractStringField(body []byte, key string) string {
	needle := `"` + key + `"`
	i := strings.Index(string(body), needle)
	if i < 0 {
		return ""
	}
	rest := string(body[i+len(needle):])
	// Walk forward to the next `"`.
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return ""
	}
	rest = rest[colon+1:]
	openQuote := strings.IndexByte(rest, '"')
	if openQuote < 0 {
		return ""
	}
	rest = rest[openQuote+1:]
	closeQuote := strings.IndexByte(rest, '"')
	if closeQuote < 0 {
		return ""
	}
	return rest[:closeQuote]
}
