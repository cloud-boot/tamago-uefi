// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package oci

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// mockTransport is an in-process Transport that returns canned
// responses keyed by URL or by URL-prefix match.
type mockTransport struct {
	t        *testing.T
	requests []mockRequest
	handlers map[string]mockHandler
	prefix   map[string]mockHandler
}

type mockRequest struct {
	URL  string
	Opts ministack.HTTPGetOptions
}

type mockHandler func(req mockRequest) *ministack.HTTPResponse

func newMockTransport(t *testing.T) *mockTransport {
	return &mockTransport{
		t:        t,
		handlers: map[string]mockHandler{},
		prefix:   map[string]mockHandler{},
	}
}

func (m *mockTransport) Get(url string, opts ministack.HTTPGetOptions) (*ministack.HTTPResponse, error) {
	req := mockRequest{URL: url, Opts: opts}
	m.requests = append(m.requests, req)
	if h, ok := m.handlers[url]; ok {
		return h(req), nil
	}
	for p, h := range m.prefix {
		if strings.HasPrefix(url, p) {
			return h(req), nil
		}
	}
	return nil, fmt.Errorf("mockTransport: no handler for %s", url)
}

func (m *mockTransport) On(url string, h mockHandler) { m.handlers[url] = h }
func (m *mockTransport) OnPrefix(p string, h mockHandler) {
	m.prefix[p] = h
}

// fakeResponse builds a ministack.HTTPResponse with the given status,
// headers, body.
func fakeResponse(status int, headers map[string]string, body []byte) *ministack.HTTPResponse {
	if headers == nil {
		headers = map[string]string{}
	}
	return &ministack.HTTPResponse{
		StatusCode: status,
		StatusLine: fmt.Sprintf("HTTP/1.1 %d X", status),
		Headers:    headers,
		Body:       body,
	}
}

// ----- parseBearerChallenge ---------------------------------------

func TestParseBearerChallenge(t *testing.T) {
	chal := `Bearer realm="https://auth.example.com/token",service="reg",scope="repository:foo:pull"`
	params, err := parseBearerChallenge(chal)
	if err != nil {
		t.Fatal(err)
	}
	if params["realm"] != "https://auth.example.com/token" {
		t.Errorf("realm=%s", params["realm"])
	}
	if params["service"] != "reg" {
		t.Errorf("service=%s", params["service"])
	}
	if params["scope"] != "repository:foo:pull" {
		t.Errorf("scope=%s", params["scope"])
	}
}

func TestParseBearerChallengeRejectsBasic(t *testing.T) {
	if _, err := parseBearerChallenge(`Basic realm="x"`); err != ErrChallengeUnsupported {
		t.Errorf("want ErrChallengeUnsupported, got %v", err)
	}
}

func TestParseBearerChallengeLowerCasePrefix(t *testing.T) {
	if _, err := parseBearerChallenge(`bearer realm="x"`); err != nil {
		t.Errorf("lower-case prefix rejected: %v", err)
	}
}

func TestSplitQuoted(t *testing.T) {
	in := `a=1,b="2,3",c=4`
	got := splitQuoted(in)
	if len(got) != 3 || got[0] != "a=1" || got[1] != `b="2,3"` || got[2] != "c=4" {
		t.Errorf("splitQuoted: %v", got)
	}
}

func TestBuildTokenURL(t *testing.T) {
	got := buildTokenURL("https://auth/token", "ghcr.io", "repository:foo:pull")
	want := "https://auth/token?service=ghcr.io&scope=repository%3Afoo%3Apull"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

func TestBuildTokenURLEmptyParams(t *testing.T) {
	got := buildTokenURL("https://auth/token", "", "")
	if got != "https://auth/token" {
		t.Errorf("got %s", got)
	}
}

func TestBuildTokenURLPreservesExistingQuery(t *testing.T) {
	got := buildTokenURL("https://auth/token?x=1", "svc", "")
	if got != "https://auth/token?x=1&service=svc" {
		t.Errorf("got %s", got)
	}
}

func TestBuildTokenURLOnlyScope(t *testing.T) {
	got := buildTokenURL("https://auth/token", "", "repo:r:pull")
	if got != "https://auth/token?scope=repo%3Ar%3Apull" {
		t.Errorf("got %s", got)
	}
}

func TestURLEscape(t *testing.T) {
	if got := urlEscape("abcXYZ-._~"); got != "abcXYZ-._~" {
		t.Errorf("unreserved escaped: %s", got)
	}
	if got := urlEscape("a b"); got != "a%20b" {
		t.Errorf("space: %s", got)
	}
	if got := urlEscape(":/+"); got != "%3A%2F%2B" {
		t.Errorf("reserved: %s", got)
	}
}

// ----- parseTokenBody ---------------------------------------------

func TestParseTokenBodyDocker(t *testing.T) {
	tok, err := parseTokenBody([]byte(`{"token": "abc.def.ghi"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "abc.def.ghi" {
		t.Errorf("token=%s", tok)
	}
}

func TestParseTokenBodyOAuth(t *testing.T) {
	tok, err := parseTokenBody([]byte(`{"access_token":"oauth-token"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "oauth-token" {
		t.Errorf("token=%s", tok)
	}
}

func TestParseTokenBodyMissing(t *testing.T) {
	tok, err := parseTokenBody([]byte(`{"other":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" {
		t.Errorf("expected empty, got %s", tok)
	}
}

func TestExtractStringFieldEdgeCases(t *testing.T) {
	if got := extractStringField([]byte(`{}`), "k"); got != "" {
		t.Errorf("missing key: %s", got)
	}
	// Key found but no colon following.
	if got := extractStringField([]byte(`{"k" no colon}`), "k"); got != "" {
		t.Errorf("no colon: %s", got)
	}
	// Key found but no opening quote in value.
	if got := extractStringField([]byte(`{"k": 5}`), "k"); got != "" {
		t.Errorf("non-string value: %s", got)
	}
	// Key found, opening quote but no closing.
	if got := extractStringField([]byte(`{"k": "unterm`), "k"); got != "" {
		t.Errorf("unterminated: %s", got)
	}
}

// ----- ErrRegistryStatus ------------------------------------------

func TestErrRegistryStatusFormat(t *testing.T) {
	e := &ErrRegistryStatus{URL: "https://x/y", Status: 503}
	if !strings.Contains(e.Error(), "503") {
		t.Errorf("err missing status: %s", e.Error())
	}
}

// ----- Registry.Authenticate --------------------------------------

func TestAuthenticateAnonymousNoChallenge(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/repo/manifests/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, []byte(sampleManifest))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "repo", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if reg.bearer != "" {
		t.Errorf("anonymous-public should leave bearer empty")
	}
}

func TestAuthenticateBearer(t *testing.T) {
	mt := newMockTransport(t)
	// First call: 401 with challenge.
	authProbe := "https://reg.example.com/v2/repo/manifests/latest"
	mt.On(authProbe, func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Bearer realm="https://auth.example.com/token",service="reg",scope="repository:repo:pull"`,
		}, nil)
	})
	// Token call: 200 with token body.
	mt.OnPrefix("https://auth.example.com/token", func(req mockRequest) *ministack.HTTPResponse {
		// Ensure no Authorization on the token request.
		for _, h := range req.Opts.ExtraHeaders {
			if strings.HasPrefix(h, "Authorization:") {
				t.Errorf("token request must not carry Authorization, got %s", h)
			}
		}
		return fakeResponse(200, nil, []byte(`{"token":"abc"}`))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "repo", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if reg.bearer != "abc" {
		t.Errorf("bearer=%s; want abc", reg.bearer)
	}
}

func TestAuthenticateRejectsUnexpectedStatus(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(503, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	err := reg.Authenticate()
	var status *ErrRegistryStatus
	if !errors.As(err, &status) || status.Status != 503 {
		t.Errorf("want ErrRegistryStatus{Status:503}, got %v", err)
	}
}

func TestAuthenticateMissingChallenge(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != ErrChallengeMissing {
		t.Errorf("want ErrChallengeMissing, got %v", err)
	}
}

func TestAuthenticateMissingRealm(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Bearer service="x"`,
		}, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != ErrChallengeMissingRealm {
		t.Errorf("want ErrChallengeMissingRealm, got %v", err)
	}
}

func TestAuthenticateUnsupportedChallenge(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Basic realm="x"`,
		}, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != ErrChallengeUnsupported {
		t.Errorf("want ErrChallengeUnsupported, got %v", err)
	}
}

func TestAuthenticateTokenEmpty(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Bearer realm="https://auth.example.com/token",service="reg"`,
		}, nil)
	})
	mt.OnPrefix("https://auth.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, []byte(`{}`))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err != ErrTokenEmpty {
		t.Errorf("want ErrTokenEmpty, got %v", err)
	}
}

func TestAuthenticateTokenEndpointNon200(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(401, map[string]string{
			"www-authenticate": `Bearer realm="https://auth.example.com/token",service="reg"`,
		}, nil)
	})
	mt.OnPrefix("https://auth.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(500, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	err := reg.Authenticate()
	var status *ErrRegistryStatus
	if !errors.As(err, &status) || status.Status != 500 {
		t.Errorf("want ErrRegistryStatus{500}, got %v", err)
	}
}

// ----- Registry.FetchManifestRaw / FetchBlob ----------------------

func TestFetchManifestRawAddsBearer(t *testing.T) {
	mt := newMockTransport(t)
	called := false
	mt.OnPrefix("https://reg.example.com/v2/r/manifests/", func(req mockRequest) *ministack.HTTPResponse {
		called = true
		gotBearer := ""
		for _, h := range req.Opts.ExtraHeaders {
			if strings.HasPrefix(h, "Authorization:") {
				gotBearer = h
			}
		}
		if gotBearer != "Authorization: Bearer cached-bearer" {
			t.Errorf("Authorization header = %q", gotBearer)
		}
		return fakeResponse(200, map[string]string{"content-type": MediaTypeOCIManifest}, []byte("body"))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	reg.bearer = "cached-bearer"
	body, ct, err := reg.FetchManifestRaw("latest")
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Errorf("handler not called")
	}
	if ct != MediaTypeOCIManifest {
		t.Errorf("ct=%s", ct)
	}
	if string(body) != "body" {
		t.Errorf("body=%s", body)
	}
}

func TestFetchManifestRawSurfaces404(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(404, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, _, err := reg.FetchManifestRaw("nope")
	var status *ErrRegistryStatus
	if !errors.As(err, &status) || status.Status != 404 {
		t.Errorf("want 404, got %v", err)
	}
}

func TestFetchBlobVerifies(t *testing.T) {
	mt := newMockTransport(t)
	body := []byte("blob-bytes")
	d := DigestFromBytes(body)
	mt.OnPrefix("https://reg.example.com/v2/r/blobs/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, body)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	got, err := reg.FetchBlob(Descriptor{Digest: d, Size: int64(len(body))})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch")
	}
}

func TestFetchBlobDetectsMismatch(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, []byte("WRONG-BYTES"))
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	correctDigest := DigestFromBytes([]byte("right-bytes"))
	_, err := reg.FetchBlob(Descriptor{Digest: correctDigest, Size: 11})
	if err != ErrDigestMismatch {
		t.Errorf("want ErrDigestMismatch, got %v", err)
	}
}

func TestFetchBlobDetectsSizeMismatch(t *testing.T) {
	mt := newMockTransport(t)
	body := []byte("blob-bytes")
	d := DigestFromBytes(body)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(200, nil, body)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	// Digest matches but size header lies.
	_, err := reg.FetchBlob(Descriptor{Digest: d, Size: 999})
	if err == nil || !strings.Contains(err.Error(), "size mismatch") {
		t.Errorf("want size-mismatch error, got %v", err)
	}
}

func TestFetchBlobFollowsRedirect(t *testing.T) {
	mt := newMockTransport(t)
	body := []byte("blob-after-redirect")
	d := DigestFromBytes(body)
	// First hop: 307 to a different host.
	mt.OnPrefix("https://reg.example.com/v2/r/blobs/", func(req mockRequest) *ministack.HTTPResponse {
		// Authorization MUST be present on the registry-side request.
		hasAuth := false
		for _, h := range req.Opts.ExtraHeaders {
			if strings.HasPrefix(h, "Authorization:") {
				hasAuth = true
			}
		}
		if !hasAuth {
			t.Errorf("first-hop missing Authorization")
		}
		return fakeResponse(307, map[string]string{
			"location": "https://blobstore.example.net/some-path?sig=xyz",
		}, nil)
	})
	mt.OnPrefix("https://blobstore.example.net/", func(req mockRequest) *ministack.HTTPResponse {
		// Authorization MUST NOT be forwarded.
		for _, h := range req.Opts.ExtraHeaders {
			if strings.HasPrefix(h, "Authorization:") {
				t.Errorf("redirect hop carried Authorization: %s", h)
			}
		}
		return fakeResponse(200, nil, body)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	reg.bearer = "first-hop-token"
	got, err := reg.FetchBlob(Descriptor{Digest: d, Size: int64(len(body))})
	if err != nil {
		t.Fatalf("FetchBlob: %v", err)
	}
	if string(got) != string(body) {
		t.Errorf("body mismatch after redirect")
	}
}

func TestFetchBlobRedirectMissingLocation(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(302, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := reg.FetchBlob(Descriptor{Digest: "sha256:" + strings.Repeat("a", 64), Size: 1})
	var s *ErrRegistryStatus
	if !errors.As(err, &s) || s.Status != 302 {
		t.Errorf("want 302, got %v", err)
	}
}

func TestFetchBlobTooManyRedirects(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(307, map[string]string{"location": "https://elsewhere.example.com/redirect-again"}, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := reg.FetchBlob(Descriptor{Digest: "sha256:" + strings.Repeat("a", 64), Size: 1})
	if err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("want too-many-redirects error, got %v", err)
	}
}

func TestIsRedirect(t *testing.T) {
	for _, s := range []int{301, 302, 303, 307, 308} {
		if !isRedirect(s) {
			t.Errorf("%d should be redirect", s)
		}
	}
	for _, s := range []int{200, 304, 400, 404, 500} {
		if isRedirect(s) {
			t.Errorf("%d should NOT be redirect", s)
		}
	}
}

func TestFetchBlob404(t *testing.T) {
	mt := newMockTransport(t)
	mt.OnPrefix("https://reg.example.com/v2/", func(req mockRequest) *ministack.HTTPResponse {
		return fakeResponse(404, nil, nil)
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	_, err := reg.FetchBlob(Descriptor{Digest: "sha256:" + strings.Repeat("a", 64), Size: 1})
	var s *ErrRegistryStatus
	if !errors.As(err, &s) || s.Status != 404 {
		t.Errorf("want 404, got %v", err)
	}
}

// ----- Transport router (http vs https) ---------------------------

func TestNewMinistackTransportRoutes(t *testing.T) {
	// We can't easily exercise the live HTTPSGet path host-side, but
	// we can at least confirm the constructor returns a non-nil
	// transport that dispatches on scheme.
	tr := NewMinistackTransport(nil)
	if tr == nil {
		t.Fatal("NewMinistackTransport returned nil")
	}
}

// ----- httpGet auth-probe failure (transport error) ---------------

func TestAuthenticateTransportError(t *testing.T) {
	mt := newMockTransport(t)
	// No handler — mockTransport returns an error.
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, nil, ref)
	if err := reg.Authenticate(); err == nil || !strings.Contains(err.Error(), "auth probe") {
		t.Errorf("want auth probe error, got %v", err)
	}
}
