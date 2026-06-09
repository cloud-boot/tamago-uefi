// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package orasoci

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in       string
		wantHost string
		wantPort string
	}{
		{"ghcr.io", "ghcr.io", ""},
		{"ghcr.io:443", "ghcr.io", "443"},
		{"127.0.0.1:8080", "127.0.0.1", "8080"},
		{"[::1]:8080", "::1", "8080"},
		{"[::1]", "[::1]", ""},
	}
	for _, tc := range tests {
		h, p := splitHostPort(tc.in)
		if h != tc.wantHost || p != tc.wantPort {
			t.Errorf("splitHostPort(%q) = (%q,%q), want (%q,%q)", tc.in, h, p, tc.wantHost, tc.wantPort)
		}
	}
}

func TestDefaultPort(t *testing.T) {
	cases := []struct {
		scheme  string
		port    string
		want    uint16
		wantErr bool
	}{
		{"http", "", 80, false},
		{"https", "", 443, false},
		{"http", "8080", 8080, false},
		{"https", "8443", 8443, false},
		{"ftp", "", 0, true},
		{"http", "notanumber", 0, true},
		{"http", "70000", 0, true},
	}
	for _, c := range cases {
		got, err := defaultPort(c.scheme, c.port)
		if (err != nil) != c.wantErr {
			t.Errorf("defaultPort(%q,%q) error = %v, wantErr %v", c.scheme, c.port, err, c.wantErr)
			continue
		}
		if got != c.want {
			t.Errorf("defaultPort(%q,%q) = %d, want %d", c.scheme, c.port, got, c.want)
		}
	}
}

func TestToHTTPHeader(t *testing.T) {
	in := map[string]string{
		"content-type":   "application/json",
		"content-length": "42",
		"accept":         "text/html, application/json",
	}
	got := toHTTPHeader(in)
	if got.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type = %q", got.Get("Content-Type"))
	}
	if got.Get("Content-Length") != "42" {
		t.Errorf("Content-Length = %q", got.Get("Content-Length"))
	}
	accept := got["Accept"]
	if len(accept) != 2 || accept[0] != "text/html" || accept[1] != "application/json" {
		t.Errorf("Accept = %#v, want split-on-comma", accept)
	}
}

func TestWriteHTTPRequestGET(t *testing.T) {
	var buf bytes.Buffer
	u, _ := url.Parse("https://ghcr.io/v2/foo/manifests/latest")
	req := &http.Request{
		Method: http.MethodGet,
		URL:    u,
		Header: http.Header{
			"Accept":        []string{"application/vnd.oci.image.manifest.v1+json"},
			"Authorization": []string{"Bearer xyz"},
		},
	}
	if err := writeHTTPRequest(&buf, req, "ghcr.io", 443, "https"); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "GET /v2/foo/manifests/latest HTTP/1.1\r\n") {
		t.Fatalf("missing request line: %q", out[:60])
	}
	if !strings.Contains(out, "Host: ghcr.io\r\n") {
		t.Errorf("missing Host header: %q", out)
	}
	if !strings.Contains(out, "Authorization: Bearer xyz\r\n") {
		t.Errorf("missing Authorization header: %q", out)
	}
	if !strings.Contains(out, "Connection: close\r\n") {
		t.Errorf("expected Connection: close")
	}
	if !strings.HasSuffix(out, "\r\n\r\n") {
		t.Errorf("expected trailing blank line, got tail %q", out[len(out)-8:])
	}
}

func TestWriteHTTPRequestNonStandardPort(t *testing.T) {
	var buf bytes.Buffer
	u, _ := url.Parse("http://example.com:8080/")
	req := &http.Request{Method: http.MethodGet, URL: u, Header: http.Header{}}
	if err := writeHTTPRequest(&buf, req, "example.com", 8080, "http"); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
	}
	if !strings.Contains(buf.String(), "Host: example.com:8080\r\n") {
		t.Errorf("Host header should include port: %q", buf.String())
	}
}

func TestWriteHTTPRequestWithBody(t *testing.T) {
	var buf bytes.Buffer
	u, _ := url.Parse("https://example.com/upload")
	body := "hello-body"
	req := &http.Request{
		Method: http.MethodPost,
		URL:    u,
		Header: http.Header{},
		Body:   io.NopCloser(strings.NewReader(body)),
	}
	if err := writeHTTPRequest(&buf, req, "example.com", 443, "https"); err != nil {
		t.Fatalf("writeHTTPRequest: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Content-Length: 10\r\n") {
		t.Errorf("missing Content-Length: %q", out)
	}
	if !strings.HasSuffix(out, body) {
		t.Errorf("body not appended: %q", out)
	}
}

// readStatusAndHeaders + streamBodyOnly tests use a real
// ministack.LineReader wrapping a bytes.Reader to simulate a conn.

func TestReadStatusAndHeadersOK(t *testing.T) {
	wire := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: application/json\r\n" +
		"Content-Length: 5\r\n" +
		"\r\n" +
		"hello"
	br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
	status, headers, err := readStatusAndHeaders(br)
	if err != nil {
		t.Fatalf("readStatusAndHeaders: %v", err)
	}
	if status != 200 {
		t.Errorf("status = %d, want 200", status)
	}
	if headers["content-type"] != "application/json" {
		t.Errorf("content-type = %q", headers["content-type"])
	}
	if headers["content-length"] != "5" {
		t.Errorf("content-length = %q", headers["content-length"])
	}
}

func TestReadStatusAndHeadersBadStatusLine(t *testing.T) {
	for _, wire := range []string{
		"BORK\r\n\r\n",
		"HTTP/1.1 NOTANUMBER OK\r\n\r\n",
		"",
	} {
		br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
		if _, _, err := readStatusAndHeaders(br); err == nil {
			t.Errorf("expected error for %q", wire)
		}
	}
}

func TestReadStatusAndHeadersBadHeaderLine(t *testing.T) {
	wire := "HTTP/1.1 200 OK\r\nnocolon\r\n\r\n"
	br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
	if _, _, err := readStatusAndHeaders(br); err == nil {
		t.Errorf("expected error for malformed header")
	}
}

func TestStreamBodyOnlyContentLength(t *testing.T) {
	br := ministack.NewLineReader(bytes.NewReader([]byte("HELLO")))
	var dst bytes.Buffer
	headers := map[string]string{"content-length": "5"}
	_, written, _, err := streamBodyOnly(br, &dst, headers)
	if err != nil {
		t.Fatalf("streamBodyOnly: %v", err)
	}
	if written != 5 {
		t.Errorf("written = %d, want 5", written)
	}
	if dst.String() != "HELLO" {
		t.Errorf("body = %q", dst.String())
	}
}

func TestStreamBodyOnlyContentLengthBadValue(t *testing.T) {
	br := ministack.NewLineReader(bytes.NewReader([]byte("HELLO")))
	var dst bytes.Buffer
	for _, cl := range []string{"-1", "abc"} {
		headers := map[string]string{"content-length": cl}
		_, _, _, err := streamBodyOnly(br, &dst, headers)
		if err == nil {
			t.Errorf("expected error for content-length=%q", cl)
		}
	}
}

func TestStreamBodyOnlyContentLengthShort(t *testing.T) {
	// Body shorter than advertised — should surface ErrUnexpectedEOF.
	br := ministack.NewLineReader(bytes.NewReader([]byte("HI")))
	var dst bytes.Buffer
	_, _, _, err := streamBodyOnly(br, &dst, map[string]string{"content-length": "5"})
	if err != io.ErrUnexpectedEOF {
		t.Errorf("err = %v, want ErrUnexpectedEOF", err)
	}
}

func TestStreamBodyOnlyIdentity(t *testing.T) {
	br := ministack.NewLineReader(bytes.NewReader([]byte("IDENTITY-BODY")))
	var dst bytes.Buffer
	_, written, _, err := streamBodyOnly(br, &dst, map[string]string{})
	if err != nil {
		t.Fatalf("streamBodyOnly: %v", err)
	}
	if written != int64(len("IDENTITY-BODY")) {
		t.Errorf("written = %d", written)
	}
	if dst.String() != "IDENTITY-BODY" {
		t.Errorf("body = %q", dst.String())
	}
}

func TestStreamBodyOnlyChunked(t *testing.T) {
	// Two chunks then terminator.
	wire := "5\r\nHELLO\r\n6\r\n WORLD\r\n0\r\n\r\n"
	br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
	var dst bytes.Buffer
	_, written, _, err := streamBodyOnly(br, &dst, map[string]string{"transfer-encoding": "chunked"})
	if err != nil {
		t.Fatalf("streamBodyOnly chunked: %v", err)
	}
	if dst.String() != "HELLO WORLD" {
		t.Errorf("body = %q", dst.String())
	}
	if written != 11 {
		t.Errorf("written = %d", written)
	}
}

func TestStreamBodyOnlyChunkedBadSize(t *testing.T) {
	wire := "ZZZ\r\nHELLO\r\n0\r\n\r\n"
	br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
	var dst bytes.Buffer
	if _, _, _, err := streamBodyOnly(br, &dst, map[string]string{"transfer-encoding": "chunked"}); err == nil {
		t.Errorf("expected error for malformed chunk size")
	}
}

func TestStreamBodyOnlyChunkedTruncated(t *testing.T) {
	// Chunk size claims 5 bytes but only 2 follow before EOF.
	wire := "5\r\nHI"
	br := ministack.NewLineReader(bytes.NewReader([]byte(wire)))
	var dst bytes.Buffer
	if _, _, _, err := streamBodyOnly(br, &dst, map[string]string{"transfer-encoding": "chunked"}); err == nil {
		t.Errorf("expected truncation error")
	}
}

// roundTripFakeConn is a fake io.ReadWriteCloser whose Read returns
// canned bytes — useful for end-to-end RoundTrip-like flow tests that
// don't need a real Stack. We can't fully exercise RoundTrip because
// it uses DialTLS/DialTCP4 directly off *ministack.Stack; the per-
// helper tests above cover the parsing logic.
type roundTripFakeConn struct {
	io.Reader
	written bytes.Buffer
}

func (c *roundTripFakeConn) Write(p []byte) (int, error) { return c.written.Write(p) }
func (c *roundTripFakeConn) Close() error                { return nil }

// TestRoundTripperUnsupportedScheme ensures we reject ws://, ftp://,
// etc. before dialing.
func TestRoundTripperUnsupportedScheme(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{}
	u, _ := url.Parse("ftp://example.com/foo")
	req := &http.Request{Method: "GET", URL: u, Header: http.Header{}}
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, ErrUnsupportedScheme) {
		t.Errorf("got %v, want ErrUnsupportedScheme", err)
	}
}

// TestRoundTripperNilURL covers the defensive nil-URL branch.
func TestRoundTripperNilURL(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{}
	req := &http.Request{Method: "GET", Header: http.Header{}}
	if _, err := rt.RoundTrip(req); err == nil {
		t.Errorf("expected error for nil URL")
	}
}

// TestNewConstructor checks the New() ctor wires fields through.
func TestNewConstructor(t *testing.T) {
	t.Parallel()
	rt := New(nil, nil)
	if rt == nil {
		t.Fatalf("New returned nil")
	}
	if rt.DialTimeout != 0 || rt.RequestTimeout != 0 {
		t.Errorf("expected zero timeouts (defaults applied at RoundTrip), got %v / %v", rt.DialTimeout, rt.RequestTimeout)
	}
}

// TestNewRepositoryWiring confirms NewRepository hands back a
// Repository whose Repo + Transport are non-nil and whose Reference
// matches what we asked for.
func TestNewRepositoryWiring(t *testing.T) {
	t.Parallel()
	link := newOrasTestLink()
	stack := ministack.New(link)
	repo, err := NewRepository(stack, nil, "ghcr.io/linuxcontainers/alpine:latest")
	if err != nil {
		t.Fatalf("NewRepository: %v", err)
	}
	if repo.Repo == nil {
		t.Errorf("Repo is nil")
	}
	if repo.Transport == nil {
		t.Errorf("Transport is nil")
	}
	if repo.Repo.Reference.Registry != "ghcr.io" {
		t.Errorf("Registry = %q", repo.Repo.Reference.Registry)
	}
	if repo.Repo.Reference.Repository != "linuxcontainers/alpine" {
		t.Errorf("Repository = %q", repo.Repo.Reference.Repository)
	}
}

// TestNewRepositoryRejectsBadRef ensures a malformed reference
// surfaces as an error rather than panicking.
func TestNewRepositoryRejectsBadRef(t *testing.T) {
	t.Parallel()
	link := newOrasTestLink()
	stack := ministack.New(link)
	if _, err := NewRepository(stack, nil, "not a real ref"); err == nil {
		t.Errorf("expected error for malformed ref")
	}
}

// orasTestLink is a minimal ministack.Link implementation suitable
// for wiring tests that don't actually move packets. Implements the
// ministack.Link interface (SendFrame, RecvFrame, MAC).
type orasTestLink struct {
	mac net.HardwareAddr
}

func newOrasTestLink() *orasTestLink {
	return &orasTestLink{mac: net.HardwareAddr{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}}
}

func (l *orasTestLink) SendFrame(frame []byte) error { return nil }
func (l *orasTestLink) RecvFrame() ([]byte, error) {
	// Return an error so the Stack's inline RX pump doesn't busy-loop
	// hot in the test. The dispatcher tolerates errors and skips.
	return nil, errors.New("orasTestLink: no frames")
}
func (l *orasTestLink) MAC() net.HardwareAddr { return l.mac }

// silence unused-import lint for the fake-conn struct kept around
// as a hook for follow-up tests that exercise RoundTrip end-to-end.
var _ = roundTripFakeConn{}

// TestResolveIPLiteralIPv4 exercises resolve()'s IPv4-literal
// short-circuit so we don't need a DNS server for known-IP hosts.
func TestResolveIPLiteralIPv4(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{}
	ip, err := rt.resolve("10.0.2.2", time.Second)
	if err != nil {
		t.Fatalf("resolve(10.0.2.2): %v", err)
	}
	if ip.String() != "10.0.2.2" {
		t.Errorf("ip = %s", ip)
	}
}

// TestResolveIPLiteralIPv6Rejected ensures we surface an error for
// IPv6 literals rather than silently doing the wrong thing.
func TestResolveIPLiteralIPv6Rejected(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{}
	if _, err := rt.resolve("::1", time.Second); err == nil {
		t.Errorf("expected IPv6 rejection")
	}
}

// TestResolveMissingDNS confirms we surface a clear error when a
// non-IP host arrives without a DNS resolver configured.
func TestResolveMissingDNS(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{DNS: nil}
	if _, err := rt.resolve("ghcr.io", time.Second); err == nil {
		t.Errorf("expected error for missing DNS")
	}
}

// TestSetDeadlineUnknownConn ensures setDeadline is a no-op on a
// non-TCP4 conn (it shouldn't panic). Exercises the type switch's
// default branch.
func TestSetDeadlineUnknownConn(t *testing.T) {
	t.Parallel()
	rt := &MinistackRoundTripper{}
	rt.setDeadline(&roundTripFakeConn{Reader: strings.NewReader("")}, time.Now())
}

// TestStreamBodyOnlyZeroLength covers the n=0 fast path of streamBounded.
func TestStreamBodyOnlyZeroLength(t *testing.T) {
	t.Parallel()
	br := ministack.NewLineReader(bytes.NewReader([]byte{}))
	var dst bytes.Buffer
	_, n, _, err := streamBodyOnly(br, &dst, map[string]string{"content-length": "0"})
	if err != nil {
		t.Fatalf("streamBodyOnly: %v", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0", n)
	}
}
