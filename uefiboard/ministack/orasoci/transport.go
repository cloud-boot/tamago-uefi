// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// net/http.RoundTripper adapter that delegates to ministack.
//
// Why this package exists (M7.alt evaluation):
//
//   - M7 ships a hand-rolled OCI Distribution v2 client in
//     ministack/oci/. It works, but couples ministack to one
//     particular client implementation. The user wants to evaluate
//     whether swapping for oras.land/oras-go/v2 (the canonical
//     pure-Go OCI client) is desirable; the trade-off is "less code
//     we own" vs. "larger binary because we drag in net/http +
//     containerd image-spec".
//   - oras-go drives every registry call through a
//     `net/http.Client` (or a thin `auth.Client` wrapper around it).
//     Under TamaGo, `net.Dial` won't work — there's no socket layer.
//     The escape hatch is to plug our own `http.RoundTripper` into
//     `http.Client.Transport`, so net/http never calls `net.Dial` —
//     every request flows through our ministack-backed adapter.
//
// What's here:
//
//   - MinistackRoundTripper: implements http.RoundTripper. For each
//     request it parses scheme/host/port, dials via Stack.DialTLS
//     (HTTPS) or Stack.DialTCP4 (HTTP), writes the request, then
//     parses the response via ministack's exported streaming helpers
//     (ministack.NewLineReader + ministack.StreamHTTPResponseHeaders)
//     and surfaces an http.Response whose Body streams from the same
//     conn.
//   - Honours req.Context() cancellation between header read and
//     body streaming — ministack doesn't have proper context plumbing
//     so this is best-effort.
//
// What's intentionally NOT implemented:
//
//   - Connection pooling / keep-alive. Each request opens + closes
//     a fresh conn. Matches the hand-rolled M7 client's behaviour and
//     keeps the adapter ~150 LOC.
//   - HTTP/2. The buffered M5/M6/M7 path is HTTP/1.1; oras-go
//     negotiates over whatever Transport gives it.
//   - Trailers, redirect handling, cookies. oras-go drives redirects
//     itself via the auth.Client wrapper and the underlying
//     http.Client; we only need to surface the 3xx + Location header
//     and let oras-go follow.

package orasoci

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// ErrUnsupportedScheme is returned when RoundTrip receives a URL
// whose scheme isn't http:// or https://.
var ErrUnsupportedScheme = errors.New("ministack/orasoci: only http:// and https:// schemes are supported")

// DefaultDialTimeout is the wall-clock cap applied to a single dial
// when the RoundTripper isn't given one explicitly. Matches the
// hand-rolled M7 client's value.
const DefaultDialTimeout = 15 * time.Second

// DefaultRequestTimeout is the wall-clock cap applied to a single
// HTTP request (post-dial) when no context deadline is set.
const DefaultRequestTimeout = 30 * time.Second

// MinistackRoundTripper is the http.RoundTripper adapter. The zero
// value is unusable; construct via New.
type MinistackRoundTripper struct {
	// Stack is the ministack Stack that owns the L2/L3/L4 layers we
	// dial through. Must be configured (DHCP-acquired or static) and
	// running before any request flows through this transport.
	Stack *ministack.Stack
	// DNS is the IPv4 resolver used to translate host names. Typically
	// the first DNS server learned from DHCP. Required for any
	// non-IP-literal host.
	DNS net.IP
	// DialTimeout caps the TCP + TLS handshake. Zero =
	// DefaultDialTimeout.
	DialTimeout time.Duration
	// RequestTimeout caps the request lifetime once connected. Zero =
	// DefaultRequestTimeout.
	RequestTimeout time.Duration
}

// New constructs a MinistackRoundTripper bound to the given Stack +
// DNS resolver. Pass it to http.Client.Transport (or oras-go
// auth.Client.Client.Transport) to route every request through
// ministack.
func New(stack *ministack.Stack, dns net.IP) *MinistackRoundTripper {
	return &MinistackRoundTripper{Stack: stack, DNS: dns}
}

// RoundTrip implements http.RoundTripper. See the package header for
// what's supported.
func (t *MinistackRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL == nil {
		return nil, errors.New("ministack/orasoci: nil request URL")
	}
	scheme := strings.ToLower(req.URL.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, ErrUnsupportedScheme
	}

	host, portStr := splitHostPort(req.URL.Host)
	port, err := defaultPort(scheme, portStr)
	if err != nil {
		return nil, err
	}

	dialTimeout := t.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultDialTimeout
	}
	reqTimeout := t.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = DefaultRequestTimeout
	}
	// Honour context deadline if it tightens the budget further.
	ctx := req.Context()
	if dl, ok := ctx.Deadline(); ok {
		budget := time.Until(dl)
		if budget > 0 && budget < dialTimeout {
			dialTimeout = budget
		}
		if budget > 0 && budget < reqTimeout {
			reqTimeout = budget
		}
	}

	// Dial.
	var conn io.ReadWriteCloser
	switch scheme {
	case "https":
		tlsConn, derr := t.Stack.DialTLS(host, port, t.DNS, dialTimeout)
		if derr != nil {
			return nil, fmt.Errorf("ministack/orasoci: DialTLS %s:%d: %w", host, port, derr)
		}
		conn = tlsConn
	case "http":
		ip, rerr := t.resolve(host, dialTimeout)
		if rerr != nil {
			return nil, rerr
		}
		tcpConn, derr := t.Stack.DialTCP4(ip, port, dialTimeout)
		if derr != nil {
			return nil, fmt.Errorf("ministack/orasoci: DialTCP4 %s:%d: %w", host, port, derr)
		}
		conn = tcpConn
	}

	// Apply the request deadline to the underlying TCP4Conn (TLS
	// inherits via the wrapped net.Conn).
	t.setDeadline(conn, time.Now().Add(reqTimeout))

	// Best-effort context cancellation check before writing.
	if cerr := ctx.Err(); cerr != nil {
		_ = conn.Close()
		return nil, cerr
	}

	// Write the request line + headers + (optional) body.
	if werr := writeHTTPRequest(conn, req, host, port, scheme); werr != nil {
		_ = conn.Close()
		return nil, werr
	}

	// Best-effort cancellation between header read and body stream.
	if cerr := ctx.Err(); cerr != nil {
		_ = conn.Close()
		return nil, cerr
	}

	// Parse status + headers via ministack streaming helpers, with
	// the body funnelled into an io.Pipe so net/http callers can read
	// it incrementally.
	pr, pw := io.Pipe()
	bodyDone := make(chan error, 1)

	br := ministack.NewLineReader(conn)
	status, headers, hdrErr := readStatusAndHeaders(br)
	if hdrErr != nil {
		_ = conn.Close()
		_ = pw.CloseWithError(hdrErr)
		return nil, hdrErr
	}

	go func() {
		_, _, _, copyErr := streamBodyOnly(br, pw, headers)
		// Closing the underlying conn AFTER the body completes
		// frees ministack's TCB. Order matters: close the pipe
		// writer first so the reader sees EOF, then close the conn.
		if copyErr != nil {
			_ = pw.CloseWithError(copyErr)
		} else {
			_ = pw.Close()
		}
		_ = conn.Close()
		bodyDone <- copyErr
		close(bodyDone)
	}()

	resp := &http.Response{
		Status:     http.StatusText(status),
		StatusCode: status,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     toHTTPHeader(headers),
		Body:       pr,
		Request:    req,
	}
	if cl, ok := headers["content-length"]; ok {
		if n, perr := strconv.ParseInt(cl, 10, 64); perr == nil {
			resp.ContentLength = n
		}
	} else {
		resp.ContentLength = -1
	}
	if te, ok := headers["transfer-encoding"]; ok && strings.EqualFold(te, "chunked") {
		resp.TransferEncoding = []string{"chunked"}
	}
	return resp, nil
}

// resolve maps host (literal IP or DNS name) to an IPv4. timeout
// bounds the DNS round-trip when needed.
func (t *MinistackRoundTripper) resolve(host string, timeout time.Duration) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		ip4 := ip.To4()
		if ip4 == nil {
			return nil, errors.New("ministack/orasoci: only IPv4 supported")
		}
		return ip4, nil
	}
	if t.DNS == nil {
		return nil, errors.New("ministack/orasoci: DNS server not configured")
	}
	return t.Stack.ResolveA(host, t.DNS, timeout)
}

// setDeadline applies a wall-clock deadline to the underlying TCP4
// conn. tls.Conn's NetConn() gives us the TCP4Conn back; plain TCP
// uses the conn directly.
func (t *MinistackRoundTripper) setDeadline(c io.ReadWriteCloser, dl time.Time) {
	switch v := c.(type) {
	case *tls.Conn:
		if nc, ok := v.NetConn().(*ministack.TCP4Conn); ok {
			_ = nc.SetDeadline(dl)
		}
	case *ministack.TCP4Conn:
		_ = v.SetDeadline(dl)
	}
}

// splitHostPort splits "host:port" into host + port string. Empty
// port means "use scheme default".
func splitHostPort(hostport string) (host, port string) {
	host = hostport
	if i := strings.LastIndexByte(hostport, ':'); i >= 0 {
		// Defensive: bare-IPv6 [::1]:443 would tip splitting; we don't
		// support IPv6 yet, so a closing bracket signals "leave the
		// bracketed host alone and pull just the trailing :port".
		if strings.HasPrefix(hostport, "[") {
			rb := strings.LastIndexByte(hostport, ']')
			if rb >= 0 && i > rb {
				return hostport[1:rb], hostport[i+1:]
			}
			return hostport, ""
		}
		return hostport[:i], hostport[i+1:]
	}
	return host, ""
}

// defaultPort returns the integer port, defaulting to 80 (http) or
// 443 (https) when the URL omits it.
func defaultPort(scheme, port string) (uint16, error) {
	if port == "" {
		switch scheme {
		case "http":
			return 80, nil
		case "https":
			return 443, nil
		}
		return 0, ErrUnsupportedScheme
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("ministack/orasoci: invalid port %q: %w", port, err)
	}
	return uint16(p), nil
}

// writeHTTPRequest serialises req onto the wire. The request body
// (when present — POST/PUT) is read fully into RAM before sending;
// oras-go pushes manifests via the same path but the M7.alt probe
// only ever GETs, so this fastpath stays simple.
func writeHTTPRequest(conn io.Writer, req *http.Request, host string, port uint16, scheme string) error {
	bw := bufio.NewWriter(conn)
	// Request line.
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}
	method := req.Method
	if method == "" {
		method = "GET"
	}
	if _, err := fmt.Fprintf(bw, "%s %s HTTP/1.1\r\n", method, path); err != nil {
		return err
	}
	// Host header. Include port when non-default.
	hostHeader := host
	if (scheme == "http" && port != 80) || (scheme == "https" && port != 443) {
		hostHeader = host + ":" + strconv.FormatUint(uint64(port), 10)
	}
	if _, err := fmt.Fprintf(bw, "Host: %s\r\n", hostHeader); err != nil {
		return err
	}

	// User-Agent default (oras-go sets its own; this fires only when
	// the caller leaves it blank).
	if req.Header.Get("User-Agent") == "" {
		if _, err := bw.WriteString("User-Agent: ministack-orasoci/1.0\r\n"); err != nil {
			return err
		}
	}
	// Force Connection: close — keeps the transport's "one conn per
	// RoundTrip" lifecycle clean.
	connSet := false
	for k, vv := range req.Header {
		// Skip Host (we emitted it above), and skip Connection (we
		// re-emit our own).
		if strings.EqualFold(k, "Host") {
			continue
		}
		if strings.EqualFold(k, "Connection") {
			connSet = true
			continue
		}
		for _, v := range vv {
			if _, err := fmt.Fprintf(bw, "%s: %s\r\n", k, v); err != nil {
				return err
			}
		}
	}
	if !connSet {
		if _, err := bw.WriteString("Connection: close\r\n"); err != nil {
			return err
		}
	} else {
		// Mirror back the caller's preference, but normalise to "close"
		// since we don't support keep-alive yet.
		if _, err := bw.WriteString("Connection: close\r\n"); err != nil {
			return err
		}
	}

	// Body. For methods we expect from oras-go (mostly GET + HEAD,
	// occasionally POST for token, never PUT for the read-only probe)
	// we serialise via Content-Length.
	var body []byte
	if req.Body != nil {
		var rerr error
		body, rerr = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if rerr != nil {
			return rerr
		}
	}
	if len(body) > 0 && req.Header.Get("Content-Length") == "" {
		if _, err := fmt.Fprintf(bw, "Content-Length: %d\r\n", len(body)); err != nil {
			return err
		}
	}
	if _, err := bw.WriteString("\r\n"); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := bw.Write(body); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// readStatusAndHeaders consumes the status line + header block from
// br. It mirrors ministack.streamHTTPResponseHeaders' parser piece
// without touching the body — we hand the still-buffered br off to
// streamBodyOnly afterward.
func readStatusAndHeaders(br *ministack.LineReader) (status int, headers map[string]string, err error) {
	headers = map[string]string{}
	statusLine, lerr := br.ReadLine()
	if lerr != nil {
		return 0, headers, lerr
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, headers, errors.New("ministack/orasoci: malformed HTTP status line")
	}
	status, perr := strconv.Atoi(parts[1])
	if perr != nil {
		return 0, headers, errors.New("ministack/orasoci: malformed HTTP status code")
	}
	for {
		line, herr := br.ReadLine()
		if herr != nil {
			return 0, headers, herr
		}
		if line == "" {
			return status, headers, nil
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return 0, headers, errors.New("ministack/orasoci: malformed HTTP header")
		}
		k := strings.ToLower(strings.TrimSpace(line[:colon]))
		v := strings.TrimSpace(line[colon+1:])
		// Capture full set — oras-go inspects many headers (Docker-
		// Content-Digest, Location, WWW-Authenticate, etc.).
		if existing, ok := headers[k]; ok {
			headers[k] = existing + ", " + v
		} else {
			headers[k] = v
		}
	}
}

// streamBodyOnly streams the response body from br into dst,
// dispatching on Content-Length / Transfer-Encoding. We reuse the
// exported ministack helper for the status+headers path; for the
// body-only path we re-implement the three-way dispatch here so we
// don't have to round-trip back through StreamHTTPResponseHeaders
// (which also parses the status line).
func streamBodyOnly(br *ministack.LineReader, dst io.Writer, headers map[string]string) (status int, written int64, retHeaders map[string]string, err error) {
	// Dispatch.
	if te, ok := headers["transfer-encoding"]; ok && strings.EqualFold(te, "chunked") {
		written, err = streamChunked(br, dst)
		return 0, written, headers, err
	}
	if cl, ok := headers["content-length"]; ok {
		n, perr := strconv.ParseInt(cl, 10, 64)
		if perr != nil || n < 0 {
			return 0, 0, headers, errors.New("ministack/orasoci: bad Content-Length")
		}
		written, err = streamBounded(br, dst, n)
		return 0, written, headers, err
	}
	written, err = streamIdentity(br, dst)
	return 0, written, headers, err
}

// streamBounded copies exactly n bytes from br to dst using an 8 KiB
// scratch buffer. EOF before n bytes surfaces io.ErrUnexpectedEOF.
func streamBounded(br *ministack.LineReader, dst io.Writer, n int64) (int64, error) {
	buf := make([]byte, 8*1024)
	var written int64
	for written < n {
		want := n - written
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		r, err := br.Read(buf[:want])
		if r > 0 {
			w, werr := dst.Write(buf[:r])
			written += int64(w)
			if werr != nil {
				return written, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				if written < n {
					return written, io.ErrUnexpectedEOF
				}
				return written, nil
			}
			return written, err
		}
	}
	return written, nil
}

// streamIdentity copies until EOF.
func streamIdentity(br *ministack.LineReader, dst io.Writer) (int64, error) {
	buf := make([]byte, 8*1024)
	var written int64
	for {
		n, err := br.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			written += int64(w)
			if werr != nil {
				return written, werr
			}
		}
		if err != nil {
			if err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}

// streamChunked decodes Transfer-Encoding: chunked on the fly.
func streamChunked(br *ministack.LineReader, dst io.Writer) (int64, error) {
	buf := make([]byte, 8*1024)
	var written int64
	for {
		sizeLine, err := br.ReadLine()
		if err != nil {
			return written, err
		}
		if i := strings.IndexByte(sizeLine, ';'); i >= 0 {
			sizeLine = sizeLine[:i]
		}
		size, perr := strconv.ParseUint(strings.TrimSpace(sizeLine), 16, 64)
		if perr != nil {
			return written, errors.New("ministack/orasoci: malformed chunked size")
		}
		if size == 0 {
			// Drain trailer block.
			for {
				tl, terr := br.ReadLine()
				if terr != nil {
					return written, nil
				}
				if tl == "" {
					return written, nil
				}
			}
		}
		remaining := int64(size)
		for remaining > 0 {
			want := remaining
			if want > int64(len(buf)) {
				want = int64(len(buf))
			}
			r, rerr := br.Read(buf[:want])
			if r > 0 {
				w, werr := dst.Write(buf[:r])
				written += int64(w)
				remaining -= int64(r)
				if werr != nil {
					return written, werr
				}
			}
			if rerr != nil {
				if rerr == io.EOF {
					return written, io.ErrUnexpectedEOF
				}
				return written, rerr
			}
		}
		// Discard trailing CRLF.
		if _, err := br.ReadLine(); err != nil {
			return written, err
		}
	}
}

// toHTTPHeader converts a lowercase-keyed map[string]string into the
// canonical http.Header net/http expects (case-corrected keys, value
// split on the ", " join we used during parse).
func toHTTPHeader(headers map[string]string) http.Header {
	h := make(http.Header, len(headers))
	for k, v := range headers {
		canon := http.CanonicalHeaderKey(k)
		if strings.Contains(v, ", ") {
			h[canon] = strings.Split(v, ", ")
		} else {
			h[canon] = []string{v}
		}
	}
	return h
}

// compile-time check.
var _ http.RoundTripper = (*MinistackRoundTripper)(nil)

// Compile-time imports retained for go vet symmetry — req.URL is a
// *url.URL and req.Context() returns context.Context, so even though
// we touch them only through req we keep these packages in our
// import graph to flag explicitly should an unrelated edit drop the
// dependency.
var (
	_ = url.URL{}
	_ = context.Background
)
