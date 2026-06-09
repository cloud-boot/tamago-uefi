// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Minimal HTTP/1.1 client (GET only) for ministack.
//
// Why hand-rolled instead of `net/http`:
//
//   - Tamago's `net` package exposes a `SocketFunc` hook the stdlib
//     dialler calls to manufacture connections; wiring it correctly
//     under the inline-RX-pump pattern (no goroutine scheduling
//     guarantees) is fragile and pulls in TLS / HPACK / cookies even
//     for a plaintext GET. M5 only needs status + Content-Length +
//     body; ~150 LOC of bespoke parsing is cheaper than 50 KB of
//     compiled `net/http` we can't easily skip.
//   - The dependency closure under tamago is small + auditable —
//     critical for the OCI loader's eventual TLS+verification chain
//     in M6/M7.
//
// What's implemented:
//
//   - HTTPGet builds a request, dials TCP4 via the supplied Stack,
//     sends the request, reads + parses the response, and returns the
//     status code, headers, and body bytes.
//   - URLs are parsed by hand (just enough for `http://host[:port]/path`).
//     If `Host` is a dotted-quad IPv4, no DNS lookup is performed;
//     otherwise the caller passes a DNS server IP and we resolve it.
//   - Transfer-Encoding: chunked is supported (M5's external endpoints
//     occasionally use it). Content-Length is preferred when present.
//   - Connection: close is forced on every request so we never have to
//     reuse the same TCB.
//
// What's intentionally NOT implemented:
//
//   - Redirects (caller can re-issue if they want).
//   - Keep-alive / pooling.
//   - Trailer headers.
//   - Anything POST/PUT/DELETE — we only ship GET in M5.
//   - HTTPS (M6 territory; layers `crypto/tls` on top of TCP4Conn).

package ministack

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// HTTP-client errors.
var (
	ErrHTTPBadURL         = errors.New("ministack: malformed HTTP URL")
	ErrHTTPBadStatusLine  = errors.New("ministack: malformed HTTP status line")
	ErrHTTPBadHeader      = errors.New("ministack: malformed HTTP header line")
	ErrHTTPBadChunk       = errors.New("ministack: malformed HTTP chunk encoding")
	ErrHTTPSchemeNotHTTP  = errors.New("ministack: only http:// URLs supported by M5 client")
	ErrHTTPResponseTooBig = errors.New("ministack: HTTP response exceeded configured cap")
)

// HTTPMaxResponseBytes caps the total response (headers + body) the
// client accepts. M5 fetches small endpoints (status + a few KB);
// guarding against runaway servers keeps memory bounded.
const HTTPMaxResponseBytes = 1 << 20 // 1 MiB

// HTTPResponse is the parsed view of a server's reply.
type HTTPResponse struct {
	// StatusCode is the numeric status (e.g. 200, 404).
	StatusCode int
	// StatusLine is the full status line minus CRLF (e.g.
	// "HTTP/1.1 200 OK").
	StatusLine string
	// Headers is keyed on the canonicalised header name (lower-case);
	// values are joined with ", " when the same header appeared
	// multiple times.
	Headers map[string]string
	// Body is the response body bytes. For chunked responses the
	// chunk framing has been stripped.
	Body []byte
}

// parsedHTTPURL is the tiny URL view ministack needs for HTTP GET.
type parsedHTTPURL struct {
	Host string // hostname or dotted-quad IPv4
	Port uint16
	Path string // including the leading slash; "?query" preserved
}

// parseHTTPURL splits an absolute http:// URL into host/port/path.
// Accepts:
//
//	http://host
//	http://host:port
//	http://host/path?query
//	http://host:port/path
//
// Returns ErrHTTPSchemeNotHTTP if the scheme isn't `http://`.
func parseHTTPURL(url string) (parsedHTTPURL, error) {
	const prefix = "http://"
	if !strings.HasPrefix(url, prefix) {
		return parsedHTTPURL{}, ErrHTTPSchemeNotHTTP
	}
	rest := url[len(prefix):]
	path := "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path = rest[i:]
		rest = rest[:i]
	}
	host := rest
	port := uint16(80)
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		// Bare-IPv6 unsupported — those would be `[host]:port`.
		host = rest[:i]
		p, err := strconv.ParseUint(rest[i+1:], 10, 16)
		if err != nil {
			return parsedHTTPURL{}, ErrHTTPBadURL
		}
		port = uint16(p)
	}
	if host == "" {
		return parsedHTTPURL{}, ErrHTTPBadURL
	}
	return parsedHTTPURL{Host: host, Port: port, Path: path}, nil
}

// HTTPGetOptions tunes a single HTTPGet call.
type HTTPGetOptions struct {
	// DNSServer is used to resolve the URL's host. If the host parses
	// as a dotted-quad IPv4 the resolver is skipped. Nil + non-IP
	// host is an error.
	DNSServer net.IP
	// DialTimeout caps the TCP handshake.
	DialTimeout time.Duration
	// RequestTimeout caps the total request + response time, after
	// the connection is established.
	RequestTimeout time.Duration
	// ExtraHeaders is appended after the canonical headers (Host,
	// User-Agent, Accept, Connection). Each entry must be the full
	// header line, e.g. "Accept-Encoding: identity".
	ExtraHeaders []string
}

// defaultDialTimeout / defaultRequestTimeout are applied when the
// caller leaves the options at their zero value.
const (
	defaultDialTimeout    = 10 * time.Second
	defaultRequestTimeout = 20 * time.Second
)

// HTTPGet fetches `url` via plaintext HTTP/1.1 using the supplied
// Stack. Returns the parsed response or an error. The Stack's local
// address + default gateway must already be configured (typically via
// DHCP4Acquire).
func (s *Stack) HTTPGet(url string, opts HTTPGetOptions) (*HTTPResponse, error) {
	u, err := parseHTTPURL(url)
	if err != nil {
		return nil, err
	}

	// Resolve the host to an IPv4.
	var ip net.IP
	if parsed := net.ParseIP(u.Host); parsed != nil {
		if parsed.To4() == nil {
			return nil, ErrTCP4InvalidAddr
		}
		ip = parsed.To4()
	} else {
		if opts.DNSServer == nil {
			return nil, ErrDNSInvalidServer
		}
		dnsTimeout := opts.DialTimeout
		if dnsTimeout <= 0 {
			dnsTimeout = defaultDialTimeout
		}
		ip, err = s.ResolveA(u.Host, opts.DNSServer, dnsTimeout)
		if err != nil {
			return nil, err
		}
	}

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	conn, err := s.DialTCP4(ip, u.Port, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	reqTimeout := opts.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = defaultRequestTimeout
	}
	conn.SetDeadline(time.Now().Add(reqTimeout))

	// Compose the request.
	req := buildHTTPRequest(u, opts.ExtraHeaders)
	if _, werr := conn.Write(req); werr != nil {
		return nil, werr
	}

	// Drain the response into a single buffer up to the cap.
	return readHTTPResponse(conn)
}

// buildHTTPRequest stamps out a minimal HTTP/1.1 GET request. We force
// `Connection: close` so the server FINs after the body and our M5
// client doesn't need to track keep-alive state.
func buildHTTPRequest(u parsedHTTPURL, extraHeaders []string) []byte {
	var sb strings.Builder
	sb.WriteString("GET ")
	sb.WriteString(u.Path)
	sb.WriteString(" HTTP/1.1\r\n")
	sb.WriteString("Host: ")
	sb.WriteString(u.Host)
	if u.Port != 80 {
		sb.WriteString(":")
		sb.WriteString(strconv.FormatUint(uint64(u.Port), 10))
	}
	sb.WriteString("\r\n")
	sb.WriteString("User-Agent: ministack/1.0\r\n")
	sb.WriteString("Accept: */*\r\n")
	sb.WriteString("Connection: close\r\n")
	for _, h := range extraHeaders {
		sb.WriteString(h)
		sb.WriteString("\r\n")
	}
	sb.WriteString("\r\n")
	return []byte(sb.String())
}

// readHTTPResponse reads from `conn` until the server FINs (or our cap
// trips) and parses out status + headers + body. Returns
// ErrHTTPResponseTooBig if the total exceeds HTTPMaxResponseBytes.
func readHTTPResponse(conn *TCP4Conn) (*HTTPResponse, error) {
	var all []byte
	chunk := make([]byte, 4096)
	for {
		n, err := conn.Read(chunk)
		if n > 0 {
			if len(all)+n > HTTPMaxResponseBytes {
				return nil, ErrHTTPResponseTooBig
			}
			all = append(all, chunk[:n]...)
		}
		if err != nil {
			// Peer closed cleanly (errTCP4PeerClosed) or any other
			// error: stop reading. We parse what we have.
			if err == errTCP4PeerClosed {
				break
			}
			// Unrecoverable — surface the error unless we already
			// have a complete response.
			if len(all) == 0 {
				return nil, err
			}
			break
		}
	}
	return parseHTTPResponse(all)
}

// parseHTTPResponse decodes the raw bytes into an HTTPResponse. The
// header / body split is the first CRLFCRLF; body decoding follows
// Transfer-Encoding (chunked) or Content-Length, falling back to
// "read all remaining" (which is fine because the server is
// Connection: close).
func parseHTTPResponse(raw []byte) (*HTTPResponse, error) {
	sep := []byte("\r\n\r\n")
	idx := bytes.Index(raw, sep)
	if idx < 0 {
		return nil, ErrHTTPBadStatusLine
	}
	headerBlock := raw[:idx]
	body := raw[idx+len(sep):]

	lines := strings.Split(string(headerBlock), "\r\n")
	if len(lines) == 0 || len(lines[0]) == 0 {
		return nil, ErrHTTPBadStatusLine
	}
	// Status line: "HTTP/1.x SSS Reason..."
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return nil, ErrHTTPBadStatusLine
	}
	statusCode, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, ErrHTTPBadStatusLine
	}

	headers := make(map[string]string)
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		i := strings.IndexByte(line, ':')
		if i < 0 {
			return nil, ErrHTTPBadHeader
		}
		k := strings.ToLower(strings.TrimSpace(line[:i]))
		v := strings.TrimSpace(line[i+1:])
		if existing, ok := headers[k]; ok {
			headers[k] = existing + ", " + v
		} else {
			headers[k] = v
		}
	}

	// Decode the body. Priority: chunked > Content-Length > rest of buffer.
	if te, ok := headers["transfer-encoding"]; ok && strings.EqualFold(te, "chunked") {
		dec, derr := decodeChunked(body)
		if derr != nil {
			return nil, derr
		}
		body = dec
	} else if cl, ok := headers["content-length"]; ok {
		n, cerr := strconv.Atoi(cl)
		if cerr != nil {
			return nil, ErrHTTPBadHeader
		}
		if n < 0 {
			return nil, ErrHTTPBadHeader
		}
		if n > len(body) {
			// We've been told more bytes than we received; the peer
			// likely closed mid-stream. Return what we have rather
			// than failing — boot probes prefer partial data + a log
			// line over zero data.
			n = len(body)
		}
		body = body[:n]
	}
	// else: identity, no Content-Length — body is whatever we collected.

	return &HTTPResponse{
		StatusCode: statusCode,
		StatusLine: lines[0],
		Headers:    headers,
		Body:       append([]byte(nil), body...),
	}, nil
}

// ----- Streaming HTTP GET (M7.1a) ---------------------------------
//
// Why a sibling API instead of widening HTTPGet:
//
//   - The buffered HTTPGet caps the entire response at
//     HTTPMaxResponseBytes so we can fit it in a single []byte.
//     Streaming swaps "build a byte slab" for "write each chunk to
//     an io.Writer", which lets OCI fetch multi-MiB layers without
//     ever holding the whole blob in RAM.
//   - The buffered path's chunked-decoder reads everything first then
//     unwraps; the streaming path has to interleave framing parsing
//     and writes.
//
// The header parse is shared between the two paths via the
// readStatusLineAndHeaders helper below.

// HTTPLineMaxBytes caps any single CRLF-terminated header / status /
// chunk-size line. 8 KiB matches the buffered-path practical limit
// (the 4096-byte read chunk plus a partial reassembly) and stays well
// inside common-sense bounds — real registries send <1 KiB headers.
const HTTPLineMaxBytes = 8 * 1024

// streamReadBufBytes is the temporary buffer the streaming path uses
// for body copies. 8 KiB matches the line cap above and is the same
// size HTTP/2 prefers for its framing; small enough to keep stack
// usage cheap under tamago.
const streamReadBufBytes = 8 * 1024

// HTTPGetStream issues a plaintext HTTP/1.1 GET against `url`,
// dials TCP4, reads the response line + headers (capped per line by
// HTTPLineMaxBytes), and streams the body into `dst` chunk-by-chunk
// using a small fixed buffer.
//
// Returns the HTTP status code, the number of body bytes written to
// `dst`, the Content-Type header value (or "" if absent), and any
// transport / parse error encountered.
//
// Unlike HTTPGet, there is NO total response cap — the caller is in
// charge of bounding `dst` (e.g. by wrapping it in an &io.LimitedWriter
// or by passing &io.Discard to throw the bytes away).
//
// Honours Content-Length and Transfer-Encoding: chunked (RFC 9112 §7.1).
// Identity (no length, no chunked) is supported: bytes are streamed
// until the peer FINs.
func (s *Stack) HTTPGetStream(url string, dst io.Writer, opts HTTPGetOptions) (status int, written int64, contentType string, err error) {
	status, written, headers, err := s.HTTPGetStreamHeaders(url, dst, opts)
	return status, written, headers["content-type"], err
}

// HTTPGetStreamHeaders is the extended variant: returns the full
// parsed header map. Used by FetchBlobStream to chase Location on a
// 3xx without a second round-trip. Header keys are lowercased; only
// content-type, content-length, transfer-encoding, and location are
// captured (the M7.1a probe needs no others).
func (s *Stack) HTTPGetStreamHeaders(url string, dst io.Writer, opts HTTPGetOptions) (status int, written int64, headers map[string]string, err error) {
	u, err := parseHTTPURL(url)
	if err != nil {
		return 0, 0, nil, err
	}
	conn, err := s.dialHTTPConn(u, opts)
	if err != nil {
		return 0, 0, nil, err
	}
	defer conn.Close()

	reqTimeout := opts.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = defaultRequestTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(reqTimeout))

	req := buildHTTPRequest(u, opts.ExtraHeaders)
	if _, werr := conn.Write(req); werr != nil {
		return 0, 0, nil, werr
	}

	br := newLineReader(conn)
	return streamHTTPResponseHeaders(br, dst)
}

// dialHTTPConn factors out the resolve+dial sequence shared between
// HTTPGet and HTTPGetStream.
func (s *Stack) dialHTTPConn(u parsedHTTPURL, opts HTTPGetOptions) (*TCP4Conn, error) {
	var ip net.IP
	if parsed := net.ParseIP(u.Host); parsed != nil {
		if parsed.To4() == nil {
			return nil, ErrTCP4InvalidAddr
		}
		ip = parsed.To4()
	} else {
		if opts.DNSServer == nil {
			return nil, ErrDNSInvalidServer
		}
		dnsTimeout := opts.DialTimeout
		if dnsTimeout <= 0 {
			dnsTimeout = defaultDialTimeout
		}
		var err error
		ip, err = s.ResolveA(u.Host, opts.DNSServer, dnsTimeout)
		if err != nil {
			return nil, err
		}
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	return s.DialTCP4(ip, u.Port, dialTimeout)
}

// streamHTTPResponseHeaders is the variant that also returns the
// parsed-out headers map (lowercase keys). Used by FetchBlobStream to
// chase Location on a 3xx without a second round-trip. The header
// names captured are kept narrow to avoid a generic-map allocation
// path; only `content-type` and `location` are surfaced.
func streamHTTPResponseHeaders(br *lineReader, dst io.Writer) (status int, written int64, headers map[string]string, err error) {
	headers = map[string]string{}
	statusLine, err := br.ReadLine()
	if err != nil {
		return 0, 0, headers, err
	}
	parts := strings.SplitN(statusLine, " ", 3)
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return 0, 0, headers, ErrHTTPBadStatusLine
	}
	status, perr := strconv.Atoi(parts[1])
	if perr != nil {
		return 0, 0, headers, ErrHTTPBadStatusLine
	}

	var contentLength int64 = -1
	chunked := false
	for {
		line, herr := br.ReadLine()
		if herr != nil {
			return 0, 0, headers, herr
		}
		if line == "" {
			break
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return 0, 0, headers, ErrHTTPBadHeader
		}
		k := strings.ToLower(strings.TrimSpace(line[:colon]))
		v := strings.TrimSpace(line[colon+1:])
		switch k {
		case "content-length":
			n, cerr := strconv.ParseInt(v, 10, 64)
			if cerr != nil || n < 0 {
				return 0, 0, headers, ErrHTTPBadHeader
			}
			contentLength = n
			headers[k] = v
		case "transfer-encoding":
			if strings.EqualFold(v, "chunked") {
				chunked = true
			}
			headers[k] = v
		case "content-type", "location":
			headers[k] = v
		}
	}

	// On a redirect, drain the body into discard (Location is
	// already captured); caller will chase.
	bodySink := dst
	if status >= 300 && status < 400 {
		bodySink = io.Discard
	}

	switch {
	case chunked:
		written, err = streamChunkedBody(br, bodySink)
	case contentLength >= 0:
		written, err = streamBoundedBody(br, bodySink, contentLength)
	default:
		written, err = streamIdentityBody(br, bodySink)
	}
	if status >= 300 && status < 400 {
		// Don't claim "we wrote N bytes" to the caller's dst when
		// in fact those went to discard.
		written = 0
	}
	return status, written, headers, err
}

// streamBoundedBody copies exactly `total` bytes from br into dst,
// pulling from br's pre-buffered tail first.
func streamBoundedBody(br *lineReader, dst io.Writer, total int64) (int64, error) {
	var written int64
	buf := make([]byte, streamReadBufBytes)
	for written < total {
		want := total - written
		if want > int64(len(buf)) {
			want = int64(len(buf))
		}
		n, err := br.Read(buf[:want])
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			written += int64(w)
			if werr != nil {
				return written, werr
			}
		}
		if err != nil {
			if err == errTCP4PeerClosed || err == io.EOF {
				if written < total {
					return written, io.ErrUnexpectedEOF
				}
				return written, nil
			}
			return written, err
		}
	}
	return written, nil
}

// streamIdentityBody copies until EOF.
func streamIdentityBody(br *lineReader, dst io.Writer) (int64, error) {
	var written int64
	buf := make([]byte, streamReadBufBytes)
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
			if err == errTCP4PeerClosed || err == io.EOF {
				return written, nil
			}
			return written, err
		}
	}
}

// streamChunkedBody decodes a Transfer-Encoding: chunked body on the
// fly per RFC 9112 §7.1: each chunk is `<size in hex>[;ext]\r\n
// <size bytes>\r\n`, body ends with a zero-size chunk and an optional
// trailer block we drop.
func streamChunkedBody(br *lineReader, dst io.Writer) (int64, error) {
	var written int64
	buf := make([]byte, streamReadBufBytes)
	for {
		sizeLine, err := br.ReadLine()
		if err != nil {
			return written, err
		}
		// Strip any chunk-extension.
		if semi := strings.IndexByte(sizeLine, ';'); semi >= 0 {
			sizeLine = sizeLine[:semi]
		}
		size, perr := strconv.ParseUint(strings.TrimSpace(sizeLine), 16, 64)
		if perr != nil {
			return written, ErrHTTPBadChunk
		}
		if size == 0 {
			// Drain trailer block (empty line terminates).
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
			n, rerr := br.Read(buf[:want])
			if n > 0 {
				w, werr := dst.Write(buf[:n])
				written += int64(w)
				remaining -= int64(n)
				if werr != nil {
					return written, werr
				}
			}
			if rerr != nil {
				if rerr == errTCP4PeerClosed || rerr == io.EOF {
					return written, ErrHTTPBadChunk
				}
				return written, rerr
			}
		}
		// Discard trailing CRLF after the chunk data.
		if _, err := br.ReadLine(); err != nil {
			return written, err
		}
	}
}

// ----- lineReader -------------------------------------------------
//
// lineReader buffers reads from any io.Reader and serves both
// CRLF-delimited lines (for headers + chunk sizes) and raw byte
// pulls (for body chunks). The body pulls drain any pre-buffered
// tail before falling back to the underlying Reader.
//
// The buffer is sized to streamReadBufBytes and is grown only when a
// single line would otherwise straddle the buffer boundary (in which
// case lineCap is enforced so a malicious server can't OOM us via a
// header line that never terminates).

type lineReader struct {
	r   io.Reader
	buf []byte
	pos int
	end int
}

// newLineReader wraps r in a fresh streamReadBufBytes-sized lineReader.
func newLineReader(r io.Reader) *lineReader {
	return &lineReader{r: r, buf: make([]byte, streamReadBufBytes)}
}

// fill reads more bytes from the underlying reader into the buffer's
// tail. Returns the same error semantics as r.Read (n>0 may come back
// with err set).
func (lr *lineReader) fill() error {
	if lr.pos > 0 {
		// Compact.
		copy(lr.buf, lr.buf[lr.pos:lr.end])
		lr.end -= lr.pos
		lr.pos = 0
	}
	if lr.end == len(lr.buf) {
		return errors.New("ministack: HTTP line exceeds buffer cap")
	}
	n, err := lr.r.Read(lr.buf[lr.end:])
	lr.end += n
	return err
}

// ReadLine returns the next CRLF-terminated line (without the CRLF).
// Lone LFs are accepted to be lenient (some upstreams have bugs).
func (lr *lineReader) ReadLine() (string, error) {
	var acc []byte
	for {
		// Search current buffer for LF.
		for i := lr.pos; i < lr.end; i++ {
			if lr.buf[i] == '\n' {
				line := lr.buf[lr.pos:i]
				// Strip CR.
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				if len(acc) > 0 {
					acc = append(acc, line...)
					line = acc
				}
				lr.pos = i + 1
				if len(line) > HTTPLineMaxBytes {
					return "", errors.New("ministack: HTTP line exceeds cap")
				}
				return string(line), nil
			}
		}
		// No LF in current buffer — accumulate + fill.
		acc = append(acc, lr.buf[lr.pos:lr.end]...)
		if len(acc) > HTTPLineMaxBytes {
			return "", errors.New("ministack: HTTP line exceeds cap")
		}
		lr.pos = lr.end
		if err := lr.fill(); err != nil {
			if lr.end > lr.pos {
				continue
			}
			return "", err
		}
	}
}

// Read drains buffered bytes first, then falls back to the underlying
// reader for fresh bytes. Matches io.Reader semantics.
func (lr *lineReader) Read(p []byte) (int, error) {
	if lr.pos < lr.end {
		n := copy(p, lr.buf[lr.pos:lr.end])
		lr.pos += n
		return n, nil
	}
	return lr.r.Read(p)
}

// decodeChunked decodes a Transfer-Encoding: chunked body. Each chunk
// is `<size in hex>\r\n<size bytes>\r\n`; the body ends with a
// zero-size chunk (`0\r\n\r\n`). Trailers are skipped silently.
func decodeChunked(raw []byte) ([]byte, error) {
	var out []byte
	pos := 0
	for {
		eol := bytes.Index(raw[pos:], []byte("\r\n"))
		if eol < 0 {
			return nil, ErrHTTPBadChunk
		}
		sizeStr := string(raw[pos : pos+eol])
		// Strip any chunk-extension after the size.
		if semi := strings.IndexByte(sizeStr, ';'); semi >= 0 {
			sizeStr = sizeStr[:semi]
		}
		size, err := strconv.ParseUint(strings.TrimSpace(sizeStr), 16, 32)
		if err != nil {
			return nil, ErrHTTPBadChunk
		}
		pos += eol + 2
		if size == 0 {
			return out, nil
		}
		if pos+int(size)+2 > len(raw) {
			return nil, ErrHTTPBadChunk
		}
		out = append(out, raw[pos:pos+int(size)]...)
		pos += int(size) + 2 // skip trailing CRLF
	}
}
