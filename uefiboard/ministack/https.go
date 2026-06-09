// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// HTTPS GET on top of the M5 HTTP/1.1 parser + the M6 TLS dial.
//
// Why a sibling file instead of extending http.go:
//
//   - The M5 plaintext path stays self-contained — it does not
//     import `crypto/tls`, so the M5 build still excludes the TLS
//     attack surface for callers (M7 unit tests, M5 regression
//     soak) that don't need it. Putting HTTPSGet in its own file
//     means `go build` only links crypto/tls in for binaries that
//     reference it.
//   - The request build + response parse helpers from M5
//     (buildHTTPRequest, readHTTPResponse, parseHTTPResponse) are
//     content-agnostic — they take a `*TCP4Conn` for reading. To
//     reuse them with a `*tls.Conn` we factor out a tiny `io.Reader`
//     loop here (the M5 helper hard-coded `*TCP4Conn`'s exact error
//     types).
//
// What's implemented:
//
//   - HTTPSGet(rawurl, opts): the HTTPS sibling of HTTPGet. Same
//     options shape (DNSServer, DialTimeout, RequestTimeout,
//     ExtraHeaders). Default port is 443 instead of 80.
//   - parseHTTPSURL: accepts `https://host[:port][/path]`.
//
// What's intentionally NOT implemented:
//
//   - URL redirects to HTTP (we MUST NOT downgrade an HTTPS request
//     to HTTP, ever).
//   - Insecure mode / cert pinning override (the embedded RootCAs
//     are the trust anchor set, full stop).

package ministack

import (
	"crypto/tls"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrHTTPSchemeNotHTTPS is returned by HTTPSGet when the URL does
// not start with `https://`.
var ErrHTTPSchemeNotHTTPS = errors.New("ministack: only https:// URLs supported by HTTPSGet")

// parseHTTPSURL splits an absolute https:// URL into host/port/path.
// Shape mirrors parseHTTPURL but defaults to port 443.
func parseHTTPSURL(url string) (parsedHTTPURL, error) {
	const prefix = "https://"
	if !strings.HasPrefix(url, prefix) {
		return parsedHTTPURL{}, ErrHTTPSchemeNotHTTPS
	}
	rest := url[len(prefix):]
	path := "/"
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		path = rest[i:]
		rest = rest[:i]
	}
	host := rest
	port := uint16(443)
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
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

// HTTPSGet fetches `rawurl` over HTTPS/1.1 via the supplied Stack.
// The Stack's local address + default gateway must already be set
// (typically by DHCP4Acquire).
//
// The trust anchors are the embedded CA bundle (see ca_bundle.go);
// `InsecureSkipVerify` is force-disabled. Servers presenting chains
// that do not link to one of the embedded roots will fail closed
// with a verification error from `tls.Conn.Handshake`.
func (s *Stack) HTTPSGet(rawurl string, opts HTTPGetOptions) (*HTTPResponse, error) {
	u, err := parseHTTPSURL(rawurl)
	if err != nil {
		return nil, err
	}

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}

	tlsConn, err := s.DialTLS(u.Host, u.Port, opts.DNSServer, dialTimeout)
	if err != nil {
		return nil, err
	}
	defer tlsConn.Close()

	reqTimeout := opts.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = defaultRequestTimeout
	}
	deadline := time.Now().Add(reqTimeout)
	if nc, ok := tlsConn.NetConn().(*TCP4Conn); ok {
		_ = nc.SetDeadline(deadline)
	}

	req := buildHTTPRequest(u, opts.ExtraHeaders)
	if _, werr := tlsConn.Write(req); werr != nil {
		return nil, werr
	}
	return readHTTPSResponse(tlsConn)
}

// HTTPSGetStream is the HTTPS sibling of HTTPGetStream — same
// semantics: status + body bytes written + content-type + error.
// No response cap; the caller bounds `dst` if they want one.
//
// Honours Content-Length and Transfer-Encoding: chunked.
func (s *Stack) HTTPSGetStream(rawurl string, dst io.Writer, opts HTTPGetOptions) (status int, written int64, contentType string, err error) {
	status, written, headers, err := s.HTTPSGetStreamHeaders(rawurl, dst, opts)
	return status, written, headers["content-type"], err
}

// HTTPSGetStreamHeaders is the extended variant: returns the full
// parsed header map (lowercase keys). Used by FetchBlobStream to
// follow Location redirects without a second round-trip.
func (s *Stack) HTTPSGetStreamHeaders(rawurl string, dst io.Writer, opts HTTPGetOptions) (status int, written int64, headers map[string]string, err error) {
	u, err := parseHTTPSURL(rawurl)
	if err != nil {
		return 0, 0, nil, err
	}
	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultDialTimeout
	}
	tlsConn, err := s.DialTLS(u.Host, u.Port, opts.DNSServer, dialTimeout)
	if err != nil {
		return 0, 0, nil, err
	}
	defer tlsConn.Close()

	reqTimeout := opts.RequestTimeout
	if reqTimeout <= 0 {
		reqTimeout = defaultRequestTimeout
	}
	if nc, ok := tlsConn.NetConn().(*TCP4Conn); ok {
		_ = nc.SetDeadline(time.Now().Add(reqTimeout))
	}

	req := buildHTTPRequest(u, opts.ExtraHeaders)
	if _, werr := tlsConn.Write(req); werr != nil {
		return 0, 0, nil, werr
	}
	br := newLineReader(tlsConn)
	return streamHTTPResponseHeaders(br, dst)
}

// readHTTPSResponse drains a *tls.Conn until EOF (peer FIN +
// close-notify) or the response cap trips, then runs the response
// through the M5 parser.
//
// We re-implement the read loop (rather than reuse readHTTPResponse)
// because that function's signature ties the read to `*TCP4Conn` and
// matches on `errTCP4PeerClosed`. The TLS conn surfaces `io.EOF`
// instead — different sentinel, same semantics — so a small loop
// here keeps the M5 helper unchanged.
func readHTTPSResponse(conn *tls.Conn) (*HTTPResponse, error) {
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
			if err == io.EOF {
				break
			}
			// Some TLS servers send close_notify before FIN; the
			// stdlib then returns its internal "tls: protocol is
			// shutdown" error rather than io.EOF on the next read.
			// We treat any post-data error as terminal so long as
			// we've gathered at least some bytes (matching the M5
			// behaviour for plaintext).
			if len(all) == 0 {
				return nil, err
			}
			break
		}
	}
	return parseHTTPResponse(all)
}
