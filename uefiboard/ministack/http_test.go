// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"bytes"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// ----- URL parsing ------------------------------------------------

func TestParseHTTPURL(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPort uint16
		wantPath string
		wantErr  error
	}{
		{"http://example.com/", "example.com", 80, "/", nil},
		{"http://example.com", "example.com", 80, "/", nil},
		{"http://example.com:8080/foo", "example.com", 8080, "/foo", nil},
		{"http://10.0.2.2:80/hello.txt", "10.0.2.2", 80, "/hello.txt", nil},
		{"http://example.com/a/b?c=d", "example.com", 80, "/a/b?c=d", nil},
		{"https://example.com/", "", 0, "", ErrHTTPSchemeNotHTTP},
		{"ftp://example.com/", "", 0, "", ErrHTTPSchemeNotHTTP},
		{"http://", "", 0, "", ErrHTTPBadURL},
		{"http://example.com:abc/", "", 0, "", ErrHTTPBadURL},
	}
	for _, c := range cases {
		got, err := parseHTTPURL(c.in)
		if err != c.wantErr {
			t.Errorf("parseHTTPURL(%q): err=%v, want %v", c.in, err, c.wantErr)
			continue
		}
		if c.wantErr != nil {
			continue
		}
		if got.Host != c.wantHost || got.Port != c.wantPort || got.Path != c.wantPath {
			t.Errorf("parseHTTPURL(%q): got %+v, want host=%s port=%d path=%s", c.in, got, c.wantHost, c.wantPort, c.wantPath)
		}
	}
}

// ----- Response parsing ------------------------------------------

func TestParseHTTPResponseContentLength(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if resp.Headers["content-type"] != "text/plain" {
		t.Errorf("content-type: %v", resp.Headers)
	}
	if !bytes.Equal(resp.Body, []byte("hello")) {
		t.Errorf("body: got %q, want %q", resp.Body, "hello")
	}
}

func TestParseHTTPResponseChunked(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if !bytes.Equal(resp.Body, []byte("hello world")) {
		t.Errorf("body: got %q, want %q", resp.Body, "hello world")
	}
}

func TestParseHTTPResponseChunkedWithExtension(t *testing.T) {
	// Chunk size lines may include a `;extension` suffix.
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;quux=42\r\nhello\r\n0\r\n\r\n")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if !bytes.Equal(resp.Body, []byte("hello")) {
		t.Errorf("body: got %q, want %q", resp.Body, "hello")
	}
}

func TestParseHTTPResponseChunkedTruncated(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel")
	_, err := parseHTTPResponse(raw)
	if err != ErrHTTPBadChunk {
		t.Errorf("want ErrHTTPBadChunk, got %v", err)
	}
}

func TestParseHTTPResponseChunkedBadSize(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZZ\r\nhello\r\n0\r\n\r\n")
	_, err := parseHTTPResponse(raw)
	if err != ErrHTTPBadChunk {
		t.Errorf("want ErrHTTPBadChunk, got %v", err)
	}
}

func TestParseHTTPResponseIdentity(t *testing.T) {
	// No Content-Length, no chunked; body is whatever is left.
	raw := []byte("HTTP/1.1 200 OK\r\nServer: tiny\r\n\r\nfreeform body bytes")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if !bytes.Equal(resp.Body, []byte("freeform body bytes")) {
		t.Errorf("body: got %q", resp.Body)
	}
}

func TestParseHTTPResponseContentLengthExceedsBuffer(t *testing.T) {
	// CL=999 but only 5 bytes follow — clamp without failing.
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\nhello")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if !bytes.Equal(resp.Body, []byte("hello")) {
		t.Errorf("body: got %q, want %q", resp.Body, "hello")
	}
}

func TestParseHTTPResponseRejectsBadStatusLine(t *testing.T) {
	raw := []byte("garbage\r\n\r\nbody")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestParseHTTPResponseRejectsMissingSeparator(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestParseHTTPResponseRejectsBadHeader(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nnocolon\r\n\r\nbody")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader, got %v", err)
	}
}

func TestParseHTTPResponseRejectsBadContentLength(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nContent-Length: NaN\r\n\r\n")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader, got %v", err)
	}
	raw2 := []byte("HTTP/1.1 200 OK\r\nContent-Length: -5\r\n\r\n")
	if _, err := parseHTTPResponse(raw2); err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader (negative), got %v", err)
	}
}

func TestParseHTTPResponseRejectsMissingStatusCode(t *testing.T) {
	raw := []byte("HTTP/1.1\r\n\r\n")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestParseHTTPResponseRejectsNonNumericStatus(t *testing.T) {
	raw := []byte("HTTP/1.1 OK Whatever\r\n\r\n")
	if _, err := parseHTTPResponse(raw); err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestParseHTTPResponseDuplicateHeaders(t *testing.T) {
	raw := []byte("HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
	resp, err := parseHTTPResponse(raw)
	if err != nil {
		t.Fatalf("parseHTTPResponse: %v", err)
	}
	if got := resp.Headers["set-cookie"]; got != "a=1, b=2" {
		t.Errorf("duplicate headers: got %q, want %q", got, "a=1, b=2")
	}
}

// ----- Request building -----------------------------------------

func TestBuildHTTPRequest(t *testing.T) {
	u := parsedHTTPURL{Host: "example.com", Port: 80, Path: "/index.html"}
	req := buildHTTPRequest(u, nil)
	s := string(req)
	if !strings.HasPrefix(s, "GET /index.html HTTP/1.1\r\n") {
		t.Errorf("request line: %q", strings.Split(s, "\r\n")[0])
	}
	if !strings.Contains(s, "Host: example.com\r\n") {
		t.Errorf("missing Host header: %q", s)
	}
	if !strings.Contains(s, "Connection: close\r\n") {
		t.Errorf("missing Connection: close header")
	}
}

func TestBuildHTTPRequestNonStandardPort(t *testing.T) {
	u := parsedHTTPURL{Host: "example.com", Port: 8080, Path: "/"}
	req := buildHTTPRequest(u, nil)
	if !strings.Contains(string(req), "Host: example.com:8080\r\n") {
		t.Errorf("Host header omitted port: %q", req)
	}
}

func TestBuildHTTPRequestExtraHeaders(t *testing.T) {
	u := parsedHTTPURL{Host: "example.com", Port: 80, Path: "/"}
	req := buildHTTPRequest(u, []string{"Accept-Encoding: identity", "X-Probe: m5"})
	s := string(req)
	if !strings.Contains(s, "Accept-Encoding: identity\r\n") {
		t.Errorf("missing custom Accept-Encoding header")
	}
	if !strings.Contains(s, "X-Probe: m5\r\n") {
		t.Errorf("missing custom X-Probe header")
	}
}

// ----- End-to-end HTTPGet over the synthetic link --------------

// tcp4HTTPServer drives the same per-link RX tape as tcp4Server, but
// instead of a fixed echoBack it constructs a real HTTP/1.1 response
// once it accepts the client's request bytes. The response is sent in
// a single segment then the server FINs.
type tcp4HTTPServer struct {
	link        *stubLink
	clientMAC   net.HardwareAddr
	serverMAC   net.HardwareAddr
	clientIP    net.IP
	serverIP    net.IP
	serverPort  uint16
	serverISS   uint32
	once        sync.Once
	done        chan struct{}
	mu          sync.Mutex
	clientSeq   uint32
	serverSeq   uint32
	clientPort  uint16
	rxBuf       []byte
	respondedAt bool
	sentFIN     bool
	respBody    []byte
}

func newTCP4HTTPServer(link *stubLink, clientMAC, serverMAC net.HardwareAddr, clientIP, serverIP net.IP, serverPort uint16, respBody []byte) *tcp4HTTPServer {
	return &tcp4HTTPServer{
		link:       link,
		clientMAC:  append(net.HardwareAddr(nil), clientMAC...),
		serverMAC:  append(net.HardwareAddr(nil), serverMAC...),
		clientIP:   append(net.IP(nil), clientIP...),
		serverIP:   append(net.IP(nil), serverIP...),
		serverPort: serverPort,
		serverISS:  0x20000000,
		done:       make(chan struct{}),
		respBody:   respBody,
	}
}

func (g *tcp4HTTPServer) start() { go g.loop() }
func (g *tcp4HTTPServer) stop()  { g.once.Do(func() { close(g.done) }) }

func (g *tcp4HTTPServer) loop() {
	idx := 0
	for {
		select {
		case <-g.done:
			return
		default:
		}
		g.link.mu.Lock()
		var fresh [][]byte
		if idx < len(g.link.sent) {
			for i := idx; i < len(g.link.sent); i++ {
				fresh = append(fresh, append([]byte(nil), g.link.sent[i]...))
			}
			idx = len(g.link.sent)
		}
		g.link.mu.Unlock()
		for _, f := range fresh {
			eth, err := ParseEthernet(f)
			if err != nil {
				continue
			}
			switch eth.EtherType {
			case EtherTypeARP:
				op, sha, spa, _, tpa, err := parseARP(eth.Payload)
				if err != nil || op != ARPOpRequest || !tpa.Equal(g.serverIP) {
					continue
				}
				reply, _ := buildARPPacket(ARPOpReply, g.serverMAC, g.serverIP, sha, spa)
				rf, _ := MarshalEthernet(sha, g.serverMAC, EtherTypeARP, reply)
				g.link.inject(rf)
			case EtherTypeIPv4:
				ip, ipBody, err := ParseIPv4(eth.Payload)
				if err != nil || ip.Protocol != IPProtoTCP {
					continue
				}
				th, payload, err := ParseTCP4(ip.Src, ip.Dst, ipBody)
				if err != nil || th.DstPort != g.serverPort {
					continue
				}
				g.handleTCP(th, payload)
			}
		}
		time.Sleep(1 * time.Millisecond)
	}
}

func (g *tcp4HTTPServer) handleTCP(th TCP4Header, payload []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.clientPort = th.SrcPort

	if th.Flags&TCPFlagSYN != 0 && th.Flags&TCPFlagACK == 0 {
		g.clientSeq = th.Seq + 1
		g.serverSeq = g.serverISS + 1
		g.sendSeg(TCPFlagSYN|TCPFlagACK, g.serverISS, g.clientSeq, nil)
		return
	}
	if len(payload) > 0 {
		if th.Seq == g.clientSeq {
			g.rxBuf = append(g.rxBuf, payload...)
			g.clientSeq += uint32(len(payload))
			// ACK what we got.
			g.sendSeg(TCPFlagACK, g.serverSeq, g.clientSeq, nil)
			// Once we have a complete request (terminator \r\n\r\n),
			// send the HTTP response + FIN.
			if !g.respondedAt && bytes.Contains(g.rxBuf, []byte("\r\n\r\n")) {
				g.respondedAt = true
				body := g.respBody
				if body == nil {
					body = []byte("hello-from-stub\n")
				}
				resp := []byte("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: " +
					itoa(len(body)) + "\r\nConnection: close\r\n\r\n")
				resp = append(resp, body...)
				g.sendSeg(TCPFlagACK|TCPFlagPSH, g.serverSeq, g.clientSeq, resp)
				g.serverSeq += uint32(len(resp))
				if !g.sentFIN {
					g.sendSeg(TCPFlagACK|TCPFlagFIN, g.serverSeq, g.clientSeq, nil)
					g.serverSeq++
					g.sentFIN = true
				}
			}
		}
		return
	}
	if th.Flags&TCPFlagFIN != 0 {
		g.clientSeq++
		g.sendSeg(TCPFlagACK, g.serverSeq, g.clientSeq, nil)
		if !g.sentFIN {
			g.sendSeg(TCPFlagACK|TCPFlagFIN, g.serverSeq, g.clientSeq, nil)
			g.serverSeq++
			g.sentFIN = true
		}
	}
}

func (g *tcp4HTTPServer) sendSeg(flags uint8, seq, ack uint32, payload []byte) {
	seg, err := MarshalTCP4(g.serverIP, g.clientIP, g.serverPort, g.clientPort, seq, ack, flags, 32768, payload)
	if err != nil {
		return
	}
	ip, err := MarshalIPv4(g.serverIP, g.clientIP, IPProtoTCP, 0xBEEF, seg)
	if err != nil {
		return
	}
	frame, err := MarshalEthernet(g.clientMAC, g.serverMAC, EtherTypeIPv4, ip)
	if err != nil {
		return
	}
	g.link.inject(frame)
}

// itoa avoids pulling strconv into the inner helper.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func TestHTTPGetEndToEnd(t *testing.T) {
	ourMAC := net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x80}
	srvMAC := net.HardwareAddr{0x52, 0x55, 0x0a, 0x00, 0x02, 0x02}
	ourIP := net.IPv4(10, 0, 2, 15)
	srvIP := net.IPv4(10, 0, 2, 2)
	mask := net.IPv4Mask(255, 255, 255, 0)

	link := newStubLink(ourMAC)
	s := New(link)
	s.SetARPTimeout(200 * time.Millisecond)
	if err := s.SetIPv4Address(ourIP, mask); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDefaultGateway(srvIP); err != nil {
		t.Fatal(err)
	}

	body := []byte("hello-via-ministack-http-client\n")
	srv := newTCP4HTTPServer(link, ourMAC, srvMAC, ourIP, srvIP, 80, body)
	srv.start()
	defer srv.stop()

	s.Start()
	defer s.Close()

	url := "http://10.0.2.2/hello.txt"
	resp, err := s.HTTPGet(url, HTTPGetOptions{
		DialTimeout:    2 * time.Second,
		RequestTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("HTTPGet: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status: got %d, want 200", resp.StatusCode)
	}
	if !bytes.Equal(resp.Body, body) {
		t.Errorf("body: got %q, want %q", resp.Body, body)
	}
}

func TestHTTPGetRejectsHTTPS(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_, err := s.HTTPGet("https://example.com/", HTTPGetOptions{})
	if err != ErrHTTPSchemeNotHTTP {
		t.Errorf("want ErrHTTPSchemeNotHTTP, got %v", err)
	}
}

func TestHTTPGetRequiresDNSForHostname(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	// URL is a hostname (not an IP) but no DNS server supplied →
	// ErrDNSInvalidServer.
	_, err := s.HTTPGet("http://example.com/", HTTPGetOptions{})
	if err != ErrDNSInvalidServer {
		t.Errorf("want ErrDNSInvalidServer, got %v", err)
	}
}

func TestHTTPGetRejectsIPv6(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	// We currently strip [] brackets from IPv6 URLs naively — but the
	// dotted-quad parser will reject "::1" as non-IPv4 and surface
	// ErrTCP4InvalidAddr.
	_, err := s.HTTPGet("http://::1/", HTTPGetOptions{})
	if err == nil {
		t.Errorf("expected error for IPv6 literal host, got nil")
	}
}

func TestHTTPGetBadURL(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_, err := s.HTTPGet("not-a-url", HTTPGetOptions{})
	if err != ErrHTTPSchemeNotHTTP {
		t.Errorf("want ErrHTTPSchemeNotHTTP, got %v", err)
	}
}

func TestDecodeChunkedEmpty(t *testing.T) {
	out, err := decodeChunked([]byte("0\r\n\r\n"))
	if err != nil {
		t.Fatalf("decodeChunked: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("expected empty body, got %q", out)
	}
}
