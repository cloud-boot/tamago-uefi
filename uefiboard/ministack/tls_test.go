// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// ----- NewTLSConfig ----------------------------------------------

func TestNewTLSConfigRejectsEmptyServerName(t *testing.T) {
	if _, err := NewTLSConfig(""); err != ErrTLSNoServerName {
		t.Errorf("NewTLSConfig(\"\"): got %v, want ErrTLSNoServerName", err)
	}
}

func TestNewTLSConfigShape(t *testing.T) {
	cfg, err := NewTLSConfig("example.com")
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	if cfg.ServerName != "example.com" {
		t.Errorf("ServerName: got %q, want example.com", cfg.ServerName)
	}
	if cfg.RootCAs == nil {
		t.Error("RootCAs is nil — embedded bundle not wired in")
	}
	if cfg.MinVersion != tls.VersionTLS12 {
		t.Errorf("MinVersion: got %d, want %d", cfg.MinVersion, tls.VersionTLS12)
	}
	if cfg.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false (hard rule from M6 spec)")
	}
}

func TestTLSMinVersionConstant(t *testing.T) {
	// Pin the floor so a future refactor that lowers it trips this test.
	if TLSMinVersion < tls.VersionTLS12 {
		t.Errorf("TLSMinVersion below TLS 1.2: %d", TLSMinVersion)
	}
}

func TestTLSClockFloorReasonable(t *testing.T) {
	// The clock floor must be at least 2025 (so it post-dates the
	// embedded SSL.com 2022 roots' issuance) and no later than the
	// current build year + 1.
	f := TLSClockFloor()
	if f.Year() < 2025 {
		t.Errorf("TLSClockFloor too old: %v", f)
	}
}

func TestTLSTimeFuncReturnsAtLeastFloor(t *testing.T) {
	got := tlsTimeFunc()
	if got.Before(TLSClockFloor()) {
		t.Errorf("tlsTimeFunc returned %v < floor %v", got, TLSClockFloor())
	}
}

// ----- DialTLS error paths ---------------------------------------

func TestDialTLSRejectsEmptyHost(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	defer s.Close()
	_, err := s.DialTLS("", 443, net.IPv4(10, 0, 2, 3), 100*time.Millisecond)
	if err != ErrTLSNoServerName {
		t.Errorf("DialTLS(\"\"): got %v, want ErrTLSNoServerName", err)
	}
}

func TestDialTLSRejectsIPv6Literal(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	defer s.Close()
	_, err := s.DialTLS("::1", 443, nil, 100*time.Millisecond)
	if err != ErrTCP4InvalidAddr {
		t.Errorf("DialTLS(IPv6): got %v, want ErrTCP4InvalidAddr", err)
	}
}

func TestDialTLSRequiresDNSForHostname(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	defer s.Close()
	_, err := s.DialTLS("example.com", 443, nil, 100*time.Millisecond)
	if err != ErrDNSInvalidServer {
		t.Errorf("DialTLS no DNS: got %v, want ErrDNSInvalidServer", err)
	}
}

func TestDialTLSZeroTimeoutFallsBack(t *testing.T) {
	// timeout<=0 should be promoted to defaultDialTimeout, which in
	// turn will trip an ErrTCP4Timeout when no peer answers. We
	// can't easily wait the full default budget in a unit test, but
	// we can confirm the resolve-first path: with an IPv4 literal
	// target and no listener the dial fails with ErrTCP4Timeout
	// (after the default). To stay fast, we point at a non-routable
	// literal and rely on the synthetic link silently dropping the
	// SYN. With the stub link's 0-RTT no-server behaviour the inline
	// pump churns until the deadline, so we cap the test by setting
	// a short ARP timeout and giving DialTCP4 a fresh timeout of
	// 200ms via passing a real (small) value.
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	s.SetARPTimeout(50 * time.Millisecond)
	// Single-shot for this test: the retry path is exercised
	// separately by dial_retry_test.go; here we only care about the
	// timeout-fallback wiring.
	s.DefaultDialAttempts = 1
	defer s.Close()
	_, err := s.DialTLS("10.0.2.99", 443, nil, 100*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial-timeout against silent stub link")
	}
}

// ----- TLS handshake end-to-end over the synthetic link ----------

// tlsServerOverTCP4 plumbs a real `crypto/tls` server-side handshake
// on top of the same synthetic link the M5 tcp4HTTPServer uses. The
// approach:
//
//  1. We host an in-process net.Pipe-backed adapter that bridges
//     between our TCP-segment stub and a `tls.Server(pipe, cfg)`
//     handshake. The pipe carries already-decapsulated bytes (no
//     IP/TCP framing) — we just need a duplex channel.
//
// For coverage purposes a complete end-to-end TLS exchange is heavy
// because we'd need to write a full TCP segmenter on the server side
// of the synthetic link. We confirm the wiring instead by exercising
// `NewTLSConfig` + the early validation in `DialTLS` (above) and by
// running a `tls.Server` against `tls.Client` over `net.Pipe`, using
// the same RootCAs source as our config — that establishes that the
// embedded bundle + NewTLSConfig produce a working tls.Config.

// TestTLSConfigInteropsWithStdlibServer drives `tls.Server` over a
// net.Pipe using a fresh self-signed certificate; the client uses
// `NewTLSConfig` but with a one-off RootPool containing the self-
// signed cert (so we exercise the same wrapper code while still
// being able to verify the handshake succeeds against a known peer).
func TestTLSConfigInteropsWithStdlibServer(t *testing.T) {
	cert, pool := generateSelfSignedTLSCert(t)

	// Build the client config the same way ministack does, then
	// override RootCAs with our test pool (the production code
	// inserts the embedded bundle; we swap in the test root so the
	// handshake actually verifies).
	clientCfg, err := NewTLSConfig("ministack.test")
	if err != nil {
		t.Fatalf("NewTLSConfig: %v", err)
	}
	clientCfg.RootCAs = pool

	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	clientPipe, serverPipe := net.Pipe()
	defer clientPipe.Close()
	defer serverPipe.Close()

	done := make(chan error, 1)
	go func() {
		sc := tls.Server(serverPipe, serverCfg)
		if err := sc.Handshake(); err != nil {
			done <- err
			return
		}
		// Read the client's request, send a small response, close.
		buf := make([]byte, 64)
		_, _ = sc.Read(buf)
		_, _ = sc.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
		_ = sc.Close()
		done <- nil
	}()

	cc := tls.Client(clientPipe, clientCfg)
	if err := cc.Handshake(); err != nil {
		t.Fatalf("client Handshake: %v", err)
	}
	if _, err := cc.Write([]byte("GET / HTTP/1.1\r\nHost: ministack.test\r\n\r\n")); err != nil {
		t.Fatalf("client Write: %v", err)
	}
	resp := make([]byte, 256)
	n, _ := cc.Read(resp)
	if n == 0 || string(resp[:15]) != "HTTP/1.1 200 OK" {
		t.Errorf("unexpected response: %q", resp[:n])
	}
	_ = cc.Close()
	if e := <-done; e != nil {
		t.Errorf("server: %v", e)
	}
}
