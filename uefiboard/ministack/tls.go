// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// TLS wrapper for ministack — M6 of Path D.
//
// Why a thin wrapper (instead of a hand-rolled TLS 1.2 client):
//
//   - Step 1 of M6 verified that Go stdlib `crypto/tls` +
//     `crypto/x509` build cleanly under GOOS=tamago across all four
//     arches (amd64, arm64, riscv64, loong64). The OS-specific bits
//     of crypto/x509 (system trust store) are not needed because we
//     populate `RootCAs` ourselves from the embedded bundle
//     (ca_bundle.go).
//   - `*TCP4Conn` already satisfies `net.Conn` (Read/Write/Close +
//     deadlines + LocalAddr/RemoteAddr), so `tls.Client(conn, cfg)`
//     wraps it directly. No adapter needed.
//   - This keeps the M6 surface ~100 LOC and the verification
//     decisions concentrated in NewTLSConfig — what versions, what
//     ciphers, what roots, what server name. Anything that needs to
//     change as the OCI registry moves CA in M7 changes here.
//
// What's implemented:
//
//   - DialTLS: ResolveA → DialTCP4 → tls.Client → Handshake. Honours
//     a single timeout that covers the full sequence.
//   - NewTLSConfig: the canonical *tls.Config the M6/M7 stack uses.
//     TLS 1.2+ only (the OCI distribution-spec requires HTTPS but
//     doesn't mandate TLS 1.3; production registries support both).
//     RootCAs is set from NewRootCAs; InsecureSkipVerify MUST be
//     false (the design doc lists this as a hard rule).
//
// What's intentionally NOT implemented:
//
//   - Client certificates / mutual TLS (M9 if ever).
//   - SNI override (the host arg already drives SNI).
//   - Session resumption (the M6/M7 probe is one-shot per fetch;
//     resumption is a complexity multiplier we don't need).
//   - OCSP stapling (boot loaders prefer fail-closed over OCSP
//     soft-fail; embedded-bundle revocation handling is M9 territory).

package ministack

import (
	"crypto/tls"
	"errors"
	"net"
	"time"
)

// ErrTLSNoServerName is returned by DialTLS when the host argument
// is empty. SNI is mandatory for our verification model (no
// IP-literal certs in the embedded bundle).
var ErrTLSNoServerName = errors.New("ministack: TLS requires a non-empty server name")

// TLSMinVersion is the lowest TLS version ministack will accept on
// the client side. TLS 1.2 is the floor — TLS 1.1 and below are
// withdrawn (RFC 8996, March 2021).
const TLSMinVersion = tls.VersionTLS12

// tlsClockFloor is the wall-clock floor ministack stamps into
// `tls.Config.Time` so chain validation works under tamago, where
// the runtime nanotime starts at 0 on boot and Go's wall-clock
// reads thus look like 1970-01-01 (the cert verifier would refuse
// every chain as "not yet valid"). The floor is set to the M6
// milestone date — late enough that every embedded root + every
// intermediate currently in the wild is already issued, early
// enough that we don't accept future-dated certs unfairly. M7+ will
// replace this with a real RTC read via EFI_RUNTIME_SERVICES.GetTime
// before ExitBootServices.
//
// Format: UnixSeconds since the Unix epoch. 1_780_610_400 =
// 2026-06-05T00:00:00 (UTC, derived as
// `datetime(2026,6,5,0,0,0).timestamp()`). Update annually if the
// loader sits in production across multiple cert-rotation cycles.
// The value MUST be after the NotBefore of every cert in every
// chain we expect to verify — Cloudflare's example.com chain
// rolled to 2026-05-31 NotBefore as of 2026-06, so any floor
// earlier than that fails verification of every Cloudflare-fronted
// host.
const tlsClockFloorUnix = 1_780_610_400

// TLSClockFloor returns the wall-clock floor as a time.Time. Use
// this when populating `tls.Config.Time` from outside the package
// (e.g. a probe wanting to see the cert chain "as of" the build
// date).
func TLSClockFloor() time.Time {
	return time.Unix(tlsClockFloorUnix, 0)
}

// tlsTimeFunc is the implementation of `tls.Config.Time`. It
// returns max(time.Now(), TLSClockFloor()) so:
//
//   - On a real platform where time.Now() is accurate, we use it.
//   - On tamago/UEFI where time.Now() starts at 1970, we substitute
//     the build floor so cert verification doesn't fail uniformly.
//
// The "max" rule prevents us from accepting an EXPIRED cert that
// was valid only at the build floor: if today is past the cert's
// NotAfter, time.Now() exceeds the floor, the floor doesn't apply,
// and verification fails — the desired behaviour.
func tlsTimeFunc() time.Time {
	now := time.Now()
	floor := TLSClockFloor()
	if now.Before(floor) {
		return floor
	}
	return now
}

// NewTLSConfig returns the standard *tls.Config ministack hands to
// `tls.Client` for outbound HTTPS. `serverName` MUST match the
// hostname the caller passed to DialTLS — it drives both SNI and
// certificate-chain verification.
//
// The returned config holds a reference to the cached embedded root
// pool; do NOT mutate the RootCAs field after construction (it is
// shared across calls).
func NewTLSConfig(serverName string) (*tls.Config, error) {
	if serverName == "" {
		return nil, ErrTLSNoServerName
	}
	pool, err := NewRootCAs()
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		ServerName: serverName,
		RootCAs:    pool,
		MinVersion: TLSMinVersion,
		Time:       tlsTimeFunc,
		// InsecureSkipVerify is left at its zero value (false) by
		// design — the hard rule from the M6 spec is "MUST be
		// false". We do not expose a knob to flip it.
	}, nil
}

// DialTLS opens a TCP4 connection to `host:port` via the ministack
// Stack, then wraps it in a TLS client using NewTLSConfig(host).
//
// Sequence:
//
//   1. Parse `host` as an IPv4 literal; if not, ResolveA via the
//      supplied DNS server.
//   2. DialTCP4 to the resolved IP + port (timeout applies).
//   3. tls.Client(conn, NewTLSConfig(host)).
//   4. Handshake with the same timeout (deadline set on the
//      underlying TCP conn so the handshake's inline reads honour it).
//   5. On any error, close the TCP conn and surface the error.
//
// `timeout` is the wall-clock cap for the WHOLE dial-+-handshake
// sequence (not per-stage), to mirror the M5 HTTPGet shape.
//
// On success the returned *tls.Conn carries the TLS state and the
// underlying TCP4Conn. Caller MUST Close() it (which closes the
// inner TCP4Conn too).
func (s *Stack) DialTLS(host string, port uint16, dnsServer net.IP, timeout time.Duration) (*tls.Conn, error) {
	if host == "" {
		return nil, ErrTLSNoServerName
	}
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	deadline := time.Now().Add(timeout)

	// Resolve the host. Skip DNS for IP-literal hosts.
	var ip net.IP
	if parsed := net.ParseIP(host); parsed != nil {
		ip4 := parsed.To4()
		if ip4 == nil {
			return nil, ErrTCP4InvalidAddr
		}
		ip = ip4
	} else {
		if dnsServer == nil {
			return nil, ErrDNSInvalidServer
		}
		resolveBudget := time.Until(deadline)
		if resolveBudget <= 0 {
			return nil, ErrTCP4Timeout
		}
		var err error
		ip, err = s.ResolveA(host, dnsServer, resolveBudget)
		if err != nil {
			return nil, err
		}
	}

	dialBudget := time.Until(deadline)
	if dialBudget <= 0 {
		return nil, ErrTCP4Timeout
	}
	tcpConn, err := s.DialTCP4(ip, port, dialBudget)
	if err != nil {
		return nil, err
	}

	cfg, err := NewTLSConfig(host)
	if err != nil {
		_ = tcpConn.Close()
		return nil, err
	}

	// Propagate the wall-clock deadline to the TCP conn so the
	// inline reads driven by tls.Handshake honour it.
	_ = tcpConn.SetDeadline(deadline)
	tlsConn := tls.Client(tcpConn, cfg)
	if err := tlsConn.Handshake(); err != nil {
		_ = tcpConn.Close()
		return nil, err
	}
	// Clear the deadline; subsequent caller may want a fresh budget
	// for the actual request. (TLS Read/Write inherit whatever
	// SetDeadline/SetReadDeadline the caller sets afterwards.)
	_ = tcpConn.SetDeadline(time.Time{})
	return tlsConn, nil
}
