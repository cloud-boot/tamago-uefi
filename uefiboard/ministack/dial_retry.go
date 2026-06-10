// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Retry-with-exponential-backoff for the ministack dial path.
//
// Why this file exists (Network reliability gap — M6.2 / Network track,
// 2026-06-10): the firmware/runtime bug saga R-amd64a..g closed cleanly
// (all four arches GREEN end-to-end) but the live HTTPS/OCI rows
// against ghcr.io kept reporting `ministack: TCP operation timed out`
// — a transport-layer flake, NOT a regression in the freshly-shipped
// stub. ministack's M5/M6 dial path was single-shot by design; a
// properly-implemented retry path (RFC 9112 §9.5 + general HTTP-client
// hygiene) turns transient TCP / DNS / TLS-handshake failures into a
// single user-visible success.
//
// What's here:
//
//   - DialTCP4WithRetry(dst, port, timeout, attempts, baseDelay):
//     loop over dialTCP4Once. Sleep `baseDelay * 2^i` between attempts
//     i=0,1,...
//   - DialTLSWithRetry(host, port, dnsServer, timeout, attempts,
//     baseDelay): same shape over dialTLSOnce.
//   - isRetryableDialError: classifies a dial-leg error as transient
//     (retry) vs deterministic (fail-fast). Certificate-validation
//     failures land in the deterministic bucket — retrying a bad chain
//     just wastes the user's deadline.
//   - dialRetrySleep: short-circuitable sleep so a closed Stack tears
//     down its in-flight retry promptly.
//
// What's intentionally NOT here:
//
//   - Per-attempt jitter. Boot-time clients with one in-flight dial
//     don't need it; thundering-herd avoidance applies to many-client
//     scenarios.
//   - A retry budget threaded through the timeout. Each attempt gets
//     the full per-attempt timeout — the spec calls for ~14 s of
//     wall-clock at the default (2+4+8 s of backoff = 14 s ON TOP of
//     attempts × per-attempt timeout). The intent is "make sure
//     transient failures don't kill the boot", not "stay within a
//     hard outer budget".

package ministack

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"strings"
	"time"
)

// DefaultDialAttemptsFallback is the per-Stack retry count used when
// Stack.DefaultDialAttempts is unset (zero). 3 attempts paired with
// DefaultDialBaseDelayFallback yields total inter-attempt backoff of
// 2 s + 4 s = 6 s on top of three per-attempt timeouts.
const DefaultDialAttemptsFallback = 3

// DefaultDialBaseDelayFallback is the per-Stack base backoff used when
// Stack.DefaultDialBaseDelay is unset (zero). Doubled on each failed
// attempt — see DialTCP4WithRetry for the schedule.
const DefaultDialBaseDelayFallback = 2 * time.Second

// ErrDialAttemptsExhausted wraps the last per-attempt error when every
// retry attempt fails. Callers can `errors.Is(err, ErrTCP4Timeout)` on
// it because the unwrap chain leads to the underlying transport error.
type ErrDialAttemptsExhausted struct {
	Attempts int
	Last     error
}

func (e *ErrDialAttemptsExhausted) Error() string {
	if e.Last == nil {
		return "ministack: dial attempts exhausted"
	}
	return "ministack: dial attempts exhausted (" +
		dialRetryItoa(e.Attempts) + " tries): " + e.Last.Error()
}

func (e *ErrDialAttemptsExhausted) Unwrap() error { return e.Last }

// dialRetryItoa is a tiny integer formatter — strconv would pull a dep that
// the tamago build path otherwise doesn't need on the error path.
func dialRetryItoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// dialAttemptsOrDefault promotes 0 / negative attempts to the Stack
// fallback so an unconfigured Stack still retries. Negative is treated
// as "use default" (callers occasionally pass -1 to mean "default").
func (s *Stack) dialAttemptsOrDefault(n int) int {
	if n <= 0 {
		if s.DefaultDialAttempts > 0 {
			return s.DefaultDialAttempts
		}
		return DefaultDialAttemptsFallback
	}
	return n
}

// dialBaseDelayOrDefault promotes 0 / negative delays similarly.
func (s *Stack) dialBaseDelayOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		if s.DefaultDialBaseDelay > 0 {
			return s.DefaultDialBaseDelay
		}
		return DefaultDialBaseDelayFallback
	}
	return d
}

// dialRetrySleep waits `d` or until the Stack closes, whichever comes
// first. Tests can drive a short wall-clock by passing a tiny baseDelay
// (e.g. 1 ms) — the loop still exercises the exponential doubling.
func (s *Stack) dialRetrySleep(d time.Duration) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-s.stopCh:
	}
}

// isRetryableDialError reports whether `err` warrants another dial
// attempt. The classification follows the spec:
//
//   - Retry on: ErrTCP4Timeout (no SYN-ACK), DNS resolution failure,
//     TLS handshake timeout / I/O error, EOF mid-handshake, ARP
//     resolution timeout.
//   - DO NOT retry on: certificate validation failure (deterministic
//     — the chain on the wire isn't going to change between attempts),
//     bad-URL / config errors (ErrTLSNoServerName, ErrTCP4InvalidAddr,
//     ErrDNSInvalidServer), or stack-state errors (ErrStackClosed).
//
// Anything not explicitly classified defaults to retryable — the cost
// of a stray retry is bounded by attempts × per-attempt timeout, the
// cost of failing a transient flake is the whole boot.
func isRetryableDialError(err error) bool {
	if err == nil {
		return false
	}
	// Deterministic configuration errors — never retry.
	switch {
	case errors.Is(err, ErrTLSNoServerName):
		return false
	case errors.Is(err, ErrTCP4InvalidAddr):
		return false
	case errors.Is(err, ErrDNSInvalidServer):
		return false
	case errors.Is(err, ErrStackClosed):
		return false
	case errors.Is(err, ErrIPv4InvalidIP):
		return false
	case errors.Is(err, ErrTCP4NoLocalAddr):
		return false
	case errors.Is(err, ErrTCP4ConnRefused):
		// RST is a clean "no" from the peer — not a transient
		// network flake. Retrying generally yields another RST and
		// just burns the user's deadline. The cases that genuinely
		// benefit from a retry-on-RST (warm load-balancer races)
		// are vanishingly rare in our boot-time profile.
		return false
	}
	// Certificate validation — Go surfaces x509.* and
	// tls.CertificateVerificationError. Retrying won't help; the
	// cert presented on the next dial is identical.
	// tls.CertificateVerificationError is a pointer type (the stdlib
	// constructs it as `&CertificateVerificationError{...}`); the
	// x509.* errors below are value types whose Error() implementations
	// are bound to the value receiver.
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	var x509Err x509.UnknownAuthorityError
	if errors.As(err, &x509Err) {
		return false
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return false
	}
	var invalidCertErr x509.CertificateInvalidError
	if errors.As(err, &invalidCertErr) {
		return false
	}
	// String-match TLS handshake failure types that don't surface as
	// the typed errors above (e.g. "tls: failed to verify certificate"
	// wrapped through a non-typed path on older stdlib versions).
	msg := err.Error()
	if strings.Contains(msg, "tls: failed to verify certificate") ||
		strings.Contains(msg, "x509: certificate") {
		return false
	}
	// Everything else is treated as transient.
	//
	// Explicitly-retryable cases worth naming:
	//
	//   - ErrTCP4Timeout (no SYN-ACK).
	//   - ErrDNSTimeout (resolver flake).
	//   - ErrARPTimeout (next-hop didn't ARP-reply yet).
	//   - io.EOF (peer dropped mid-handshake).
	//
	// Explicit non-retryable cases (deterministic — see switch above):
	//
	//   - ErrTCP4ConnRefused: peer RST = a clean "no", not a flake.
	//   - ErrTLSNoServerName / ErrTCP4InvalidAddr /
	//     ErrDNSInvalidServer / ErrIPv4InvalidIP: caller bug.
	//   - ErrStackClosed: nothing to dial through.
	//   - Cert validation: chain on the wire won't change.
	_ = io.EOF
	return true
}

// DialTCP4WithRetry dials TCP4 with up to `attempts` retries on
// transient failures. Sleep schedule between attempts:
//
//	attempt 0 fails → sleep baseDelay
//	attempt 1 fails → sleep baseDelay*2
//	attempt 2 fails → sleep baseDelay*4
//	...
//	attempt N-1 fails → return ErrDialAttemptsExhausted wrapping the
//	                     last error.
//
// With the defaults (attempts=3, baseDelay=2s) the cumulative
// inter-attempt sleep is 2 + 4 = 6 s; total wall-clock budget is
// roughly 3 × `timeout` + 6 s.
//
// `attempts <= 0` is promoted to Stack.DefaultDialAttempts (or
// DefaultDialAttemptsFallback). `baseDelay <= 0` is promoted similarly.
// `attempts == 1` collapses to single-shot behaviour (no sleep, no
// wrapped error — the raw per-attempt error is surfaced).
func (s *Stack) DialTCP4WithRetry(dst net.IP, port uint16, timeout time.Duration, attempts int, baseDelay time.Duration) (*TCP4Conn, error) {
	attempts = s.dialAttemptsOrDefault(attempts)
	baseDelay = s.dialBaseDelayOrDefault(baseDelay)

	var lastErr error
	delay := baseDelay
	for i := 0; i < attempts; i++ {
		conn, err := s.dialTCP4Once(dst, port, timeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !isRetryableDialError(err) {
			// Deterministic — surface raw, don't wrap.
			return nil, err
		}
		if i == attempts-1 {
			break
		}
		s.dialRetrySleep(delay)
		delay *= 2
	}
	if attempts == 1 {
		return nil, lastErr
	}
	return nil, &ErrDialAttemptsExhausted{Attempts: attempts, Last: lastErr}
}

// DialTLSWithRetry is the TLS sibling of DialTCP4WithRetry. Each
// attempt invokes dialTLSOnce (TCP4 dial + tls.Handshake) with the
// per-attempt `timeout`. Retry classification is the same — note in
// particular that a certificate-validation failure is NOT retried
// (the cert presented on the wire is not going to change between
// attempts; retrying just wastes the user's deadline).
//
// `attempts <= 0` promoted to Stack.DefaultDialAttempts (or
// fallback). `baseDelay <= 0` promoted similarly. `attempts == 1`
// collapses to single-shot behaviour.
func (s *Stack) DialTLSWithRetry(host string, port uint16, dnsServer net.IP, timeout time.Duration, attempts int, baseDelay time.Duration) (*tls.Conn, error) {
	attempts = s.dialAttemptsOrDefault(attempts)
	baseDelay = s.dialBaseDelayOrDefault(baseDelay)

	var lastErr error
	delay := baseDelay
	for i := 0; i < attempts; i++ {
		conn, err := s.dialTLSOnce(host, port, dnsServer, timeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if !isRetryableDialError(err) {
			return nil, err
		}
		if i == attempts-1 {
			break
		}
		s.dialRetrySleep(delay)
		delay *= 2
	}
	if attempts == 1 {
		return nil, lastErr
	}
	return nil, &ErrDialAttemptsExhausted{Attempts: attempts, Last: lastErr}
}
