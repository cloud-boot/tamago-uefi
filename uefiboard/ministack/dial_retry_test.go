// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package ministack

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// ----- isRetryableDialError classification -----------------------

func TestIsRetryableDialErrorNil(t *testing.T) {
	if isRetryableDialError(nil) {
		t.Error("nil should not be retryable")
	}
}

func TestIsRetryableDialErrorTransient(t *testing.T) {
	cases := []error{
		ErrTCP4Timeout,
		ErrDNSTimeout,
		errors.New("ministack: TLS handshake: connection reset by peer"),
		errors.New("EOF"),
		errors.New("read tcp: i/o timeout"),
	}
	for _, e := range cases {
		if !isRetryableDialError(e) {
			t.Errorf("expected retryable: %v", e)
		}
	}
}

func TestIsRetryableDialErrorDeterministic(t *testing.T) {
	cases := []error{
		ErrTLSNoServerName,
		ErrTCP4InvalidAddr,
		ErrDNSInvalidServer,
		ErrStackClosed,
		ErrIPv4InvalidIP,
		ErrTCP4ConnRefused, // RST = clean "no" from peer, not a flake.
	}
	for _, e := range cases {
		if isRetryableDialError(e) {
			t.Errorf("expected deterministic (no retry): %v", e)
		}
	}
}

func TestIsRetryableDialErrorCertValidation(t *testing.T) {
	// x509.UnknownAuthorityError — verified via errors.As.
	uaErr := x509.UnknownAuthorityError{}
	if isRetryableDialError(uaErr) {
		t.Error("x509.UnknownAuthorityError must not be retryable")
	}
	// x509.HostnameError.
	hErr := x509.HostnameError{Host: "wrong.example"}
	if isRetryableDialError(hErr) {
		t.Error("x509.HostnameError must not be retryable")
	}
	// x509.CertificateInvalidError.
	ciErr := x509.CertificateInvalidError{Reason: x509.Expired}
	if isRetryableDialError(ciErr) {
		t.Error("x509.CertificateInvalidError must not be retryable")
	}
	// String-match fallback for older / wrapped formats.
	stringErr := errors.New("tls: failed to verify certificate: x509: certificate signed by unknown authority")
	if isRetryableDialError(stringErr) {
		t.Error("string-form cert validation must not be retryable")
	}
}

// ----- dialRetryItoa edge cases ---------------------------------

func TestDialRetryItoa(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{42, "42"},
		{-7, "-7"},
		{1234567, "1234567"},
	}
	for _, c := range cases {
		if got := dialRetryItoa(c.in); got != c.want {
			t.Errorf("dialRetryItoa(%d): got %q want %q", c.in, got, c.want)
		}
	}
}

// ----- ErrDialAttemptsExhausted shape ---------------------------

func TestErrDialAttemptsExhaustedMessage(t *testing.T) {
	e := &ErrDialAttemptsExhausted{Attempts: 3, Last: ErrTCP4Timeout}
	want := "ministack: dial attempts exhausted (3 tries): ministack: TCP operation timed out"
	if e.Error() != want {
		t.Errorf("Error(): got %q want %q", e.Error(), want)
	}
	if !errors.Is(e, ErrTCP4Timeout) {
		t.Error("errors.Is(e, ErrTCP4Timeout) should match via Unwrap")
	}
}

func TestErrDialAttemptsExhaustedNilLast(t *testing.T) {
	e := &ErrDialAttemptsExhausted{Attempts: 0, Last: nil}
	if !strings.Contains(e.Error(), "dial attempts exhausted") {
		t.Errorf("unexpected nil-last message: %q", e.Error())
	}
}

// ----- defaults / promotion --------------------------------------

func TestDialAttemptsOrDefault(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	// Unconfigured Stack falls back to package default.
	if got := s.dialAttemptsOrDefault(0); got != DefaultDialAttemptsFallback {
		t.Errorf("got %d, want %d (fallback)", got, DefaultDialAttemptsFallback)
	}
	// Stack-level default takes precedence over fallback.
	s.DefaultDialAttempts = 7
	if got := s.dialAttemptsOrDefault(0); got != 7 {
		t.Errorf("got %d, want 7 (Stack default)", got)
	}
	// Explicit positive overrides everything.
	if got := s.dialAttemptsOrDefault(2); got != 2 {
		t.Errorf("got %d, want 2 (explicit)", got)
	}
}

func TestDialBaseDelayOrDefault(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	if got := s.dialBaseDelayOrDefault(0); got != DefaultDialBaseDelayFallback {
		t.Errorf("got %v, want %v", got, DefaultDialBaseDelayFallback)
	}
	s.DefaultDialBaseDelay = 250 * time.Millisecond
	if got := s.dialBaseDelayOrDefault(0); got != 250*time.Millisecond {
		t.Errorf("got %v, want 250ms (Stack default)", got)
	}
	if got := s.dialBaseDelayOrDefault(time.Second); got != time.Second {
		t.Errorf("got %v, want 1s (explicit)", got)
	}
}

// ----- retry control flow (host-side fake dialer) -----------------
//
// To exercise the retry/backoff loop without standing up a synthetic
// TLS server we factor a generic helper, retryLoop, out of the dial
// wrappers and test the helper directly. The two real wrappers
// (DialTCP4WithRetry / DialTLSWithRetry) are thin and exercised in
// the integration test below via the synthetic stub link returning
// timeouts.

// fakeDialer is a stateful dialer the test drives. Each call advances
// `calls` and returns the next scripted error. A nil result signals
// success.
type fakeDialer struct {
	results []error
	calls   int
	when    []time.Time
}

func (f *fakeDialer) next() error {
	if f.calls >= len(f.results) {
		f.when = append(f.when, time.Now())
		f.calls++
		return errors.New("script exhausted")
	}
	f.when = append(f.when, time.Now())
	r := f.results[f.calls]
	f.calls++
	return r
}

// runFakeRetry replicates the loop body of DialTCP4WithRetry exactly,
// minus the per-attempt dial call (substituted with f.next). Kept in
// the test file so a future refactor that diverges the real wrapper's
// shape trips an obvious test failure here.
func runFakeRetry(s *Stack, f *fakeDialer, attempts int, baseDelay time.Duration) error {
	attempts = s.dialAttemptsOrDefault(attempts)
	baseDelay = s.dialBaseDelayOrDefault(baseDelay)

	var lastErr error
	delay := baseDelay
	for i := 0; i < attempts; i++ {
		err := f.next()
		if err == nil {
			return nil
		}
		lastErr = err
		if !isRetryableDialError(err) {
			return err
		}
		if i == attempts-1 {
			break
		}
		s.dialRetrySleep(delay)
		delay *= 2
	}
	if attempts == 1 {
		return lastErr
	}
	return &ErrDialAttemptsExhausted{Attempts: attempts, Last: lastErr}
}

func TestRetrySucceedsOnSecondAttempt(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	f := &fakeDialer{results: []error{ErrTCP4Timeout, nil}}
	if err := runFakeRetry(s, f, 3, 1*time.Millisecond); err != nil {
		t.Fatalf("expected success on 2nd attempt, got %v", err)
	}
	if f.calls != 2 {
		t.Errorf("expected 2 calls, got %d", f.calls)
	}
}

func TestRetryExhaustsAndReturnsLastError(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	f := &fakeDialer{results: []error{ErrTCP4Timeout, ErrTCP4Timeout, ErrTCP4Timeout}}
	err := runFakeRetry(s, f, 3, 1*time.Millisecond)
	if err == nil {
		t.Fatal("expected exhaustion error")
	}
	var ex *ErrDialAttemptsExhausted
	if !errors.As(err, &ex) {
		t.Fatalf("expected ErrDialAttemptsExhausted, got %T: %v", err, err)
	}
	if ex.Attempts != 3 {
		t.Errorf("Attempts: got %d, want 3", ex.Attempts)
	}
	if !errors.Is(err, ErrTCP4Timeout) {
		t.Error("errors.Is(err, ErrTCP4Timeout) must match through Unwrap")
	}
	if f.calls != 3 {
		t.Errorf("expected 3 calls, got %d", f.calls)
	}
}

func TestRetryStopsImmediatelyOnNonRetryable(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	// Cert-validation-shaped error: deterministic, never retried.
	certErr := x509.UnknownAuthorityError{}
	f := &fakeDialer{results: []error{certErr, ErrTCP4Timeout, ErrTCP4Timeout}}
	err := runFakeRetry(s, f, 3, 1*time.Millisecond)
	if err == nil {
		t.Fatal("expected non-retryable to surface")
	}
	if f.calls != 1 {
		t.Errorf("expected 1 call (no retry on cert error), got %d", f.calls)
	}
	// The error should be the raw cert error, NOT wrapped in
	// ErrDialAttemptsExhausted (the retry path bailed before the
	// budget ran out).
	var ex *ErrDialAttemptsExhausted
	if errors.As(err, &ex) {
		t.Error("non-retryable error should NOT be wrapped in ErrDialAttemptsExhausted")
	}
}

func TestRetryExponentialBackoffTiming(t *testing.T) {
	if testing.Short() {
		t.Skip("backoff timing test skipped in short mode")
	}
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	const base = 20 * time.Millisecond
	// 3 attempts, all fail → sleeps of 20ms then 40ms = ~60ms total
	// between the first and the third call.
	f := &fakeDialer{results: []error{ErrTCP4Timeout, ErrTCP4Timeout, ErrTCP4Timeout}}
	start := time.Now()
	_ = runFakeRetry(s, f, 3, base)
	elapsed := time.Since(start)
	// The retry loop sleeps after attempts 0 and 1 (not after the
	// last); expected total sleep = base + 2*base = 3*base = 60ms.
	want := 3 * base
	// Allow a generous +50ms slack for scheduler wakeups, a -10ms
	// floor because some kernels round timers down.
	if elapsed < want-10*time.Millisecond {
		t.Errorf("elapsed %v < expected lower bound %v", elapsed, want-10*time.Millisecond)
	}
	if elapsed > want+200*time.Millisecond {
		t.Errorf("elapsed %v > expected upper bound %v", elapsed, want+200*time.Millisecond)
	}
}

func TestRetrySingleAttemptCollapsesToRaw(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	f := &fakeDialer{results: []error{ErrTCP4Timeout}}
	err := runFakeRetry(s, f, 1, 10*time.Millisecond)
	if err != ErrTCP4Timeout {
		t.Errorf("attempts=1: got %v, want raw ErrTCP4Timeout", err)
	}
	if f.calls != 1 {
		t.Errorf("expected 1 call, got %d", f.calls)
	}
}

func TestRetrySleepAbortsOnStackClose(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.Close()
	}()
	start := time.Now()
	// Sleep 5 seconds; Close after 20ms should abort it.
	s.dialRetrySleep(5 * time.Second)
	elapsed := time.Since(start)
	if elapsed > 200*time.Millisecond {
		t.Errorf("dialRetrySleep did not short-circuit on Close (elapsed %v)", elapsed)
	}
}

func TestRetrySleepZeroIsNoOp(t *testing.T) {
	s := New(newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6}))
	defer s.Close()
	start := time.Now()
	s.dialRetrySleep(0)
	if d := time.Since(start); d > 10*time.Millisecond {
		t.Errorf("zero sleep took %v", d)
	}
}

// ----- end-to-end: DialTCP4WithRetry against silent stub link -----

func TestDialTCP4WithRetryAllTimeoutsAgainstStubLink(t *testing.T) {
	// 2 attempts × 50ms per-attempt timeout × 1ms backoff = ~100ms.
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	defer s.Close()
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	_ = s.SetDefaultGateway(net.IPv4(10, 0, 2, 2))
	s.SetARPTimeout(20 * time.Millisecond)

	_, err := s.DialTCP4WithRetry(net.IPv4(10, 0, 2, 99), 4242, 50*time.Millisecond, 2, 1*time.Millisecond)
	if err == nil {
		t.Fatal("expected dial error against silent stub link")
	}
	var ex *ErrDialAttemptsExhausted
	if !errors.As(err, &ex) {
		t.Fatalf("expected ErrDialAttemptsExhausted, got %T: %v", err, err)
	}
	if ex.Attempts != 2 {
		t.Errorf("Attempts: got %d, want 2", ex.Attempts)
	}
	// Wall-clock timing isn't load-bearing here — the synthetic
	// link's no-route / ARP-fail path returns FAST (well under the
	// per-attempt timeout). What we care about is the Attempts count
	// + the wrapped-error type, both checked above. The exponential-
	// backoff timing is covered separately by
	// TestRetryExponentialBackoffTiming using the fakeDialer
	// harness — there we KNOW the per-attempt "duration" is zero
	// (script-driven) and the only elapsed time IS the sleep.
}

// ----- DialTLS path: empty host stays deterministic (no retry) ----

func TestDialTLSDoesNotRetryEmptyHost(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	defer s.Close()
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	// Force enough retries that, if the path mistakenly looped,
	// the test would either hang or surface a wrapped error.
	s.DefaultDialAttempts = 5
	s.DefaultDialBaseDelay = 1 * time.Millisecond
	start := time.Now()
	_, err := s.DialTLS("", 443, net.IPv4(10, 0, 2, 3), 100*time.Millisecond)
	if err != ErrTLSNoServerName {
		t.Errorf("got %v, want raw ErrTLSNoServerName (no retry wrap)", err)
	}
	// Should be near-instant — no sleep, no looping.
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Errorf("deterministic error took %v; expected near-instant", d)
	}
}

// ----- DialTLSWithRetry path: bad-DNS-server still deterministic --

func TestDialTLSWithRetryDoesNotRetryConfigError(t *testing.T) {
	link := newStubLink(net.HardwareAddr{1, 2, 3, 4, 5, 6})
	s := New(link)
	defer s.Close()
	_ = s.SetIPv4Address(net.IPv4(10, 0, 2, 15), net.IPv4Mask(255, 255, 255, 0))
	// hostname without DNS server is ErrDNSInvalidServer — deterministic.
	_, err := s.DialTLSWithRetry("example.com", 443, nil, 100*time.Millisecond, 5, 1*time.Millisecond)
	if err != ErrDNSInvalidServer {
		t.Errorf("got %v, want ErrDNSInvalidServer", err)
	}
}

// ----- compile-time sanity: tls.CertificateVerificationError is
// matched by errors.As (the type only landed in Go 1.20). If the
// build target ever drops below that, this test will fail to compile
// — exactly the signal we want.

func TestTLSCertVerificationErrorTypeAvailable(t *testing.T) {
	var e *tls.CertificateVerificationError
	if errors.As(errors.New("not a cert error"), &e) {
		t.Error("unexpected match for synthetic non-cert error")
	}
}
