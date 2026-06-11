// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side tests for FetchBlobToBuffer — the sprint 2D'' zero-
// transient OCI streaming path that writes directly into a caller-
// owned []byte (no bytes.Buffer growth, no .Bytes()-alias slice).
//
// Coverage parity with fetch_stream_test.go's matrix: happy, digest
// mismatch, size mismatch, redirect, redirect-no-location, non-200,
// transport error, bad descriptor digest, transport not streaming,
// too-many-redirects — plus the buffer-shape paths that are unique
// to the slice-backed sink: buffer-too-small, body-overflow.

package oci

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
)

// ----- happy path: digest verifies into pre-sized slice ---------

func TestFetchBlobToBufferHappy(t *testing.T) {
	body := []byte(strings.Repeat("k", 3500))
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}

	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		// Drip-feed in 3 chunks to exercise fixedSliceWriter offset.
		dst.Write(body[:1000])
		dst.Write(body[1000:2500])
		n, _ := dst.Write(body[2500:])
		return 200, int64(1000 + 1500 + n), map[string]string{}, nil
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)

	out := make([]byte, len(body))
	n, err := reg.FetchBlobToBuffer(desc, out)
	if err != nil {
		t.Fatalf("FetchBlobToBuffer: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n: got %d, want %d", n, len(body))
	}
	if !bytes.Equal(out, body) {
		t.Errorf("body mismatch")
	}
}

// ----- happy path: oversize slice (caller picked target.Size+pad) ----

func TestFetchBlobToBufferOversizeSlice(t *testing.T) {
	body := []byte("oversize-ok")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(body)
		return 200, int64(n), map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)

	out := make([]byte, len(body)+512) // caller pre-allocated tail-pad room
	n, err := reg.FetchBlobToBuffer(desc, out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n: got %d", n)
	}
	if !bytes.Equal(out[:len(body)], body) {
		t.Errorf("body mismatch in prefix")
	}
}

// ----- digest mismatch ------------------------------------------

func TestFetchBlobToBufferDigestMismatch(t *testing.T) {
	body := []byte("real-body")
	wrongBody := []byte("WRONG-BODY")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(wrongBody))}

	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(wrongBody)
		return 200, int64(n), map[string]string{}, nil
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(wrongBody))
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err != ErrDigestMismatch {
		t.Errorf("want ErrDigestMismatch, got %v", err)
	}
}

// ----- size mismatch (transport delivered fewer than declared) ------

func TestFetchBlobToBufferSizeMismatch(t *testing.T) {
	body := []byte("12345")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: 999}

	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(body)
		return 200, int64(n), map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, 999)
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err == nil || !strings.Contains(err.Error(), "blob size mismatch") {
		t.Errorf("want size mismatch, got %v", err)
	}
}

// ----- caller buffer too small for declared descriptor size --------

func TestFetchBlobToBufferTooSmall(t *testing.T) {
	body := []byte("body")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: 1024}
	mt := newStreamMock(t)
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, 16) // way too small
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err != ErrBlobBufferTooSmall {
		t.Errorf("want ErrBlobBufferTooSmall, got %v", err)
	}
}

// ----- transport delivers more bytes than the buffer can hold ------

func TestFetchBlobToBufferOverflow(t *testing.T) {
	// Descriptor declares Size=4 but the registry sends 100 bytes.
	// Caller-owned slice is exactly 4 bytes; the 5th byte must
	// surface ErrBlobBufferOverflow.
	want := []byte("body")
	desc := Descriptor{Digest: DigestFromBytes(want), Size: int64(len(want))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		// Try to write 100 bytes into a 4-byte sink; the writer
		// returns short on the second chunk.
		dst.Write(want)
		n, werr := dst.Write([]byte(strings.Repeat("X", 96)))
		_ = n
		if werr == nil {
			t.Errorf("expected fixedSliceWriter overflow error on overrun, got nil")
		}
		// Return whatever the transport saw — the streaming path will
		// surface the error.
		return 200, int64(len(want) + n), map[string]string{}, werr
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(want))
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err != ErrBlobBufferOverflow {
		t.Errorf("want ErrBlobBufferOverflow, got %v", err)
	}
}

// ----- redirect chain --------------------------------------------

func TestFetchBlobToBufferRedirect(t *testing.T) {
	body := []byte("redirected-body")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}

	mt := newStreamMock(t)
	initialURL := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	finalURL := "https://cdn.example.com/blob123"

	mt.OnStream(initialURL, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 307, 0, map[string]string{"location": finalURL}, nil
	})
	mt.OnStream(finalURL, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(body)
		return 200, int64(n), map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(body))
	n, err := reg.FetchBlobToBuffer(desc, out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n: got %d", n)
	}
	if !bytes.Equal(out, body) {
		t.Errorf("body mismatch on redirected blob")
	}
}

// ----- redirect with empty Location ------------------------------

func TestFetchBlobToBufferRedirectNoLocation(t *testing.T) {
	body := []byte("never-served")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(body))
	_, err := reg.FetchBlobToBuffer(desc, out)
	var rs *ErrRegistryStatus
	if !errors.As(err, &rs) || rs.Status != 302 {
		t.Errorf("want ErrRegistryStatus(302), got %v", err)
	}
}

// ----- non-200 status -------------------------------------------

func TestFetchBlobToBufferNon200(t *testing.T) {
	body := []byte("body")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 404, 0, map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(body))
	_, err := reg.FetchBlobToBuffer(desc, out)
	var rs *ErrRegistryStatus
	if !errors.As(err, &rs) || rs.Status != 404 {
		t.Errorf("want 404, got %v", err)
	}
}

// ----- transport error -----------------------------------------

func TestFetchBlobToBufferTransportErr(t *testing.T) {
	body := []byte("body")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	want := errors.New("nope")
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 0, 0, nil, want
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, len(body))
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err != want {
		t.Errorf("want transport err, got %v", err)
	}
}

// ----- bad descriptor digest -----------------------------------

func TestFetchBlobToBufferBadDigest(t *testing.T) {
	mt := newStreamMock(t)
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, 16)
	_, err := reg.FetchBlobToBuffer(Descriptor{Digest: "not:a:digest"}, out)
	if err == nil {
		t.Errorf("expected parse error")
	}
}

// ----- transport doesn't implement StreamTransport --------------

func TestFetchBlobToBufferNoStreaming(t *testing.T) {
	mt := newMockTransport(t)
	desc := Descriptor{Digest: DigestFromBytes([]byte("x")), Size: 1}
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, 1)
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err != ErrTransportNotStreaming {
		t.Errorf("want ErrTransportNotStreaming, got %v", err)
	}
}

// ----- too many redirects --------------------------------------

func TestFetchBlobToBufferTooManyRedirects(t *testing.T) {
	body := []byte("x")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: 1}
	mt := newStreamMock(t)
	mt.OnStream("https://reg.example.com/v2/r/blobs/"+desc.Digest, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{"location": "https://cdn1.example.com/x"}, nil
	})
	mt.OnStream("https://cdn1.example.com/x", func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{"location": "https://cdn2.example.com/x"}, nil
	})
	mt.OnStream("https://cdn2.example.com/x", func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{"location": "https://cdn3.example.com/x"}, nil
	})
	mt.OnStream("https://cdn3.example.com/x", func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{"location": "https://cdn4.example.com/x"}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	out := make([]byte, 1)
	_, err := reg.FetchBlobToBuffer(desc, out)
	if err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("want too-many-redirects, got %v", err)
	}
}

// ----- direct unit tests for the slice-writer ----------------------

func TestFixedSliceWriterAtCapacity(t *testing.T) {
	w := &fixedSliceWriter{buf: make([]byte, 4)}
	n, err := w.Write([]byte("ABCD"))
	if err != nil || n != 4 {
		t.Errorf("first Write: n=%d err=%v want 4,nil", n, err)
	}
	if !bytes.Equal(w.buf, []byte("ABCD")) {
		t.Errorf("buf=%q", w.buf)
	}
	// Empty write at boundary is fine.
	n, err = w.Write(nil)
	if err != nil || n != 0 {
		t.Errorf("empty Write at boundary: n=%d err=%v", n, err)
	}
	// Any further non-empty write overflows.
	n, err = w.Write([]byte("X"))
	if err != ErrBlobBufferOverflow || n != 0 {
		t.Errorf("over-boundary Write: n=%d err=%v want 0,overflow", n, err)
	}
}

func TestFixedSliceWriterPartialOverrun(t *testing.T) {
	w := &fixedSliceWriter{buf: make([]byte, 3)}
	n, err := w.Write([]byte("ABCDE"))
	if err != ErrBlobBufferOverflow {
		t.Errorf("want overflow err, got %v", err)
	}
	if n != 3 {
		t.Errorf("partial copy len: got %d want 3", n)
	}
	if !bytes.Equal(w.buf, []byte("ABC")) {
		t.Errorf("buf=%q", w.buf)
	}
}
