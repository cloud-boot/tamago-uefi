// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side tests for the M7.1a OCI streaming-fetch path
// (FetchBlobStream + StreamTransport contract).

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

// streamHandler is the per-URL function the mock streaming transport
// calls when it sees a GetStream request.
type streamHandler func(url string, dst io.Writer, opts ministack.HTTPGetOptions) (status int, written int64, headers map[string]string, err error)

// streamMockTransport is a Transport that also satisfies
// StreamTransport. The buffered Get path delegates to the embedded
// mockTransport (reused so the existing fetch_test.go scaffolding
// still works); the GetStream path runs a streamHandler the test
// installs per-URL.
type streamMockTransport struct {
	*mockTransport
	streamHandlers map[string]streamHandler
}

func newStreamMock(t *testing.T) *streamMockTransport {
	return &streamMockTransport{
		mockTransport:  newMockTransport(t),
		streamHandlers: map[string]streamHandler{},
	}
}

func (s *streamMockTransport) OnStream(url string, h streamHandler) {
	s.streamHandlers[url] = h
}

func (s *streamMockTransport) GetStream(url string, dst io.Writer, opts ministack.HTTPGetOptions) (status int, written int64, headers map[string]string, err error) {
	if h, ok := s.streamHandlers[url]; ok {
		return h(url, dst, opts)
	}
	return 0, 0, nil, errors.New("streamMockTransport: no stream handler for " + url)
}

// ----- happy path: digest verifies -------------------------------

func TestFetchBlobStreamHappy(t *testing.T) {
	body := []byte(strings.Repeat("k", 3500)) // > common 1 KiB so the loop iterates a few times
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}

	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(body)
		return 200, int64(n), map[string]string{}, nil
	})

	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)

	var out bytes.Buffer
	n, err := reg.FetchBlobStream(desc, &out)
	if err != nil {
		t.Fatalf("FetchBlobStream: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n: got %d, want %d", n, len(body))
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Errorf("body mismatch")
	}
}

// ----- digest mismatch ------------------------------------------

func TestFetchBlobStreamDigestMismatch(t *testing.T) {
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
	var out bytes.Buffer
	_, err := reg.FetchBlobStream(desc, &out)
	if err != ErrDigestMismatch {
		t.Errorf("want ErrDigestMismatch, got %v", err)
	}
}

// ----- size mismatch --------------------------------------------

func TestFetchBlobStreamSizeMismatch(t *testing.T) {
	body := []byte("12345")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: 999} // wrong size

	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		n, _ := dst.Write(body)
		return 200, int64(n), map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	_, err := reg.FetchBlobStream(desc, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "blob size mismatch") {
		t.Errorf("want size mismatch, got %v", err)
	}
}

// ----- redirect chain --------------------------------------------

func TestFetchBlobStreamRedirect(t *testing.T) {
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
	var out bytes.Buffer
	n, err := reg.FetchBlobStream(desc, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if n != int64(len(body)) {
		t.Errorf("n: got %d", n)
	}
	if !bytes.Equal(out.Bytes(), body) {
		t.Errorf("body mismatch on redirected blob")
	}
}

// ----- redirect with empty Location ------------------------------

func TestFetchBlobStreamRedirectNoLocation(t *testing.T) {
	body := []byte("never-served")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 302, 0, map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	_, err := reg.FetchBlobStream(desc, io.Discard)
	var rs *ErrRegistryStatus
	if !errors.As(err, &rs) || rs.Status != 302 {
		t.Errorf("want ErrRegistryStatus(302), got %v", err)
	}
}

// ----- non-200 status -------------------------------------------

func TestFetchBlobStreamNon200(t *testing.T) {
	body := []byte("body")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: int64(len(body))}
	mt := newStreamMock(t)
	url := "https://reg.example.com/v2/r/blobs/" + desc.Digest
	mt.OnStream(url, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		return 404, 0, map[string]string{}, nil
	})
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	_, err := reg.FetchBlobStream(desc, io.Discard)
	var rs *ErrRegistryStatus
	if !errors.As(err, &rs) || rs.Status != 404 {
		t.Errorf("want 404, got %v", err)
	}
}

// ----- transport error -----------------------------------------

func TestFetchBlobStreamTransportErr(t *testing.T) {
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
	_, err := reg.FetchBlobStream(desc, io.Discard)
	if err != want {
		t.Errorf("want transport err, got %v", err)
	}
}

// ----- bad descriptor digest -----------------------------------

func TestFetchBlobStreamBadDigest(t *testing.T) {
	mt := newStreamMock(t)
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	_, err := reg.FetchBlobStream(Descriptor{Digest: "not:a:digest"}, io.Discard)
	if err == nil {
		t.Errorf("expected parse error")
	}
}

// ----- transport doesn't implement StreamTransport --------------

func TestFetchBlobStreamNoStreaming(t *testing.T) {
	mt := newMockTransport(t) // bare mock — Get only, no GetStream
	desc := Descriptor{Digest: DigestFromBytes([]byte("x")), Size: 1}
	ref := &Ref{Scheme: "https", Host: "reg.example.com", Repo: "r", Reference: "latest"}
	reg := NewRegistryWithTransport(mt, net.IPv4(127, 0, 0, 1), ref)
	_, err := reg.FetchBlobStream(desc, io.Discard)
	if err != ErrTransportNotStreaming {
		t.Errorf("want ErrTransportNotStreaming, got %v", err)
	}
}

// ----- too many redirects --------------------------------------

func TestFetchBlobStreamTooManyRedirects(t *testing.T) {
	body := []byte("x")
	desc := Descriptor{Digest: DigestFromBytes(body), Size: 1}
	mt := newStreamMock(t)
	// Every URL responds with a redirect to a fresh URL.
	cycle := 0
	mt.OnStream("https://reg.example.com/v2/r/blobs/"+desc.Digest, func(_ string, dst io.Writer, _ ministack.HTTPGetOptions) (int, int64, map[string]string, error) {
		cycle++
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
	_, err := reg.FetchBlobStream(desc, io.Discard)
	if err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("want too-many-redirects, got %v", err)
	}
}
