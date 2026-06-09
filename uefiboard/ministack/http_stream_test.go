// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-side tests for the M7.1a streaming HTTP/1.1 path
// (streamHTTPResponseHeaders + chunked / content-length / identity
// decoders + lineReader). These tests do NOT touch the TCP path;
// they run streamHTTPResponseHeaders against an in-memory io.Reader
// holding a synthetic HTTP response. The Stack-level HTTPGetStream
// path is covered indirectly by the live OCI probe (you can't smoke
// it from host tests without a real network).

package ministack

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestStreamContentLength(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	status, written, headers, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 200 {
		t.Errorf("status: got %d, want 200", status)
	}
	if written != 11 {
		t.Errorf("written: got %d, want 11", written)
	}
	if out.String() != "hello world" {
		t.Errorf("body: got %q, want %q", out.String(), "hello world")
	}
	if headers["content-type"] != "text/plain" {
		t.Errorf("content-type: %q", headers["content-type"])
	}
}

func TestStreamChunked(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	status, written, _, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 200 {
		t.Errorf("status: %d", status)
	}
	if written != 11 {
		t.Errorf("written: %d", written)
	}
	if out.String() != "hello world" {
		t.Errorf("body: %q", out.String())
	}
}

func TestStreamChunkedExtension(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;junk=1\r\nhello\r\n0\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	_, written, _, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if written != 5 || out.String() != "hello" {
		t.Errorf("got %q (%d)", out.String(), written)
	}
}

func TestStreamChunkedTruncated(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	_, _, _, err := streamHTTPResponseHeaders(br, &out)
	if err != ErrHTTPBadChunk {
		t.Errorf("want ErrHTTPBadChunk, got %v", err)
	}
}

func TestStreamChunkedBadSize(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nXYZ\r\nhello\r\n0\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	_, _, _, err := streamHTTPResponseHeaders(br, &out)
	if err != ErrHTTPBadChunk {
		t.Errorf("want ErrHTTPBadChunk, got %v", err)
	}
}

func TestStreamIdentity(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Type: app/octet\r\n\r\nidentity-body-no-length"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	status, written, _, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 200 || written != int64(len("identity-body-no-length")) {
		t.Errorf("got status=%d written=%d", status, written)
	}
	if out.String() != "identity-body-no-length" {
		t.Errorf("body: %q", out.String())
	}
}

func TestStreamContentLengthTruncated(t *testing.T) {
	// Claims 100 bytes, gives 3, then EOF.
	raw := "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nabc"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	_, written, _, err := streamHTTPResponseHeaders(br, &out)
	if err != io.ErrUnexpectedEOF {
		t.Errorf("want io.ErrUnexpectedEOF, got %v (written=%d)", err, written)
	}
	if written != 3 {
		t.Errorf("written: got %d, want 3", written)
	}
}

func TestStreamBadStatusLine(t *testing.T) {
	raw := "NOTHTTP\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	_, _, _, err := streamHTTPResponseHeaders(br, &out)
	if err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestStreamBadStatusCode(t *testing.T) {
	raw := "HTTP/1.1 ABC OK\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	_, _, _, err := streamHTTPResponseHeaders(br, io.Discard)
	if err != ErrHTTPBadStatusLine {
		t.Errorf("want ErrHTTPBadStatusLine, got %v", err)
	}
}

func TestStreamBadHeader(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nThisHasNoColon\r\n\r\nx"
	br := newLineReader(strings.NewReader(raw))
	_, _, _, err := streamHTTPResponseHeaders(br, io.Discard)
	if err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader, got %v", err)
	}
}

func TestStreamBadContentLength(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: notanumber\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	_, _, _, err := streamHTTPResponseHeaders(br, io.Discard)
	if err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader, got %v", err)
	}
}

func TestStreamNegativeContentLength(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n"
	br := newLineReader(strings.NewReader(raw))
	_, _, _, err := streamHTTPResponseHeaders(br, io.Discard)
	if err != ErrHTTPBadHeader {
		t.Errorf("want ErrHTTPBadHeader, got %v", err)
	}
}

func TestStreamRedirectDrainsBody(t *testing.T) {
	// 302 + body + Location header — body MUST land in discard, not
	// the supplied dst.
	raw := "HTTP/1.1 302 Found\r\nLocation: https://elsewhere/\r\nContent-Length: 5\r\n\r\nWHATX"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	status, written, headers, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 302 {
		t.Errorf("status: %d", status)
	}
	if written != 0 {
		t.Errorf("written: got %d, want 0 (redirect)", written)
	}
	if out.Len() != 0 {
		t.Errorf("dst was written-to on redirect: %q", out.String())
	}
	if headers["location"] != "https://elsewhere/" {
		t.Errorf("location: %q", headers["location"])
	}
}

func TestLineReaderLongLine(t *testing.T) {
	// Line of 4 KiB chars + CRLF — sits within HTTPLineMaxBytes.
	long := strings.Repeat("X", 4096)
	raw := "HTTP/1.1 200 OK\r\nX-Big: " + long + "\r\nContent-Length: 1\r\n\r\nQ"
	br := newLineReader(strings.NewReader(raw))
	var out bytes.Buffer
	status, written, _, err := streamHTTPResponseHeaders(br, &out)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if status != 200 || written != 1 || out.String() != "Q" {
		t.Errorf("got status=%d written=%d body=%q", status, written, out.String())
	}
}

func TestLineReaderOverCap(t *testing.T) {
	// HTTPLineMaxBytes is 8192; serve a 16-KiB never-terminated line.
	raw := "HTTP/1.1 200 OK\r\nX-Toolong: " + strings.Repeat("X", 20000)
	br := newLineReader(strings.NewReader(raw))
	_, _, _, err := streamHTTPResponseHeaders(br, io.Discard)
	if err == nil {
		t.Errorf("expected cap error, got nil")
	}
}
