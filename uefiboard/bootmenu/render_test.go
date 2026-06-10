// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package bootmenu

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func sampleRenderCfg(t *testing.T) *BootConfig {
	t.Helper()
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse(sampleConfig): %v", err)
	}
	return cfg
}

func TestRender_FirstFramePrologue(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 10); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "\x1b[H") {
		t.Errorf("first frame does not start with cursor-home ANSI; got prefix = %q", firstN(out, 16))
	}
	if !strings.Contains(out, "\x1b[2J") {
		t.Errorf("first frame missing erase-in-display; got = %q", firstN(out, 32))
	}
}

func TestRender_TitleAndCountdownVisible(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 7); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "cloud-boot menu") {
		t.Errorf("title not painted; out = %s", out)
	}
	if !strings.Contains(out, "Auto-boot in 7s") {
		t.Errorf("countdown line missing; out = %s", out)
	}
}

func TestRender_CountdownZeroSuppressed(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 0); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Auto-boot in") {
		t.Errorf("countdown 0 should not show 'Auto-boot in'; out = %s", out)
	}
	if !strings.Contains(out, "Use Up/Down") {
		t.Errorf("countdown 0 should show navigation hint; out = %s", out)
	}
}

func TestRender_SelectionCursorMoves(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 5); err != nil {
		t.Fatalf("Render(sel=0): %v", err)
	}
	first := buf.String()
	buf.Reset()
	if err := r.Render(cfg, 1, 5); err != nil {
		t.Fatalf("Render(sel=1): %v", err)
	}
	second := buf.String()

	// Subsequent frame must still issue the cursor-home prologue so the
	// in-place redraw works on a real terminal.
	if !strings.HasPrefix(second, "\x1b[H") {
		t.Errorf("second frame missing cursor-home; got prefix = %q", firstN(second, 8))
	}

	// First frame: alpine-latest is selected, rescue is not.
	firstAlpineLine := lineContaining(first, "alpine-latest")
	firstRescueLine := lineContaining(first, "rescue")
	if !strings.Contains(firstAlpineLine, "> ") {
		t.Errorf("first frame: alpine-latest should have > cursor; line = %q", firstAlpineLine)
	}
	if strings.Contains(firstRescueLine, "> ") {
		t.Errorf("first frame: rescue should not have > cursor; line = %q", firstRescueLine)
	}

	// Second frame: rescue is selected, alpine-latest is not.
	secondAlpineLine := lineContaining(second, "alpine-latest")
	secondRescueLine := lineContaining(second, "rescue")
	if strings.Contains(secondAlpineLine, "> ") {
		t.Errorf("second frame: alpine-latest should not have > cursor; line = %q", secondAlpineLine)
	}
	if !strings.Contains(secondRescueLine, "> ") {
		t.Errorf("second frame: rescue should have > cursor; line = %q", secondRescueLine)
	}
}

func TestRender_NilSink(t *testing.T) {
	r := &Renderer{Width: 60}
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 5); !errors.Is(err, ErrNoSink) {
		t.Errorf("Render with nil Out: err = %v, want ErrNoSink", err)
	}
}

func TestRender_DefaultWidth(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf} // Width = 0 → defaultWidth
	cfg := sampleRenderCfg(t)
	if err := r.Render(cfg, 0, 5); err != nil {
		t.Fatalf("Render: %v", err)
	}
	// Find the first non-ANSI '+' (start of the top border line).
	out := buf.Bytes()
	plus := bytes.IndexByte(out, '+')
	if plus < 0 {
		t.Fatalf("no '+' found in output (first 64 = %q)", firstN(string(out), 64))
	}
	// Top border runs from `plus` until the next '\n'; its length is
	// the rendered width.
	end := plus
	for end < len(out) && out[end] != '\n' {
		end++
	}
	line := out[plus:end]
	if len(line) != defaultWidth {
		t.Errorf("default-width top border length = %d, want %d (line = %q)", len(line), defaultWidth, line)
	}
}

func TestRender_LongLabelTruncates(t *testing.T) {
	cfg := &BootConfig{
		Title:   "t",
		Entries: []Entry{{Label: strings.Repeat("X", 200), KernelRef: "k"}},
	}
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 40}
	if err := r.Render(cfg, 0, 0); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "...") {
		t.Errorf("expected '...' truncation marker in output; got = %s", buf.String())
	}
}

func TestRender_SelectedOutOfRangeClamps(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	cfg := sampleRenderCfg(t)
	// selected = 99 should clamp to last entry without panic.
	if err := r.Render(cfg, 99, 0); err != nil {
		t.Fatalf("Render(sel=99): %v", err)
	}
	if !strings.Contains(lineContaining(buf.String(), "rescue"), "> ") {
		t.Errorf("clamped-to-last did not put cursor on last entry; out = %s", buf.String())
	}

	buf.Reset()
	if err := r.Render(cfg, -5, 0); err != nil {
		t.Fatalf("Render(sel=-5): %v", err)
	}
	if !strings.Contains(lineContaining(buf.String(), "alpine-latest"), "> ") {
		t.Errorf("clamped-to-first did not put cursor on first entry; out = %s", buf.String())
	}
}

func TestRender_EmptyTitleFallback(t *testing.T) {
	cfg := &BootConfig{
		Entries: []Entry{{Label: "only", KernelRef: "k"}},
	}
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Width: 60}
	if err := r.Render(cfg, 0, 0); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "cloud-boot") {
		t.Errorf("empty title should fall back to 'cloud-boot'; out = %s", buf.String())
	}
}

func TestRenderErr_ErrorString(t *testing.T) {
	if got := ErrNoSink.Error(); got != "bootmenu: Renderer.Out is nil" {
		t.Errorf("ErrNoSink.Error() = %q", got)
	}
}

// failingWriter returns an error on Write. Used to cover the
// out.Write error path.
type failingWriter struct{}

var errFailingWrite = errors.New("failingWriter: forced")

func (failingWriter) Write([]byte) (int, error) { return 0, errFailingWrite }

func TestRender_WriteError(t *testing.T) {
	r := &Renderer{Out: failingWriter{}, Width: 60}
	cfg := sampleRenderCfg(t)
	err := r.Render(cfg, 0, 5)
	if !errors.Is(err, errFailingWrite) {
		t.Errorf("Render write error: err = %v, want errFailingWrite", err)
	}
}

func firstN(s string, n int) string {
	if len(s) < n {
		return s
	}
	return s[:n]
}

func lineContaining(s, needle string) string {
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
