// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package bootmenu

import (
	"errors"
	"strings"
	"testing"
)

// sampleConfig is the canonical M9.0 acceptance fixture — two entries,
// title + timeout + default, optional initrd_ref present on one entry
// and absent on the other. Mirrors the spec exactly so a regression in
// either the field tags or the gohcl decoder shape would fail this
// test first.
const sampleConfig = `
title   = "cloud-boot menu"
timeout = 10
default = "alpine-latest"

entry "alpine-latest" {
  kernel_ref = "ghcr.io/myorg/alpine-kernel:latest"
  cmdline    = "console=ttyAMA0,115200 root=/dev/ram0"
  initrd_ref = "ghcr.io/myorg/alpine-initrd:latest"
}

entry "rescue" {
  kernel_ref = "ghcr.io/myorg/rescue-kernel:latest"
  cmdline    = "console=ttyAMA0,115200 single"
}
`

func TestParseSample(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Title != "cloud-boot menu" {
		t.Errorf("Title: got %q, want %q", cfg.Title, "cloud-boot menu")
	}
	if cfg.Timeout != 10 {
		t.Errorf("Timeout: got %d, want 10", cfg.Timeout)
	}
	if cfg.Default != "alpine-latest" {
		t.Errorf("Default: got %q, want %q", cfg.Default, "alpine-latest")
	}
	if len(cfg.Entries) != 2 {
		t.Fatalf("Entries: got %d, want 2", len(cfg.Entries))
	}

	e0 := cfg.Entries[0]
	if e0.Label != "alpine-latest" {
		t.Errorf("Entries[0].Label: got %q, want %q", e0.Label, "alpine-latest")
	}
	if e0.KernelRef != "ghcr.io/myorg/alpine-kernel:latest" {
		t.Errorf("Entries[0].KernelRef: got %q", e0.KernelRef)
	}
	if e0.InitrdRef != "ghcr.io/myorg/alpine-initrd:latest" {
		t.Errorf("Entries[0].InitrdRef: got %q", e0.InitrdRef)
	}
	if e0.Cmdline != "console=ttyAMA0,115200 root=/dev/ram0" {
		t.Errorf("Entries[0].Cmdline: got %q", e0.Cmdline)
	}

	e1 := cfg.Entries[1]
	if e1.Label != "rescue" {
		t.Errorf("Entries[1].Label: got %q, want %q", e1.Label, "rescue")
	}
	if e1.KernelRef != "ghcr.io/myorg/rescue-kernel:latest" {
		t.Errorf("Entries[1].KernelRef: got %q", e1.KernelRef)
	}
	if e1.InitrdRef != "" {
		t.Errorf("Entries[1].InitrdRef: got %q, want empty", e1.InitrdRef)
	}
	if e1.Cmdline != "console=ttyAMA0,115200 single" {
		t.Errorf("Entries[1].Cmdline: got %q", e1.Cmdline)
	}
}

// TestFindEntry exercises both the hit (Default resolves to the first
// entry) and miss (unknown label) branches.
func TestFindEntry(t *testing.T) {
	cfg, err := Parse([]byte(sampleConfig))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	got, ok := cfg.FindEntry("alpine-latest")
	if !ok {
		t.Fatal("FindEntry(alpine-latest): want ok=true")
	}
	if got.KernelRef != "ghcr.io/myorg/alpine-kernel:latest" {
		t.Errorf("FindEntry: KernelRef=%q", got.KernelRef)
	}
	if _, ok := cfg.FindEntry("does-not-exist"); ok {
		t.Error("FindEntry(does-not-exist): want ok=false")
	}
}

func TestParseEmptyInput(t *testing.T) {
	_, err := Parse(nil)
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("Parse(nil): got %v, want ErrEmptyInput", err)
	}
	_, err = Parse([]byte{})
	if !errors.Is(err, ErrEmptyInput) {
		t.Errorf("Parse([]byte{}): got %v, want ErrEmptyInput", err)
	}
}

func TestParseNoEntries(t *testing.T) {
	// Valid HCL but no entry blocks — Parse must surface ErrNoEntries
	// rather than returning an empty menu.
	input := `title = "empty"` + "\n" + `timeout = 0` + "\n"
	_, err := Parse([]byte(input))
	if !errors.Is(err, ErrNoEntries) {
		t.Errorf("Parse(no entries): got %v, want ErrNoEntries", err)
	}
}

func TestParseSyntaxError(t *testing.T) {
	// Unbalanced brace — HCL parser must surface the diagnostic; we
	// wrap it with a "bootmenu: HCL syntax error" prefix so the
	// caller can grep for it in QEMU logs.
	_, err := Parse([]byte(`entry "broken" {`))
	if err == nil {
		t.Fatal("Parse(broken): want error, got nil")
	}
	if !strings.HasPrefix(err.Error(), "bootmenu: HCL syntax error") &&
		!strings.HasPrefix(err.Error(), "bootmenu: HCL decode error") {
		t.Errorf("Parse(broken): want syntax/decode error prefix, got %q", err.Error())
	}
}

func TestParseDecodeError(t *testing.T) {
	// Syntactically valid HCL but `kernel_ref` (required) is missing
	// on the only entry — gohcl must surface that as a decode error.
	input := `
entry "no-kernel" {
  cmdline = "console=ttyAMA0,115200"
}
`
	_, err := Parse([]byte(input))
	if err == nil {
		t.Fatal("Parse(missing kernel_ref): want error, got nil")
	}
	if !strings.Contains(err.Error(), "kernel_ref") {
		t.Errorf("Parse: error should mention missing kernel_ref, got %q", err.Error())
	}
}

func TestParseDuplicateLabel(t *testing.T) {
	input := `
entry "dup" {
  kernel_ref = "ghcr.io/x/k1:latest"
}
entry "dup" {
  kernel_ref = "ghcr.io/x/k2:latest"
}
`
	_, err := Parse([]byte(input))
	if !errors.Is(err, ErrDuplicateLabel) {
		t.Errorf("Parse(dup labels): got %v, want ErrDuplicateLabel", err)
	}
}

func TestParseDefaultNotFound(t *testing.T) {
	input := `
default = "ghost"
entry "real" {
  kernel_ref = "ghcr.io/x/k:latest"
}
`
	_, err := Parse([]byte(input))
	if !errors.Is(err, ErrDefaultNotFound) {
		t.Errorf("Parse(unknown default): got %v, want ErrDefaultNotFound", err)
	}
}

// TestParseDefaultEmptyOK: an explicitly-empty / omitted Default is
// fine — the menu just requires an interactive selection.
func TestParseDefaultEmpty(t *testing.T) {
	input := `
entry "only" {
  kernel_ref = "ghcr.io/x/k:latest"
}
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Default != "" {
		t.Errorf("Default: got %q, want empty", cfg.Default)
	}
	if len(cfg.Entries) != 1 {
		t.Errorf("Entries: got %d, want 1", len(cfg.Entries))
	}
}

// TestParseMinimalEntry: only the required `kernel_ref` attribute is
// present; both InitrdRef and Cmdline are absent.
func TestParseMinimalEntry(t *testing.T) {
	input := `
entry "tiny" {
  kernel_ref = "ghcr.io/x/k:latest"
}
`
	cfg, err := Parse([]byte(input))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Entries) != 1 {
		t.Fatalf("Entries: got %d, want 1", len(cfg.Entries))
	}
	e := cfg.Entries[0]
	if e.Label != "tiny" || e.KernelRef != "ghcr.io/x/k:latest" || e.InitrdRef != "" || e.Cmdline != "" {
		t.Errorf("unexpected entry: %+v", e)
	}
}
