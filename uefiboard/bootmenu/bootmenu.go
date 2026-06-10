// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Package bootmenu defines the HCL boot-menu schema cloud-boot fetches
// from the DHCP-option-67-advertised OCI ref (the M9 "DHCP-discovered
// OCI boot menu" feature) and exposes a single Parse entry point that
// turns the raw HCL bytes into a typed *BootConfig.
//
// Schema (four keys, no more):
//
//	title   = "cloud-boot menu"      # rendered at the top of the menu (M9.1)
//	timeout = 10                     # seconds before auto-booting Default
//	default = "alpine-latest"        # label of the entry to auto-select
//
//	entry "alpine-latest" {
//	    kernel_ref = "ghcr.io/myorg/alpine-kernel:latest"
//	    initrd_ref = "ghcr.io/myorg/alpine-initrd:latest"   # optional
//	    cmdline    = "console=ttyAMA0,115200 root=/dev/ram0" # optional
//	}
//
//	entry "rescue" {
//	    kernel_ref = "ghcr.io/myorg/rescue-kernel:latest"
//	    cmdline    = "console=ttyAMA0,115200 single"
//	}
//
// The schema is intentionally minimal — M9.0 only proves the
// DHCP→OCI→HCL chain; richer features (templating, per-entry hashes,
// per-entry signatures, environment overrides, conditional inclusion)
// land in later sprints if and when the boot-menu use case demands
// them.
//
// Why hashicorp/hcl/v2 (not openweft/weft-hcl): weft-hcl is the
// openweft VM-definition parser — its public surface is
// ReadVMs(configDir) → []Row, which is heavily coupled to the
// on-disk config-dir + `version = "1"` validation + arch token
// resolution + OCI/HTTP attribute resolution that VM rows need.
// None of those are appropriate for a 4-key boot-menu HCL fetched
// from an OCI blob. hashicorp/hcl/v2 + gohcl gives us exactly the
// "parse bytes → typed struct" shape M9.0 needs, with the same
// upstream parser weft-hcl itself wraps, so there's no semantic
// drift between the two.
package bootmenu

import (
	"errors"
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
)

// BootConfig is the top-level HCL schema cloud-boot fetches from the
// DHCP-advertised OCI ref. It MUST contain at least one Entry — Parse
// surfaces ErrNoEntries otherwise (an empty menu is never useful).
type BootConfig struct {
	// Title appears at the top of the rendered menu (M9.1). Optional;
	// an empty title is valid and the renderer is responsible for the
	// fallback wording.
	Title string `hcl:"title,optional"`

	// Timeout is seconds before auto-selecting Default. Zero means
	// "wait forever for an explicit keypress" (M9.2). Optional;
	// omitted = 0.
	Timeout int `hcl:"timeout,optional"`

	// Default is the label of the entry to auto-boot when the timeout
	// elapses (M9.2). Optional; when empty the menu requires an
	// explicit selection and never auto-boots.
	Default string `hcl:"default,optional"`

	// Entries is the ordered list of boot options. The order is the
	// declaration order in the HCL source (gohcl preserves it). Must
	// contain at least one entry; Parse surfaces ErrNoEntries if not.
	Entries []Entry `hcl:"entry,block"`
}

// Entry is one row in the rendered menu. The label is the HCL block
// label (`entry "alpine-latest" { ... }`) and doubles as the Default
// match key. KernelRef is the only required body attribute — InitrdRef
// and Cmdline default to empty.
type Entry struct {
	Label     string `hcl:"label,label"`
	KernelRef string `hcl:"kernel_ref"`
	InitrdRef string `hcl:"initrd_ref,optional"`
	Cmdline   string `hcl:"cmdline,optional"`
}

// Errors surfaced by Parse.
var (
	// ErrNoEntries means the parsed HCL contained zero `entry` blocks.
	// A boot menu with no choices is never useful — surface it loudly
	// rather than letting the caller dispatch on an empty slice.
	ErrNoEntries = errors.New("bootmenu: HCL config has zero entry blocks")

	// ErrEmptyInput means Parse was handed a zero-length byte slice.
	// Distinct error from a parse failure so the caller (e.g. the
	// phase2 probe) can print a clearer message ("OCI blob was empty"
	// vs. "OCI blob did not parse").
	ErrEmptyInput = errors.New("bootmenu: empty input")

	// ErrDuplicateLabel means two `entry` blocks share the same
	// label. Default would be ambiguous, and the renderer's
	// keystroke-→-label map would be ambiguous too. Surfaced at parse
	// time so misconfigured menus fail closed.
	ErrDuplicateLabel = errors.New("bootmenu: duplicate entry label")

	// ErrDefaultNotFound means the top-level `default = "..."` value
	// does not match any entry's label. Caught here so the runtime
	// doesn't silently fall through to "no auto-boot".
	ErrDefaultNotFound = errors.New("bootmenu: default does not match any entry label")
)

// Parse decodes `hclBytes` into a *BootConfig. The input is expected
// to be native HCL syntax (NOT JSON); the source name "bootconfig.hcl"
// is used only for diagnostic messages.
//
// Validation performed (in order):
//
//  1. Input must be non-empty (ErrEmptyInput).
//  2. HCL syntax must parse (returns the gohcl diagnostics wrapped).
//  3. gohcl.DecodeBody must succeed against the BootConfig schema.
//  4. Every Entry.Label must be unique (ErrDuplicateLabel).
//  5. If Default is set it MUST match an Entry.Label (ErrDefaultNotFound).
//  6. There MUST be at least one entry (ErrNoEntries).
//
// On success the returned *BootConfig is ready for the M9.1 renderer
// and the M9.2 dispatch step.
func Parse(hclBytes []byte) (*BootConfig, error) {
	if len(hclBytes) == 0 {
		return nil, ErrEmptyInput
	}
	parser := hclparse.NewParser()
	file, diags := parser.ParseHCL(hclBytes, "bootconfig.hcl")
	if diags.HasErrors() {
		return nil, fmt.Errorf("bootmenu: HCL syntax error: %s", diags.Error())
	}
	var cfg BootConfig
	if dd := gohcl.DecodeBody(file.Body, nil, &cfg); dd.HasErrors() {
		return nil, fmt.Errorf("bootmenu: HCL decode error: %s", dd.Error())
	}
	if len(cfg.Entries) == 0 {
		return nil, ErrNoEntries
	}
	seen := make(map[string]struct{}, len(cfg.Entries))
	for _, e := range cfg.Entries {
		if _, dup := seen[e.Label]; dup {
			return nil, fmt.Errorf("%w: %q", ErrDuplicateLabel, e.Label)
		}
		seen[e.Label] = struct{}{}
	}
	if cfg.Default != "" {
		if _, ok := seen[cfg.Default]; !ok {
			return nil, fmt.Errorf("%w: default=%q", ErrDefaultNotFound, cfg.Default)
		}
	}
	return &cfg, nil
}

// FindEntry returns the entry whose Label matches `label` (case-
// sensitive). The bool return is false when no entry matches. Provided
// as a convenience for the M9.2 dispatch step (and for tests of the
// Default-lookup path).
func (c *BootConfig) FindEntry(label string) (Entry, bool) {
	for _, e := range c.Entries {
		if e.Label == label {
			return e, true
		}
	}
	return Entry{}, false
}

// _ keeps hcl in the import set even if the file ever loses its
// direct hcl.* reference; without it goimports + future refactors
// could silently drop the dep and the JSON/native-syntax pivot point
// would slip.
var _ hcl.Body = (hcl.Body)(nil)
