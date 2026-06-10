// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tamago

// Linter-style check: surfaces accidental `time.Sleep` calls in
// single-goroutine tamago probe paths so future code doesn't silently
// regress into the R-M9.2a / R-M8.3b blocking-time.Sleep failure mode.
//
// What counts as a "single-G probe path":
//
//   - `phase2_*.go` files at the repository root (the phase-2 probe
//     entry points; each one runs as `package main`'s sole top-level
//     goroutine after the cpuinit hand-off).
//
// What is explicitly EXEMPT:
//
//   - `uefiboard/ministack/*.go` — ministack runs the rxLoop goroutine
//     alongside the caller, so the timer wheel IS being driven and
//     `time.Sleep` inside an rxLoop yield (rxLoopIdleSleep) or a
//     ministack helper that runs concurrently with rxLoop is safe.
//   - `*_test.go` files — host-side tests run under the standard Go
//     runtime where time.Sleep works as designed.
//   - `*_host.go` / `dtb_*_host.go` — host-only build-tagged shims.
//
// Implementation: scan the file set with `go/parser` + `go/ast`,
// emit a `t.Errorf` per offending call so the failing list is
// human-readable.

package uefiboard_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoTimeSleepInPhase2Probes scans every phase2_*.go file at the
// repository root and fails if it finds a `time.Sleep` call.
// `busyWait` is the correct replacement; see uefiboard/doc.go and
// R-M9.2a in docs/tamago-uefi-phase2-oci-loader.md.
func TestNoTimeSleepInPhase2Probes(t *testing.T) {
	// Walk up from CWD to the repo root (first ancestor containing
	// go.mod). Test binaries live in <repo>/uefiboard so this is one
	// dirname up in the normal case, but be defensive about it.
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}

	entries, err := os.ReadDir(repoRoot)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", repoRoot, err)
	}
	var probes []string
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "phase2_") {
			continue
		}
		if !strings.HasSuffix(name, ".go") {
			continue
		}
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		if strings.HasSuffix(name, "_stub.go") {
			// stub files are host-side shims (no probe runtime in
			// the build closure); time.Sleep there is unreachable
			// from the tamago single-G path.
			continue
		}
		probes = append(probes, filepath.Join(repoRoot, name))
	}
	if len(probes) == 0 {
		t.Fatal("found zero phase2_*.go probe files; scan path wrong?")
	}

	fset := token.NewFileSet()
	hits := 0
	for _, path := range probes {
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Errorf("parse %s: %v", path, err)
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if pkg.Name == "time" && sel.Sel.Name == "Sleep" {
				pos := fset.Position(call.Pos())
				t.Errorf("%s:%d: time.Sleep call in single-G probe path — use busyWait instead (see uefiboard/doc.go)", pos.Filename, pos.Line)
				hits++
			}
			return true
		})
	}
	if hits == 0 {
		t.Logf("scanned %d phase2 probe files; no time.Sleep calls — good.", len(probes))
	}
}

// findRepoRoot walks up from the current working directory until it
// finds a directory containing `go.mod`, returning that path. Returns
// an error if no ancestor matches before reaching "/".
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", os.ErrNotExist
		}
		dir = parent
	}
}
