// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Package genufs is a thin Go wrapper around the sibling genufs.sh
// script. It exists so that cloud-boot's live-FreeBSD-boot harness
// (internal/livefreebsdboot/run.sh and any Go test that wants to
// own its image refresh) can invoke the image-rebuild step from Go
// without shelling-out boilerplate.
//
// The contract is intentionally minimal:
//
//   - Refresh() runs genufs.sh and returns the absolute path to the
//     freshly-built UFS2 image plus an error on any failure (script
//     exit nonzero, env malformed, etc).
//   - The output path is stable (/tmp/genufs/ufs2-fresh.img by
//     default; overridable via the GENUFS_OUT environment variable
//     so callers can sandbox in CI).
//   - We do NOT cache: every call to Refresh() rebuilds the image
//     so the live test always exercises a fresh oracle. The dockerd
//     layer cache + the cloudboot/makefs:freebsd image are what
//     make the rebuild fast (~3-5 s on a developer laptop).
package genufs

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

// DefaultOutput is the stable path written by genufs.sh when
// GENUFS_OUT is unset. Documented here so callers don't need to
// hard-code "/tmp/genufs/...".
const DefaultOutput = "/tmp/genufs/ufs2-fresh.img"

// Test seams. The real implementations live in this file; tests
// rebind them to fakes so we can exercise the success / failure
// branches of Refresh without pulling in docker + a multi-hundred-
// megabyte FreeBSD ISO.
var (
	scriptPathFn = scriptPath
	commandFn    = exec.Command
	outResolveFn = func() string {
		if out := os.Getenv("GENUFS_OUT"); out != "" {
			return out
		}
		return DefaultOutput
	}
	// callerFn wraps runtime.Caller(0) behind a function pointer so
	// the !ok branch (which runtime.Caller can never trip for a
	// stack frame we just entered) is reachable from a test.
	callerFn = func() (file string, ok bool) {
		_, f, _, ok := runtime.Caller(0)
		return f, ok
	}
)

// Refresh runs the genufs.sh script that lives alongside this Go
// file and returns the absolute path of the produced UFS2 image.
//
// stdout/stderr from the script are streamed to the same fds of
// the calling process so that interactive callers see the build
// progress in real time and CI logs capture failures verbatim.
//
// The returned path is the value of GENUFS_OUT if set in the
// process environment, otherwise DefaultOutput.
func Refresh() (string, error) {
	return refresh(os.Stdout, os.Stderr)
}

// refresh is the dependency-injectable inner form of Refresh,
// exposed at package scope so tests can drive stdout/stderr without
// interfering with the test runner's own streams.
func refresh(stdout, stderr io.Writer) (string, error) {
	scriptPath, err := scriptPathFn()
	if err != nil {
		return "", err
	}
	cmd := commandFn("bash", scriptPath)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("genufs.sh: %w", err)
	}
	return outResolveFn(), nil
}

// scriptPath returns the absolute path to genufs.sh, which is
// expected to live in the same directory as this source file.
// runtime.Caller resolves to the file's compile-time path; this is
// stable for the Go modules + replace-directive layout used in the
// cloud-boot monorepo (no rewriting, no GOROOT-relative tricks).
func scriptPath() (string, error) {
	thisFile, ok := callerFn()
	if !ok {
		return "", fmt.Errorf("genufs: cannot resolve own source path via runtime.Caller")
	}
	dir := filepath.Dir(thisFile)
	p := filepath.Join(dir, "genufs.sh")
	if _, err := os.Stat(p); err != nil {
		return "", fmt.Errorf("genufs: locate script: %w", err)
	}
	return p, nil
}
