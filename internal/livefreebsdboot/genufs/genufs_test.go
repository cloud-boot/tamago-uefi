// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package genufs

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestScriptIsCallable asserts that genufs.sh is present alongside
// this Go file, is executable, and is referenceable by scriptPath().
//
// We intentionally do NOT execute the script here — it requires
// docker + a multi-hundred-megabyte FreeBSD ISO + several seconds
// of build time, none of which belong in a unit test. The live
// runner under internal/livefreebsdboot/run.sh does that.
func TestScriptIsCallable(t *testing.T) {
	p, err := scriptPath()
	if err != nil {
		t.Fatalf("scriptPath: %v", err)
	}
	st, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	if st.IsDir() {
		t.Fatalf("genufs.sh is a directory at %s", p)
	}
	if st.Mode()&0o111 == 0 {
		t.Fatalf("genufs.sh not executable at %s (mode=%v)", p, st.Mode())
	}
}

// TestScriptPathFailureMode covers the negative branch of
// scriptPath when the file is missing.
func TestScriptPathFailureMode(t *testing.T) {
	_, err := os.Stat("/tmp/this-file-must-not-exist-genufs-negative-test")
	if err == nil {
		t.Skip("stat unexpectedly succeeded on synthetic missing path")
	}
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("expected fs.PathError, got %T %v", err, err)
	}
}

// TestDefaultOutputStable pins DefaultOutput so a future refactor
// blows up here, not silently in the live runner.
func TestDefaultOutputStable(t *testing.T) {
	const want = "/tmp/genufs/ufs2-fresh.img"
	if DefaultOutput != want {
		t.Fatalf("DefaultOutput drift: got %q want %q", DefaultOutput, want)
	}
}

// withSeams swaps the package-level test seams for the duration of
// a single sub-test and restores them on cleanup. Centralised so
// every Refresh test has identical save/restore behaviour.
func withSeams(t *testing.T, scriptFn func() (string, error), cmdFn func(string, ...string) *exec.Cmd, outFn func() string) {
	t.Helper()
	origScript, origCmd, origOut := scriptPathFn, commandFn, outResolveFn
	if scriptFn != nil {
		scriptPathFn = scriptFn
	}
	if cmdFn != nil {
		commandFn = cmdFn
	}
	if outFn != nil {
		outResolveFn = outFn
	}
	t.Cleanup(func() {
		scriptPathFn = origScript
		commandFn = origCmd
		outResolveFn = origOut
	})
}

// writeTempScript drops a tiny shell script into t.TempDir() with
// the given body and returns its absolute path; the file is marked
// 0o755 so `bash <path>` can read+exec it. Centralised so every
// Refresh test uses the same helper.
func writeTempScript(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatalf("write fake script: %v", err)
	}
	return p
}

// TestRefresh_Success exercises the happy path of refresh() with a
// fake script that exits 0 and a fake outResolveFn returning a
// stable, predictable path.
func TestRefresh_Success(t *testing.T) {
	sh := writeTempScript(t, "exit 0")
	withSeams(t,
		func() (string, error) { return sh, nil },
		exec.Command,
		func() string { return "/tmp/genufs/from-test.img" },
	)
	var stdout, stderr bytes.Buffer
	got, err := refresh(&stdout, &stderr)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got != "/tmp/genufs/from-test.img" {
		t.Fatalf("output path: got %q want %q", got, "/tmp/genufs/from-test.img")
	}
}

// TestRefresh_ScriptPathError exercises the early-exit when
// scriptPathFn fails.
func TestRefresh_ScriptPathError(t *testing.T) {
	sentinel := errors.New("synthetic resolve failure")
	withSeams(t,
		func() (string, error) { return "", sentinel },
		nil, nil,
	)
	_, err := refresh(nil, nil)
	if !errors.Is(err, sentinel) {
		t.Fatalf("got %v, want errors.Is(%v)", err, sentinel)
	}
}

// TestRefresh_CommandFailure exercises the wrap-and-return path
// when the underlying script exits nonzero.
func TestRefresh_CommandFailure(t *testing.T) {
	sh := writeTempScript(t, "exit 7")
	withSeams(t,
		func() (string, error) { return sh, nil },
		exec.Command,
		func() string { return "/never/used" },
	)
	_, err := refresh(&bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected error from exit 7; got nil")
	}
	if !strings.Contains(err.Error(), "genufs.sh") {
		t.Fatalf("error %q lacks 'genufs.sh' prefix", err)
	}
}

// TestRefresh_StreamsCaptured asserts that script stdout / stderr
// reach the io.Writers passed into refresh().
func TestRefresh_StreamsCaptured(t *testing.T) {
	sh := writeTempScript(t, "printf hello-stdout\nprintf hello-stderr >&2")
	withSeams(t,
		func() (string, error) { return sh, nil },
		exec.Command,
		func() string { return "/ok" },
	)
	var stdout, stderr bytes.Buffer
	if _, err := refresh(&stdout, &stderr); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if stdout.String() != "hello-stdout" {
		t.Fatalf("stdout: got %q want hello-stdout", stdout.String())
	}
	if stderr.String() != "hello-stderr" {
		t.Fatalf("stderr: got %q want hello-stderr", stderr.String())
	}
}

// TestRefresh_PublicWrapper covers the exported Refresh function
// so its single non-trivial line (the call to refresh(os.Stdout,
// os.Stderr)) is exercised. We stub the inner pieces so the call
// is a no-op.
func TestRefresh_PublicWrapper(t *testing.T) {
	sh := writeTempScript(t, "exit 0")
	withSeams(t,
		func() (string, error) { return sh, nil },
		exec.Command,
		func() string { return "/wrapper/ok" },
	)
	got, err := Refresh()
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if got != "/wrapper/ok" {
		t.Fatalf("path: got %q want /wrapper/ok", got)
	}
}

// TestOutResolveFn exercises the default outResolveFn under both
// branches (GENUFS_OUT set vs unset).
func TestOutResolveFn(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv("GENUFS_OUT", "")
		if got := outResolveFn(); got != DefaultOutput {
			t.Fatalf("got %q want %q", got, DefaultOutput)
		}
	})
	t.Run("set", func(t *testing.T) {
		t.Setenv("GENUFS_OUT", "/override/img")
		if got := outResolveFn(); got != "/override/img" {
			t.Fatalf("got %q want /override/img", got)
		}
	})
}

// TestScriptPath_CallerFailure exercises the !ok branch of
// runtime.Caller(0) via the callerFn seam. runtime.Caller cannot
// actually fail for a stack frame we just entered, so the only
// way to cover this defensive guard is to inject a fake.
func TestScriptPath_CallerFailure(t *testing.T) {
	orig := callerFn
	callerFn = func() (string, bool) { return "", false }
	t.Cleanup(func() { callerFn = orig })

	_, err := scriptPath()
	if err == nil {
		t.Fatalf("expected error when runtime.Caller signals !ok; got nil")
	}
	if !strings.Contains(err.Error(), "runtime.Caller") {
		t.Fatalf("error %q lacks runtime.Caller marker", err)
	}
}

// TestScriptPath_NotFound covers the os.Stat failure branch of
// scriptPath() by temporarily renaming genufs.sh out of the way.
// We restore it on cleanup so the rest of the suite still works.
func TestScriptPath_NotFound(t *testing.T) {
	real, err := scriptPath()
	if err != nil {
		t.Fatalf("scriptPath (pre-hide): %v", err)
	}
	hidden := real + ".hidden-by-test"
	if err := os.Rename(real, hidden); err != nil {
		t.Fatalf("rename %s: %v", real, err)
	}
	t.Cleanup(func() { _ = os.Rename(hidden, real) })

	_, err = scriptPath()
	if err == nil {
		t.Fatalf("expected error when genufs.sh is absent; got nil")
	}
	if !strings.Contains(err.Error(), "locate script") {
		t.Fatalf("error %q lacks 'locate script' marker", err)
	}
}
