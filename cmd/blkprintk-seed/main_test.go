// Host-side tests for the blkprintk-seed helper.
//
// Three properties matter: (1) the file exists with the right size
// after `seed`; (2) the first 16 bytes are exactly
// BlkPrintkScratchMagic; (3) the remainder is zero-filled. We also
// confirm error paths: size below the magic-marker length must
// surface as an error, and a write target the OS refuses must
// propagate.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func TestSeed_Standard(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	const sz = 1024 * 1024
	if err := seed(path, sz); err != nil {
		t.Fatalf("seed: %v", err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after seed: %v", err)
	}
	if st.Size() != sz {
		t.Errorf("seeded file size = %d, want %d", st.Size(), sz)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read seeded file: %v", err)
	}
	if got := body[:16]; !bytes.Equal(got, uefiboard.BlkPrintkScratchMagic[:]) {
		t.Errorf("magic at offset 0 = % x, want % x", got, uefiboard.BlkPrintkScratchMagic[:])
	}
	for i := 16; i < len(body); i++ {
		if body[i] != 0 {
			t.Errorf("body[%d] = 0x%02x, want 0x00 (zero-fill)", i, body[i])
			break
		}
	}
}

func TestSeed_TooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.img")
	if err := seed(path, 8); err == nil {
		t.Fatal("seed with size < magic length should fail")
	}
}

func TestSeed_BadPath(t *testing.T) {
	// /nonexistent-dir/... is not creatable by a regular user.
	if err := seed("/nonexistent-dir-XYZ-blkprintk-seed/scratch.img", 1024*1024); err == nil {
		t.Fatal("seed to non-writable path should fail")
	}
}

func TestParseArgs(t *testing.T) {
	t.Run("empty out triggers usage error", func(t *testing.T) {
		_, _, err := parseArgs("", 1)
		if err == nil {
			t.Fatal("expected error on empty out")
		}
		if _, ok := err.(*usageError); !ok {
			t.Errorf("expected *usageError, got %T", err)
		}
	})
	t.Run("zero size triggers usage error", func(t *testing.T) {
		_, _, err := parseArgs("/tmp/foo", 0)
		if err == nil {
			t.Fatal("expected error on zero size")
		}
		if _, ok := err.(*usageError); !ok {
			t.Errorf("expected *usageError, got %T", err)
		}
	})
	t.Run("negative size triggers usage error", func(t *testing.T) {
		_, _, err := parseArgs("/tmp/foo", -1)
		if err == nil {
			t.Fatal("expected error on negative size")
		}
	})
	t.Run("valid args return scaled bytes", func(t *testing.T) {
		out, sz, err := parseArgs("/tmp/foo.img", 4)
		if err != nil {
			t.Fatalf("parseArgs: %v", err)
		}
		if out != "/tmp/foo.img" {
			t.Errorf("out = %q, want /tmp/foo.img", out)
		}
		if sz != 4*1024*1024 {
			t.Errorf("sz = %d, want %d", sz, 4*1024*1024)
		}
	})
}

func TestUsageError(t *testing.T) {
	err := &usageError{msg: "hello"}
	if got := err.Error(); got != "hello" {
		t.Errorf("usageError.Error() = %q, want %q", got, "hello")
	}
}

func TestRunMain_SuccessExitCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	var stdout, stderr bytes.Buffer
	code := runMain(path, 1, &stdout, &stderr)
	if code != 0 {
		t.Errorf("runMain exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	if !bytes.Contains(stdout.Bytes(), []byte("wrote 1048576-byte")) {
		t.Errorf("stdout missing summary line: %q", stdout.String())
	}
}

func TestRunMain_UsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain("", 1, &stdout, &stderr)
	if code != 2 {
		t.Errorf("runMain (empty -out) = %d, want 2", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("usage")) {
		t.Errorf("stderr missing 'usage': %q", stderr.String())
	}
}

func TestRunMain_SeedFailureExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain("/nonexistent-dir-XYZ-blkprintk-seed/scratch.img", 1, &stdout, &stderr)
	if code != 1 {
		t.Errorf("runMain (bad path) = %d, want 1", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("blkprintk-seed:")) {
		t.Errorf("stderr missing 'blkprintk-seed:': %q", stderr.String())
	}
}
