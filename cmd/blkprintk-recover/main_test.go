// Host-side tests for the blkprintk-recover helper.
//
// We exercise:
//
//   - successful recovery from a synthetic ring-frame disk file;
//   - the "probe never wrote" path (scratch still carries the magic);
//   - malformed frame surfacing as a decode error;
//   - a missing input file surfacing as an I/O error.

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

func TestRun_RecoversProbeOutput(t *testing.T) {
	// Build a synthetic ring-frame: writeCount=3, payload=banner+\n.
	ring := uefiboard.NewBlkRingBuffer()
	ring.AppendString("phase2-blkprintk: recovered payload\n")
	ring.IncrementWriteCount()
	ring.IncrementWriteCount()
	ring.IncrementWriteCount()
	frame := ring.Serialize()

	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	// Pad to 1 MiB so the recover tool reads as much as is meaningful.
	body := make([]byte, 1024*1024)
	copy(body, frame)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout := captureStdout(t, func() {
		if err := run(path); err != nil {
			t.Fatalf("run: %v", err)
		}
	})
	want := "phase2-blkprintk: recovered payload\n"
	if stdout != want {
		t.Errorf("recovered payload = %q, want %q", stdout, want)
	}
}

func TestRun_UnwrittenScratchSurfacesAsErrProbeNotRun(t *testing.T) {
	// Seed the file with the magic at offset 0 — same shape as the
	// blkprintk-seed tool produces.
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	body := make([]byte, 1024*1024)
	copy(body, uefiboard.BlkPrintkScratchMagic[:])
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := run(path)
	if err == nil {
		t.Fatal("expected error from run() on a scratch with the magic still in place")
	}
	if _, ok := err.(*errProbeNotRun); !ok {
		t.Errorf("expected *errProbeNotRun, got %T (%v)", err, err)
	}
}

func TestRun_MissingFile(t *testing.T) {
	if err := run("/no-such-path-blkprintk-recover-test"); err == nil {
		t.Fatal("expected error from run() on missing file")
	}
}

func TestRun_ShortFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.img")
	if err := os.WriteFile(path, []byte{1, 2, 3}, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := run(path); err == nil {
		t.Fatal("expected error from run() on short file")
	}
}

func TestRun_CorruptFrame(t *testing.T) {
	// Build a synthetic frame whose header claims a payload size
	// larger than capacity — DecodeBlkRingFrame must reject it.
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	body := make([]byte, uefiboard.BlkRingCapacity)
	// Header: writeCount=1, payload=oversized.
	body[0] = 1
	// payload count = capacity + 1 (little-endian uint64).
	body[8] = byte((uefiboard.BlkRingPayloadCapacity + 1) & 0xff)
	body[9] = byte(((uefiboard.BlkRingPayloadCapacity + 1) >> 8) & 0xff)
	body[10] = byte(((uefiboard.BlkRingPayloadCapacity + 1) >> 16) & 0xff)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	err := run(path)
	if err == nil {
		t.Fatal("expected error from run() on corrupt frame")
	}
	if _, isUnwritten := err.(*errProbeNotRun); isUnwritten {
		t.Errorf("error should NOT be *errProbeNotRun (frame is corrupt, not unwritten): %v", err)
	}
}

func TestMagicAtOffset0_ShortFrame(t *testing.T) {
	if magicAtOffset0([]byte{1, 2, 3}) {
		t.Error("magicAtOffset0 should be false for too-short frame")
	}
}

func TestMagicAtOffset0_MatchingFrame(t *testing.T) {
	body := make([]byte, 64)
	copy(body, uefiboard.BlkPrintkScratchMagic[:])
	if !magicAtOffset0(body) {
		t.Error("magicAtOffset0 should be true for matching frame")
	}
}

func TestMagicAtOffset0_NonMatchingFrame(t *testing.T) {
	body := make([]byte, 64)
	body[0] = 0xff
	if magicAtOffset0(body) {
		t.Error("magicAtOffset0 should be false for non-matching frame")
	}
}

func TestRunMain_UsageExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain("", &stdout, &stderr)
	if code != 2 {
		t.Errorf("runMain(\"\") = %d, want 2", code)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("usage")) {
		t.Errorf("stderr missing 'usage': %q", stderr.String())
	}
}

func TestRunMain_SuccessExitCode(t *testing.T) {
	ring := uefiboard.NewBlkRingBuffer()
	ring.AppendString("hello\n")
	ring.IncrementWriteCount()
	frame := ring.Serialize()
	body := make([]byte, 1024*1024)
	copy(body, frame)
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runMain(path, &stdout, &stderr)
	if code != 0 {
		t.Errorf("runMain success exit code = %d, want 0; stderr=%q", code, stderr.String())
	}
	if stdout.String() != "hello\n" {
		t.Errorf("stdout = %q, want %q", stdout.String(), "hello\n")
	}
}

func TestRunMain_UnwrittenScratchExitCode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "scratch.img")
	body := make([]byte, 1024*1024)
	copy(body, uefiboard.BlkPrintkScratchMagic[:])
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	var stdout, stderr bytes.Buffer
	code := runMain(path, &stdout, &stderr)
	if code != 3 {
		t.Errorf("runMain unwritten-scratch exit code = %d, want 3", code)
	}
}

func TestRunMain_GenericFailureExitCode(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runMain("/no-such-path-blkprintk-recover-runmain", &stdout, &stderr)
	if code != 1 {
		t.Errorf("runMain missing-file exit code = %d, want 1", code)
	}
}

func TestErrProbeNotRunMessage(t *testing.T) {
	err := &errProbeNotRun{path: "/tmp/foo"}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("/tmp/foo")) ||
		!bytes.Contains([]byte(got), []byte("R-M1'a")) {
		t.Errorf("errProbeNotRun.Error() = %q, expected path + R-M1'a", got)
	}
}

// captureStdout swaps os.Stdout for a pipe while fn runs, then
// returns the captured text. Used to verify the recover tool prints
// the payload to stdout, not stderr.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	done := make(chan struct{})
	var buf bytes.Buffer
	go func() {
		_, _ = buf.ReadFrom(r)
		close(done)
	}()
	fn()
	w.Close()
	<-done
	os.Stdout = old
	return buf.String()
}
