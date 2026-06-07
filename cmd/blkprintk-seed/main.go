// blkprintk-seed — host-side helper that creates / re-initialises the
// dedicated scratch disk image consumed by the Phase-2 M1.6 Block-IO
// side-channel probe.
//
// Usage:
//
//	blkprintk-seed -out scratch.img [-size-mib 1]
//
// The output is a raw disk image whose LBA 0 begins with
// `uefiboard.BlkPrintkScratchMagic` (the 16-byte sentinel the probe
// recognises) and is zero-filled for the remainder. The probe reads
// LBA 0 of each writable bare-disk handle the firmware exposes and
// writes its captured-output frame ONLY to the disk whose LBA 0
// matches that sentinel — so the probe will not clobber the ESP /
// boot-disk on hypervisors that expose them with
// `LogicalPartition == 0`.
//
// 1 MiB is plenty for the 32 KiB ring; we leave headroom for future
// per-arch frames stacked at LBA 64, LBA 128, etc.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// usageError is returned by parseArgs when the caller passed bad
// flag values; runMain maps it to exit code 2.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

// parseArgs validates the CLI flags. Returns the validated (path,
// sizeBytes) pair or an error. Extracted from runMain so the test
// suite can exercise the validation logic without writing a file.
func parseArgs(out string, sizeMiB int) (string, int64, error) {
	if out == "" {
		return "", 0, &usageError{msg: "usage: blkprintk-seed -out <path> [-size-mib <n>]"}
	}
	if sizeMiB <= 0 {
		return "", 0, &usageError{msg: "blkprintk-seed: -size-mib must be positive"}
	}
	return out, int64(sizeMiB) * 1024 * 1024, nil
}

// runMain is the testable body of main(). It returns the exit code
// it would have called os.Exit with; main() just propagates that.
// `stdout` and `stderr` are exposed so the test suite can capture
// output without swapping `os.Stdout` / `os.Stderr` globally.
func runMain(out string, sizeMiB int, stdout, stderr io.Writer) int {
	path, sz, err := parseArgs(out, sizeMiB)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if err := seed(path, sz); err != nil {
		fmt.Fprintln(stderr, "blkprintk-seed:", err)
		return 1
	}
	fmt.Fprintf(stdout, "blkprintk-seed: wrote %d-byte scratch image with magic at LBA 0 to %s\n",
		sz, path)
	return 0
}

func main() {
	out := flag.String("out", "", "output scratch disk image path (required)")
	sizeMiB := flag.Int("size-mib", 1, "scratch disk size in MiB")
	flag.Parse()
	os.Exit(runMain(*out, *sizeMiB, os.Stdout, os.Stderr))
}

// seed creates `path` with size `sizeBytes`, writes the
// BlkPrintkScratchMagic at offset 0, and zero-fills the rest. The
// underlying OS guarantees zero bytes for sparse-tail regions on
// darwin/linux, so a single Write + Truncate + Sync suffices.
func seed(path string, sizeBytes int64) error {
	if sizeBytes < int64(len(uefiboard.BlkPrintkScratchMagic)) {
		return errors.New("scratch size smaller than magic-marker length")
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(uefiboard.BlkPrintkScratchMagic[:]); err != nil {
		return err
	}
	if err := f.Truncate(sizeBytes); err != nil {
		return err
	}
	// Force kernel buffer flush so subsequent QEMU/vfkit runs see the
	// magic.
	return f.Sync()
}
