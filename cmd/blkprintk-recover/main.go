// blkprintk-recover — host-side post-halt helper that reads the
// dedicated scratch disk image written by the Phase-2 M1.6 Block-IO
// side-channel probe and prints the captured probe output.
//
// Usage:
//
//	blkprintk-recover -in scratch.img
//
// Reads bytes [0..BlkRingCapacity) (32 KiB) of the file, validates the
// 16-byte BlkPrintkScratchMagic at the front is GONE (the probe
// overwrites it with the ring frame on every successful Flush), then
// uses uefiboard.DecodeBlkRingFrame to extract the (writeCount,
// payload) pair and dumps `payload` to stdout.
//
// Exit codes:
//
//	0 — successful recovery; payload printed to stdout.
//	1 — file open / read / decode failure (error to stderr).
//	2 — usage error.
//	3 — the file still carries the BlkPrintkScratchMagic at offset 0,
//	    meaning the probe never wrote anything (R-M1'a NOT resolved on
//	    this hypervisor / configuration).

package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// runMain is the testable body of main(). It returns the exit code
// it would have called os.Exit with; main() just propagates that.
// `stdout` and `stderr` are exposed so the test suite can capture
// output without globally swapping os.Stdout / os.Stderr.
func runMain(in string, stdout, stderr io.Writer) int {
	if in == "" {
		fmt.Fprintln(stderr, "usage: blkprintk-recover -in <path>")
		return 2
	}
	err := runStreams(in, stdout, stderr)
	if err == nil {
		return 0
	}
	fmt.Fprintln(stderr, "blkprintk-recover:", err)
	if _, isUnwritten := err.(*errProbeNotRun); isUnwritten {
		return 3
	}
	return 1
}

func main() {
	in := flag.String("in", "", "scratch disk image to recover from (required)")
	flag.Parse()
	os.Exit(runMain(*in, os.Stdout, os.Stderr))
}

type errProbeNotRun struct{ path string }

func (e *errProbeNotRun) Error() string {
	return "scratch disk at " + e.path + " still carries the BlkPrintkScratchMagic — the probe never wrote to it (R-M1'a NOT resolved)"
}

// run reads `path`, validates the frame, prints the payload to
// stdout, and prints a one-line summary to stderr. Kept around as a
// shim for the existing tests; new tests use runStreams directly.
func run(path string) error {
	return runStreams(path, os.Stdout, os.Stderr)
}

// runStreams is the io.Writer-injected core. Stdout receives the
// recovered payload bytes verbatim; stderr receives the one-line
// summary. Errors include the unwritten-scratch case as
// *errProbeNotRun so the host launcher can exit 3.
func runStreams(path string, stdout, stderr io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	frame := make([]byte, uefiboard.BlkRingCapacity)
	if _, err := io.ReadFull(f, frame); err != nil {
		return err
	}
	if magicAtOffset0(frame) {
		return &errProbeNotRun{path: path}
	}
	writeCount, payload, err := uefiboard.DecodeBlkRingFrame(frame)
	if err != nil {
		return err
	}
	fmt.Fprintf(stderr, "blkprintk-recover: writeCount=%d payloadBytes=%d\n",
		writeCount, len(payload))
	_, err = stdout.Write(payload)
	return err
}

func magicAtOffset0(frame []byte) bool {
	if len(frame) < len(uefiboard.BlkPrintkScratchMagic) {
		return false
	}
	for i, b := range uefiboard.BlkPrintkScratchMagic {
		if frame[i] != b {
			return false
		}
	}
	return true
}
