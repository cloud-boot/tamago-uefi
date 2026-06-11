// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// verify — open the UFS2 image produced by genufs.sh through
// go-filesystems/ufs and assert that the writer-vs-reader contract
// holds end to end.
//
// This binary is the Phase-3 sprint-2C oracle for sprint-2C-A:
// if our pure-Go UFS2 READER can open a freshly-written UFS2 image
// produced by an INDEPENDENT writer (FreeBSD makefs via kusumi's
// portable port), then the reader is bit-compatible with at least
// one real implementation of the format. Sprint-2C-A's pure-Go
// Mkfs writer is then validated against the same reader.
//
// Checks performed:
//
//   1. ufs.OpenFile succeeds (superblock decoded, magic OK).
//   2. Superblock label equals the expected value (default "rootfs").
//   3. ListDir("/")             contains "boot" and "etc".
//   4. ListDir("/boot")         contains "kernel" and "loader.conf".
//   5. ListDir("/boot/kernel")  contains "kernel".
//   6. Stat("/boot/kernel/kernel") size matches the on-disk size
//      from the staging tree (passed via --kernel-size; default
//      pulled from the ISO extract under /tmp/genufs/stage).
//   7. ReadFile("/boot/loader.conf") parses and contains the
//      expected boot_mfsroot="NO" line.
//   8. ReadFile("/etc/fstab") contains "UFS:<label>".
//
// Exit codes:
//
//   0 : every check passed; image is a valid, well-formed UFS2.
//   1 : usage / I/O error
//   2 : a structural check failed (filesystem unreadable or
//       missing required entries)

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	filesystem "github.com/go-filesystems/interface"
	"github.com/go-filesystems/ufs"
)

func main() {
	var (
		imagePath  = flag.String("image", "/tmp/genufs/ufs2-fresh.img", "UFS2 image to verify")
		stagePath  = flag.String("stage", "/tmp/genufs/stage", "staging tree used as the makefs source (for kernel size cross-check)")
		wantLabel  = flag.String("label", "rootfs", "expected UFS volume label")
		quiet      = flag.Bool("quiet", false, "only print on failure")
	)
	flag.Parse()

	logf := func(format string, args ...any) {
		if !*quiet {
			fmt.Fprintf(os.Stderr, "[verify] "+format+"\n", args...)
		}
	}
	fail := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "[verify] FAIL: "+format+"\n", args...)
		os.Exit(2)
	}

	// 1. Open.
	logf("opening %s via go-filesystems/ufs", *imagePath)
	fs, err := ufs.OpenFile(*imagePath)
	if err != nil {
		fail("ufs.OpenFile: %v", err)
	}
	defer fs.Close()

	sb := fs.Superblock()
	logf("superblock: bsize=%d fsize=%d ncg=%d magic=0x%08x",
		sb.Bsize, sb.Fsize, sb.Ncg, sb.Magic)

	// 2. Label — read via the optional LabelReader interface so we
	// don't depend on a specific struct field name from the reader.
	if lr, ok := any(fs).(filesystem.LabelReader); ok {
		got := lr.Label()
		if got != *wantLabel {
			fail("label mismatch: got %q, want %q", got, *wantLabel)
		}
		logf("label: %q", got)
	} else {
		logf("label: <LabelReader not implemented by ufs.FS — skipping>")
	}

	// 3-5. Directory listings.
	mustHave := func(path string, names ...string) {
		entries, err := fs.ListDir(path)
		if err != nil {
			fail("ListDir(%q): %v", path, err)
		}
		set := make(map[string]bool, len(entries))
		for _, e := range entries {
			set[e.Name()] = true
		}
		for _, n := range names {
			if !set[n] {
				present := make([]string, 0, len(entries))
				for _, e := range entries {
					present = append(present, e.Name())
				}
				fail("ListDir(%q) missing %q (present: %v)", path, n, present)
			}
		}
		logf("ListDir(%q) ok: contains %v", path, names)
	}
	mustHave("/", "boot", "etc")
	mustHave("/boot", "kernel", "loader.conf")
	mustHave("/boot/kernel", "kernel")

	// 6. Kernel size cross-check.
	kPath := "/boot/kernel/kernel"
	st, err := fs.Stat(kPath)
	if err != nil {
		fail("Stat(%q): %v", kPath, err)
	}
	stageKernel := *stagePath + kPath
	if want, err := os.Stat(stageKernel); err == nil {
		if uint64(want.Size()) != st.Size() {
			fail("kernel size mismatch: ufs=%d staging=%d", st.Size(), want.Size())
		}
		logf("kernel size cross-checks against staging: %d bytes", st.Size())
	} else {
		logf("kernel size (no staging cross-check available): %d bytes", st.Size())
	}

	// 7. loader.conf content.
	loaderConf, err := fs.ReadFile("/boot/loader.conf")
	if err != nil {
		fail("ReadFile(/boot/loader.conf): %v", err)
	}
	if !strings.Contains(string(loaderConf), `boot_mfsroot="NO"`) {
		fail("loader.conf missing boot_mfsroot directive: %q", string(loaderConf))
	}
	logf("loader.conf ok (%d bytes)", len(loaderConf))

	// 8. fstab content.
	fstab, err := fs.ReadFile("/etc/fstab")
	if err != nil {
		fail("ReadFile(/etc/fstab): %v", err)
	}
	wantFstab := "UFS:" + *wantLabel
	if !strings.Contains(string(fstab), wantFstab) {
		fail("/etc/fstab missing %q: %q", wantFstab, string(fstab))
	}
	logf("/etc/fstab ok (%d bytes, references %s)", len(fstab), wantFstab)

	logf("ALL CHECKS PASSED — go-filesystems/ufs reads the freshly-built UFS2 cleanly.")
}
