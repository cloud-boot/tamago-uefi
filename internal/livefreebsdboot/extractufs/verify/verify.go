// Copyright (c) 2026, cloud-boot
// SPDX-License-Identifier: BSD-3-Clause

// Verify opens the extracted FreeBSD UFS2 partition with
// github.com/go-filesystems/ufs and prints a short report:
//
//   - superblock magic + block size
//   - listing of /boot/kernel
//   - stat of /boot/kernel/kernel
//   - presence + first line of /boot/loader.conf if available
//
// Exits non-zero on any failure so the script can be wired into CI.

//go:build !inspect && !export

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	ufs "github.com/go-filesystems/ufs"
)

func main() {
	path := flag.String("img", "freebsd-ufs2-full.img", "path to extracted UFS2 image")
	flag.Parse()

	fs, err := ufs.OpenFile(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", *path, err)
		os.Exit(1)
	}
	defer fs.Close()
	sb := fs.Superblock()
	fmt.Printf("superblock: bsize=%d fsize=%d ncg=%d magic=ok\n",
		sb.Bsize, sb.Fsize, sb.Ncg)

	entries, err := fs.ListDir("/boot/kernel")
	if err != nil {
		fmt.Fprintf(os.Stderr, "ListDir /boot/kernel: %v\n", err)
		os.Exit(2)
	}
	var foundKernel bool
	fmt.Printf("/boot/kernel: %d entries\n", len(entries))
	for _, e := range entries {
		if e.Name() == "kernel" {
			foundKernel = true
		}
	}
	if !foundKernel {
		fmt.Fprintln(os.Stderr, "/boot/kernel/kernel NOT FOUND in directory listing")
		os.Exit(3)
	}

	st, err := fs.Stat("/boot/kernel/kernel")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Stat /boot/kernel/kernel: %v\n", err)
		os.Exit(4)
	}
	fmt.Printf("/boot/kernel/kernel: size=%d bytes mode=0%o\n", st.Size(), st.Mode())

	// /boot/loader.conf is optional but worth reporting.
	if data, err := fs.ReadFile("/boot/loader.conf"); err == nil {
		line := strings.SplitN(string(data), "\n", 2)[0]
		fmt.Printf("/boot/loader.conf: %d bytes; first line: %q\n", len(data), line)
	} else {
		fmt.Printf("/boot/loader.conf: not present (%v) — fine for fixture\n", err)
	}

	fmt.Println("OK — go-filesystems/ufs successfully read the extracted partition")
}
