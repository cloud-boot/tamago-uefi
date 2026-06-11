// Copyright (c) 2026, cloud-boot
// SPDX-License-Identifier: BSD-3-Clause
//
// inspect_boot is a tiny helper (sibling of verify) that enumerates
// /boot and /boot/kernel and prints sizes. Useful to plan the
// minimal fixture: we want to know which files the loader really
// needs vs. what we can drop.

//go:build inspect && !export

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	ufs "github.com/go-filesystems/ufs"
)

func main() {
	path := flag.String("img", "freebsd-ufs2-full.img", "image")
	flag.Parse()
	fs, err := ufs.OpenFile(*path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer fs.Close()
	for _, dir := range []string{"/boot", "/boot/kernel", "/boot/defaults"} {
		fmt.Printf("\n== %s ==\n", dir)
		entries, err := fs.ListDir(dir)
		if err != nil {
			fmt.Printf("(error: %v)\n", err)
			continue
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, e := range entries {
			n := e.Name()
			if n == "." || n == ".." {
				continue
			}
			full := dir + "/" + n
			st, err := fs.Stat(full)
			if err != nil {
				fmt.Printf("%-40s ?\n", n)
				continue
			}
			fmt.Printf("%-40s %d\n", n, st.Size())
		}
	}
}
