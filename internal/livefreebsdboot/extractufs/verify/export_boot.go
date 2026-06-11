// Copyright (c) 2026, cloud-boot
// SPDX-License-Identifier: BSD-3-Clause
//
// export_boot walks /boot recursively in the source UFS2 image and
// writes the file tree out to a host directory (or a uncompressed tar
// stream on stdout when -tar is passed).
//
// This bridges the extractufs sprint (this package) to the genufs
// sprint (sibling 2C-C): genufs will build a tiny fresh UFS2 from
// these files, producing the streaming-friendly fixture that
// cloud-boot's live test consumes. We CAN'T do that here because
// makefs / a Go UFS2 writer is exactly what 2C-C ships.

//go:build export

package main

import (
	"archive/tar"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	filesystem "github.com/go-filesystems/interface"
	ufs "github.com/go-filesystems/ufs"
)

func main() {
	img := flag.String("img", "freebsd-ufs2-full.img", "source UFS image")
	root := flag.String("root", "/boot", "subtree to export")
	outDir := flag.String("out", "", "host directory to write tree into (mutually exclusive with -tar)")
	tarOut := flag.Bool("tar", false, "stream a tar to stdout instead of writing a directory")
	flag.Parse()
	if (*outDir == "") == !*tarOut {
		fmt.Fprintln(os.Stderr, "exactly one of -out or -tar must be set")
		os.Exit(2)
	}
	fs, err := ufs.OpenFile(*img)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer fs.Close()

	var tw *tar.Writer
	if *tarOut {
		tw = tar.NewWriter(os.Stdout)
		defer tw.Close()
	}

	if err := walk(fs, *root, *outDir, tw); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(3)
	}
}

func walk(fs *ufs.FS, srcPath, dstDir string, tw *tar.Writer) error {
	entries, err := fs.ListDir(srcPath)
	if err != nil {
		return fmt.Errorf("list %s: %w", srcPath, err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == "." || name == ".." {
			continue
		}
		full := strings.TrimRight(srcPath, "/") + "/" + name
		st, err := fs.Stat(full)
		if err != nil {
			return fmt.Errorf("stat %s: %w", full, err)
		}
		mode := st.Mode()
		isDir := mode&0o170000 == 0o040000
		if isDir {
			if dstDir != "" {
				if err := os.MkdirAll(filepath.Join(dstDir, full), 0o755); err != nil {
					return err
				}
			}
			if tw != nil {
				if err := tw.WriteHeader(&tar.Header{
					Name:     strings.TrimPrefix(full, "/") + "/",
					Mode:     int64(mode & 0o7777),
					Typeflag: tar.TypeDir,
				}); err != nil {
					return err
				}
			}
			if err := walk(fs, full, dstDir, tw); err != nil {
				return err
			}
			continue
		}
		if !isRegular(mode) {
			// Skip symlinks/devices for now; loader.conf et al. are
			// regular files, kernel modules are regular files.
			continue
		}
		data, err := fs.ReadFile(full)
		if err != nil {
			return fmt.Errorf("read %s: %w", full, err)
		}
		if dstDir != "" {
			out := filepath.Join(dstDir, full)
			if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(out, data, 0o644); err != nil {
				return err
			}
		}
		if tw != nil {
			if err := tw.WriteHeader(&tar.Header{
				Name:     strings.TrimPrefix(full, "/"),
				Mode:     int64(mode & 0o7777),
				Size:     int64(len(data)),
				Typeflag: tar.TypeReg,
			}); err != nil {
				return err
			}
			if _, err := io.Copy(tw, strings.NewReader(string(data))); err != nil {
				return err
			}
		}
		_ = st.Inode()
	}
	return nil
}

func isRegular(mode uint16) bool { return mode&0o170000 == 0o100000 }

// Compile-time use of filesystem package to satisfy `go vet`.
var _ filesystem.DirEntry = (filesystem.DirEntry)(nil)
