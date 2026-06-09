// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Decompress returns the bytes of the chained EFI payload embedded
// into this binary. The on-disk embed (chained_<arch>.efi.gz) is
// gzip-compressed at build time to keep the parent PE32+ small
// enough to clear the M6.1 EDK2 OVMF PE-size threshold on amd64
// (see cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §5 M6.1).
//
// The decompression is done at call time, not at package init():
// the parent only calls Decompress when the phase2_efi_handover
// probe runs, so paying the cost lazily keeps the boot path lean
// for builds that don't exercise the chain-boot mechanism.

package embed_chained

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
)

// ErrEmptyEmbed is returned by Decompress when the build did not
// stage a chained payload into the embed slot. On tamago this means
// the chainedhello:efi:<arch> Taskfile step didn't run; on host
// (where tests live) it's the default state unless a test overrides
// the package-private chainedEFIGz var.
var ErrEmptyEmbed = errors.New("embed_chained: chainedEFIGz is empty")

// Decompress inflates the embedded gzip-compressed chained EFI
// payload and returns the raw PE32+ bytes. Returns an error if the
// embed is empty or the gzip stream is malformed.
func Decompress() ([]byte, error) {
	if len(chainedEFIGz) == 0 {
		return nil, ErrEmptyEmbed
	}
	r, err := gzip.NewReader(bytes.NewReader(chainedEFIGz))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		// io.ReadAll returns the partial slice on error; normalise to
		// nil so callers can treat (nil, err) as "use err only".
		return nil, err
	}
	return out, nil
}
