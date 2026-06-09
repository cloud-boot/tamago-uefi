// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build tamago && amd64

package embed_chained_tiny

import _ "embed"

// Only variants C (TamaGo runtime floor) and Z (hand-rolled 1 KiB
// PE32+) are embedded — variants A and B are dropped to keep the
// PARENT binary itself under the M6.1 amd64 firmware-LoadImage
// threshold. tinyA/B/C are all within 600 bytes of each other on
// amd64 (the TamaGo runtime is the floor); embedding all three
// gzipped would push the parent to ~3.8 MiB and the firmware would
// fail to load the parent BEFORE our probe ever ran. C alone is
// the canonical "TamaGo floor at ~1.7 MiB" datapoint we need; Z is
// the "is there ANY size that works" datapoint.

//go:embed tiny_C_amd64.efi.gz
var tinyCGz []byte

//go:embed tiny_Z_amd64.efi.gz
var tinyZGz []byte

//go:embed tiny_Z64K_amd64.efi.gz
var tinyZ64KGz []byte

//go:embed tiny_Z1M_amd64.efi.gz
var tinyZ1MGz []byte

//go:embed tiny_Z2M_amd64.efi.gz
var tinyZ2MGz []byte

// tinyAGz and tinyBGz are kept as empty slices so the host-tests
// pass and the variant table stays uniform; Decompress treats empty
// slices as ErrEmptyEmbed and the probe handles that as a FAIL row.
var (
	tinyAGz []byte
	tinyBGz []byte
)
