// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build tamago && riscv64

package embed_chained

import _ "embed"

//go:embed chained_riscv64.efi
var ChainedEFI []byte
