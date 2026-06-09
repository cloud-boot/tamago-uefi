// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build tamago && loong64

package embed_chained

import _ "embed"

//go:embed chained_loong64.efi.gz
var chainedEFIGz []byte
