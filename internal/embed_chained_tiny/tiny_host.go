// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tamago

package embed_chained_tiny

// Host-build placeholders. The real bytes live in tiny_amd64.go
// behind the tamago+amd64 build tag.
var (
	tinyAGz    []byte
	tinyBGz    []byte
	tinyCGz    []byte
	tinyZGz    []byte
	tinyZ64KGz []byte
	tinyZ1MGz  []byte
	tinyZ2MGz  []byte
)
