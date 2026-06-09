// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

//go:build !tamago

package embed_chained

// chainedEFIGz is empty on host builds. The per-arch tamago files
// (chained_<arch>.go) embed the real gzipped payload via go:embed;
// on host the variable still has to exist so the package compiles
// (Decompress is host-testable by reassigning chainedEFIGz inside
// the test file, see decompress_test.go).
var chainedEFIGz []byte
