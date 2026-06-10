// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host stub for FetchQemuDTB (Phase 2, M8.6).
// On the host there is no fw_cfg MMIO window — return
// ErrNotImplementedOnHost so callers (and unit tests) see a clean
// error rather than a segfault from dereferencing 0x09020000.
//
// Mirrors the loadimage_host.go / initrd_protocol_host.go stub
// pattern. The host-buildable surface (errors + parser + constants)
// lives in dtb_fetch.go and is unit-tested without going anywhere
// near MMIO.

//go:build !tamago

package uefiboard

// FetchQemuDTB host stub. Returns ErrNotImplementedOnHost so callers
// see a meaningful error.
func FetchQemuDTB() ([]byte, error) {
	return nil, ErrNotImplementedOnHost
}
