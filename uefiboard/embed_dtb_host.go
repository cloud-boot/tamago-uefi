// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — EmbeddedArm64VirtDTB host stub. The host
// build can't drive the firmware, but the embedded DTB IS legitimately
// available as data — so host tests CAN read the embedded bytes for
// regression sanity (e.g. "did the embedded file get corrupted by a
// merge?"). We use `//go:embed` here too so host-side coverage of the
// PublishDTB flow can exercise a real DTB sample.

//go:build !tamago

package uefiboard

import _ "embed"

//go:embed embed_dtb_arm64_virt.dtb
var hostEmbeddedArm64VirtDTB []byte

// EmbeddedArm64VirtDTB returns a copy of the baked-in arm64 virt DTB
// for host-side use (unit tests, codegen verifiers). Mirrors the
// tamago build's behaviour so the function signature stays consistent.
func EmbeddedArm64VirtDTB() []byte {
	if len(hostEmbeddedArm64VirtDTB) == 0 {
		return []byte{}
	}
	out := make([]byte, len(hostEmbeddedArm64VirtDTB))
	copy(out, hostEmbeddedArm64VirtDTB)
	return out
}
