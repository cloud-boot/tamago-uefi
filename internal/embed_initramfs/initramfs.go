// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package embed_initramfs

import _ "embed"

// initramfsCPIOGz is the embedded gzip-compressed cpio bytes. The
// raw blob is intentionally NOT exported so callers go through
// Bytes() and get a defensive copy (or, when they prove they will
// only read, the unsafe-shared slice via RawBytes()).
//
//go:embed initramfs.cpio.gz
var initramfsCPIOGz []byte

// Bytes returns a fresh copy of the embedded initramfs cpio.gz blob.
// The returned slice is safe to mutate; modifying it does NOT affect
// subsequent calls. Use this when the caller is going to pass the
// bytes into firmware-owned memory (uefiboard.PublishInitrd takes a
// copy internally — see initrd_protocol_tamago.go — so RawBytes()
// is also fine, but Bytes() is the safe default).
func Bytes() []byte {
	out := make([]byte, len(initramfsCPIOGz))
	copy(out, initramfsCPIOGz)
	return out
}

// RawBytes returns the underlying embedded slice without copying.
// Callers MUST treat it as read-only (modifying it would corrupt
// future Bytes() returns and break the protocol-callback path on
// re-publish). Provided as an escape hatch for the streaming
// pipeline where the bytes only need to flow into PublishInitrd
// which itself takes a copy.
func RawBytes() []byte {
	return initramfsCPIOGz
}

// Size returns the size of the embedded blob in bytes. Useful for
// caller diagnostics that want to log the initrd footprint without
// allocating a copy via Bytes().
func Size() int {
	return len(initramfsCPIOGz)
}
