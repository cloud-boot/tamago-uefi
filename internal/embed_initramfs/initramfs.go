// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

// Package embed_initramfs ships a minimal gzip-compressed cpio
// (initramfs) blob for each live-supported arch (arm64, riscv64,
// loong64). The M8.4 MODE C path publishes the blob via
// uefiboard.PublishInitrd so the Linux EFI-stub finds an initrd at
// LINUX_EFI_INITRD_MEDIA_GUID and proceeds past the no-initrd
// DataAbort observed at the M8.3 acceptance gate.
//
// Per-arch fan-out
//
// Until M8.10 a single arm64 cpio.gz was embedded. M8.11/M8.12 brought
// riscv64 + loong64 live; the kernel for each arch unpacks the
// initramfs and runs /init as PID 1, so /init MUST be a native ELF
// for the running arch (arm64 /init on a riscv64 kernel reports
// "No working init found"). Per-arch blobs are gated by build tags
// in initramfs_<arch>.go.
//
// All per-arch /init sources live in init_src/init.go and build via
// init_src/build.sh, which now produces three blobs.
package embed_initramfs

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
