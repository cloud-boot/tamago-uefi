// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — live MMIO fw_cfg reader for QEMU's
// synthesised DTB (Phase 2, M8.6). Host stubs + constants live in
// dtb_fetch.go.
//
// Build is split per arch so the MMIO base + register width stay
// honest:
//
//   - arm64 virt: MMIO at 0x09020000, selector port at +0x08
//     (16-bit BE write), data port at +0x00 (8/16/32-bit reads,
//     sequential reads advance an internal pointer). This is what
//     we implement here.
//
//   - amd64: fw_cfg uses port-IO at 0x510 (selector) + 0x511 (data) —
//     a different access pattern. Not implemented in M8.6 because
//     amd64 firmware (OVMF) hands out ACPI exclusively and the
//     existing M8.4 DTB probe + EFI-stub path doesn't traverse FDT
//     on amd64 anyway.
//
//   - riscv64 virt: MMIO at 0x10100000. Same wire format as arm64.
//     Future M8.x extension can route here if rv64 gains a DTB
//     publish path.
//
//   - loong64: no fw_cfg device exposed at all on QEMU virt.
//
// For arches without a known MMIO base, FetchQemuDTB returns
// ErrFwCfgUnsupportedArch — caller treats the same as "no DTB
// available" and falls back to whatever DTB-less path the kernel
// can take.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// FetchQemuDTB reads QEMU's synthesised flattened Device Tree Blob
// via the fw_cfg MMIO device. Returns the DTB bytes (allocated on
// the Go heap) on success.
//
// Procedure (per QEMU docs/specs/fw_cfg.rst):
//
//  1. Write the FILE_DIR selector (0x0019) big-endian to the
//     selector port.
//  2. Read the leading 4-byte big-endian count from the data port.
//  3. For each of `count` entries, read 64 bytes from the data port
//     (each entry is { uint32 size BE, uint16 select BE, uint16
//     reserved, char name[56] NUL-padded }). Match name == "etc/fdt".
//  4. Once the matching entry is found, write its `select` field
//     big-endian to the selector port, then read `size` bytes from
//     the data port into the returned slice.
//
// Error returns:
//
//   - ErrFwCfgUnsupportedArch  — this build is not arm64 (M8.6
//     scope; amd64+rv64+loong64 not wired).
//   - ErrFwCfgEmptyFileDir     — fw_cfg responded but FILE_DIR.count
//     is zero (sanity-floor; should never happen on QEMU virt).
//   - ErrFwCfgDTBNotFound      — FILE_DIR walked to completion with
//     no etc/fdt entry. Means QEMU didn't synthesise a DTB (e.g.
//     `-no-fdt` flag, or the firmware swallowed the fdt fwcfg
//     registration in a custom build).
//   - ErrFwCfgDTBTooLarge      — matched entry's announced size is
//     above FwCfgMaxFDTSize. Refuses to allocate the buffer to
//     prevent a malformed fw_cfg from exhausting the heap.
//
// Lifetime: the returned bytes live on the Go heap. The caller is
// expected to either (a) hand them to PublishDTB (which copies into
// firmware-owned EfiBootServicesData pool memory before
// InstallConfigurationTable) or (b) consume + drop them before
// ExitBootServices — once EBS runs, the Go heap goes away when the
// kernel takes over, but the firmware-installed configuration table
// entry (set up by PublishDTB) lives on.
func FetchQemuDTB() ([]byte, error) {
	base, ok := fwCfgMMIOBase()
	if !ok {
		return nil, ErrFwCfgUnsupportedArch
	}

	// Step 1: select FILE_DIR (selector 0x0019, BE).
	fwCfgSelect(base, FwCfgSelectorFileDir)

	// Step 2: read the 4-byte BE count of entries.
	count := fwCfgReadU32BE(base)
	if count == 0 {
		return nil, ErrFwCfgEmptyFileDir
	}

	// Step 3: walk count entries, matching name == "etc/fdt".
	// We keep a single 64-byte scratch buffer; each iteration
	// overwrites it. Found = capture (size, select) and break.
	var (
		entry      [64]byte
		foundSize  uint32
		foundSel   uint16
		fdtMatched bool
	)
	for i := uint32(0); i < count; i++ {
		fwCfgReadBytes(base, entry[:])
		size, sel, name := fwCfgParseFileDirEntry(entry[:])
		if name == FwCfgFDTName {
			foundSize = size
			foundSel = sel
			fdtMatched = true
			// Do NOT break — fw_cfg's data-port read pointer is
			// per-selector and advances on every byte read, so the
			// next selector write (step 4) resets it cleanly without
			// us having to drain the remaining FILE_DIR bytes.
			break
		}
	}
	if !fdtMatched {
		return nil, ErrFwCfgDTBNotFound
	}
	if foundSize == 0 {
		// An etc/fdt entry with zero bytes is degenerate; treat as
		// "no DTB available" so the caller can fall back.
		return nil, ErrFwCfgDTBNotFound
	}
	if foundSize > FwCfgMaxFDTSize {
		return nil, ErrFwCfgDTBTooLarge
	}

	// Step 4: select the matched entry, then read `foundSize` bytes.
	fwCfgSelect(base, foundSel)
	out := make([]byte, int(foundSize))
	fwCfgReadBytes(base, out)
	return out, nil
}

// fwCfgMMIOBase returns the per-arch fw_cfg MMIO base address, and a
// bool indicating whether this arch has a known fw_cfg base. Per-arch
// definitions live in dtb_fetch_<arch>_tamago.go (arm64 is the only
// arch with a known base in M8.6; other arches return (0, false)
// which collapses to ErrFwCfgUnsupportedArch in FetchQemuDTB).
//
// Declared here without a body; per-arch tamago files supply the
// implementation:
//   - dtb_fetch_arm64_tamago.go: returns (FwCfgArm64MMIOBase, true).
//   - dtb_fetch_other_tamago.go: returns (0, false) on amd64,
//     loong64, riscv64 (M8.6 scope is arm64-only).

// fwCfgSelect writes a 16-bit big-endian selector to the selector
// port. The selector port is a 16-bit register; QEMU's fw_cfg ABI
// stipulates big-endian regardless of host endianness (see QEMU
// docs/specs/fw_cfg.rst §"Selector Register").
func fwCfgSelect(base uint64, sel uint16) {
	// Big-endian byte order: high byte first.
	beHi := byte(sel >> 8)
	beLo := byte(sel & 0xff)
	addr := uintptr(base + uint64(FwCfgSelectorPort))
	// Write as two consecutive byte stores so the MMIO controller
	// sees a single 16-bit BE word. On arm64-virt the QEMU fw_cfg
	// model accepts both 16-bit and dual-byte access; using two
	// byte stores avoids depending on the compiler's choice of
	// register width for a `*uint16` store across architectures.
	*(*byte)(unsafe.Pointer(addr)) = beHi
	*(*byte)(unsafe.Pointer(addr + 1)) = beLo
}

// fwCfgReadU32BE reads 4 sequential bytes from the data port and
// returns them as a big-endian uint32. The fw_cfg FILE_DIR's leading
// count word is laid out BE per the ABI.
func fwCfgReadU32BE(base uint64) uint32 {
	addr := uintptr(base + uint64(FwCfgDataPort))
	b0 := *(*byte)(unsafe.Pointer(addr))
	b1 := *(*byte)(unsafe.Pointer(addr))
	b2 := *(*byte)(unsafe.Pointer(addr))
	b3 := *(*byte)(unsafe.Pointer(addr))
	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3)
}

// fwCfgReadBytes fills dst with sequential byte reads from the data
// port. Per QEMU's fw_cfg ABI the data port advances an internal
// pointer on every byte read; after a selector write the pointer is
// reset to the start of the selected file.
func fwCfgReadBytes(base uint64, dst []byte) {
	addr := uintptr(base + uint64(FwCfgDataPort))
	for i := range dst {
		dst[i] = *(*byte)(unsafe.Pointer(addr))
	}
}
