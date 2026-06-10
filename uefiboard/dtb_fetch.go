// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — fw_cfg (QEMU firmware-config device) DTB
// fetcher (Phase 2, M8.6). Host-buildable surface (errors + constants);
// live MMIO walker lives in dtb_fetch_tamago.go.
//
// What this is: a pure-Go reader of QEMU's synthesised flattened
// Device Tree Blob via the arm64 `virt` machine's fw_cfg MMIO
// register window at base 0x09020000. The fw_cfg device exposes a
// FILE_DIR pseudo-file (selector 0x0019) containing a count + array of
// 64-byte FwCfgFile entries; the entry whose name is "etc/fdt" carries
// the selector + size of the firmware-synthesised FDT that QEMU
// constructs from `-M virt` + `-cpu` + device-tree fragments emitted by
// each attached device. EDK2 on virt would normally select this same
// entry at platform-init and republish via gBS->InstallConfigurationTable;
// when the firmware does NOT (R-M8.5a — EDK2 arm64 sees ACPI-as-primary
// because UEFI 2.10 §5 prefers ACPI, so the FDT path is skipped) we
// can fetch it ourselves and install it via the M8.6
// InstallConfigurationTable wrapper.
//
// Reference: QEMU docs/specs/fw_cfg.rst — the canonical wire-format
// description. Selector 0x0019 = FW_CFG_FILE_DIR; each FwCfgFile entry
// is { uint32 size (BE), uint16 select (BE), uint16 reserved, char
// name[56] (NUL-padded) }. On arm64 virt the MMIO window is at
// 0x09020000 with the layout:
//
//	+0x00  data port  (read 8/16/32 bits; sequential reads advance)
//	+0x08  selector   (write 16-bit BE to pick a file/key)
//	+0x10  DMA control (not used by this reader; we do PIO reads)
//
// We deliberately do PIO reads (not DMA): the DMA path requires
// allocating + posting a fw_cfg_dma_access descriptor with a 64-bit
// physical address, and the M8.6 budget calls for simplicity over a
// ~64 KiB DTB blob (every byte read takes one MMIO load, so ~64K
// loads at QEMU virt MMIO ≈ a few ms wall-clock — well below the live
// boot budget). The DMA path would be appropriate if we ever start
// fetching multi-MiB blobs.
//
// This file is host-buildable so the error constants + the FW_CFG
// constants can be unit-tested without going anywhere near firmware
// MMIO. The live MMIO walker lives in dtb_fetch_tamago.go.

package uefiboard

import "errors"

// FwCfg* are the QEMU firmware-config wire-format constants. Pinned
// from upstream QEMU docs/specs/fw_cfg.rst (revision matches QEMU
// v9.2.0 — same revision the kernelboot live runner uses).
const (
	// FwCfgArm64MMIOBase is the base physical address of the fw_cfg
	// MMIO window on the arm64 `virt` machine. Fixed by QEMU's
	// hw/arm/virt.c::a15memmap[VIRT_FW_CFG].base and stable across
	// every QEMU release since v2.10 (the arm64 virt board freeze).
	FwCfgArm64MMIOBase uint64 = 0x09020000

	// FwCfgDataPort is the byte offset of the data register relative
	// to the MMIO base. Reads from this register advance an internal
	// pointer; after a 16-bit selector write at +0x08, sequential
	// reads at +0x00 return the selected file's bytes.
	FwCfgDataPort uintptr = 0x00

	// FwCfgSelectorPort is the byte offset of the 16-bit selector
	// register. Writes are big-endian on every QEMU target (QEMU
	// chose BE for selector + size fields independent of the host's
	// or guest's endianness; the data payload itself follows the
	// per-file convention — for FILE_DIR, BE; for "etc/fdt", the
	// FDT itself is BE per devicetree spec).
	FwCfgSelectorPort uintptr = 0x08

	// FwCfgSelectorFileDir is the well-known selector for the
	// FILE_DIR pseudo-file. Reading from it returns:
	//
	//   uint32  count           (BE — number of FwCfgFile entries)
	//   FwCfgFile entries[count]  (each entry is 64 bytes — see below)
	//
	// The count is uint32 (not uint16) per QEMU's fw_cfg ABI.
	FwCfgSelectorFileDir uint16 = 0x0019

	// FwCfgFileEntrySize is the on-wire byte size of one FwCfgFile
	// entry: 4 (size BE) + 2 (select BE) + 2 (reserved) + 56 (name) = 64.
	FwCfgFileEntrySize int = 64

	// FwCfgFileNameSize is the byte width of the name[] field inside
	// a FwCfgFile entry. Names shorter than 56 bytes are NUL-padded.
	FwCfgFileNameSize int = 56

	// FwCfgFDTName is the canonical name under which QEMU exposes
	// the synthesised flattened Device Tree Blob via fw_cfg. Verified
	// against hw/arm/virt.c::create_fdt + fw_cfg_add_file calls in
	// QEMU v9.2.0 source.
	FwCfgFDTName = "etc/fdt"
)

// FwCfgMaxFDTSize caps the maximum DTB size FetchQemuDTB will accept
// from fw_cfg. The QEMU virt board's synthesised DTB on a 4 GiB guest
// with virtio-blk + virtio-net is ~10 KiB; capping at 256 KiB leaves
// generous headroom (real-world arm64 server DTBs top out near
// 200 KiB) without allowing pathological/malicious sizes through.
const FwCfgMaxFDTSize = 256 * 1024

// ErrNotImplementedOnHost is returned by FetchQemuDTB on the host
// build — there is no MMIO to read. Distinct from ErrFwCfgDTBNotFound
// (which signals "fw_cfg device responded but the etc/fdt entry isn't
// in its FILE_DIR table") so host-side tests can switch on the cause.
var ErrNotImplementedOnHost = errors.New("uefi: FetchQemuDTB not implemented on host")

// ErrFwCfgDTBNotFound is returned when the fw_cfg FILE_DIR walk
// completes without finding an entry named FwCfgFDTName. On QEMU virt
// arm64 this means the DTB was suppressed (e.g. `-no-fdt` or a
// firmware bug); on non-virt arm64 boards or on amd64 fw_cfg won't
// carry an "etc/fdt" file at all (the firmware uses ACPI exclusively).
var ErrFwCfgDTBNotFound = errors.New("uefi: fw_cfg FILE_DIR has no etc/fdt entry")

// ErrFwCfgDTBTooLarge is returned when the matched etc/fdt entry's
// announced size exceeds FwCfgMaxFDTSize. Sanity floor: a malformed or
// malicious fw_cfg response should not be allowed to allocate an
// unbounded buffer.
var ErrFwCfgDTBTooLarge = errors.New("uefi: fw_cfg etc/fdt size exceeds FwCfgMaxFDTSize")

// ErrFwCfgEmptyFileDir is returned when the FILE_DIR's leading count
// is zero — fw_cfg responded but has no files registered. On QEMU
// virt this is essentially impossible (it always registers at least
// a few entries: bootorder, ramfb, vgaroms, etc.); surfaced as a
// distinct error so a regression here is unambiguous.
var ErrFwCfgEmptyFileDir = errors.New("uefi: fw_cfg FILE_DIR has zero entries")

// ErrFwCfgUnsupportedArch is returned by FetchQemuDTB on tamago
// builds for architectures where the MMIO base is not the standard
// QEMU virt 0x09020000 — currently amd64 (uses port-IO at 0x510/0x511,
// not MMIO) and loong64 (no fw_cfg). riscv64 virt uses MMIO at
// 0x10100000 — a future M8.x extension can add a per-arch base.
var ErrFwCfgUnsupportedArch = errors.New("uefi: fw_cfg MMIO base not known for this architecture")

// fwCfgParseFileDirEntry decodes one 64-byte FwCfgFile entry from the
// raw fw_cfg FILE_DIR response. Exposed package-private so the host
// tests can exercise the parser independently of the live MMIO reader.
//
// Returns (size, select, name) where size + select are decoded from
// the big-endian on-wire form (per QEMU's fw_cfg ABI) and name is the
// trimmed NUL-padded ASCII string. Returns ("") for the name if the
// 56-byte slice is all NULs (impossible on real fw_cfg but defensive).
func fwCfgParseFileDirEntry(raw []byte) (size uint32, sel uint16, name string) {
	if len(raw) < FwCfgFileEntrySize {
		return 0, 0, ""
	}
	// size: 4 bytes BE.
	size = uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
	// select: 2 bytes BE.
	sel = uint16(raw[4])<<8 | uint16(raw[5])
	// raw[6:8] reserved.
	// name: 56 bytes NUL-padded ASCII.
	end := 8 + FwCfgFileNameSize
	nameSlice := raw[8:end]
	// Find first NUL.
	n := 0
	for n < len(nameSlice) && nameSlice[n] != 0 {
		n++
	}
	name = string(nameSlice[:n])
	return size, sel, name
}
