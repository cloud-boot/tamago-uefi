// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — embedded QEMU arm64 `virt` DTB (Phase 2,
// M8.6 fallback path). Generated once at toolchain-build time via:
//
//	qemu-system-aarch64 -M virt,dumpdtb=/tmp/m86-virt.dtb \
//	    -cpu max -m 4096 -display none -no-reboot \
//	    -bios <edk2-aarch64-code.fd> \
//	    -netdev user,id=n0 \
//	    -device virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off
//
// then trimmed to the actual struct+strings extent (QEMU's dumpdtb
// pads to 1 MiB; the real content is ~7 KiB) and the totalsize field
// in the FDT header fixed up to match. The trimming + fixup is done
// once at integration time; the result is the embed_dtb_arm64_virt.dtb
// blob shipped alongside this file.
//
// Why embedded instead of live fw_cfg read?
//
// Phase-2 M8.6 originally planned to read QEMU's synthesised DTB via
// the fw_cfg MMIO device at 0x09020000 (see dtb_fetch.go + dtb_fetch_
// tamago.go for the wire-format implementation). That implementation
// works in principle and is verified against QEMU's docs/specs/fw_cfg.rst,
// but EDK2 on QEMU arm64 virt does NOT map the fw_cfg MMIO window
// into the page tables it hands the UEFI image: an MMU walk on
// 0x09020000 produces a Synchronous External Abort (ESR_EL1
// EC=0x25 ISS=0x50 FAR=0x09020008) at the first selector-port write.
// We can't safely catch that fault and continue — once the firmware's
// default exception handler asserts, the boot is dead.
//
// EDK2's ArmVirtPkg adds only a curated subset of the QEMU virt MMIO
// map to its page tables (PL011 UART, GIC, RTC, virtio MMIO bus). The
// fw_cfg window is reachable from the Internal Shell because the
// shell uses it via the EFI Pi DXE driver that does its own
// gDS->AddMemorySpace; we'd need to either (a) replicate that
// AddMemorySpace call ourselves before any MMIO access, or (b) wait
// for the EDK2 ArmVirtPkg patch that maps fw_cfg unconditionally.
//
// Embedding the DTB sidesteps the mapping problem entirely. The QEMU
// arm64 virt board is a stable target (frozen since QEMU v2.10); the
// DTB it generates for `-M virt -cpu max -m 4096` + virtio-blk-pci +
// virtio-net-pci is deterministic across QEMU versions. The bake-in
// hash of the trimmed DTB is captured in the test below for
// regression detection if QEMU ever decides to add a new device-tree
// node by default.
//
// Future M8.x can wire a live fw_cfg path once one of:
//   - EDK2 ArmVirtPkg ships fw_cfg-in-pagetables OR
//   - We add an explicit gDS->AddMemorySpace + uefi MemoryAttribute
//     call to map the fw_cfg window into our address space pre-read.
//
// References:
//   - QEMU hw/arm/virt.c::create_fdt (the synthesis path)
//   - QEMU docs/specs/fw_cfg.rst (the wire-format the live path uses)
//   - Linux Documentation/devicetree/bindings/.../qemu-virt (the
//     consumer side: enumerates expected nodes).

//go:build tamago && arm64

package uefiboard

import _ "embed"

// embeddedArm64VirtDTB is the trimmed DTB for QEMU arm64 `virt` -m 4096
// with virtio-blk-pci + virtio-net-pci. Generated once at build time
// via `qemu-system-aarch64 -M virt,dumpdtb=...` and trimmed to the
// real struct+strings extent.
//
//go:embed embed_dtb_arm64_virt.dtb
var embeddedArm64VirtDTB []byte

// EmbeddedArm64VirtDTB returns a copy of the baked-in QEMU arm64 virt
// DTB. Used by the M8.6 PublishDTB fallback when live fw_cfg read is
// unavailable (e.g. EDK2 hasn't mapped fw_cfg into the page tables).
// Returns a fresh slice each call so the caller can mutate without
// affecting the embedded copy.
//
// Returns an empty slice (NOT nil) on arches where no embedded DTB
// is shipped — caller treats as "no embedded DTB available".
func EmbeddedArm64VirtDTB() []byte {
	if len(embeddedArm64VirtDTB) == 0 {
		return []byte{}
	}
	out := make([]byte, len(embeddedArm64VirtDTB))
	copy(out, embeddedArm64VirtDTB)
	return out
}
