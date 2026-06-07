// Phase-2 M1.6 probe — gated on `-tags phase2_blkprintk`.
//
// VZ-observability side-channel: walks every controller publishing
// EFI_BLOCK_IO_PROTOCOL, finds the dedicated scratch disk (identified
// by a 16-byte magic-marker the host pre-stages at LBA 0), binds a
// 32 KiB ring buffer to that disk's LBA 0, and registers the ring as
// a tee sink on `uefiboard.BlkSink`. Subsequent prints are mirrored
// to the scratch disk while still going to ConOut. The probe then
// runs the same M1.5 PCI-IO + SNP enumeration the
// `phase2_pcienum,phase2_snpenum` build runs.
//
// The result: every byte the probe prints to ConOut is ALSO mirrored
// to the scratch disk's LBA-0 region. On hypervisors that DON'T
// surface ConOut (Apple VZ via vfkit 0.6.3 — see R-M1'a), the host
// recovers the probe output by reading the scratch disk file
// post-halt. On hypervisors that DO surface ConOut (QEMU+EDK2 — all
// 4 arches), the side-channel content lines up byte-for-byte with
// the ConOut output, so the disk-recovered text is a host-side
// regression test against the live serial log.
//
// **Magic-marker protocol.** The host stages the scratch disk with
// the 16 bytes `BlkPrintkScratchMagic` at offset 0 of LBA 0 (i.e.
// bytes [0..16) of the raw disk file). The probe reads LBA 0 of
// every writable bare-disk handle and binds the ring to the first
// disk whose LBA-0 prefix matches. This guarantees we NEVER clobber
// the ESP / boot-disk on a hypervisor that exposes it as
// `LogicalPartition == 0` (e.g. raw VFAT ISO image) — those disks
// won't carry our magic.
//
// `phase2_blkprintk` IMPLIES `phase2_pcienum` + `phase2_snpenum` (the
// Taskfile sets all three when building BOOT*-BLKPRINT.EFI), so the
// dispatcher (phase2_dispatch.go) runs both walks inside the same
// run. M1.6 ships no probe of its own beyond the bind step — the
// VALUE of this build is the captured PCI+SNP output, not a new
// enumeration.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_pcienum,phase2_snpenum,phase2_blkprintk \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `blkprintk:efi:<arch>` for the per-arch wiring.)

//go:build phase2_blkprintk && tamago

package main

import (
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// blkPrintkLBA is the starting LBA on the scratch disk that the ring
// flushes to. LBA 0 is the canonical choice — the host inspects bytes
// 0..32767 of the disk file.
const blkPrintkLBA = 0

// runBlkPrintkSetup is called by phase2_dispatch.go BEFORE the
// pcienum + snpenum walks. It enumerates EFI_BLOCK_IO_PROTOCOL
// handles, reads LBA 0 of each writable bare disk, picks the first
// disk whose LBA-0 prefix matches BlkPrintkScratchMagic, binds a
// fresh BlkRingBuffer to that handle's LBA 0, and registers it as
// uefiboard.BlkSink so subsequent prints are teed to disk.
//
// On failure (no Block IO handles published, no marked scratch disk
// present, bind fails) the function logs a one-line "no side-channel
// available" message and returns; the rest of the probe continues
// with ConOut-only output. This degrades the VZ run to "same as M1.5"
// rather than aborting, so a successful R-M1'a resolution can be
// detected by the presence of recoverable bytes in the disk file.
func runBlkPrintkSetup() {
	println("phase2-blkprintk: LocateHandleBuffer(EFI_BLOCK_IO_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIBlockIOProtocolGUID)
	if err != nil {
		println("phase2-blkprintk: LocateHandleBuffer FAILED:", err.Error())
		println("phase2-blkprintk: VZ side-channel UNAVAILABLE (firmware does not publish EFI_BLOCK_IO_PROTOCOL)")
		return
	}
	if len(handles) == 0 {
		println("phase2-blkprintk: no EFI_BLOCK_IO_PROTOCOL handles published")
		println("phase2-blkprintk: VZ side-channel UNAVAILABLE")
		return
	}
	println("phase2-blkprintk: handles=", len(handles))

	for i, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIBlockIOProtocolGUID)
		if err != nil {
			println("phase2-blkprintk:   handle", i, "HandleProtocol FAILED:", err.Error())
			continue
		}
		media, ok := uefiboard.BlockIOMedia(iface)
		if !ok {
			println("phase2-blkprintk:   handle", i, "Media is NULL or unreadable")
			continue
		}
		println("phase2-blkprintk:   handle", i,
			"MediaId=", uint64(media.MediaId),
			"MediaPresent=", uint64(media.MediaPresent),
			"ReadOnly=", uint64(media.ReadOnly),
			"LogicalPartition=", uint64(media.LogicalPartition),
			"BlockSize=", uint64(media.BlockSize),
			"LastBlock=", uint64(media.LastBlock))

		if media.MediaPresent == 0 {
			continue
		}
		if media.ReadOnly != 0 {
			continue
		}
		if media.LogicalPartition != 0 {
			// Skip partitions — we want the bare-disk scratch image.
			continue
		}
		if media.BlockSize == 0 {
			continue
		}

		// Magic-marker check: read LBA 0 and look for
		// BlkPrintkScratchMagic at the start. This is the canonical
		// way to differentiate the dedicated scratch disk from any
		// other writable bare-disk the firmware exposes (typically the
		// ESP image when the ISO is mounted as a virtio-blk drive).
		blockBuf := make([]byte, int(media.BlockSize))
		if err := uefiboard.BlockIOReadBlocks(iface, media.MediaId, blkPrintkLBA, blockBuf); err != nil {
			println("phase2-blkprintk:   handle", i, "ReadBlocks(LBA 0) FAILED:", err.Error())
			continue
		}
		if !matchesScratchMagic(blockBuf) {
			println("phase2-blkprintk:   handle", i, "LBA 0 does not carry the scratch magic; skipping")
			continue
		}

		ring := uefiboard.NewBlkRingBuffer()
		if err := ring.BindBlockIO(iface, media.MediaId, media.BlockSize, blkPrintkLBA); err != nil {
			println("phase2-blkprintk:   handle", i, "BindBlockIO FAILED:", err.Error())
			continue
		}

		uefiboard.BlkSink = ring
		println("phase2-blkprintk: BlkSink BOUND to handle", i, "LBA", uint64(blkPrintkLBA),
			"BlockSize=", uint64(media.BlockSize))
		return
	}

	println("phase2-blkprintk: no scratch disk with the magic marker found; degrading to ConOut-only")
}

// matchesScratchMagic reports whether the first
// `len(BlkPrintkScratchMagic)` bytes of `buf` match
// `BlkPrintkScratchMagic` (the canonical 16-byte sentinel the host
// pre-stages at LBA 0 of the dedicated scratch disk).
func matchesScratchMagic(buf []byte) bool {
	if len(buf) < len(uefiboard.BlkPrintkScratchMagic) {
		return false
	}
	for i, b := range uefiboard.BlkPrintkScratchMagic {
		if buf[i] != b {
			return false
		}
	}
	return true
}

// runBlkPrintkTeardown is called by phase2_dispatch.go AFTER the
// pcienum + snpenum walks. It pushes the sentinel byte through the
// teed sink so the ring flushes a final frame to disk (the host
// reads this as the canonical post-halt state). The sentinel is
// 0x04 (ASCII EOT) — chosen to never appear in the probe's
// hex-only output.
func runBlkPrintkTeardown() {
	if uefiboard.BlkSink == nil {
		println("phase2-blkprintk: BlkSink not bound; nothing to flush")
		return
	}
	println("phase2-blkprintk: final flush via sentinel byte")
	uefiboard.BlkSink.BlkPrintk(uefiboard.BlkSentinel)
	// Make sure we land at least one Flush even if the auto-flush
	// hasn't tripped (e.g. tiny probe output).
	if err := uefiboard.BlkSink.Flush(); err != nil {
		println("phase2-blkprintk: final Flush returned:", err.Error())
		return
	}
	println("phase2-blkprintk: final Flush OK; WriteCount=", uefiboard.BlkSink.WriteCount(),
		"TotalBytes=", uefiboard.BlkSink.Total())
}
