// cloud-boot UEFI board — pre-ExitBootServices capture for the M2-B
// post-EBS experiment (Phase 2, M2-B — R-M2c Option B narrow).
//
// Host-buildable: no //go:build tamago directive. The `CapturedState`
// struct is pure data; the live capture function lives in
// `post_ebs_capture_tamago.go` (it needs Boot Services to walk PCI
// caps, read MAC, allocate runtime pages). This split lets the host
// unit tests exercise the captured-state shape without pulling in
// firmware-call thunks.
//
// Background: R-M2c was diagnosed as Case IV — under Apple VZ
// (vfkit 0.6.3 / arm64) the host-side virtio-net device, when accessed
// from a UEFI-context client, accepts the full Virtio 1.1 §3.1.1
// init sequence but never reads the avail ring; no TX frame ever
// leaves the guest. The Linux-on-VZ rail works because its
// virtio-net runs POST-ExitBootServices on bare metal. Option B
// hypothesises that VZ gates the UEFI-context virtio-net client
// specifically, and that the same device driven post-EBS via direct
// MMIO will unlock TX/RX.
//
// This experiment pre-captures everything we'll need post-EBS,
// crosses the EBS boundary, then re-drives the same device through
// direct `unsafe.Pointer` MMIO (no PciIo.Mem.Read/Write because
// Boot Services are gone). If TX/RX then works, Option B is the
// VZ rail.
//
// References:
//
//   - Virtio 1.1 §3.1.1 — driver init choreography (replayed post-EBS).
//   - Virtio 1.1 §4.1.4 — PCI capability layout (parsed pre-EBS).
//   - Virtio 1.1 §4.1.5.1 — COMMON_CFG register table.
//   - UEFI 2.10 §7.4 — ExitBootServices contract.
//   - UEFI 2.10 §7.2 — AllocatePages + EFI_MEMORY_TYPE values.
//   - cloud-boot/docs/tamago-uefi-phase2-oci-loader.md §3 M2 — R-M2c
//     Case IV diagnosis that motivated this experiment.

package uefiboard

// CapturedState holds everything the M2-B post-EBS path needs about
// one virtio-net device. Populated by `CapturePreEBS` while Boot
// Services are still alive; consumed by `InitVirtioNetPostEBS`,
// `TransmitFramePostEBS`, and `ReceiveFramePostEBS` after
// ExitBootServices has torn the firmware down.
//
// **Lifetime invariant.** Every pointer-shaped field on this struct
// (the four cap base addresses, the two virtqueue rings, the
// blkprintk scratch) MUST point at memory the firmware will leave
// alone across ExitBootServices. We arrange that by allocating those
// regions with `EfiRuntimeServicesData` (UEFI 2.10 §7.2 — runtime
// data survives EBS; firmware will not reclaim it). The MMIO BAR
// windows are physical addresses the platform exposes
// hardware-side, so they're stable across EBS by definition (the
// hardware doesn't go away when we drop firmware).
//
// On a 1:1-mapped UEFI image (every UEFI arch we target — amd64,
// arm64-virt, loong64-virt, riscv64-virt — runs identity-mapped
// while still in Boot Services), the captured physical addresses
// are ALSO usable as Go-side virtual addresses post-EBS until we
// install our own page tables. The post-EBS direct-MMIO path
// dereferences these as `unsafe.Pointer` without re-mapping.
type CapturedState struct {
	// PciIO is the live EFI_PCI_IO_PROTOCOL pointer captured pre-EBS.
	// USELESS post-EBS (the protocol's function table lives inside
	// firmware memory that EBS tore down) but kept here for the
	// pre-EBS phase of the experiment when we still need to do the
	// final reset / status writes if any.
	PciIO uint64

	// PCICommonCfgPhys is the physical address of the virtio modern
	// VIRTIO_PCI_CAP_COMMON_CFG region (BAR base + cap offset).
	// Discovered pre-EBS via the existing VirtioModernConfig + a
	// GetBarAttributes round-trip. Post-EBS the bytes 0..56 at this
	// address are the live COMMON_CFG MMIO window (Virtio 1.1
	// §4.1.5.1).
	PCICommonCfgPhys uint64

	// PCINotifyCfgPhys + PCINotifyOffMultiplier — the per-queue
	// notification window (Virtio 1.1 §4.1.4.4). The post-EBS
	// doorbell is at `PCINotifyCfgPhys + queue_notify_off *
	// PCINotifyOffMultiplier`.
	PCINotifyCfgPhys       uint64
	PCINotifyOffMultiplier uint32

	// PCIIsrCfgPhys is the physical address of the
	// VIRTIO_PCI_CAP_ISR_CFG region. M2-B doesn't use interrupts
	// (we busy-poll the used ring post-EBS) but the address is
	// captured for symmetry + future use.
	PCIIsrCfgPhys uint64

	// PCIDeviceCfgPhys + PCIDeviceCfgLength — the device-specific
	// config region (Virtio 1.1 §5.1.4). MAC at offset 0 is read
	// PRE-EBS into the `MAC` field below; post-EBS we only need
	// the address if we want to re-read the link status.
	PCIDeviceCfgPhys   uint64
	PCIDeviceCfgLength uint32

	// VQRingsPhys[0] = RX ring base, VQRingsPhys[1] = TX ring base.
	// Each is a single page (4 KiB) of EfiRuntimeServicesData
	// allocated pre-EBS; the descriptor table sits at offset 0,
	// the avail ring at PostEBSAvailOffset, the used ring at
	// PostEBSUsedOffset (computed from `ComputeVirtqueueLayout`).
	// 64 descriptors is plenty for a single ARP RTT.
	VQRingsPhys [2]uint64

	// VQRingsLayout[i] is the byte-offset map for vqRingsPhys[i]
	// — captured pre-EBS so the post-EBS path doesn't need to
	// recompute it (the math is host-buildable and stable, but
	// pre-capturing avoids a second arithmetic surface post-EBS).
	VQRingsLayout [2]VirtqueueLayout

	// VQNotifyOff[i] is the queue_notify_off value the device
	// published for queue i. Captured pre-EBS via SelectQueue +
	// QueueNotifyOff. The post-EBS doorbell is at
	// `PCINotifyCfgPhys + VQNotifyOff[i] * PCINotifyOffMultiplier`.
	VQNotifyOff [2]uint16

	// MAC is the device's published MAC address. Read pre-EBS via
	// the existing `DeviceCfgRead8` path (which uses PciIo.Mem.Read,
	// which goes away post-EBS).
	MAC MAC6

	// BlkPrintkScratchPhys is the physical address of a single page
	// (4 KiB) of EfiRuntimeServicesData allocated pre-EBS, intended
	// to receive post-EBS diagnostic bytes via direct
	// `unsafe.Pointer` write. The scratch is NOT host-observable
	// post-EBS (the host can only snoop virtio-net traffic or read
	// the pre-EBS LBA-0 blkprintk stream from the scratch disk),
	// but it's useful for in-RAM debugging if a JTAG is attached.
	BlkPrintkScratchPhys uint64

	// BlkPrintkScratchOffset tracks the next free byte in the
	// post-EBS scratch buffer. Bumped by `postEBSScratchPrint`.
	// Reset to 0 by `ExitToBareMetal`.
	BlkPrintkScratchOffset uint32

	// rxPoolPhys + rxPoolSize — pre-allocated EfiRuntimeServicesData
	// region the post-EBS RX queue carves its per-descriptor
	// buffers from. Sized for queue-size * (hdr + frame) =
	// 64 * 1530 ≈ 96 KiB rounded up to 25 pages. Allocated by
	// `CapturePreEBS`; lifetime ends only when the platform resets.
	rxPoolPhys uint64
	rxPoolSize uint32

	// txScratchPhys + txScratchSize — pre-allocated
	// EfiRuntimeServicesData region the post-EBS TX path stages
	// outgoing frames in. One page = 4 KiB is plenty for the M2-B
	// experiment's single-ARP TX.
	txScratchPhys uint64
	txScratchSize uint32

	// FeatureMask is the accepted-features mask the post-EBS init
	// will write back to DriverFeature. Pre-EBS we read the device-
	// offered bitmap and intersect with our hard-required bits
	// (VERSION_1 + MAC) plus the standard M2 mask. Post-EBS we just
	// replay this value.
	FeatureMask uint64

	// DeviceFeaturesOffered is the raw bitmap the device returned
	// for DeviceFeatureSelect=0/1. Captured pre-EBS for diagnostic
	// echo; the post-EBS path re-reads it to confirm the device
	// still publishes the same set after EBS.
	DeviceFeaturesOffered uint64
}

// PostEBSScratchSize is the byte length of the post-EBS diagnostic
// scratch buffer. One page (4 KiB) is enough for a few dozen
// short status lines; the post-EBS path is intentionally
// dep-light (no Go runtime printk because gBS->ConOut is gone),
// so the format is "raw bytes appended in order".
const PostEBSScratchSize uint32 = 4096

// IsCaptured reports whether `CapturePreEBS` populated every
// must-have field. Used by the dispatcher to short-circuit
// post-EBS when the pre-EBS phase didn't complete.
func (s *CapturedState) IsCaptured() bool {
	if s == nil {
		return false
	}
	if s.PCICommonCfgPhys == 0 {
		return false
	}
	if s.PCINotifyCfgPhys == 0 {
		return false
	}
	if s.PCIDeviceCfgPhys == 0 {
		return false
	}
	if s.VQRingsPhys[0] == 0 || s.VQRingsPhys[1] == 0 {
		return false
	}
	if s.BlkPrintkScratchPhys == 0 {
		return false
	}
	if s.MAC.IsZero() {
		return false
	}
	return true
}
