// cloud-boot UEFI board — Packed virtqueue allocator (Phase 2,
// M2-A experiment).
//
// `NewPackedVirtqueue` is the live constructor: it computes the
// on-page layout, allocates the backing pages via gBS->AllocatePages
// (EfiBootServicesData — released at ExitBootServices, exactly the
// lifetime virtqueues need), zeros the allocation, and returns a
// driver-side `PackedVirtqueue` ready for descriptor publication.
//
// All allocation + cache-coherency invariants documented in
// `virtqueue_tamago.go` apply unchanged: on every UEFI arch we
// target the physical address returned by AllocatePages is
// identity-mapped during Boot Services, and EfiBootServicesData is
// hardware-cache-coherent (UEFI 2.10 §2.3.x and §7.2).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// NewPackedVirtqueue allocates and zeroes the backing memory for a
// packed virtqueue of the given size, and returns a driver-side
// handle. The caller next calls `cfg.SetQueueDesc/Driver/Device(...)`
// to publish the per-region physical addresses to the device, then
// `cfg.SetQueueEnable(1)`.
//
// Per Virtio 1.1 §2.7, the three address-publish registers carry
// different meanings than for split-ring:
//
//	queue_desc   → physical address of the descriptor ring
//	queue_driver → physical address of the driver-event region
//	queue_device → physical address of the device-event region
//
// Same register offsets as split-ring; only the interpretation of
// what's stored at each address differs. The driver is responsible
// for publishing the correct addresses for the negotiated layout.
//
// Size MUST be a power of two between 1 and 32768; 0 or non-pow2
// returns an error.
func NewPackedVirtqueue(size uint16, queueIdx uint16, notifyOff uint16) (*PackedVirtqueue, error) {
	if size == 0 || (size&(size-1)) != 0 {
		return nil, ErrPackedQueueSizeTooSmall
	}
	layout := ComputePackedVirtqueueLayout(size)
	// Round up to whole pages.
	pages := (uintptr(layout.TotalSize) + EfiPageSize - 1) / EfiPageSize
	if pages == 0 {
		pages = 1
	}
	phys, err := AllocatePages(EfiBootServicesData, pages)
	if err != nil {
		return nil, err
	}
	if phys == 0 {
		return nil, ErrAllocReturnedZero
	}
	// Zero the allocation. AllocatePages does NOT zero per UEFI 2.10
	// §7.2.1; we must do it ourselves because a non-zero F_AVAIL bit
	// on a descriptor would make the device think the driver
	// already published a buffer it never wrote.
	base := uintptr(phys)
	total := pages * EfiPageSize
	zeroPages(base, total)

	q := NewPackedVirtqueueFromAlloc(phys, base, size, queueIdx)
	q.NotifyOff = notifyOff
	return q, nil
}
