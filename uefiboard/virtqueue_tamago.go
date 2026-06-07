// cloud-boot UEFI board — Virtqueue allocator (Phase 2, M2).
//
// `NewVirtqueue` is the live constructor: it computes the on-page
// layout, allocates the backing pages via gBS->AllocatePages
// (EfiBootServicesData — released at ExitBootServices, exactly the
// lifetime virtqueues need), zeros the allocation, and returns a
// driver-side `Virtqueue` ready for descriptor publication.
//
// On every UEFI arch we target (amd64, arm64-virt, riscv64-virt,
// loong64), the physical address returned by AllocatePages is
// identity-mapped into the virtual address space during Boot
// Services. The virtio device reads the descriptor table via DMA
// using the physical address; the driver writes to the same memory
// via its virtual-identity-mapped address. Both views see the same
// bytes — the cache-coherency guarantee firmware provides for
// EfiBootServicesData (UEFI 2.10 §2.3.x and §7.2 — "All memory
// regions reported by GetMemoryMap are required to be
// hardware-cache-coherent for boot services") makes that safe.
//
// We do NOT call `Map(BusMasterCommonBuffer)` here — that's the
// EFI_PCI_IO_PROTOCOL Map.Map API (UEFI 2.10 §13.4.6), which would
// be the *strictly correct* path on a system with an IOMMU active.
// On QEMU+EDK2 and on Apple VZ (the M2 validation targets) the
// firmware leaves the IOMMU in pass-through mode so the
// physical-address-equals-bus-address shortcut works. M2's design
// doc records this in §3 M2 / cache-coherency; M3+ may switch to
// the Map API once we have an IOMMU scenario.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"errors"
	"unsafe"
)

// NewVirtqueue allocates and zeroes the backing memory for a split
// virtqueue of the given size, and returns a driver-side handle. The
// caller next calls `cfg.SetQueueDesc/Driver/Device(q.BasePhys + offset)`
// to publish the per-region physical addresses to the device, then
// `cfg.SetQueueEnable(1)`.
//
// Size MUST be a power of two between 1 and 32768; 0 or non-pow2
// returns an error.
func NewVirtqueue(size uint16, queueIdx uint16, notifyOff uint16) (*Virtqueue, error) {
	if size == 0 || (size&(size-1)) != 0 {
		return nil, ErrInvalidQueueSize
	}
	layout := ComputeVirtqueueLayout(size)
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
	// §7.2.1; we must do it ourselves because the device interprets a
	// non-zero used-ring `idx` as "already published frames".
	base := uintptr(phys)
	total := pages * EfiPageSize
	zeroPages(base, total)

	q := NewVirtqueueFromAlloc(phys, base, size, queueIdx)
	q.NotifyOff = notifyOff
	return q, nil
}

// zeroPages writes zeros across `n` bytes starting at `base`. Uses
// `unsafe.Slice` to get a Go []byte view; the runtime's clear() (or
// the compiler's memclr) zeroes the slice.
func zeroPages(base uintptr, n uintptr) {
	s := unsafe.Slice((*byte)(unsafe.Pointer(base)), int(n))
	for i := range s {
		s[i] = 0
	}
}

// AllocDMABuffer allocates a single page-aligned chunk for use as a
// device-DMA-visible buffer (TX/RX frames in the virtio-net driver).
// Returns the physical base + the host-side pointer (identity-mapped
// during Boot Services). Returns 0,0,err on failure.
func AllocDMABuffer(size uintptr) (phys uint64, addr uintptr, err error) {
	if size == 0 {
		return 0, 0, errors.New("uefi: AllocDMABuffer: size=0")
	}
	pages := (size + EfiPageSize - 1) / EfiPageSize
	phys, err = AllocatePages(EfiBootServicesData, pages)
	if err != nil {
		return 0, 0, err
	}
	if phys == 0 {
		return 0, 0, ErrAllocReturnedZero
	}
	addr = uintptr(phys)
	zeroPages(addr, pages*EfiPageSize)
	return phys, addr, nil
}

// ErrInvalidQueueSize is returned by NewVirtqueue if the requested
// size is 0 or not a power of two.
var ErrInvalidQueueSize = errors.New("uefi: virtqueue: queue size must be a non-zero power of two")

// ErrAllocReturnedZero is returned if AllocatePages reports SUCCESS
// but the returned base is 0 — firmware bug, defensive guard.
var ErrAllocReturnedZero = errors.New("uefi: virtqueue: AllocatePages returned addr=0 with SUCCESS")
