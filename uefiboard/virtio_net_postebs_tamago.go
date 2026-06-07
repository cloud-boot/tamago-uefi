// cloud-boot UEFI board — post-ExitBootServices virtio-net rail:
// live MMIO accessors + init/TX/RX state machine (Phase 2, M2-B —
// R-M2c Option B narrow).
//
// All direct-MMIO operations against the captured physical addresses
// live here. The pure-data surface (struct shape, trace constants,
// EncodeTraceMarker) is in `virtio_net_postebs.go` and host-buildable.
//
// Why direct MMIO instead of going back through PciIo.Mem.Read/Write:
// Boot Services are gone after `ExitToBareMetal`. The
// EFI_PCI_IO_PROTOCOL function pointers live in firmware-owned
// memory that EBS torch'd. We have to drive the device the same
// way Linux does: by dereferencing the captured physical
// addresses (which are also virtual addresses on the
// identity-mapped UEFI image, valid as long as we don't install
// new page tables).
//
// References:
//
//   - Virtio 1.1 §3.1.1 driver init — same sequence as M2 but with
//     direct MMIO transport.
//   - Virtio 1.1 §4.1.5.1 — COMMON_CFG register table.
//   - Virtio 1.1 §4.1.4.4 — notification address arithmetic.
//   - Linux drivers/virtio/virtio_pci_modern.c — canonical pure-MMIO
//     driver; we follow its idioms (esp. its use of `readl/writel`
//     for 32-bit fields and `iowrite16` for 16-bit doorbells).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"sync/atomic"
	"unsafe"
)

// mmioReadU8 / mmioReadU16 / mmioReadU32 / mmioReadU64 — direct MMIO
// reads against a physical address (which on an identity-mapped UEFI
// image is also the virtual address). Used by the post-EBS init for
// COMMON_CFG / DEVICE_CFG reads.
//
// Why `atomic.LoadUint32` for the 32-bit read: arm64's regular load
// isn't guaranteed to be observed as a single MMIO transaction
// without LDAR semantics; LoadUint32 provides that. For 16-bit
// there's no atomic.LoadUint16 in the stdlib — the COMMON_CFG
// register at the 16-bit offsets is always naturally aligned to
// 2 bytes and the firmware-allocated BAR window is on a
// page-aligned base, so a plain LE16 read of the underlying byte
// pair is single-transaction on every arch we target.

//go:nosplit
func mmioReadU8(phys uint64) uint8 {
	return *(*uint8)(unsafe.Pointer(uintptr(phys)))
}

//go:nosplit
func mmioReadU16(phys uint64) uint16 {
	return *(*uint16)(unsafe.Pointer(uintptr(phys)))
}

//go:nosplit
func mmioReadU32(phys uint64) uint32 {
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(uintptr(phys))))
}

//go:nosplit
func mmioReadU64(phys uint64) uint64 {
	return *(*uint64)(unsafe.Pointer(uintptr(phys)))
}

//go:nosplit
func mmioWriteU8(phys uint64, v uint8) {
	*(*uint8)(unsafe.Pointer(uintptr(phys))) = v
}

//go:nosplit
func mmioWriteU16(phys uint64, v uint16) {
	*(*uint16)(unsafe.Pointer(uintptr(phys))) = v
}

//go:nosplit
func mmioWriteU32(phys uint64, v uint32) {
	atomic.StoreUint32((*uint32)(unsafe.Pointer(uintptr(phys))), v)
}

//go:nosplit
func mmioWriteU64(phys uint64, v uint64) {
	*(*uint64)(unsafe.Pointer(uintptr(phys))) = v
}

// commonCfg* — typed helpers for COMMON_CFG accesses. They take the
// CapturedState (which holds the COMMON_CFG physical base) plus the
// register offset (one of the `VirtioCfg*` constants from
// `virtio_modern.go`) and route through the mmio* primitives.

func commonCfgU8(state *CapturedState, offset uint64) uint8 {
	return mmioReadU8(state.PCICommonCfgPhys + offset)
}
func commonCfgU16(state *CapturedState, offset uint64) uint16 {
	return mmioReadU16(state.PCICommonCfgPhys + offset)
}
func commonCfgU32(state *CapturedState, offset uint64) uint32 {
	return mmioReadU32(state.PCICommonCfgPhys + offset)
}
func commonCfgWriteU8(state *CapturedState, offset uint64, v uint8) {
	mmioWriteU8(state.PCICommonCfgPhys+offset, v)
}
func commonCfgWriteU16(state *CapturedState, offset uint64, v uint16) {
	mmioWriteU16(state.PCICommonCfgPhys+offset, v)
}
func commonCfgWriteU32(state *CapturedState, offset uint64, v uint32) {
	mmioWriteU32(state.PCICommonCfgPhys+offset, v)
}
func commonCfgWriteU64(state *CapturedState, offset uint64, v uint64) {
	mmioWriteU64(state.PCICommonCfgPhys+offset, v)
}

// postEBSDeviceFeatures64 reads the full 64-bit device-offered
// bitmap via the COMMON_CFG select-then-read dance, but with direct
// MMIO instead of PciIo.Mem.Read.
func postEBSDeviceFeatures64(state *CapturedState) uint64 {
	commonCfgWriteU32(state, VirtioCfgDeviceFeatureSelect, 0)
	lo := commonCfgU32(state, VirtioCfgDeviceFeature)
	commonCfgWriteU32(state, VirtioCfgDeviceFeatureSelect, 1)
	hi := commonCfgU32(state, VirtioCfgDeviceFeature)
	return uint64(lo) | uint64(hi)<<32
}

// postEBSSetDriverFeatures64 writes the negotiated bitmap to
// DriverFeature via the matching select+write dance.
func postEBSSetDriverFeatures64(state *CapturedState, v uint64) {
	commonCfgWriteU32(state, VirtioCfgDriverFeatureSelect, 0)
	commonCfgWriteU32(state, VirtioCfgDriverFeature, uint32(v&0xFFFFFFFF))
	commonCfgWriteU32(state, VirtioCfgDriverFeatureSelect, 1)
	commonCfgWriteU32(state, VirtioCfgDriverFeature, uint32(v>>32))
}

// InitVirtioNetPostEBS replays the Virtio 1.1 §3.1.1 driver init
// sequence post-ExitBootServices, driving the device entirely
// through direct MMIO. Returns the bound *VirtioNetPostEBS or an
// error sentinel.
//
// The init-trace byte per step is appended to
// `state.BlkPrintkScratch` so the host can recover a coarse
// "advanced to step X" diagnostic even when no virtio-net frame
// reaches the host. (The scratch is only readable by an in-VM
// debugger / JTAG attach — the host snoop sees only what we TX
// over virtio-net.)
func InitVirtioNetPostEBS(state *CapturedState) (*VirtioNetPostEBS, error) {
	if state == nil || !state.IsCaptured() {
		return nil, ErrPostEBSNoCapture
	}
	v := &VirtioNetPostEBS{State: state}
	traceIdx := 0
	traceStep := func(b byte) {
		if traceIdx < len(v.InitTrace) {
			v.InitTrace[traceIdx] = b
			traceIdx++
		}
		PostEBSScratchAppend(state, b)
	}

	traceStep(postEBSTraceStart)

	// Step 1: RESET (DeviceStatus = 0).
	commonCfgWriteU8(state, VirtioCfgDeviceStatus, 0)
	// Sample once for the trace; don't gate on it.
	_ = commonCfgU8(state, VirtioCfgDeviceStatus)
	traceStep(postEBSTraceReset)

	// Step 2: ACKNOWLEDGE.
	commonCfgWriteU8(state, VirtioCfgDeviceStatus, VirtioStatusAcknowledge)
	traceStep(postEBSTraceAck)

	// Step 3: DRIVER.
	commonCfgWriteU8(state, VirtioCfgDeviceStatus, VirtioStatusAcknowledge|VirtioStatusDriver)
	traceStep(postEBSTraceDriver)

	// Step 4: read device-offered features, negotiate.
	deviceFeats := postEBSDeviceFeatures64(state)
	traceStep(postEBSTraceFeaturesRead)
	if deviceFeats&VirtioFeatureVersion1 == 0 {
		traceStep(postEBSTraceFailMarker)
		return v, ErrNotModernDevice
	}
	if deviceFeats&VirtioNetFeatureMAC == 0 {
		traceStep(postEBSTraceFailMarker)
		return v, ErrNoMACFeature
	}
	negotiated := deviceFeats & VirtioNetAcceptedFeatures
	v.NegotiatedFeatures = negotiated
	postEBSSetDriverFeatures64(state, negotiated)
	traceStep(postEBSTraceFeaturesWritten)

	// Step 5: FEATURES_OK + verify it sticks.
	commonCfgWriteU8(state, VirtioCfgDeviceStatus,
		VirtioStatusAcknowledge|VirtioStatusDriver|VirtioStatusFeaturesOK)
	status := commonCfgU8(state, VirtioCfgDeviceStatus)
	if status&VirtioStatusFeaturesOK == 0 {
		traceStep(postEBSTraceFailMarker)
		return v, ErrFeaturesNotOK
	}
	traceStep(postEBSTraceFeaturesOK)

	// Step 6: per-queue setup.
	rxq, err := postEBSSetupQueue(state, VirtioNetRxQueueIdx)
	if err != nil {
		traceStep(postEBSTraceFailMarker)
		return v, err
	}
	v.RxQ = rxq
	traceStep(postEBSTraceQRx)

	txq, err := postEBSSetupQueue(state, VirtioNetTxQueueIdx)
	if err != nil {
		traceStep(postEBSTraceFailMarker)
		return v, err
	}
	v.TxQ = txq
	traceStep(postEBSTraceQTx)

	// Step 7: DRIVER_OK.
	commonCfgWriteU8(state, VirtioCfgDeviceStatus,
		VirtioStatusAcknowledge|VirtioStatusDriver|VirtioStatusFeaturesOK|VirtioStatusDriverOK)
	traceStep(postEBSTraceDriverOK)

	// Pre-post the RX buffers.
	if err := v.fillRxPostEBS(); err != nil {
		traceStep(postEBSTraceFailMarker)
		return v, err
	}
	// Doorbell RX so the device sees the available buffers.
	postEBSNotifyQueue(state, VirtioNetRxQueueIdx, state.VQNotifyOff[VirtioNetRxQueueIdx])
	traceStep(postEBSTraceRxFilled)

	return v, nil
}

// postEBSSetupQueue configures one virtqueue post-EBS: selects the
// queue, reads the max size, writes our size (capped at 64), writes
// the captured ring base addresses, and enables the queue.
func postEBSSetupQueue(state *CapturedState, queueIdx uint16) (*Virtqueue, error) {
	commonCfgWriteU16(state, VirtioCfgQueueSelect, queueIdx)

	maxSize := commonCfgU16(state, VirtioCfgQueueSize)
	if maxSize == 0 {
		return nil, ErrQueueNotAvailable
	}
	// We allocated rings sized for the layout's stored queue size; cap
	// at maxSize and round to power of two.
	size := state.VQRingsLayout[queueIdx].Size
	if size > maxSize {
		size = maxSize
	}
	for size&(size-1) != 0 {
		size &= size - 1
	}
	if size == 0 {
		return nil, ErrInvalidQueueSize
	}
	commonCfgWriteU16(state, VirtioCfgQueueSize, size)

	// Read notify_off post-EBS for cross-check; we use the
	// pre-captured value to drive the doorbell.
	_ = commonCfgU16(state, VirtioCfgQueueNotifyOff)

	// Build the driver-side Virtqueue handle pointing at the
	// pre-allocated ring memory.
	q := NewVirtqueueFromAlloc(state.VQRingsPhys[queueIdx], uintptr(state.VQRingsPhys[queueIdx]), size, queueIdx)
	q.NotifyOff = state.VQNotifyOff[queueIdx]

	// Publish the descriptor / avail / used ring physical addresses.
	descAddr := q.BasePhys + uint64(q.Layout.DescTableOffset)
	availAddr := q.BasePhys + uint64(q.Layout.AvailRingOffset)
	usedAddr := q.BasePhys + uint64(q.Layout.UsedRingOffset)
	commonCfgWriteU64(state, VirtioCfgQueueDesc, descAddr)
	commonCfgWriteU64(state, VirtioCfgQueueDriver, availAddr)
	commonCfgWriteU64(state, VirtioCfgQueueDevice, usedAddr)
	commonCfgWriteU16(state, VirtioCfgQueueEnable, 1)
	return q, nil
}

// postEBSNotifyQueue writes the queue index to the per-queue
// notification address. Direct MMIO, no PciIo.Mem.Write. Per
// Virtio 1.1 §4.1.4.4 the doorbell address is
//
//	NotifyCfgPhys + queue_notify_off * NotifyOffMultiplier
//
// And the value is the 16-bit queue index. The R-M2c live narrow
// established that VZ honours a 32-bit write at the per-queue slot;
// we keep that width to stay compatible with both QEMU+EDK2 and VZ.
func postEBSNotifyQueue(state *CapturedState, queueIdx uint16, queueNotifyOff uint16) {
	addr := state.PCINotifyCfgPhys + uint64(queueNotifyOff)*uint64(state.PCINotifyOffMultiplier)
	mmioWriteU32(addr, uint32(queueIdx))
}

// fillRxPostEBS pre-posts queue-size RX buffers on the RX virtqueue.
// Each buffer is carved out of `state.rxPoolPhys` (pre-allocated
// pre-EBS), so we don't need to call AllocatePages here (which is
// gone post-EBS).
func (v *VirtioNetPostEBS) fillRxPostEBS() error {
	if v.RxQ == nil {
		return ErrQueueNotAvailable
	}
	state := v.State
	if state.rxPoolPhys == 0 {
		return ErrPostEBSNoCapture
	}
	bufSize := uintptr(VirtioNetHdrSize + VirtioNetMaxFrameSize)
	for i := uint16(0); i < v.RxQ.Layout.Size; i++ {
		off := uintptr(i) * bufSize
		if off+bufSize > uintptr(state.rxPoolSize) {
			break
		}
		addr := uintptr(state.rxPoolPhys) + off
		phys := state.rxPoolPhys + uint64(off)
		if _, err := v.RxQ.AddBuffer(addr, phys, uint32(bufSize), true); err != nil {
			return err
		}
	}
	return nil
}

// TransmitFramePostEBS sends one Ethernet frame over the TX
// virtqueue, post-EBS, via direct MMIO. Returns nil on completion,
// or a timeout sentinel if the device doesn't publish the used-ring
// entry within the busy-poll budget.
//
// Memory shape: the frame is staged into the TX scratch slab
// (pre-allocated by CapturePreEBS via state.txScratchPhys), with a
// 12-byte all-zero virtio_net_hdr prepended.
func (v *VirtioNetPostEBS) TransmitFramePostEBS(frame []byte) error {
	state := v.State
	if v.TxQ == nil || state.txScratchPhys == 0 {
		return ErrPostEBSNoCapture
	}
	totalLen := VirtioNetHdrSize + len(frame)
	if uint32(totalLen) > state.txScratchSize {
		return ErrFrameTooShort
	}
	// Zero the virtio_net_hdr (12 bytes) + copy the frame payload
	// into the post-EBS TX scratch.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(state.txScratchPhys))), totalLen)
	for i := 0; i < VirtioNetHdrSize; i++ {
		dst[i] = 0
	}
	copy(dst[VirtioNetHdrSize:], frame)

	PostEBSScratchAppend(state, postEBSTraceTxSubmit)
	descIdx, err := v.TxQ.AddBuffer(uintptr(state.txScratchPhys), state.txScratchPhys,
		uint32(totalLen), false)
	if err != nil {
		PostEBSScratchAppend(state, postEBSTraceFailMarker)
		return err
	}
	postEBSNotifyQueue(state, VirtioNetTxQueueIdx, state.VQNotifyOff[VirtioNetTxQueueIdx])
	PostEBSScratchAppend(state, postEBSTraceTxNotify)

	// Busy-poll for completion. Budget is bigger than M2's because
	// we're post-EBS without a wall-clock anchor; the host will hit
	// the harness's max-wall-clock if this hangs.
	const pollBudget = 1000000
	for spin := 0; spin < pollBudget; spin++ {
		gotIdx, _, ok := v.TxQ.PollUsed()
		if !ok {
			continue
		}
		_ = v.TxQ.Reclaim(gotIdx)
		PostEBSScratchAppend(state, postEBSTraceTxCompletion)
		_ = descIdx
		return nil
	}
	return ErrTransmitTimeout
}

// ReceiveFramePostEBS busy-polls the RX virtqueue for one new
// frame. Returns the Ethernet payload (header stripped) on success
// or `ErrReceiveTimeout` if the budget elapses.
func (v *VirtioNetPostEBS) ReceiveFramePostEBS(budget int) ([]byte, error) {
	if v.RxQ == nil {
		return nil, ErrPostEBSNoCapture
	}
	state := v.State
	for spin := 0; spin < budget; spin++ {
		descIdx, length, ok := v.RxQ.PollUsed()
		if !ok {
			continue
		}
		PostEBSScratchAppend(state, postEBSTraceRxCompletion)
		buf := v.RxQ.Buffers[descIdx]
		raw := unsafe.Slice((*byte)(unsafe.Pointer(buf.Addr)), int(length))
		out := make([]byte, len(raw))
		copy(out, raw)
		_ = v.RxQ.Reclaim(descIdx)
		// Re-post the buffer so the device can land another frame.
		if _, err := v.RxQ.AddBuffer(buf.Addr, buf.Phys, buf.Len, true); err == nil {
			postEBSNotifyQueue(state, VirtioNetRxQueueIdx, state.VQNotifyOff[VirtioNetRxQueueIdx])
		}
		return StripVirtioNetHdr(out)
	}
	return nil, ErrReceiveTimeout
}
