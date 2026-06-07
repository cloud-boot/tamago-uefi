// cloud-boot UEFI board — Virtio-net driver: live device bring-up + TX/RX
// (Phase 2, M2).
//
// `OpenVirtioNet(pciIO)` drives the full init sequence per Virtio 1.1
// §3.1.1, allocates the rxq + txq, pre-posts N receive buffers, and
// returns a `*VirtioNet` ready for `TransmitFrame` / `ReceiveFrame`.
//
// References:
//
//   - Virtio 1.1 §3.1.1 — the 8-step status-bit dance below.
//   - Virtio 1.1 §5.1.2 — virtio-net queue indices (rxq=0, txq=1).
//   - Virtio 1.1 §5.1.4 — MAC at DeviceCfg offset 0.
//   - OvmfPkg/VirtioNetDxe/SnpInitialize.c — EDK2's equivalent of
//     OpenVirtioNet; we follow the same ordering (not its code).

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import "unsafe"

// VirtioNet wraps one initialised virtio-net device. Held by the
// caller for the lifetime of the probe; the underlying virtqueue
// pages live until ExitBootServices (EfiBootServicesData).
type VirtioNet struct {
	// Cfg is the modern-transport handle (BARs + offsets + the pciIO
	// pointer). Every register access routes through here.
	Cfg *VirtioModernConfig

	// MAC is the device-published MAC address (Virtio 1.1 §5.1.4).
	// Read after FEATURES_OK at OpenVirtioNet completion.
	MAC MAC6

	// NegotiatedFeatures records what the driver-feature handshake
	// settled on. Exposed for the probe's "we accepted X" diagnostic.
	NegotiatedFeatures uint64

	// rxq / txq are the two virtqueues set up by OpenVirtioNet.
	rxq *Virtqueue
	txq *Virtqueue
}

// OpenVirtioNetWithFeatures drives the full bring-up of one virtio-net
// device with a caller-supplied accepted-features override. The
// override is applied AFTER the device's offered bitmap is read, so
// the negotiated mask is `deviceFeats & overrideAcceptedFeatures`
// (with VIRTIO_F_VERSION_1 and VIRTIO_NET_F_MAC requirements still
// enforced).
//
// Used by the R-M2c narrow to test whether widening the accepted set
// (e.g. acknowledging Apple's private bits 28/29) unblocks the TX
// path on VZ.
func OpenVirtioNetWithFeatures(pciIO uint64, overrideAcceptedFeatures uint64) (*VirtioNet, error) {
	return openVirtioNetCore(pciIO, overrideAcceptedFeatures)
}

// OpenVirtioNet drives the full bring-up of one virtio-net device.
// Caller has located the EFI_PCI_IO_PROTOCOL handle and verified
// VID:DID = 1AF4:1041 (modern net).
//
// On success the device is in DRIVER_OK state, rxq is pre-posted
// with VirtioNetRxRingSize buffers, txq is empty + ready, and MAC
// is set.
func OpenVirtioNet(pciIO uint64) (*VirtioNet, error) {
	return openVirtioNetCore(pciIO, VirtioNetAcceptedFeatures)
}

// openVirtioNetCore is the body of OpenVirtioNet, parameterised on the
// accepted-features mask. The mask MUST include VirtioFeatureVersion1
// and VirtioNetFeatureMAC or AcceptFeatures will reject the
// negotiation (those are M2's hard requirements).
func openVirtioNetCore(pciIO uint64, acceptedFeatures uint64) (*VirtioNet, error) {
	// Sanity-check that this really is a modern virtio-net device.
	// The probe should have done this already; we double-check
	// because OpenVirtioNet is the public API + a wrong DID here is
	// catastrophic (we'd write to the wrong device's MMIO).
	did, err := PciIOReadConfigU16(pciIO, PCICfgDeviceID)
	if err != nil {
		return nil, err
	}
	if did != VirtioPCIDeviceIDModernNet {
		return nil, ErrInitWrongDeviceID
	}

	cfg, err := InitVirtioModernConfig(pciIO)
	if err != nil {
		return nil, err
	}

	// Step 0 — defensive PCI bus-master + memory enable.
	// EFI_PCI_IO_PROTOCOL.Attributes(Enable, Memory | BusMaster)
	// asserts the device-side BME bit so the device's DMA can flow.
	// Live narrow finding (R-M2c, 2026-06-07): both QEMU+EDK2 and
	// Apple VZ pre-enable these bits at firmware bind time, so this
	// call is observed as a no-op on the canonical PCI command
	// register read-back (`PciIOReadConfigU16(pciIO, PCICfgCommand)`
	// returns `0x07` on QEMU+EDK2 and `0x16` on VZ both BEFORE and
	// AFTER the call). Kept as a defensive guard for hypothetical
	// future firmware that doesn't pre-enable; harmless when the
	// bits are already set.
	if attrErr := PciIOAttributesEnable(pciIO, EFIPciIOAttributeMemory|EFIPciIOAttributeBusMaster); attrErr != nil {
		return nil, attrErr
	}

	// Step 1: full reset (write 0 to DeviceStatus).
	if err := cfg.SetDeviceStatus(0); err != nil {
		return nil, err
	}
	// Spec §3.1.1: after reset, DeviceStatus reads back as 0.
	if s, err := cfg.DeviceStatus(); err != nil {
		return nil, err
	} else if s != 0 {
		// Some firmware needs a moment; we don't sleep — fall through.
		_ = s
	}

	// Step 2: ACKNOWLEDGE.
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge); err != nil {
		return nil, err
	}
	// Step 3: DRIVER.
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge | VirtioStatusDriver); err != nil {
		return nil, err
	}

	// Step 4: read DeviceFeature, mask, write DriverFeature.
	deviceFeats, err := cfg.DeviceFeatures64()
	if err != nil {
		return nil, err
	}
	// VERSION_1 + MAC remain hard requirements; otherwise we honour
	// the caller-supplied accepted mask.
	if deviceFeats&VirtioFeatureVersion1 == 0 {
		return nil, ErrNotModernDevice
	}
	negotiated := deviceFeats & acceptedFeatures
	if negotiated&VirtioNetFeatureMAC == 0 {
		return nil, ErrNoMACFeature
	}
	if err := cfg.SetDriverFeatures64(negotiated); err != nil {
		return nil, err
	}

	// Step 5: FEATURES_OK + verify the device accepted our subset.
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge | VirtioStatusDriver | VirtioStatusFeaturesOK); err != nil {
		return nil, err
	}
	status, err := cfg.DeviceStatus()
	if err != nil {
		return nil, err
	}
	if status&VirtioStatusFeaturesOK == 0 {
		return nil, ErrFeaturesNotOK
	}

	// Step 6: queue setup.
	rxq, err := setupQueue(cfg, VirtioNetRxQueueIdx, VirtioNetRxRingSize)
	if err != nil {
		return nil, err
	}
	txq, err := setupQueue(cfg, VirtioNetTxQueueIdx, VirtioNetTxRingSize)
	if err != nil {
		return nil, err
	}

	// Step 7: DRIVER_OK.
	if err := cfg.SetDeviceStatus(VirtioStatusAcknowledge | VirtioStatusDriver | VirtioStatusFeaturesOK | VirtioStatusDriverOK); err != nil {
		return nil, err
	}

	// Read MAC (6 bytes from DeviceCfg @ offset 0). R-M1.6a bounds
	// check is enforced inside `DeviceCfgRead8`.
	var mac MAC6
	for i := uint32(0); i < 6; i++ {
		b, err := cfg.DeviceCfgRead8(i)
		if err != nil {
			return nil, err
		}
		mac[i] = b
	}
	if mac.IsZero() {
		// Some firmwares fill MAC lazily after DRIVER_OK; we don't
		// retry here, but we surface the suspicious read so the
		// probe can flag it. (QEMU and VZ both publish the MAC by
		// the time we get here.)
		return nil, ErrMACReadFailed
	}

	v := &VirtioNet{
		Cfg:                cfg,
		MAC:                mac,
		NegotiatedFeatures: negotiated,
		rxq:                rxq,
		txq:                txq,
	}

	// Pre-post N receive buffers so the device has somewhere to
	// land incoming frames.
	if err := v.fillRxRing(); err != nil {
		return nil, err
	}
	// Notify the device that the rxq has buffers available — VZ in
	// particular won't deliver frames otherwise.
	if err := cfg.NotifyQueue(VirtioNetRxQueueIdx, rxq.NotifyOff); err != nil {
		return nil, err
	}

	return v, nil
}

// setupQueue performs the per-queue init: select, read max-size,
// write our size (= max), allocate the Virtqueue, write its
// descriptor/avail/used physical addresses, enable.
func setupQueue(cfg *VirtioModernConfig, queueIdx uint16, desiredSize uint16) (*Virtqueue, error) {
	if err := cfg.SelectQueue(queueIdx); err != nil {
		return nil, err
	}
	maxSize, err := cfg.QueueSize()
	if err != nil {
		return nil, err
	}
	if maxSize == 0 {
		// Device doesn't have this queue; spec says the driver
		// should not use it.
		return nil, ErrQueueNotAvailable
	}
	size := desiredSize
	if size > maxSize {
		size = maxSize
	}
	// Round size DOWN to a power of two; some QEMU versions report
	// non-power-of-two QueueSize on legacy queues.
	for size&(size-1) != 0 {
		size &= size - 1
	}
	if size == 0 {
		return nil, ErrInvalidQueueSize
	}
	if err := cfg.SetQueueSize(size); err != nil {
		return nil, err
	}
	notifyOff, err := cfg.QueueNotifyOff()
	if err != nil {
		return nil, err
	}
	q, err := NewVirtqueue(size, queueIdx, notifyOff)
	if err != nil {
		return nil, err
	}
	// Publish addresses.
	descAddr := q.BasePhys + uint64(q.Layout.DescTableOffset)
	availAddr := q.BasePhys + uint64(q.Layout.AvailRingOffset)
	usedAddr := q.BasePhys + uint64(q.Layout.UsedRingOffset)
	if err := cfg.SetQueueDesc(descAddr); err != nil {
		return nil, err
	}
	if err := cfg.SetQueueDriver(availAddr); err != nil {
		return nil, err
	}
	if err := cfg.SetQueueDevice(usedAddr); err != nil {
		return nil, err
	}
	if err := cfg.SetQueueEnable(1); err != nil {
		return nil, err
	}
	return q, nil
}

// ErrQueueNotAvailable surfaces the spec's "QueueSize=0 means queue
// doesn't exist" condition.
var ErrQueueNotAvailable = vpciError("uefi: virtio-net: device reports QueueSize=0 for required queue")

// fillRxRing posts VirtioNetRxRingSize receive buffers on the rxq.
// Each buffer is `VirtioNetHdrSize + VirtioNetMaxFrameSize` bytes
// (the device writes the virtio header first, then the Ethernet
// frame).
func (v *VirtioNet) fillRxRing() error {
	for i := uint16(0); i < v.rxq.Layout.Size; i++ {
		phys, addr, err := AllocDMABuffer(VirtioNetHdrSize + VirtioNetMaxFrameSize)
		if err != nil {
			return err
		}
		// writable=true ⇒ VIRTQ_DESC_F_WRITE set.
		if _, err := v.rxq.AddBuffer(addr, phys, VirtioNetHdrSize+VirtioNetMaxFrameSize, true); err != nil {
			return err
		}
	}
	return nil
}

// RxQueue / TxQueue expose the per-direction *Virtqueue handles. The
// fields themselves stay unexported so callers can't reseat them; these
// getters give the R-M2c diagnostic dump (and any future
// observability surface) read-only access to descriptor / avail / used
// ring bytes.
func (v *VirtioNet) RxQueue() *Virtqueue { return v.rxq }
func (v *VirtioNet) TxQueue() *Virtqueue { return v.txq }

// TransmitFrame prepends a virtio_net_hdr to `frame`, allocates a
// DMA-visible buffer, copies the header + payload in, enqueues it
// on the txq, notifies the device, and polls the used ring for
// completion (the device returns the descriptor when it has read
// the frame and pushed it onto the host network).
//
// Polls for up to ~100ms (10000 * ~10us each, accounting for the
// firmware call overhead). On VZ this is far more than needed; on
// QEMU+EDK2 the round-trip is usually < 1ms.
func (v *VirtioNet) TransmitFrame(frame []byte) error {
	totalLen := VirtioNetHdrSize + len(frame)
	phys, addr, err := AllocDMABuffer(uintptr(totalLen))
	if err != nil {
		return err
	}
	// Header is already zero-initialised by AllocDMABuffer.
	// Copy the frame payload after the header.
	dst := unsafe.Slice((*byte)(unsafe.Pointer(addr)), totalLen)
	copy(dst[VirtioNetHdrSize:], frame)

	if _, err := v.txq.AddBuffer(addr, phys, uint32(totalLen), false /* writable=false: TX is device-read-only */); err != nil {
		return err
	}
	// Notify the device.
	if err := v.Cfg.NotifyQueue(VirtioNetTxQueueIdx, v.txq.NotifyOff); err != nil {
		return err
	}
	// Poll for TX completion. Budget bumped to 200000 from M2's
	// initial 10000 — the R-M2c live narrow surfaced that even on
	// QEMU+EDK2 amd64 a 10000-spin window can occasionally miss the
	// device's used-ring publish under load (especially with the
	// diagnostic side-channel tee writing to a virtio-blk scratch
	// disk between TX submissions). 200000 polls is still a small
	// fraction of a second of wall-clock; the device's true
	// round-trip on a healthy QEMU host is in the microseconds, so
	// no real-world workload should see this budget exhaust.
	for spin := 0; spin < 200000; spin++ {
		gotIdx, _, ok := v.txq.PollUsed()
		if !ok {
			continue
		}
		// Free the descriptor slot.
		_ = v.txq.Reclaim(gotIdx)
		return nil
	}
	return ErrTransmitTimeout
}

// ReceiveFrame polls the rxq for one new frame. Returns the Ethernet
// payload (header stripped) on success, or ErrReceiveTimeout if no
// frame arrives within `pollIterations` busy-spin cycles (~100ms
// equivalent on QEMU; less on VZ).
//
// The returned slice is a copy from the descriptor's DMA buffer —
// safe to retain after this call returns (and after the descriptor
// is reclaimed and refilled).
func (v *VirtioNet) ReceiveFrame(pollIterations int) ([]byte, error) {
	for spin := 0; spin < pollIterations; spin++ {
		descIdx, length, ok := v.rxq.PollUsed()
		if !ok {
			continue
		}
		// `length` is the byte count the device wrote (header + frame).
		buf := v.rxq.Buffers[descIdx]
		raw := unsafe.Slice((*byte)(unsafe.Pointer(buf.Addr)), int(length))
		// Copy out so we don't have to keep the descriptor pinned
		// while the caller inspects the bytes.
		out := make([]byte, len(raw))
		copy(out, raw)
		// Reclaim + refill so the device has somewhere to land the
		// next frame.
		_ = v.rxq.Reclaim(descIdx)
		// Re-post the same descriptor's buffer (it's still
		// allocated; we just need the device to see it as available
		// again).
		if _, err := v.rxq.AddBuffer(buf.Addr, buf.Phys, buf.Len, true); err != nil {
			// Re-post failed; we're degraded but the frame we just
			// captured is still good to return.
		}
		if err := v.Cfg.NotifyQueue(VirtioNetRxQueueIdx, v.rxq.NotifyOff); err != nil {
			// Same — degraded but we have the frame.
		}
		return StripVirtioNetHdr(out)
	}
	return nil, ErrReceiveTimeout
}

// ErrTransmitTimeout / ErrReceiveTimeout fire when the busy-poll
// loop's iteration budget is exhausted. Surfaced cleanly so the
// probe can distinguish "device didn't respond at all" from "device
// rejected the frame" (different status surfaces).
var (
	ErrTransmitTimeout = vpciError("uefi: virtio-net: TX poll timeout (device did not return descriptor)")
	ErrReceiveTimeout  = vpciError("uefi: virtio-net: RX poll timeout (no frame received within budget)")
)
