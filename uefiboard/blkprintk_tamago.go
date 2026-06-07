// cloud-boot UEFI board — Block IO side-channel print sink (Phase 2,
// M1.6) — live Flush thunk.
//
// The ring + serializer + wrap-around live in blkprintk.go and are
// host-testable. This file ships the Flush method that calls into
// EFI_BLOCK_IO_PROTOCOL.WriteBlocks + FlushBlocks; it's gated on
// `tamago` so the host test harness compiles without efiCall.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// Flush serializes the ring buffer's current state to disk via the
// bound EFI_BLOCK_IO_PROTOCOL.WriteBlocks call, then issues
// FlushBlocks to push firmware caches through to the device.
//
// Workflow:
//
//  1. Bump the monotonic write counter (so the in-frame count
//     reflects the flush we're about to do, not the previous one).
//  2. Serialize the ring into a BlkRingCapacity-byte frame.
//  3. WriteBlocks(ring.lba, frame).
//  4. FlushBlocks — required because firmware caches MAY hold the
//     write until the next idle moment, but we're about to halt so
//     there's no idle moment.
//  5. ResetAutoFlush so the next auto-flush trigger uses a fresh
//     byte budget.
//
// Returns the underlying *EFIError if WriteBlocks or FlushBlocks
// fails; or ErrNoBlockIOSink if BindBlockIO wasn't called.
func (r *BlkRingBuffer) Flush() error {
	if !r.IsBound() {
		return ErrNoBlockIOSink
	}
	r.IncrementWriteCount()
	frame := r.Serialize()
	if err := BlockIOWriteBlocks(r.blockIO, r.mediaID, r.lba, frame); err != nil {
		return err
	}
	if err := BlockIOFlushBlocks(r.blockIO); err != nil {
		// Best-effort flush — if the firmware refuses, the write
		// already landed in the firmware's write-cache and most VMs
		// will commit it on halt. Surface the error so the caller can
		// log + decide.
		return err
	}
	r.ResetAutoFlush()
	return nil
}

// BlkPrintk is the byte-stream entry point — wire it up the same way
// the ConOut sink is wired (printk in board.go) when the side-channel
// is in use. Appends the byte to the ring; on the sentinel byte
// (`BlkSentinel`), flushes immediately; otherwise flushes only when
// the auto-flush threshold is crossed.
//
// Returns no error — failures inside Flush are swallowed (we still
// have the ring in RAM, and the next flush attempt may succeed). The
// alternative — propagating the error — would require every printk
// caller to handle it, which Phase 1 / M0 / M1 / M1.5 don't.
func (r *BlkRingBuffer) BlkPrintk(b byte) {
	r.Append(b)
	if b == BlkSentinel {
		_ = r.Flush()
		return
	}
	if r.AutoFlushReady() {
		_ = r.Flush()
	}
}
