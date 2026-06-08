// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// tamago-build deadline checker — uses an iteration cap instead of
// time.Since. Under the UEFI runtime, time.Since has been observed
// to misbehave (Nanotime quirks or Boot Services / scheduler
// interaction), making wall-clock comparisons unreliable. A hard
// iter cap guarantees the inline RX pump terminates; on QEMU+EDK2
// the ARP/ICMP reply usually arrives within 2-3 iterations, so the
// cap is academic for the happy path.

//go:build tamago

package ministack

import "time"

// maxPumpIters is the iteration cap for the inline RX pump loops in
// resolveARP and PingOnce. Each iteration calls link.RecvFrame which
// is bounded (~256 PCI MMIO reads on the tamago path), so the total
// loop wall-clock is in the seconds range — comparable to a 1-2 s
// network timeout, which is what the callers ask for.
const maxPumpIters = 1_000_000

type deadlineChecker struct {
	n    int
	stop int
}

func newDeadlineChecker(timeout time.Duration) *deadlineChecker {
	// timeout is unused on tamago; honored on host. Kept in the API
	// for symmetry.
	_ = timeout
	return &deadlineChecker{stop: maxPumpIters}
}

// expired reports whether the iteration cap has been reached.
func (d *deadlineChecker) expired() bool {
	return d.n >= d.stop
}

// tick advances the iteration counter. Called once per pump iteration.
func (d *deadlineChecker) tick() {
	d.n++
}
