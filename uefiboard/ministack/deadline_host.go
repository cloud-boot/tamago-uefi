// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Host-build deadline checker — used by unit tests where `time.Since`
// behaves normally. The tamago target uses an iter-count fallback
// (see deadline_tamago.go) because time.Since has been observed to
// misbehave under the UEFI runtime.

//go:build !tamago

package ministack

import "time"

// deadlineChecker bounds the inline RX pump loop. Honors the caller's
// timeout via wall-clock on host builds.
type deadlineChecker struct {
	start   time.Time
	timeout time.Duration
}

func newDeadlineChecker(timeout time.Duration) *deadlineChecker {
	return &deadlineChecker{start: time.Now(), timeout: timeout}
}

// expired reports whether the wall-clock deadline has passed.
func (d *deadlineChecker) expired() bool {
	return time.Since(d.start) >= d.timeout
}

// tick is a no-op on host. The tamago variant uses it to count iters.
func (d *deadlineChecker) tick() {}
