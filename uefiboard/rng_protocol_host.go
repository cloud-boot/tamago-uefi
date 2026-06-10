// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — host-side rng entropy stub. Used only
// when building on a non-tamago target (i.e. `go test`); the live
// tamago build pulls a crypto/rand-backed source from
// rng_protocol_tamago.go.
//
// The stub is deterministic (a counter starting at 0xA0 + offset)
// so unit tests in rng_protocol_test.go can assert exact byte
// patterns without flake. Tests that need to exercise short-read
// handling can override rngEntropy directly.

//go:build !tamago

package uefiboard

import "unsafe"

func init() {
	rngEntropy = readDeterministicHost
}

//go:nosplit
func readDeterministicHost(buf uintptr, n uintptr) uintptr {
	for i := uintptr(0); i < n; i++ {
		*(*byte)(unsafe.Pointer(buf + i)) = byte(0xA0) + byte(i)
	}
	return n
}
