// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board -- io.Writer adapter over gST->ConOut
// (Phase 2, M9.1 fallback path).
//
// The M9.1 boot-menu renderer writes its frame as a single []byte to
// an io.Writer sink. The production sink is a go-virtio/console
// VirtioConsole. When the firmware has no virtio-console device
// (a runner without `-device virtio-serial-pci -device virtconsole`,
// or a target whose firmware doesn't expose virtio-serial at all),
// the renderer falls back to this adapter, which routes Write through
// the same printk path board.go uses for runtime serial output.
//
// Lifetime: shares a single goroutine-unsafe sink (the ConOut
// protocol). The menu loop is single-goroutine so there's no
// contention. After ExitBootServices the ConOut protocol is invalid
// and Write becomes a no-op — but the M9.2 menu loop runs WHILE
// boot services are alive (LoadImage / StartImage destroy boot
// services only inside the chosen entry's chained handoff), so this
// adapter is always called from the live-BS phase.
//
// Gated on `tamago` because the printk path itself only links in the
// tamago build (board.go is tamago-only). Host tests construct the
// Renderer with a *bytes.Buffer directly, so they never need this
// adapter.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

// ConOutWriter implements io.Writer over the same printk path runtime
// prints already use. Zero-value safe: Write on a zero ConOutWriter
// emits to the package-global conOut variable established by
// cpuinit_<arch>.s, which is the only path callers should rely on.
type ConOutWriter struct{}

// Write emits every byte of p through printk. Returns len(p), nil
// unconditionally — the underlying firmware call has no per-byte
// failure mode the M9.1 menu cares about (the renderer's contract
// is "best-effort paint"; if the firmware drops a byte the next
// 100 ms tick repaints).
func (ConOutWriter) Write(p []byte) (int, error) {
	for _, c := range p {
		printk(c)
	}
	return len(p), nil
}
