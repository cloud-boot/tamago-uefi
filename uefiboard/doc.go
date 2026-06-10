// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

// Package uefiboard wraps the UEFI Boot Services + a small set of
// EFI_*_PROTOCOL bindings the cloud-boot Phase-2 probes use to drive
// virtio devices, allocate firmware-owned pages, hand control to a
// chained EFI image, and (M9.1+) render an interactive menu on either
// a virtio-console or ConOut sink.
//
// # Things that BLOCK or MISBEHAVE under TamaGo+UEFI
//
// Read this list before adding new probe / loader code that depends
// on the Go runtime's scheduler-driven primitives. The TamaGo runtime
// runs single-threaded with `haveSysmon = false` on every supported
// arch (amd64, arm64, riscv64, loong64) — see
// tamago-pie/src/runtime/proc.go const declaration of `haveSysmon`.
// That means:
//
//   - NO sysmon background thread → no off-G timer wheel servicing.
//   - NO netpoll-driven wakeup → ministack uses inline RX pumping
//     (see `ministack/arp.go`, `ministack/udp4.go`, the
//     "drive RX inline" pattern).
//   - NO async preemption thread on arm64/riscv64/loong64. amd64 post
//     R-amd64g has SIGURG-based async preemption for cooperating
//     long-running goroutines, but that does NOT bring a timer-driver
//     thread back; the timer wheel still needs an active G to advance.
//
// Concrete consequences:
//
//   - time.Sleep(d) BLOCKS PAST ITS DEADLINE when no other goroutine
//     is alive to advance the timer wheel. The kernel-side scheduler
//     parks the calling G on a timer; with sysmon disabled and no
//     other runnable G, nothing wakes it. Use `busyWait(d)` (see
//     `phase2_dhcp_oci_menu.go`) — a spin loop on `time.Now()` — when
//     the call site is the sole goroutine. (`time.Sleep` is safe to
//     use INSIDE the rxLoop of `ministack/stack.go` because that loop
//     is itself the timer driver for ministack — sleeping there yields
//     the scheduler but the next loop iteration drives the wheel.)
//
//   - io.Pipe / chan-based producer-consumer pairs DEADLOCK the moment
//     the consumer blocks on Read before the producer goroutine has
//     been scheduled. See R-M8.3b (io.Pipe → buffered bytes.Buffer
//     refactor in `phase2_oci_kernel_boot.go`).
//
//   - select { case <-ch: case <-time.After(d): } has BOTH failure
//     modes above. Avoid in single-goroutine code paths.
//
//   - sync.WaitGroup.Wait() / chan receive blocks of any kind in a
//     loader path that's currently the sole G will hang forever.
//     Use synchronous helpers + tight polling instead.
//
// # M9.1 virtio-console subdevice not surfaced by EDK2 stable202408 arm64
//
// R-M9.1a (DOCUMENTED 2026-06-10) — when QEMU is launched with
// `-device virtio-serial-pci -device virtconsole,...`, the modern
// virtio-console PCI subdevice (vendor 0x1AF4, device 0x1043) is
// NOT enumerated through `EFI_PCI_IO_PROTOCOL` on EDK2 stable202408
// arm64 virt. Root cause: EDK2's `OvmfPkg/VirtioDxe` driver
// `BindingStart`s on the virtio-console PCI handle BY_DRIVER, which
// removes the bare `EFI_PCI_IO_PROTOCOL` instance from the OS-facing
// handle space (UEFI 2.10 §6.3 — a BY_DRIVER open hides the protocol
// from `LocateHandleBuffer`). The driver then publishes its own
// child-device protocols (`EFI_SERIAL_IO_PROTOCOL`,
// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL`) on the child handle, which is the
// way the firmware exposes the device to ConOut.
//
// Operational mode: `LocateVirtioConsolePciIO` returns 0, and the
// M9.1 menu probe falls back to `ConOutWriter{}`, which routes the
// menu through `gST->ConOut`. The firmware's
// `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` is itself backed by the same
// virtio-console child handle (when `-device virtconsole` is wired),
// so the bytes still reach the QEMU char-device sink the user
// configured — they just go through the firmware's text-mode wrapper
// instead of the raw virtio-console transport.
//
// The virtio-console transport path (OpenVirtioConsole +
// UEFITransport) is exercised by the host-side tests
// (`virtio_uefi_transport_test.go` mocks the EFI_PCI_IO_PROTOCOL
// methods) so the M9.1 code is verified end-to-end at the unit-test
// level even when no firmware exposes 0x1043 to OS enumeration. A
// future M9.x sub-task can validate the real-firmware virtio-console
// path on either (a) an amd64 q35 runner with a newer EDK2 build
// (stable202605+ reportedly relaxes the BY_DRIVER hide) or (b) a
// QEMU virtio-console-pci shim that publishes the bare PCI handle
// (no VirtioDxe binding).
package uefiboard
