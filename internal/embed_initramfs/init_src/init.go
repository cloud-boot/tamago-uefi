// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Minimal arm64 Linux /init for the cloud-boot tamago-uefi M8.5
// initramfs. When the Linux EFI-stub kernel finishes unpacking the
// in-memory initramfs published via LINUX_EFI_INITRD_MEDIA_GUID, it
// execs /init as PID 1. This binary prints a marker line on every
// available console-ish path then halts cleanly via reboot(2).
//
// Why this is in a sub-package (not the parent embed_initramfs)
//
// The parent package targets the tamago-uefi build (which runs as
// EFI in UEFI/firmware context, not as Linux userspace). This file
// instead targets GOOS=linux GOARCH=arm64 — completely different
// build tags, ABI, and runtime. We isolate it under init_src/ so
// the parent's `go build` never tries to compile a Linux-syscall
// program with tamago build tags, and `go vet ./...` over the
// parent module skips it cleanly via the explicit build tag below.
//
// Build (host, reproducible):
//
//	cd internal/embed_initramfs/init_src
//	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
//	    go build -trimpath -ldflags='-s -w' -o init ./init.go
//
// Then package as cpio.gz alongside the embed:
//
//	mkdir -p root && cp init root/init && chmod +x root/init
//	(cd root && find . | LC_ALL=C sort | cpio -o -H newc) \
//	    | gzip -9n > ../initramfs.cpio.gz
//
// The single static binary is ~1.3 MiB stripped; the resulting
// cpio.gz is ~520 KiB. Reproducible thanks to -trimpath +
// LC_ALL=C sort + gzip -n.

//go:build ignore

package main

import (
	"os"
	"syscall"
)

// LINUX_REBOOT_CMD_POWER_OFF is the third argument to the reboot(2)
// syscall that powers the machine off cleanly. We prefer power-off
// to halt because QEMU's -no-reboot turns it into qemu-exit, which
// gives a deterministic end-of-run for the live test harness.
const linuxRebootCmdPowerOff = 0x4321FEDC

// LINUX_REBOOT_MAGIC1 / LINUX_REBOOT_MAGIC2 are the two magic
// numbers reboot(2) requires. Without these the kernel returns
// -EINVAL and we'd loop forever.
const (
	linuxRebootMagic1 = 0xFEE1DEAD
	linuxRebootMagic2 = 0x28121969
)

// banner is printed verbatim to every console-ish FD we can find.
// The leading newlines push it past any in-flight kernel log
// fragment so a grep on the QEMU stdout reliably matches.
const banner = "\n\n[M8.5] /init reached. cloud-boot tamago-uefi initramfs handoff PASS.\n\n"

func main() {
	// Stdout (fd 1) is what the kernel wires to the console when
	// the EFI-stub passes console=ttyAMA0,115200. Write there
	// first so the most likely path succeeds early.
	_, _ = os.Stdout.WriteString(banner)

	// Belt-and-suspenders: open /dev/console directly. On some
	// kernels stdout is not wired up for the very first userspace
	// process, so writing the marker to /dev/console as well
	// guarantees the QEMU stdout sees it.
	if f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
		_, _ = f.WriteString(banner)
		_ = f.Sync()
		_ = f.Close()
	}

	// kmsg gives a second backup path that ends up in dmesg even
	// if console wiring is broken.
	if f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0); err == nil {
		_, _ = f.WriteString(banner)
		_ = f.Close()
	}

	// Clean power-off so the live test harness sees QEMU exit.
	// If reboot fails (no CAP_SYS_BOOT in some pid-namespace
	// edge case, etc.), fall through to the spin-forever loop so
	// the kernel doesn't panic on init exit.
	_, _, _ = syscall.Syscall(
		syscall.SYS_REBOOT,
		uintptr(uint32(linuxRebootMagic1)),
		uintptr(uint32(linuxRebootMagic2)),
		uintptr(uint32(linuxRebootCmdPowerOff)),
	)

	// If reboot returned (it shouldn't on success), park here
	// forever rather than letting PID 1 exit, which would panic
	// the kernel with "Attempted to kill init!".
	for {
		select {}
	}
}
