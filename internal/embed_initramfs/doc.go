// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

// Package embed_initramfs ships a minimal gzip-compressed cpio
// (initramfs) blob the M8.4 MODE C path publishes via
// uefiboard.PublishInitrd, so the Linux EFI-stub finds an initrd at
// LINUX_EFI_INITRD_MEDIA_GUID and proceeds past the no-initrd
// DataAbort observed at the M8.3 acceptance gate.
//
// Why an embed and not OCI streaming
//
// The OCI streaming path is exercised separately for the kernel
// layer (siderolabs/kernel — see phase2_oci_kernel_boot.go). For the
// initrd we did not find a publicly-pullable matching artifact in
// the M8.4 budget: siderolabs publishes initramfs only as part of
// the `installer` aggregate (multi-layer, ~120 MiB), and there is
// no anonymous standalone initramfs OCI ref in the Talos catalogue.
// Pushing a hand-rolled one to ttl.sh would work but adds an
// extra runtime dependency (ttl.sh's 24h TTL) to every live-test
// invocation; embedding gives a deterministic boot that doesn't
// drift if ttl.sh is unreachable or expires.
//
// M8.5 update — real /init binary
//
// Until M8.5 the embed was a 260-byte cpio.gz containing only a
// shell-script /init. The arm64 Linux kernel could LoadFile2 the
// blob (see the "Loaded initrd from LINUX_EFI_INITRD_MEDIA_GUID"
// trace line) but then failed silently at unpack/exec time because
// (a) /init was #!/bin/sh and no /bin/sh existed in the rootfs and
// (b) the kernel rejects shell-script init on the populate_rootfs
// path before it ever tries to spawn anything. M8.5 replaces the
// fixture with a statically-linked aarch64 Go program (~1.3 MiB
// stripped, ~570 KiB after gzip) that prints a marker line on
// /dev/console + /dev/kmsg + stdout, then powers off cleanly via
// reboot(2) LINUX_REBOOT_CMD_POWER_OFF. This is the smallest
// /init the kernel will actually exec end-to-end.
//
// Layout (cpio newc + gzip):
//
//	./init    (static aarch64 ELF, ~1.3 MiB, no libc)
//
// Total compressed size: ~570 KiB — still small enough to inline
// in the EFI binary; the parent kernelboot EFI grows from the
// previous ~7 MiB baseline by under 1 MiB.
//
// Construction (host-side, reproducible)
//
// The /init source + build script live in the init_src/ sibling
// directory. To rebuild from scratch:
//
//	cd internal/embed_initramfs/init_src
//	./build.sh
//
// The script:
//   - GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -trimpath
//     -ldflags='-s -w' produces a deterministic static ELF /init
//   - LC_ALL=C sort gives a deterministic cpio entry order
//   - gzip -n drops mtime/filename from the gzip header
// Result: bit-reproducible initramfs.cpio.gz for a fixed Go
// toolchain version.
//
// Multiarch
//
// Today the M8.x kernel-boot path is arm64-only (live) — see
// kernelboot_arm64.go. The riscv64 + loong64 MODE C scaffolding
// from M8.3 doesn't yet boot Linux end-to-end (no validated public
// EFI-stub kernel OCI ref for those archs), so a single arm64
// /init covers the only live target. When riscv64/loong64 join,
// either fan this embed out to per-arch blobs (init_src/init.<arch>
// builds + per-arch *.cpio.gz embeds) or keep a single blob with
// per-arch /init.<arch> ELFs plus a tiny static dispatcher — TBD
// per M8.x as those archs come online.
//
// The blob is gzip-compressed (`1f 8b 08` magic) so the MODE C
// gzip-detect path in phase2_oci_kernel_boot.go treats it
// identically to a real distro initramfs (which is always
// gzip-compressed cpio per Documentation/admin-guide/initrd.rst).
package embed_initramfs
