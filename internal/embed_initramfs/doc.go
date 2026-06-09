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
// The initrd is tiny by design (a single executable /init that
// prints a marker line and otherwise does nothing — when init
// exits the kernel panics "Attempted to kill init!", which is
// itself a clean PASS marker for "kernel reached userspace from
// initramfs"). The point of M8.4 is to prove the DTB + initrd
// handoff plumbing, not to ship a usable distro.
//
// Layout (cpio newc + gzip):
//
//	./init    (executable shell script, 169 bytes, just `echo` + sync)
//
// Total compressed size: ~260 bytes — small enough to inline in
// the EFI binary with negligible footprint.
//
// Construction (host-side, reproduced from internal notes):
//
//	mkdir -p root && cat > root/init <<'SH'
//	#!/bin/sh
//	echo "cloud-boot-m83: init reached" > /dev/console
//	sync
//	SH
//	chmod +x root/init
//	(cd root && find . | LC_ALL=C sort | cpio -o -H newc | gzip -9n) \
//	    > initramfs.cpio.gz
//
// The blob is gzip-compressed (`1f 8b 08` magic) so the MODE C
// gzip-detect path in phase2_oci_kernel_boot.go treats it
// identically to a real distro initramfs (which is always
// gzip-compressed cpio per Documentation/admin-guide/initrd.rst).
package embed_initramfs
