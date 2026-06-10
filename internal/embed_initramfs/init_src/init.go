// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Minimal aarch64 Linux /init for the cloud-boot tamago-uefi
// initramfs. When the Linux EFI-stub kernel finishes unpacking the
// in-memory initramfs published via LINUX_EFI_INITRD_MEDIA_GUID it
// execs /init as PID 1. Up to M8.5 this binary only printed a marker
// line then powered off; this Phase 2 Path D iteration brings up a
// real, useful "minimal Linux userspace":
//
//  1. Mount the standard pseudo-filesystems (/proc, /sys, /dev,
//     /tmp). Without /proc + /sys nothing further can introspect
//     the running kernel; /dev as a tmpfs lets us open /dev/kmsg
//     even when devtmpfs auto-mount is off; /tmp gives us a
//     scratch surface for diagnostics that don't deserve disk.
//  2. Read /proc/cmdline and echo it to /dev/kmsg so the kernel
//     log captures the operator-visible boot arguments — handy
//     when triaging "why did /init see <X>" tickets.
//  3. Print a clear banner identifying this as the Path D /init.
//  4. Dump the standard "did the box come up sane?" facts:
//     kernel version (uname), mount table, total RAM, CPU count,
//     and how long it took to get from kernel entry to PID 1.
//  5. Pause 5 seconds so a human watching the QEMU console can
//     read the output before the box vanishes.
//  6. Power off cleanly via reboot(2) LINUX_REBOOT_CMD_POWER_OFF
//     so the live-test harness sees a deterministic QEMU exit.
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
// Use init_src/build.sh to do all of the above in one shot.

//go:build ignore

package main

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// bannerLine is the load-bearing identification string the live
// test harness greps for. Kept as a single line so a single grep
// matches; the surrounding newlines push it past any in-flight
// kernel log fragment.
const bannerLine = "cloud-boot/openweft Phase 2 Path D — /init userspace reached"

// LINUX_REBOOT_* — magic constants the reboot(2) syscall requires.
// Without MAGIC1+MAGIC2 the kernel returns -EINVAL. We use
// CMD_POWER_OFF (not CMD_HALT) because QEMU's -no-reboot maps that
// to qemu-exit, giving a deterministic end-of-run.
const (
	linuxRebootMagic1       = 0xFEE1DEAD
	linuxRebootMagic2       = 0x28121969
	linuxRebootCmdPowerOff  = 0x4321FEDC
)

// mountSpec describes a single pseudo-filesystem mount the /init
// performs at startup. The fields mirror the mount(2) arguments
// directly so the loop below stays trivially auditable.
type mountSpec struct {
	source string // 1st arg to mount(2); cosmetic for pseudo-fs
	target string // mount point; created if missing
	fstype string // "proc", "sysfs", "devtmpfs", "tmpfs"
	flags  uintptr
	data   string
	mode   os.FileMode // mkdir mode if target needs creating
}

// pseudoMounts is the fixed list of mounts the /init brings up
// before anything else. Order matters slightly: /proc first so a
// subsequent failure can still surface in /proc/self/mountinfo if
// we wire that in later. We try devtmpfs for /dev (kernel-managed,
// gives us the real device nodes) and fall back to a plain tmpfs
// if the kernel was built without CONFIG_DEVTMPFS — we don't fail
// hard either way, because the banner write is best-effort.
var pseudoMounts = []mountSpec{
	{source: "proc", target: "/proc", fstype: "proc", mode: 0555},
	{source: "sysfs", target: "/sys", fstype: "sysfs", mode: 0555},
	{source: "devtmpfs", target: "/dev", fstype: "devtmpfs", mode: 0755},
	{source: "tmpfs", target: "/tmp", fstype: "tmpfs", mode: 01777},
}

// mountAll attempts every pseudo-mount and returns the per-mount
// outcome as a list of human-readable status strings. We never
// abort PID 1 on a mount failure — the worst case (no /proc) just
// means the later facts-dump prints "(unavailable)" for every
// field, but the banner + power-off path still work.
func mountAll() []string {
	out := make([]string, 0, len(pseudoMounts))
	for _, m := range pseudoMounts {
		// Ensure the mount point exists. ENOENT here would be
		// fatal to the mount(2) call below, so fail-fast log
		// it and move on rather than panic.
		if err := os.MkdirAll(m.target, m.mode); err != nil && !os.IsExist(err) {
			out = append(out, fmt.Sprintf("%s: mkdir failed: %v", m.target, err))
			continue
		}
		err := syscall.Mount(m.source, m.target, m.fstype, m.flags, m.data)
		if err != nil {
			// Devtmpfs may not be compiled in; degrade to tmpfs
			// silently so /dev/kmsg open below still has a
			// chance via a fallback mknod path (skipped here
			// for size — the banner write to stdout still
			// works because the kernel pre-wires fd 0/1/2).
			if m.fstype == "devtmpfs" {
				if err2 := syscall.Mount("tmpfs", m.target, "tmpfs", 0, ""); err2 == nil {
					out = append(out, fmt.Sprintf("%s: tmpfs (devtmpfs unavailable: %v)", m.target, err))
					continue
				}
			}
			out = append(out, fmt.Sprintf("%s: mount(%s) failed: %v", m.target, m.fstype, err))
			continue
		}
		out = append(out, fmt.Sprintf("%s: %s mounted", m.target, m.fstype))
	}
	return out
}

// readFileBest reads the file at path and returns its contents or
// a "(unavailable: …)" sentinel string if the read fails. Used by
// the facts-dump section so a missing /proc entry never crashes
// PID 1 — every fact gracefully degrades to a visible "we couldn't
// see this" marker the operator can grep for.
func readFileBest(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(unavailable: %v)", err)
	}
	return string(b)
}

// kernelRelease returns the kernel release string in `uname -r`
// form via the uname(2) syscall. The bytes in syscall.Utsname are
// fixed-size int8 arrays NUL-terminated; we slice up to the NUL.
func kernelRelease() string {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return fmt.Sprintf("(unavailable: %v)", err)
	}
	return utsString(u.Release[:]) + " " + utsString(u.Machine[:])
}

// utsByte is the union of element types syscall.Utsname's char
// arrays use across Linux archs: int8 on arm64 (signed char ABI),
// uint8 on riscv64 / loong64 / amd64 (unsigned char ABI). A
// generic helper keeps the conversion arch-portable without an
// unsafe-cast trick.
type utsByte interface{ int8 | uint8 }

// utsString turns a NUL-terminated char array (the field type of
// syscall.Utsname; arch-dependent element type) into a Go string.
// The conversion is byte-by-byte because the array element type
// varies (int8 on arm64, uint8 on riscv64/loong64/amd64); the
// generic constraint lets a single function handle both.
func utsString[T utsByte](b []T) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// totalRAMMiB parses /proc/meminfo for the MemTotal kB line and
// returns the value converted to MiB. Returns 0 + a degraded
// string on any parse failure so the caller can print "(unknown)"
// instead of crashing.
func totalRAMMiB() (uint64, string) {
	b, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, fmt.Sprintf("(unavailable: %v)", err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		f := strings.Fields(line)
		// Expected layout: "MemTotal:   12345 kB".
		if len(f) < 2 {
			return 0, "(MemTotal field malformed)"
		}
		kB, err := strconv.ParseUint(f[1], 10, 64)
		if err != nil {
			return 0, fmt.Sprintf("(MemTotal parse: %v)", err)
		}
		mib := kB / 1024
		return mib, fmt.Sprintf("%d MiB", mib)
	}
	return 0, "(MemTotal line not found)"
}

// cpuCount returns the number of online CPUs. We prefer
// runtime.NumCPU (cheap, no I/O), but cross-check against
// /proc/cpuinfo "processor" lines to surface mismatches that
// would indicate a sched-affinity or NR_CPUS mis-configuration.
func cpuCount() string {
	rt := runtime.NumCPU()
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return fmt.Sprintf("%d (runtime; /proc/cpuinfo unavailable: %v)", rt, err)
	}
	procs := bytes.Count(b, []byte("processor\t"))
	if procs == 0 {
		// arm64 /proc/cpuinfo uses "processor\t:" too but spacing
		// can vary; fall back to a substring count.
		procs = bytes.Count(b, []byte("processor"))
	}
	if procs == rt {
		return fmt.Sprintf("%d", rt)
	}
	return fmt.Sprintf("%d (runtime=%d, /proc/cpuinfo=%d — mismatch)", rt, rt, procs)
}

// uptimeSeconds parses /proc/uptime (first field) and returns the
// seconds-since-boot as a float. Used for the boot-time-elapsed
// fact so the operator can see how fast PID 1 came up.
func uptimeSeconds() (float64, string) {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, fmt.Sprintf("(unavailable: %v)", err)
	}
	f := strings.Fields(string(b))
	if len(f) < 1 {
		return 0, "(empty)"
	}
	s, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return 0, fmt.Sprintf("(parse: %v)", err)
	}
	return s, fmt.Sprintf("%.2fs", s)
}

// kmsgWrite opens /dev/kmsg and writes a single line; failures are
// silently swallowed because /dev/kmsg can be absent on kernels
// without CONFIG_PRINTK or when /dev wasn't mounted. The intent is
// "best-effort kernel-log mirror", not a hard contract.
func kmsgWrite(line string) {
	f, err := os.OpenFile("/dev/kmsg", os.O_WRONLY, 0)
	if err != nil {
		return
	}
	defer f.Close()
	// kmsg expects single-line writes; truncate any embedded
	// newlines to spaces so a multi-line cmdline doesn't get
	// split into multiple kmsg records with weird levels.
	clean := strings.ReplaceAll(strings.TrimRight(line, "\n"), "\n", " ")
	_, _ = f.WriteString(clean + "\n")
}

// printlnAll prints a line to stdout AND /dev/console (best-effort)
// so the operator sees the same text regardless of how the kernel
// wired the early-userspace console. We don't deduplicate — the
// extra copy on /dev/console is cheap and worth the resilience.
func printlnAll(consoleFd *os.File, s string) {
	_, _ = os.Stdout.WriteString(s + "\n")
	if consoleFd != nil {
		_, _ = consoleFd.WriteString(s + "\n")
	}
}

func main() {
	t0 := time.Now()

	// Open /dev/console early as a backup write path. On some
	// kernels stdout is not wired up for PID 1 until later in
	// boot, but /dev/console works the moment devtmpfs is up.
	// We open before mounting so even if devtmpfs mount fails
	// we still try the path (it may be a real device node baked
	// into the initramfs by some future build).
	var consoleFd *os.File

	// Mount the pseudo-filesystems. Print the result table after
	// /dev is (hopefully) up so we have a chance at /dev/console.
	mountResults := mountAll()

	// Now /dev should exist (either devtmpfs or tmpfs fallback);
	// try /dev/console for the dual-write path.
	if f, err := os.OpenFile("/dev/console", os.O_WRONLY, 0); err == nil {
		consoleFd = f
		defer consoleFd.Close()
	}

	// Banner — the load-bearing identification line.
	printlnAll(consoleFd, "")
	printlnAll(consoleFd, bannerLine)
	printlnAll(consoleFd, "")
	kmsgWrite(bannerLine)

	// Mount results.
	printlnAll(consoleFd, "Pseudo-filesystem mounts:")
	for _, r := range mountResults {
		printlnAll(consoleFd, "  "+r)
	}

	// Kernel cmdline — echo to kmsg too, where it joins the rest
	// of the early-boot record for triage.
	cmdline := strings.TrimRight(readFileBest("/proc/cmdline"), "\n")
	printlnAll(consoleFd, "Kernel cmdline: "+cmdline)
	kmsgWrite("init: kernel cmdline = " + cmdline)

	// Kernel release.
	printlnAll(consoleFd, "Kernel: "+kernelRelease())

	// Mounted filesystems — print the whole table so the operator
	// can confirm proc/sys/dev/tmp all came up cleanly.
	printlnAll(consoleFd, "Mounts:")
	mounts := readFileBest("/proc/mounts")
	for _, line := range strings.Split(strings.TrimRight(mounts, "\n"), "\n") {
		if line == "" {
			continue
		}
		printlnAll(consoleFd, "  "+line)
	}

	// RAM, CPUs, uptime.
	_, ramStr := totalRAMMiB()
	printlnAll(consoleFd, "Total RAM: "+ramStr)
	printlnAll(consoleFd, "CPUs: "+cpuCount())
	_, upStr := uptimeSeconds()
	printlnAll(consoleFd, "Uptime: "+upStr)
	printlnAll(consoleFd, fmt.Sprintf("/init wall time: %s", time.Since(t0)))

	// 5-second pause so a human watching the live test can read
	// the output before the box vanishes. Long enough to scroll
	// up in a sluggish terminal; short enough to keep CI snappy.
	printlnAll(consoleFd, "")
	printlnAll(consoleFd, "Sleeping 5s before power-off…")
	time.Sleep(5 * time.Second)

	// Power-off. We swallow the result because on success this
	// call never returns; on failure we drop to the spin-forever
	// loop below rather than letting PID 1 exit (which would
	// panic the kernel with "Attempted to kill init!").
	printlnAll(consoleFd, "Powering off via reboot(2)…")
	_, _, _ = syscall.Syscall(
		syscall.SYS_REBOOT,
		uintptr(uint32(linuxRebootMagic1)),
		uintptr(uint32(linuxRebootMagic2)),
		uintptr(uint32(linuxRebootCmdPowerOff)),
	)

	// reboot(2) shouldn't return on success. If it does, park
	// here forever — exiting PID 1 panics the kernel.
	for {
		select {}
	}
}
