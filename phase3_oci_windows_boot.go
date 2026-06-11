// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-3 sprint-4 probe — OS-agnostic OCI boot, Windows scaffolding.
// Gated on `-tags phase3_oci_windows_boot && tamago && amd64`.
//
// SPRINT 4 STATUS: SCAFFOLDING ONLY (not yet live-runnable).
//
// Mirrors the FreeBSD probe (`phase2_oci_freebsd_boot.go`) one-for-one
// up to LoadImage of the OS-specific EFI loader; the divergence is at
// the rootfs surface:
//
//   FreeBSD: \EFI\BOOT\BOOTX64.EFI = freebsd-loader.efi
//            rootfs = UFS via go-filesystems/ufs
//
//   Windows: \EFI\Microsoft\Boot\bootmgfw.efi = Windows Boot Manager
//            rootfs = NTFS — needs real NTFS driver (go-filesystems/ntfs
//                     today is the NTFSIMG1 synthetic format and does
//                     NOT read real Windows-formatted NTFS; see Sprint 4
//                     architectural document.)
//
// Boot sequence (UEFI Windows):
//
//   1. firmware enumerates ESP, finds \EFI\Microsoft\Boot\bootmgfw.efi
//   2. bootmgfw reads \EFI\Microsoft\Boot\BCD (Boot Configuration Data,
//      a Windows registry hive) — needs an SFS on the Windows partition
//      since BCD is on the system reserved partition or the C: NTFS
//      volume
//   3. bootmgfw loads \Windows\System32\winload.efi
//   4. winload loads \Windows\System32\ntoskrnl.exe + boot drivers
//   5. ntoskrnl initializes the kernel
//
// Hard requirements firmware-side:
//
//   - NTFS driver (EDK2 OVMF does NOT ship one — the .inf for
//      NtfsDxe was removed from upstream years ago over Microsoft IP
//      concerns). The community NtfsPkg (e.g. KillaMaaki/NtfsDxe) is
//      a third-party DXE driver we would need to inject into OVMF or
//      reimplement Go-side via go-filesystems/ntfs.
//   - Secure Boot keys (for Win 11 modern builds; Win 10 LTSC can
//      run with TESTSIGNING + Secure Boot disabled).
//   - TPM 2.0 (Win 11 only — there is a separate parallel sprint for
//      TPM 2.0 wiring; out of scope here).
//
// Sprint 4 PASS gates (scaffolding only, no live boot):
//
//   - Probe compiles under `phase3_oci_windows_boot`.
//   - Stub honors !tag / non-amd64 builds (matches FreeBSD pattern).
//   - Sprint 4 docs section in phase3-multi-os-oci-boot.md updated.
//   - go-filesystems/ntfs gap precisely documented.
//
// Sprint 4 explicit out-of-scope:
//
//   - Live QEMU Windows boot (blocked on real NTFS support).
//   - BCD construction (sprint 4.1 — embed pre-built BCD from a
//     reference Windows install).
//   - Secure Boot key enrollment (sprint 4.2).
//   - TPM 2.0 measurement (separate parallel sprint).
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase3_oci_windows_boot \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase3_oci_windows_boot && tamago && amd64

package main

import (
	"runtime"
	"time"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// windowsBootTargetRef — OCI artifact streaming source for the Windows
// disk image. Empty = fail closed (mirrors freebsdBootTargetRef). The
// runner will inject the ref via `-X main.windowsBootTargetRef=...`
// at link time once the image-pipeline gates are reachable. Sprint 4
// is scaffolding only so this constant is unused on the live path.
var windowsBootTargetRef = ""

// windowsBootMaxImageSize caps the streamed image to keep the runtime
// heap intact. Windows 10 LTSC install media is ~4 GiB, well past
// anything the current tamago streaming pipeline can absorb (Sprint
// 2E noted the residual OOM at ~251 MiB peak working set). Sprint 4
// will need to either chunk-stream the image into block-IO-backed
// storage or stage it via a host-backed virtio-blk path before this
// becomes meaningful.
const windowsBootMaxImageSize = 1024 * 1024 * 1024 // 1 GiB — diagnostic cap only

// windowsBootEFIPath is the canonical UEFI Windows Boot Manager path.
// Note: this is NOT the fallback \EFI\BOOT\BOOTX64.EFI — Windows
// installs its loader at the Microsoft-specific subpath and registers
// a UEFI variable Boot#### entry pointing at it; the fallback path
// is used only by setup media. A clean Windows install on the ESP
// will have BOTH locations populated.
const windowsBootEFIPath = "\\EFI\\Microsoft\\Boot\\bootmgfw.efi"

// windowsBootFallbackEFIPath is the UEFI removable-media fallback
// boot path. Most Windows installation ISOs put bootmgfw.efi here
// too so removable boot works without a Boot#### variable. We try
// the Microsoft-specific path first, then fall back.
const windowsBootFallbackEFIPath = "\\EFI\\BOOT\\BOOTX64.EFI"

// runOCIWindowsBootProbe is the entry point the dispatcher calls when
// the `phase3_oci_windows_boot` build tag is set. Sprint 4
// scaffolding: prints intent + per-component gap status, exits.
//
// The probe body intentionally does NOT attempt the full network +
// stream + publish chain yet — sprint 4 explicit gate is "scaffolding
// shipped", not "live boot attempted". Wiring the full chain would
// only get as far as LoadImage(bootmgfw.efi) before hitting the NTFS
// driver gap; better to make the gap explicit at probe entry than to
// emit misleading "PublishBlockIO OK" gates and crash silently 30s
// later inside bootmgfw's BCD reader.
func runOCIWindowsBootProbe() {
	println("phase3-oci-windows-boot: Sprint 4 SCAFFOLDING -- arch =", runtime.GOARCH)
	println("phase3-oci-windows-boot: target ref (unused this sprint) =", windowsBootTargetRef)
	println("phase3-oci-windows-boot: EFI loader path =", windowsBootEFIPath)
	println("phase3-oci-windows-boot: fallback path   =", windowsBootFallbackEFIPath)
	println("phase3-oci-windows-boot: --- gap status (sprint 4 architectural) ---")
	println("phase3-oci-windows-boot: NTFS rootfs driver: GAP -- go-filesystems/ntfs is NTFSIMG1 (synthetic), NOT real on-disk NTFS")
	println("phase3-oci-windows-boot: BCD store: GAP -- strategy is embed pre-built BCD from reference install (sprint 4.1)")
	println("phase3-oci-windows-boot: Secure Boot: GAP -- need cert enrollment for Windows 11 (sprint 4.2)")
	println("phase3-oci-windows-boot: TPM 2.0: tracked in parallel sprint -- out of scope here")
	println("phase3-oci-windows-boot: target Windows version: 10 LTSC IoT 2021 (less strict than 11; supported through 2032)")
	println("phase3-oci-windows-boot: --- end gap status ---")
	println("phase3-oci-windows-boot: WINDOWS-BOOT SCAFFOLDING COMPLETE -- no live boot attempted this sprint")

	// Reference symbol uses so the import set is real and refactor
	// guards work — these compile-time checks ensure the publish-side
	// trampolines, ministack, and OCI registry surfaces remain
	// available to sprint 4.1+ without re-discovery.
	if false { // dead code; type-checking only
		_, _ = uefiboard.PublishBlockIO(nil)
		var _ *ministack.Stack
		var _ oci.Ref
		_ = time.Now()
	}
}
