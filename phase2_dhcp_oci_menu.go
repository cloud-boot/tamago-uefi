// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M9.0 / M9.1 / M9.2 probe — DHCP-discovered OCI boot menu.
//
// Gated on `-tags phase2_dhcp_oci_menu && tamago`.
//
// Why this probe exists (the M9 roadmap):
//
//   - Production cloud-boot deployments want zero-touch boot: the
//     DHCP server advertises an OCI ref via Bootfile-Name (option 67)
//     instead of the PXE-style `tftp://server/file`. cloud-boot
//     fetches a small HCL boot-menu artifact from that ref, then
//     renders an interactive menu on virtio-console (or ConOut
//     fallback), takes EFI keystrokes from gST->ConIn, and dispatches
//     the chosen entry through LoadImage + StartImage.
//
//   - M9.0 (SHIPPED 2026-06-09): DHCP option 67 -> OCI fetch ->
//     bootmenu.Parse -> print to ConOut + halt.
//
//   - M9.1 (this sprint): virtio-console open + bootmenu.Renderer
//     paints the menu each tick.
//
//   - M9.2 (this sprint): EFI_SIMPLE_TEXT_INPUT_PROTOCOL ReadKeyStroke
//     polling drives the selection cursor; Enter dispatches the
//     selected entry's KernelRef/InitrdRef/Cmdline through the same
//     MODE-C wiring as phase2_oci_kernel_boot.go.
//
// Flow:
//
//  1. Locate a modern virtio-console PCI device (1AF4:1043). If
//     present, open it as the menu sink; otherwise fall back to a
//     ConOutWriter that routes the menu through gST->ConOut.
//  2. Bring up virtio-net + DHCP (same MODE-C boilerplate).
//  3. Parse DHCP option 67 as an OCI ref; fetch the HCL boot-menu
//     blob; bootmenu.Parse to a *BootConfig.
//  4. Drain any stale ConIn keystrokes and seed the selection cursor
//     at the Default entry's index.
//  5. Render loop: paint -> ReadKeyNonblocking -> handle key OR
//     time.Sleep(100 ms). On Enter, dispatch the selected entry.
//     On ESC, halt. On Up/Down/Home/End, move the cursor.
//
// Live test guard (M9_LIVE_AUTOCONFIRM=1 in the runner): the M9.2
// live runner sets this env-equivalent (a compile-time flag, since we
// have no env on tamago) by injecting the keystroke through a
// stand-alone `live:arm64:interactive` mode that the runner kicks off
// per-arch. See internal/livedhcpocimenu/run.sh for the wiring.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase2_dhcp_oci_menu \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" \
//	    -o app_<arch>_dhcpocimenu.elf .

//go:build phase2_dhcp_oci_menu && tamago

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"net"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	vconsole "github.com/go-virtio/console"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/cloud-boot/tamago-uefi/uefiboard/bootmenu"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack"
	"github.com/cloud-boot/tamago-uefi/uefiboard/ministack/oci"
)

// dhcpOCIMenuMaxBlobSize caps the streamed HCL config blob at 1 MiB.
// A typical boot-menu HCL is a few hundred bytes to a few KiB; past 1
// MiB the artifact is almost certainly a misroute (a kernel/initrd
// ref pointing at the menu slot).
const dhcpOCIMenuMaxBlobSize = 1 * 1024 * 1024

// dhcpOCIMenuMaxLayerSize caps the per-entry kernel/initrd layer size
// at 64 MiB. Matches kernelBootMaxLayerSize in phase2_oci_kernel_boot
// for parity. siderolabs arm64 layer is ~22 MiB compressed.
const dhcpOCIMenuMaxLayerSize = 64 * 1024 * 1024

// dhcpOCIMenuVmlinuzName is the path inside the kernel tar layer
// whose contents are the EFI-stub Linux kernel. Matches the
// siderolabs convention.
const dhcpOCIMenuVmlinuzName = "boot/vmlinuz"

// dhcpOCIMenuTickInterval is the per-frame redraw / ConIn poll
// cadence. 100 ms is below the human-perceptible cursor-update
// threshold while burning negligible CPU; the firmware ConIn is
// fully event-driven so polling at 100 ms costs at most one
// firmware call per tick.
const dhcpOCIMenuTickInterval = 100 * time.Millisecond

// runDHCPOCIMenuProbe is the entry point the dispatcher
// (phase2_dispatch.go) calls when the `phase2_dhcp_oci_menu` build
// tag is set. M9.1 + M9.2 scope: full interactive menu loop with
// per-entry dispatch.
func runDHCPOCIMenuProbe() {
	println("phase2-dhcp-oci-menu: M9.2 -- DHCP option 67 -> OCI fetch -> HCL parse -> interactive menu -> dispatch")
	println("phase2-dhcp-oci-menu: arch =", runtime.GOARCH)

	// Locate a virtio-console PCI device for the menu sink. If none is
	// bound (runner without -device virtio-serial-pci -device
	// virtconsole), fall back to ConOutWriter so the menu still
	// renders over the firmware's primary serial console.
	var menuSink io.Writer
	if vcIO := uefiboard.LocateVirtioConsolePciIO(); vcIO != 0 {
		vc, vcErr := uefiboard.OpenVirtioConsole(vcIO)
		if vcErr != nil {
			println("phase2-dhcp-oci-menu: virtio-console open failed:", vcErr.Error(), "-- falling back to ConOut")
			menuSink = uefiboard.ConOutWriter{}
		} else {
			println("phase2-dhcp-oci-menu: virtio-console opened OK")
			menuSink = vc
		}
	} else {
		println("phase2-dhcp-oci-menu: no virtio-console device bound; using ConOut fallback for menu render")
		menuSink = uefiboard.ConOutWriter{}
	}

	pciIO := locateVirtioNetForMenu()
	if pciIO == 0 {
		println("phase2-dhcp-oci-menu: no modern virtio-net device found")
		println("phase2-dhcp-oci-menu: MENU FAIL: no virtio-net device")
		return
	}
	vn, err := uefiboard.OpenVirtioNet(pciIO)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: OpenVirtioNet:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: device UP. MAC =", vn.MAC.String())

	link := ministack.NewLinkFromVirtioNet(vn)
	s := ministack.New(link)
	s.Start()

	lease, err := s.DHCP4Acquire(10 * time.Second)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: DHCP4Acquire:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: lease acquired")
	println("phase2-dhcp-oci-menu:   IP =", lease.IP.String())

	if lease.BootfileName == "" {
		println("phase2-dhcp-oci-menu: no DHCP option 67; abort")
		return
	}
	println("phase2-dhcp-oci-menu: bootfile-name =", lease.BootfileName)

	if len(lease.DNS) == 0 {
		println("phase2-dhcp-oci-menu: MENU FAIL: DHCP returned no DNS server")
		return
	}
	if err := s.SetIPv4Address(lease.IP, lease.Mask); err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: SetIPv4Address:", err.Error())
		return
	}
	if lease.Gateway != nil {
		if err := s.SetDefaultGateway(lease.Gateway); err != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: SetDefaultGateway:", err.Error())
			return
		}
	}
	if _, perr := ministack.NewRootCAs(); perr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: NewRootCAs:", perr.Error())
		return
	}
	println("phase2-dhcp-oci-menu: embedded roots =", ministack.EmbeddedRootCount())

	ref, err := oci.ParseRef(lease.BootfileName)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: ParseRef:", err.Error())
		return
	}
	println("phase2-dhcp-oci-menu: parsed ref host=" + ref.Host + " repo=" + ref.Repo + " ref=" + ref.Reference)

	reg := oci.NewRegistry(s, lease.DNS[0], ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 60 * time.Second
	if err := reg.Authenticate(); err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: Authenticate:", err.Error())
		return
	}

	rawIndex, contentType, err := reg.FetchManifestRaw(ref.Reference)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: FetchManifestRaw(index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: ParseIndex:", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: PickPlatform:", perr.Error())
			return
		}
		mraw, _, ferr := reg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-dhcp-oci-menu: MENU FAIL: FetchManifestRaw(picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}

	m, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: ParseManifest:", err.Error())
		return
	}
	if len(m.Layers) == 0 {
		println("phase2-dhcp-oci-menu: MENU FAIL: manifest has zero layers")
		return
	}
	target := m.Layers[0]
	if target.Size > dhcpOCIMenuMaxBlobSize {
		println("phase2-dhcp-oci-menu: MENU FAIL: HCL blob exceeds 1 MiB cap (size =", int(target.Size), ")")
		return
	}
	println("phase2-dhcp-oci-menu: HCL blob digest =", target.Digest)
	println("phase2-dhcp-oci-menu: HCL blob size   =", int(target.Size))

	var buf bytes.Buffer
	startNS := time.Now().UnixNano()
	n, ferr := reg.FetchBlobStream(target, &buf)
	elapsedMS := (time.Now().UnixNano() - startNS) / 1_000_000
	if ferr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: FetchBlobStream:", ferr.Error())
		println("phase2-dhcp-oci-menu: bytes-written-before-error =", int(n))
		return
	}
	println("phase2-dhcp-oci-menu: streamed", int(n), "bytes; SHA-256 verified OK")
	println("phase2-dhcp-oci-menu: streaming elapsed (ms) =", int(elapsedMS))

	cfg, perr := bootmenu.Parse(buf.Bytes())
	if perr != nil {
		println("phase2-dhcp-oci-menu: MENU FAIL: bootmenu.Parse:", perr.Error())
		return
	}
	println("phase2-dhcp-oci-menu: parsed BootConfig")
	println("phase2-dhcp-oci-menu:   title =", cfg.Title)
	println("phase2-dhcp-oci-menu:   timeout =", strconv.Itoa(cfg.Timeout), "s")
	println("phase2-dhcp-oci-menu:   default =", cfg.Default)
	println("phase2-dhcp-oci-menu:   entries =", strconv.Itoa(len(cfg.Entries)))

	// M9.2 interactive menu loop. Drain any stale keystrokes (e.g. a
	// stray Enter from the EFI shell auto-boot) then enter the
	// render -> poll -> dispatch tick loop.
	if rerr := uefiboard.ResetConIn(false); rerr != nil {
		println("phase2-dhcp-oci-menu: ConIn.Reset (non-fatal):", rerr.Error())
	}

	renderer := &bootmenu.Renderer{Out: menuSink}
	selected := indexOfDefault(cfg)
	selectedLabel, dispatchOK := menuLoop(renderer, cfg, selected, s, lease.DNS[0])
	if !dispatchOK {
		println("phase2-dhcp-oci-menu: menu loop returned without dispatch (ESC or empty menu)")
		return
	}
	println("phase2-dhcp-oci-menu: dispatch complete for entry:", selectedLabel)
}

// indexOfDefault returns the index of the entry whose Label matches
// cfg.Default, or 0 if cfg.Default is empty / no match. bootmenu.Parse
// already verifies that a non-empty Default matches some entry, so the
// "no match" fall-back is for the empty-Default case (the menu starts
// on the first entry and waits for user selection without auto-boot).
func indexOfDefault(cfg *bootmenu.BootConfig) int {
	if cfg.Default == "" {
		return 0
	}
	for i, e := range cfg.Entries {
		if e.Label == cfg.Default {
			return i
		}
	}
	return 0
}

// menuLoop drives the interactive menu: per-tick render + ConIn poll,
// with auto-boot at the cfg.Timeout deadline (cancelled by any
// keystroke). Returns (label, true) when an entry was dispatched, or
// ("", false) when the user pressed ESC or the loop exited without
// dispatch.
//
// Auto-boot semantics:
//   - cfg.Timeout > 0 AND cfg.Default != "" : auto-boot the Default
//     entry after the countdown expires.
//   - any keystroke pushes the deadline 24h into the future (the user
//     is now driving; no auto-boot).
//   - cfg.Timeout == 0 OR cfg.Default == "" : the loop polls forever
//     (no auto-boot; the user MUST press Enter or ESC).
func menuLoop(
	renderer *bootmenu.Renderer,
	cfg *bootmenu.BootConfig,
	startSelected int,
	s *ministack.Stack,
	dns net.IP,
) (string, bool) {
	if len(cfg.Entries) == 0 {
		println("phase2-dhcp-oci-menu: menu has zero entries; nothing to dispatch")
		return "", false
	}
	selected := startSelected
	if selected < 0 || selected >= len(cfg.Entries) {
		selected = 0
	}

	// Auto-boot deadline: only armed when both Timeout > 0 and Default
	// is set (an explicit auto-boot target). Otherwise the loop polls
	// forever and the user must drive the menu.
	autoBootArmed := cfg.Timeout > 0 && cfg.Default != ""
	deadline := time.Now()
	if autoBootArmed {
		deadline = deadline.Add(time.Duration(cfg.Timeout) * time.Second)
	}

	println("phase2-dhcp-oci-menu: entering menu loop; autoBootArmed =", autoBootArmed, "selected =", selected, "entries =", len(cfg.Entries))
	for {
		var countdown int
		if autoBootArmed {
			remaining := time.Until(deadline) / time.Second
			if remaining < 0 {
				remaining = 0
			}
			countdown = int(remaining)
		}
		if err := renderer.Render(cfg, selected, countdown); err != nil {
			println("phase2-dhcp-oci-menu: render error (non-fatal):", err.Error())
		}

		k, kerr := uefiboard.ReadKeyNonblocking()
		if errors.Is(kerr, uefiboard.ErrNoKey) || errors.Is(kerr, uefiboard.ErrNoConIn) {
			// No key pending. If the auto-boot countdown has burned
			// out, dispatch the Default entry. Otherwise pause one
			// tick and continue polling.
			if autoBootArmed && time.Now().After(deadline) {
				entry := cfg.Entries[selected]
				println("phase2-dhcp-oci-menu: auto-boot countdown expired; dispatching:", entry.Label)
				bootEntry(entry, s, dns)
				return entry.Label, true
			}
			busyWait(dhcpOCIMenuTickInterval)
			continue
		}
		if kerr != nil {
			println("phase2-dhcp-oci-menu: ReadKeyNonblocking error (non-fatal):", kerr.Error())
			busyWait(dhcpOCIMenuTickInterval)
			continue
		}

		// Any keystroke disarms auto-boot — the user is now driving.
		autoBootArmed = false

		switch {
		case k.ScanCode == uefiboard.ScanCodeUp:
			if selected > 0 {
				selected--
			}
		case k.ScanCode == uefiboard.ScanCodeDown:
			if selected < len(cfg.Entries)-1 {
				selected++
			}
		case k.ScanCode == uefiboard.ScanCodeHome:
			selected = 0
		case k.ScanCode == uefiboard.ScanCodeEnd:
			selected = len(cfg.Entries) - 1
		case k.UnicodeChar == uefiboard.UnicodeCharEnter:
			entry := cfg.Entries[selected]
			println("phase2-dhcp-oci-menu: Enter pressed; dispatching:", entry.Label)
			bootEntry(entry, s, dns)
			return entry.Label, true
		case k.ScanCode == uefiboard.ScanCodeESC:
			println("phase2-dhcp-oci-menu: ESC pressed; halting menu")
			return "", false
		default:
			// Ignored — unknown key. Re-render on the next tick so the
			// countdown line still reflects the disarmed state.
		}
	}
}

// bootEntry runs the per-entry MODE-C dispatch sequence: stream the
// kernel layer, extract vmlinuz, (optionally) stream + publish the
// initrd, publish the embedded DTB on arm64, UninstallAllRNG, set the
// cmdline, LoadImage + StartImage.
//
// Mirrors runKernelBootLinuxKernel in phase2_oci_kernel_boot.go but
// keyed off a bootmenu.Entry instead of the kernelBoot* per-arch
// constants. The probe-prefix on every println is
// "phase2-dhcp-oci-menu:" so the M9.2 live runner can grep for the
// dispatch trace without false matches against the M8.3 kernelboot
// probe (which doesn't run in this binary anyway, but parity matters
// for tail-readable serial logs).
func bootEntry(entry bootmenu.Entry, s *ministack.Stack, dns net.IP) {
	println("phase2-dhcp-oci-menu: bootEntry: label =", entry.Label)
	println("phase2-dhcp-oci-menu: bootEntry: kernel_ref =", entry.KernelRef)
	if entry.InitrdRef != "" {
		println("phase2-dhcp-oci-menu: bootEntry: initrd_ref =", entry.InitrdRef)
	}
	if entry.Cmdline != "" {
		println("phase2-dhcp-oci-menu: bootEntry: cmdline =", entry.Cmdline)
	}

	// Stream the kernel layer + extract boot/vmlinuz.
	kref, err := oci.ParseRef(entry.KernelRef)
	if err != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: ParseRef(kernel):", err.Error())
		return
	}
	kreg := oci.NewRegistry(s, dns, kref)
	kreg.DialTimeout = 15 * time.Second
	kreg.RequestTimeout = 120 * time.Second
	if err := kreg.Authenticate(); err != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: Authenticate(kernel):", err.Error())
		return
	}

	rawIndex, contentType, err := kreg.FetchManifestRaw(kref.Reference)
	if err != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: FetchManifestRaw(kernel/index):", err.Error())
		return
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: ParseIndex(kernel):", perr.Error())
			return
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: PickPlatform(kernel):", perr.Error())
			return
		}
		mraw, _, ferr := kreg.FetchManifestRaw(picked.Digest)
		if ferr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: FetchManifestRaw(kernel/picked):", ferr.Error())
			return
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}

	mfst, err := oci.ParseManifest(rawManifest)
	if err != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: ParseManifest(kernel):", err.Error())
		return
	}
	if len(mfst.Layers) == 0 {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: kernel manifest has zero layers")
		return
	}
	klayer := mfst.Layers[0]
	if klayer.Size > dhcpOCIMenuMaxLayerSize {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: kernel layer exceeds 64 MiB cap")
		return
	}
	println("phase2-dhcp-oci-menu: bootEntry: kernel layer digest =", klayer.Digest)
	println("phase2-dhcp-oci-menu: bootEntry: kernel layer size   =", int(klayer.Size))

	vmlinuz, streamedN, eerr := streamExtractVmlinuzMenu(kreg, klayer, dhcpOCIMenuVmlinuzName)
	if eerr != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: streamExtractVmlinuz:", eerr.Error())
		println("phase2-dhcp-oci-menu: streamed-before-error bytes =", int(streamedN))
		return
	}
	println("phase2-dhcp-oci-menu: bootEntry: streamed", int(streamedN), "bytes; SHA-256 verified OK")
	println("phase2-dhcp-oci-menu: bootEntry: extracted vmlinuz bytes =", len(vmlinuz))
	if len(vmlinuz) < 2 || vmlinuz[0] != 'M' || vmlinuz[1] != 'Z' {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: vmlinuz is not PE32+ (no MZ)")
		return
	}
	println("phase2-dhcp-oci-menu: bootEntry: vmlinuz PE header OK (MZ)")

	// DTB publish (mirror runKernelBootLinuxKernel). On non-arm64 the
	// embedded DTB returns empty and we skip the publish.
	var publishedDTB []byte
	fwCfgDTB, fetchErr := uefiboard.FetchQemuDTB()
	if fetchErr == nil && len(fwCfgDTB) > 0 {
		println("phase2-dhcp-oci-menu: bootEntry: FetchQemuDTB OK; bytes =", len(fwCfgDTB))
		publishedDTB = fwCfgDTB
	} else {
		embedded := uefiboard.EmbeddedArm64VirtDTB()
		if len(embedded) > 0 {
			println("phase2-dhcp-oci-menu: bootEntry: using embedded arm64-virt DTB; bytes =", len(embedded))
			publishedDTB = embedded
		}
	}
	if len(publishedDTB) > 0 {
		if perr := uefiboard.PublishDTB(publishedDTB); perr != nil {
			println("phase2-dhcp-oci-menu: bootEntry: PublishDTB failed (non-fatal):", perr.Error())
		} else {
			println("phase2-dhcp-oci-menu: bootEntry: DTB published (", len(publishedDTB), "bytes)")
		}
	}

	yanked := uefiboard.UninstallAllRNG()
	println("phase2-dhcp-oci-menu: bootEntry: UninstallAllRNG: yanked", yanked, "firmware RNG interface(s)")

	handle, lerr := uefiboard.LoadImage(vmlinuz)
	if lerr != nil {
		println("phase2-dhcp-oci-menu: bootEntry FAIL: LoadImage:", lerr.Error())
		return
	}
	println("phase2-dhcp-oci-menu: bootEntry: LoadImage OK")

	if entry.Cmdline != "" {
		if soErr := uefiboard.SetLoadOptions(handle, entry.Cmdline); soErr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: SetLoadOptions:", soErr.Error())
			return
		}
		println("phase2-dhcp-oci-menu: bootEntry: SetLoadOptions OK; cmdline len =", len(entry.Cmdline))
	}

	var initrdHandle uintptr
	if entry.InitrdRef != "" {
		println("phase2-dhcp-oci-menu: bootEntry: streaming initrd from OCI:", entry.InitrdRef)
		initrdBytes, ierr := fetchInitrdFromOCIMenu(s, dns, entry.InitrdRef)
		if ierr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: fetchInitrdFromOCI:", ierr.Error())
			return
		}
		println("phase2-dhcp-oci-menu: bootEntry: initrd fetched + decompressed; bytes =", len(initrdBytes))
		ihandle, perr := uefiboard.PublishInitrd(initrdBytes)
		if perr != nil {
			println("phase2-dhcp-oci-menu: bootEntry FAIL: PublishInitrd:", perr.Error())
			return
		}
		initrdHandle = ihandle
		println("phase2-dhcp-oci-menu: bootEntry: PublishInitrd OK")
	}

	println("phase2-dhcp-oci-menu: bootEntry: StartImage entering EFI-stub kernel")
	println("phase2-dhcp-oci-menu: ---- kernel-side output below this line ----")
	status, sErr := uefiboard.StartImage(handle)
	println("phase2-dhcp-oci-menu: ---- kernel-side output above this line ----")
	println("phase2-dhcp-oci-menu: bootEntry: StartImage returned exit_status =", int(status))
	if sErr != nil {
		println("phase2-dhcp-oci-menu: bootEntry: kernel reported non-success:", sErr.Error())
	}

	if initrdHandle != 0 {
		if uerr := uefiboard.UnpublishInitrd(initrdHandle); uerr != nil {
			println("phase2-dhcp-oci-menu: bootEntry: UnpublishInitrd warning:", uerr.Error())
		}
	}
	if status != 0 {
		if uerr := uefiboard.UnloadImage(handle); uerr != nil {
			println("phase2-dhcp-oci-menu: bootEntry: UnloadImage warning:", uerr.Error())
		}
	}
	println("phase2-dhcp-oci-menu: bootEntry: DISPATCH COMPLETE for", entry.Label)
}

// streamExtractVmlinuzMenu is the menu-local copy of
// streamExtractVmlinuz from phase2_oci_kernel_boot.go. The original is
// only compiled when phase2_oci_kernel_boot is set; the menu binary
// doesn't enable that tag, so we duplicate the routine with the same
// shape + same memory budget. Returns
// (vmlinuz-slice-into-firmware-memory, streamed-byte-count, err).
func streamExtractVmlinuzMenu(reg *oci.Registry, desc oci.Descriptor, name string) ([]byte, int64, error) {
	var buf bytes.Buffer
	n, ferr := reg.FetchBlobStream(desc, &buf)
	if ferr != nil {
		return nil, n, ferr
	}
	gz, gerr := gzip.NewReader(bytes.NewReader(buf.Bytes()))
	if gerr != nil {
		return nil, n, gerr
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		hdr, herr := tr.Next()
		if herr == io.EOF {
			return nil, n, errVmlinuzNotFoundMenu
		}
		if herr != nil {
			return nil, n, herr
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			continue
		}
		hname := hdr.Name
		if len(hname) >= 2 && hname[0] == '.' && hname[1] == '/' {
			hname = hname[2:]
		}
		if hname != name {
			continue
		}
		sz := int(hdr.Size)
		if sz <= 0 {
			return nil, n, errVmlinuzEmptyMenu
		}
		pages := uintptr((sz + int(uefiboard.EfiPageSize) - 1) / int(uefiboard.EfiPageSize))
		addr, aerr := uefiboard.AllocatePages(uefiboard.EfiLoaderData, pages)
		if aerr != nil {
			return nil, n, aerr
		}
		dst := unsafe.Slice((*byte)(unsafe.Pointer(uintptr(addr))), sz)
		nRead, rerr := io.ReadFull(tr, dst)
		if rerr != nil {
			return nil, n, rerr
		}
		if nRead != sz {
			return nil, n, errVmlinuzShortReadMenu
		}
		return dst, n, nil
	}
}

// fetchInitrdFromOCIMenu mirrors fetchInitrdFromOCI from
// phase2_oci_kernel_boot.go. Same shape; renamed to avoid a
// double-definition when both probes' tags happen to be set in the
// same binary (an unlikely combination, but the rename keeps both
// translation units valid).
func fetchInitrdFromOCIMenu(s *ministack.Stack, dns net.IP, refStr string) ([]byte, error) {
	ref, err := oci.ParseRef(refStr)
	if err != nil {
		return nil, err
	}
	reg := oci.NewRegistry(s, dns, ref)
	reg.DialTimeout = 15 * time.Second
	reg.RequestTimeout = 120 * time.Second
	if aerr := reg.Authenticate(); aerr != nil {
		return nil, aerr
	}
	rawIndex, contentType, ferr := reg.FetchManifestRaw(ref.Reference)
	if ferr != nil {
		return nil, ferr
	}
	var rawManifest []byte
	if oci.IsIndex(rawIndex, contentType) {
		idx, perr := oci.ParseIndex(rawIndex)
		if perr != nil {
			return nil, perr
		}
		picked, perr := oci.PickPlatform(idx, "linux", runtime.GOARCH)
		if perr != nil {
			return nil, perr
		}
		mraw, _, merr := reg.FetchManifestRaw(picked.Digest)
		if merr != nil {
			return nil, merr
		}
		rawManifest = mraw
	} else {
		rawManifest = rawIndex
	}
	m, mperr := oci.ParseManifest(rawManifest)
	if mperr != nil {
		return nil, mperr
	}
	if len(m.Layers) == 0 {
		return nil, errInitrdNoLayersMenu
	}
	target := m.Layers[0]
	if target.Size > dhcpOCIMenuMaxLayerSize {
		return nil, errInitrdLayerTooBigMenu
	}
	var buf bytes.Buffer
	if _, serr := reg.FetchBlobStream(target, &buf); serr != nil {
		return nil, serr
	}
	raw := buf.Bytes()
	if len(raw) >= 3 && raw[0] == 0x1f && raw[1] == 0x8b && raw[2] == 0x08 {
		gz, gerr := gzip.NewReader(bytes.NewReader(raw))
		if gerr != nil {
			return nil, gerr
		}
		defer gz.Close()
		out, rerr := io.ReadAll(gz)
		if rerr != nil {
			return nil, rerr
		}
		return out, nil
	}
	return raw, nil
}

// errorStringMenu is a tiny local error type so the menu extractor
// doesn't pull errors.New into the M9.2 build closure (it's already
// imported for errors.Is on ErrNoKey, so this is purely a parity
// nicety with the kernelboot probe's local errorString type).
type errorStringMenu string

func (e errorStringMenu) Error() string { return string(e) }

var (
	errVmlinuzNotFoundMenu  = errorStringMenu("vmlinuz entry not found in tar.gz layer")
	errVmlinuzEmptyMenu     = errorStringMenu("vmlinuz tar entry has zero size")
	errVmlinuzShortReadMenu = errorStringMenu("short read on vmlinuz tar entry")
	errInitrdNoLayersMenu   = errorStringMenu("initrd OCI manifest has zero layers")
	errInitrdLayerTooBigMenu = errorStringMenu("initrd layer size exceeds 64 MiB cap")
)

// busyWait spin-waits for `d` using runtime.Nanotime-style probing
// via time.Now. The menu loop uses this instead of time.Sleep because
// time.Sleep in the M9.2 single-goroutine probe environment relies on
// the scheduler's timer thread which, when no concurrent goroutines
// are alive to drive it, can block past the requested deadline.
// busyWait is single-threaded and predictable — same pattern as the
// "drive RX inline" workaround documented in
// phase2_oci_kernel_boot.go (R-M8.3b).
func busyWait(d time.Duration) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		// no-op — burning CPU. The 100 ms tick is small enough that
		// this is unnoticeable to the user; the kernel-side scheduler
		// is not yet running so we're not stealing cycles from anyone.
	}
}

// locateVirtioNetForMenu mirrors locateVirtioNetForKernelBoot in
// phase2_oci_kernel_boot.go. Local copy because the kernelboot probe
// is gated on a different build tag — sharing would force the menu
// probe to pull the entire kernelboot probe into its build closure,
// doubling the binary size for no functional benefit.
func locateVirtioNetForMenu() uint64 {
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		return 0
	}
	for _, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIPciIOProtocolGUID)
		if err != nil {
			continue
		}
		vid, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgVendorID)
		if err != nil {
			continue
		}
		did, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgDeviceID)
		if err != nil {
			continue
		}
		if vid == uefiboard.VirtioPCIVendorID && did == uefiboard.VirtioPCIDeviceIDModernNet {
			return iface
		}
	}
	return 0
}

// _ keep the vconsole import in the set even if the only reference
// is in the locator (which lives in uefiboard). Avoids a future
// goimports pass silently dropping the dep when refactoring.
var _ = vconsole.TxPollIterations
