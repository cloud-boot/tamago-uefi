// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-3 DOOM bare-metal demo probe.
// Gated on `-tags phase3_oci_doom_boot && tamago && amd64`.
//
// Strategy:
//
//   - Locate the first virtio-gpu (VID:DID = 0x1AF4:0x1050), virtio-sound
//     (0x1059), and virtio-input (0x1052) devices among the
//     EFI_PCI_IO_PROTOCOL handles.
//
//   - Bring each up via the pure-Go go-virtio drivers (gpu / sound / input)
//     using the existing UEFITransport adapter that already powers
//     virtio-net + virtio-console.
//
//   - For virtio-gpu: GET_DISPLAY_INFO + SetupFramebuffer at the first
//     enabled scanout's native dimensions; hand the resulting
//     Framebuffer to the godoom tamago backend's GPUAdapter so DOOM's
//     320×200 canvas blits BGRA-converted into the device-backed memory
//     and Flush()es to the host.
//
//   - For virtio-sound: PCMSetParams (16-bit signed LE, mono, 11025 Hz)
//     + PCMPrepare + PCMStart on the first output stream; hand it to
//     the godoom backend's SoundAdapter, which translates DOOM's u8
//     dmx lumps to s16le on the fly.
//
//   - For virtio-input: wrap the keyboard device's ReadEvent through
//     the godoom backend's InputAdapter, which translates evdev codes
//     to the HID-usage flavour the Frontend's keymap expects.
//
//   - Boot the engine: build a Frontend wiring the three adapters,
//     SetVirtualFileSystem(embedwad.New("doom1.wad", DOOM1WAD())),
//     then gore.Run(frontend, nil).
//
// Honest failure modes captured in the probe prints:
//
//   - Any of the three devices missing — the probe surfaces a "no
//     virtio-XXX device" diag and continues with a nil adapter; the
//     Frontend's nil-tolerant paths keep the engine running with that
//     subsystem silenced (best-effort demo > no demo).
//
//   - Empty WAD (build did not opt in to the `embedwad` tag) — the
//     probe refuses to start the engine and exits with a clear "no
//     WAD" diag so the operator knows to rebuild.
//
//   - virtio-gpu may not bind under EDK2 OVMF until ExitBootServices
//     hands control over (similar to virtio-console finding in R-M9.1a);
//     the probe surfaces the OpenVirtioGPU error and continues into
//     a nil-GPU run so the audio + input plumbing still gets exercised.
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_blkprintk,phase3_oci_doom_boot,embedwad \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase3_oci_doom_boot && tamago && amd64

package main

import (
	gore "github.com/cloud-boot/godoom"
	doomback "github.com/cloud-boot/godoom/backend/tamago"
	"github.com/cloud-boot/godoom/embedwad"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
	"github.com/go-virtio/gpu"
	"github.com/go-virtio/input"
	"github.com/go-virtio/sound"
)

// virtioInputReaderShim adapts a *input.VirtioInput to the
// godoom backend's virtioInputReader interface (ReadEventRaw triple).
// The backend deliberately defines a structural interface so it stays
// free of an import-time dependency on go-virtio/input.
type virtioInputReaderShim struct {
	dev *input.VirtioInput
}

// ReadEventRaw drains one event from the device's eventq (non-blocking)
// and exposes its (Type, Code, Value) triple. ErrEventNotReady is
// surfaced as ok=false so the backend treats it as an empty poll.
func (s *virtioInputReaderShim) ReadEventRaw() (uint16, uint16, uint32, bool) {
	if s == nil || s.dev == nil {
		return 0, 0, 0, false
	}
	ev, err := s.dev.ReadEvent(false)
	if err != nil || ev == nil {
		return 0, 0, 0, false
	}
	return ev.Type, ev.Code, ev.Value, true
}

// runOCIDOOMBootProbe is the entry point the dispatcher calls when the
// `phase3_oci_doom_boot` build tag is set. It enumerates PCI for the
// three virtio devices DOOM needs, wires them through the godoom
// backend adapters, and starts the engine.
func runOCIDOOMBootProbe() {
	println("phase3-oci-doom-boot: DOOM on TamaGo+UEFI bare-metal — first viral demo")

	wad := embedwad.DOOM1WAD()
	if len(wad) == 0 {
		println("phase3-oci-doom-boot: DOOMBOOT FAIL: no WAD embedded")
		println("phase3-oci-doom-boot: rebuild with -tags embedwad after dropping doom1.wad into")
		println("phase3-oci-doom-boot: cloud-boot/godoom/internal/embedwad/")
		return
	}
	println("phase3-oci-doom-boot: WAD embedded, size =", len(wad), "bytes")

	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFIPciIOProtocolGUID)
	if err != nil {
		println("phase3-oci-doom-boot: DOOMBOOT FAIL: LocateHandleBuffer:", err.Error())
		return
	}
	println("phase3-oci-doom-boot: scanned", len(handles), "PCI handles")

	gpuPCI, sndPCI, inPCI := findVirtioDOOMDevices(handles)

	gpuAdapter := openGPU(gpuPCI)
	soundAdapter := openSound(sndPCI)
	inputAdapter := openInput(inPCI)

	if gpuAdapter == nil {
		println("phase3-oci-doom-boot: WARN: no virtio-gpu adapter — engine will run headless")
	}
	if soundAdapter == nil {
		println("phase3-oci-doom-boot: WARN: no virtio-sound adapter — engine will run mute")
	}
	if inputAdapter == nil {
		println("phase3-oci-doom-boot: WARN: no virtio-input adapter — engine will run inputless")
	}

	frontend := doomback.New(gpuAdapter, soundAdapter, inputAdapter)
	frontend.SetTitle("DOOM Shareware Startup")

	gore.SetVirtualFileSystem(embedwad.New("doom1.wad", wad))
	gore.EnableQuitting(false)

	println("phase3-oci-doom-boot: handing off to gore.Run — DOOM main loop starting")
	gore.Run(frontend, []string{"-iwad", "doom1.wad"})
	println("phase3-oci-doom-boot: gore.Run returned (engine quit)")
}

// findVirtioDOOMDevices walks the EFI_PCI_IO_PROTOCOL handles and
// returns the first match for virtio-gpu, virtio-sound, and
// virtio-input. Missing devices come back as 0; the caller surfaces a
// warning + runs the engine with the corresponding adapter nil.
func findVirtioDOOMDevices(handles []uint64) (gpuPCI, sndPCI, inPCI uint64) {
	for _, h := range handles {
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFIPciIOProtocolGUID)
		if err != nil {
			continue
		}
		vid, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgVendorID)
		if err != nil || vid != uefiboard.VirtioPCIVendorID {
			continue
		}
		did, err := uefiboard.PciIOReadConfigU16(iface, uefiboard.PCICfgDeviceID)
		if err != nil {
			continue
		}
		switch did {
		case 0x1050: // modern virtio-gpu
			if gpuPCI == 0 {
				gpuPCI = iface
				println("phase3-oci-doom-boot: virtio-gpu  @ handle", h)
			}
		case 0x1059: // modern virtio-sound
			if sndPCI == 0 {
				sndPCI = iface
				println("phase3-oci-doom-boot: virtio-snd  @ handle", h)
			}
		case 0x1052: // modern virtio-input
			if inPCI == 0 {
				inPCI = iface
				println("phase3-oci-doom-boot: virtio-in   @ handle", h)
			}
		}
	}
	return
}

// openGPU brings up the virtio-gpu device, allocates a framebuffer
// matching the first enabled scanout's dimensions, and returns the
// godoom backend's GPUAdapter wrapping it. Returns nil on any failure
// (the engine then runs headless).
func openGPU(pciIO uint64) *doomback.GPUAdapter {
	if pciIO == 0 {
		return nil
	}
	println("phase3-oci-doom-boot: opening virtio-gpu…")
	t := uefiboard.NewUEFITransport(pciIO)
	dev, err := gpu.OpenVirtioGPU(t)
	if err != nil {
		println("phase3-oci-doom-boot: OpenVirtioGPU FAILED:", err.Error())
		return nil
	}
	println("phase3-oci-doom-boot: virtio-gpu UP, num_scanouts =", uint64(dev.NumScanouts))
	displays, err := dev.DisplayInfo()
	if err != nil {
		println("phase3-oci-doom-boot: DisplayInfo FAILED:", err.Error())
		return nil
	}
	var d gpu.Display
	for _, di := range displays {
		if di.Enabled {
			d = di
			break
		}
	}
	if d.Width == 0 || d.Height == 0 {
		println("phase3-oci-doom-boot: no enabled scanout with non-zero dimensions")
		return nil
	}
	println("phase3-oci-doom-boot: scanout", uint64(d.ScanoutID), "size =",
		uint64(d.Width), "x", uint64(d.Height))
	fb, err := dev.SetupFramebuffer(d.ScanoutID, d.Width, d.Height)
	if err != nil {
		println("phase3-oci-doom-boot: SetupFramebuffer FAILED:", err.Error())
		return nil
	}
	return doomback.NewGPUAdapter(fb, fb.Pix, int(fb.Width), int(fb.Height))
}

// openSound brings up the virtio-sound device, configures the first
// output stream for DOOM's 11025 Hz mono S16_LE format, transitions to
// RUNNING, and returns the godoom backend's SoundAdapter wrapping it.
// Returns nil on any failure (the engine then runs mute).
func openSound(pciIO uint64) *doomback.SoundAdapter {
	if pciIO == 0 {
		return nil
	}
	println("phase3-oci-doom-boot: opening virtio-sound…")
	t := uefiboard.NewUEFITransport(pciIO)
	dev, err := sound.OpenVirtioSound(t)
	if err != nil {
		println("phase3-oci-doom-boot: OpenVirtioSound FAILED:", err.Error())
		return nil
	}
	println("phase3-oci-doom-boot: virtio-snd UP, streams =", uint64(dev.Device.Streams))
	if dev.Device.Streams == 0 {
		println("phase3-oci-doom-boot: no PCM streams advertised")
		return nil
	}
	// Stream 0 is conventionally the first output on QEMU's
	// virtio-sound-pci. PCMInfo would disambiguate input vs output,
	// but the MVP demo just trusts the device layout.
	const streamID uint32 = 0
	p := sound.PCMParams{
		BufferBytes: 8192,
		PeriodBytes: 1024,
		Channels:    1,
		Format:      sound.PCMFmtS16,
		Rate:        sound.PCMRate11025,
	}
	if err := dev.PCMSetParams(streamID, p); err != nil {
		println("phase3-oci-doom-boot: PCMSetParams FAILED:", err.Error())
		return nil
	}
	if err := dev.PCMPrepare(streamID); err != nil {
		println("phase3-oci-doom-boot: PCMPrepare FAILED:", err.Error())
		return nil
	}
	if err := dev.PCMStart(streamID); err != nil {
		println("phase3-oci-doom-boot: PCMStart FAILED:", err.Error())
		return nil
	}
	println("phase3-oci-doom-boot: PCM stream", uint64(streamID), "RUNNING (11025 Hz mono S16_LE)")
	return doomback.NewSoundAdapter(soundWriteShim{dev}, streamID)
}

// soundWriteShim adapts a *sound.VirtioSound to the godoom backend's
// virtioSound interface (one-method Write). Pure forwarding.
type soundWriteShim struct{ dev *sound.VirtioSound }

// Write forwards to the underlying device's Write.
func (s soundWriteShim) Write(streamID uint32, frames []byte) (int, error) {
	return s.dev.Write(streamID, frames)
}

// openInput brings up the virtio-input device and returns the godoom
// backend's InputAdapter wrapping its ReadEvent path. Returns nil on
// any failure (the engine then runs inputless).
func openInput(pciIO uint64) *doomback.InputAdapter {
	if pciIO == 0 {
		return nil
	}
	println("phase3-oci-doom-boot: opening virtio-input…")
	t := uefiboard.NewUEFITransport(pciIO)
	dev, err := input.OpenVirtioInput(t)
	if err != nil {
		println("phase3-oci-doom-boot: OpenVirtioInput FAILED:", err.Error())
		return nil
	}
	name := dev.Info.Name
	if name == "" {
		name = "(unnamed)"
	}
	println("phase3-oci-doom-boot: virtio-in UP, name =", name)
	return doomback.NewInputAdapter(&virtioInputReaderShim{dev: dev})
}
