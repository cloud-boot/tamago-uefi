// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Phase-2 M6.2 de-risk probe — gated on `-tags
// phase2_efi_tiny_handover`. amd64-only by intent (the EDK2 OVMF
// CpuPageTableLib bug is amd64-specific; the other three arches
// already PASS chain-boot at 1.7 MiB per M8.0).
//
// Goal: find the largest PE32+ size at which gBS->LoadImage SUCCEEDS
// on amd64 OVMF (edk2-stable202408) when issued from a TamaGo parent.
// We embed four tiny variants spanning the relevant size band — three
// TamaGo PIE builds at the ~1.7 MiB runtime floor (A/B/C, mostly to
// confirm the harness works) and one hand-rolled minimal PE32+ at
// 1 KiB (Z) — and try each in turn. If a variant LoadImage's cleanly,
// we record it as a PASS; if it #GP's at CpuDxe.dll +0x110C, the
// parent never reaches the per-variant PASS line and the live runner
// observes the firmware-side exception block instead.
//
// Each iteration prints:
//
//	M6.2: variant=<V> size=<N>
//	M6.2: variant=<V> LoadImage OK    (or LoadImage FAILED: <err>)
//	M6.2: variant=<V> StartImage entering
//	M6.2: variant=<V> StartImage returned exit_status=<X>
//	M6.2: variant=<V> RESULT=PASS|FAIL
//
// For variants A and B the StartImage call is expected to return
// cleanly via gBS->Exit (the child wires that). For variant C the
// child halts in the runtime spin-loop and StartImage will NEVER
// return — we skip the StartImage call entirely for C (its purpose
// is purely to measure LoadImage). For variant Z the child returns
// from its 3-byte `xor eax,eax; ret` directly to StartImage's
// caller, which gives a clean PASS the same way as A/B.
//
// Build:
//
//	GOOS=tamago GOARCH=amd64 $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_efi_tiny_handover \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

//go:build phase2_efi_tiny_handover && tamago && amd64

package main

import (
	"runtime"

	"github.com/cloud-boot/tamago-uefi/internal/embed_chained_tiny"
	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// runEFITinyHandoverProbe is the entry point the dispatcher calls when
// the `phase2_efi_tiny_handover` build tag is set.
func runEFITinyHandoverProbe() {
	println("phase2-efi-tiny-handover: M6.2 de-risk -- chained LoadImage threshold sweep")
	println("phase2-efi-tiny-handover: arch =", runtime.GOARCH)

	for _, v := range embed_chained_tiny.Variants() {
		runOneVariant(v)
	}

	println("phase2-efi-tiny-handover: SWEEP DONE")
}

// runOneVariant tries one of the four M6.2 variants end-to-end.
// Variant C skips the StartImage call because its child halts in the
// TamaGo runtime spin-loop with no Exit hook — StartImage would never
// return. For C, "LoadImage OK" alone is the PASS signal.
func runOneVariant(v string) {
	payload, err := embed_chained_tiny.Decompress(v)
	if err == embed_chained_tiny.ErrEmptyEmbed {
		// Variant intentionally not embedded into the parent — see
		// tiny_amd64.go for why A and B are dropped. Skip cleanly.
		println("phase2-efi-tiny-handover: variant=" + v + " SKIPPED (not embedded; see tiny_amd64.go)")
		return
	}
	if err != nil {
		println("phase2-efi-tiny-handover: variant=" + v + " Decompress FAILED:", err.Error())
		println("phase2-efi-tiny-handover: variant=" + v + " RESULT=FAIL")
		return
	}
	println("phase2-efi-tiny-handover: variant=" + v + " size=" + itoa(len(payload)))

	if len(payload) < 2 || payload[0] != 'M' || payload[1] != 'Z' {
		println("phase2-efi-tiny-handover: variant=" + v + " payload[0:2] is not 'MZ'")
		println("phase2-efi-tiny-handover: variant=" + v + " RESULT=FAIL")
		return
	}

	handle, err := uefiboard.LoadImage(payload)
	if err != nil {
		println("phase2-efi-tiny-handover: variant=" + v + " LoadImage FAILED:", err.Error())
		println("phase2-efi-tiny-handover: variant=" + v + " RESULT=FAIL")
		return
	}
	println("phase2-efi-tiny-handover: variant=" + v + " LoadImage OK, handle=" + hexUintptrTiny(handle))

	if v == embed_chained_tiny.VariantC {
		// tinyC's child halts in TamaGo's spin-loop with no Exit
		// hook; StartImage would never return. LoadImage-OK is
		// sufficient PASS for this slot.
		println("phase2-efi-tiny-handover: variant=" + v + " StartImage SKIPPED (child has no Exit hook)")
		println("phase2-efi-tiny-handover: variant=" + v + " RESULT=PASS (LoadImage only)")
		return
	}

	println("phase2-efi-tiny-handover: variant=" + v + " StartImage entering")
	status, sErr := uefiboard.StartImage(handle)
	println("phase2-efi-tiny-handover: variant=" + v + " StartImage returned exit_status=" + hexUintptrTiny(status))
	if sErr != nil {
		println("phase2-efi-tiny-handover: variant=" + v + " child reported non-success:", sErr.Error())
	}

	// Same UnloadImage policy as the M8.0 probe: only call it when
	// the child returned with a non-zero status (the success path
	// already tore the child down via gBS->Exit and a follow-up
	// UnloadImage would return EFI_INVALID_PARAMETER).
	if status != 0 {
		if err := uefiboard.UnloadImage(handle); err != nil {
			println("phase2-efi-tiny-handover: variant=" + v + " UnloadImage warning:", err.Error())
		}
	}

	println("phase2-efi-tiny-handover: variant=" + v + " RESULT=PASS")
}

// hexUintptrTiny renders a uintptr as 0x-prefixed hex without pulling
// fmt. Local copy of phase2_efi_handover.go's hexUintptr so the M6.2
// probe doesn't co-depend on the M8.0 probe file's helpers.
func hexUintptrTiny(v uintptr) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v != 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	i--
	buf[i] = 'x'
	i--
	buf[i] = '0'
	return string(buf[i:])
}

// itoa renders a non-negative int as decimal without pulling
// strconv. Used for the size= line.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	if n < 0 {
		return "-" + itoa(-n)
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
