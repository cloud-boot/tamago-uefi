// Phase-2 M1.5 probe — gated on `-tags phase2_snpenum`.
//
// Walks every controller publishing EFI_SIMPLE_NETWORK_PROTOCOL,
// opens the protocol on each handle, then reads
// `*This->Mode` and prints HwAddressSize / MediaPresent / State /
// CurrentAddress (MAC) for each. NO Start / Initialize / Transmit /
// Receive — M1.5 is pure enumeration. A future M-step that wraps SNP
// as a netstack LinkEndpoint will add the function thunks; today the
// goal is to confirm SNP is reachable through the same
// LocateHandleBuffer + HandleProtocol path the M1 PCI probe validated.
//
// This file is independent of phase2_pcienum.go. Build EITHER:
//
//	-tags ...,phase2_pcienum            (PCI IO walk, no SNP)
//	-tags ...,phase2_snpenum            (SNP walk, no PCI IO)
//	-tags ...,phase2_pcienum,phase2_snpenum
//	                                    (both — PCI IO then SNP)
//
// When both tags are set, the PCI walk runs first, then the SNP walk
// runs from the same `runPhase2Probe` entry-point. See
// phase2_pcienum.go for the PCI half.
//
// Build:
//
//	GOOS=tamago GOARCH=<arch> $TAMAGO/bin/go build \
//	    -tags linkcpuinit,linkramstart,phase2_snpenum \
//	    -trimpath -buildmode=pie -ldflags "-E cpuinit" -o app.elf .
//
// (See Taskfile.yaml `snpenum:efi:<arch>` for the per-arch wiring.)

//go:build phase2_snpenum && tamago

package main

import (
	"unsafe"

	"github.com/cloud-boot/tamago-uefi/uefiboard"
)

// runSNPEnumProbe walks every EFI_SIMPLE_NETWORK_PROTOCOL handle published
// by firmware, peeks `*This->Mode`, and prints the MAC + status flags
// for each. The probe never calls `Start` / `Initialize` / `Transmit` /
// `Receive`; the Mode struct is firmware-allocated and stays valid
// while we're still in Boot Services. See
// uefiboard/simple_network_protocol.go for the EFI_SIMPLE_NETWORK_MODE
// layout reference.
func runSNPEnumProbe() {
	println("phase2-snpenum: LocateHandleBuffer(EFI_SIMPLE_NETWORK_PROTOCOL_GUID)")
	handles, err := uefiboard.LocateHandleBuffer(&uefiboard.EFISimpleNetworkProtocolGUID)
	if err != nil {
		println("phase2-snpenum: LocateHandleBuffer FAILED:", err.Error())
		println("phase2-snpenum: firmware does not publish EFI_SIMPLE_NETWORK_PROTOCOL (acceptable on QEMU+EDK2 risc/loong where the PciBus driver doesn't bind SNP)")
		return
	}
	if len(handles) == 0 {
		println("phase2-snpenum: no EFI_SIMPLE_NETWORK_PROTOCOL handles published")
		return
	}
	println("phase2-snpenum: handles=", len(handles))

	for i, h := range handles {
		println("phase2-snpenum: handle", i, "=", h)
		iface, err := uefiboard.HandleProtocol(h, &uefiboard.EFISimpleNetworkProtocolGUID)
		if err != nil {
			println("phase2-snpenum:   HandleProtocol FAILED:", err.Error())
			continue
		}
		dumpOneSNP(iface)
	}
	println("phase2-snpenum: done. handles=", len(handles))
}

// dumpOneSNP reads `*snp->Mode` and prints the relevant fields. We do
// NOT call any function in the SNP entry table — the protocol-instance
// pointer (`snp`) points at firmware memory whose first 64 bits are
// the protocol Revision, followed by function-pointer slots; the
// `Mode` field sits at offset 120. We follow the pointer and read the
// EFI_SIMPLE_NETWORK_MODE struct verbatim.
func dumpOneSNP(snp uint64) {
	// `Mode` is *EFI_SIMPLE_NETWORK_MODE at offset 120.
	modePtrSlot := snp + 120 // = snpModeOffset; literal here so a typo in the const surfaces fast.
	modePtr := *(*uint64)(unsafe.Pointer(uintptr(modePtrSlot)))
	if modePtr == 0 {
		println("phase2-snpenum:   *Mode is NULL — firmware has not allocated mode struct")
		return
	}
	mode := (*uefiboard.EFISimpleNetworkMode)(unsafe.Pointer(uintptr(modePtr)))
	println("phase2-snpenum:   State=", uint64(mode.State),
		"HwAddressSize=", uint64(mode.HwAddressSize),
		"MediaPresent=", uint64(mode.MediaPresent),
		"MediaPresentSupported=", uint64(mode.MediaPresentSupported),
		"IfType=", uint64(mode.IfType))
	// MAC = first HwAddressSize bytes of CurrentAddress.Addr[]. Bound
	// to 32 (sizeof EFI_MAC_ADDRESS) so a malformed firmware that
	// reports HwAddressSize > 32 doesn't read past the slot.
	n := uint64(mode.HwAddressSize)
	if n > 32 {
		n = 32
	}
	println("phase2-snpenum:   MAC = ", macHex(mode.CurrentAddress.Addr[:int(n)]))
	println("phase2-snpenum:   PermanentAddress = ", macHex(mode.PermanentAddress.Addr[:int(n)]))
}

// macHex lives in phase2_snpenum_helpers.go so the host test in
// phase2_snpenum_test.go can exercise it without pulling efiCall in.
