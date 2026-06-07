// Host-side tests for efi_events.go's type-surface.
//
// The thunk wrappers (CreateEvent/WaitForEvent/CloseEvent) live in
// efi_events_tamago.go and aren't host-exercisable — they need a real
// gBS. The type-surface in efi_events.go IS host-buildable, so we pin
// the few public constants/methods here.

package uefiboard

import "testing"

func TestEFIEvent_IsZero(t *testing.T) {
	var z EFIEvent
	if !z.IsZero() {
		t.Errorf("zero EFIEvent should report IsZero() == true")
	}
	nz := EFIEvent(0x12345678)
	if nz.IsZero() {
		t.Errorf("non-zero EFIEvent(0x12345678) should report IsZero() == false")
	}
}

func TestEFIEventTypeConstants(t *testing.T) {
	// Spec values per UEFI 2.10 §7.1.1. Pin them so a typo in the
	// flag-bit hex is caught.
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"EFIEventTimer", EFIEventTimer, 0x80000000},
		{"EFIEventRuntime", EFIEventRuntime, 0x40000000},
		{"EFIEventNotifyWait", EFIEventNotifyWait, 0x00000100},
		{"EFIEventNotifySignal", EFIEventNotifySignal, 0x00000200},
		{"EFIEventSignalExitBoot", EFIEventSignalExitBoot, 0x00000201},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = 0x%08x, want 0x%08x", c.name, c.got, c.want)
		}
	}
}

func TestTPLConstants(t *testing.T) {
	cases := []struct {
		name string
		got  uint32
		want uint32
	}{
		{"Application", TPLApplication, 4},
		{"Callback", TPLCallback, 8},
		{"Notify", TPLNotify, 16},
		{"HighLevel", TPLHighLevel, 31},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("TPL%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestBootServicesOffsets(t *testing.T) {
	// Pin the gBS function-pointer offsets from efi_events.go +
	// protocols_tamago.go references. Values come from
	// MdePkg/Include/Uefi/UefiSpec.h struct order.
	cases := []struct {
		name string
		got  int
		want int
	}{
		{"CreateEvent", efiBSCreateEvent, 80},
		{"SetTimer", efiBSSetTimer, 88},
		{"WaitForEvent", efiBSWaitForEvent, 96},
		{"SignalEvent", efiBSSignalEvent, 104},
		{"CloseEvent", efiBSCloseEvent, 112},
		{"CheckEvent", efiBSCheckEvent, 120},
		{"HandleProtocol", efiBSHandleProtocol, 152},
		{"LocateHandleBuffer", efiBSLocateHandleBuffer, 312},
		{"LocateProtocol", efiBSLocateProtocol, 320},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("efiBS%s offset = %d, want %d", c.name, c.got, c.want)
		}
	}
}
