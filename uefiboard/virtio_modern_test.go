// Host-side tests for virtio_modern.go.
//
// Three concerns:
//
//   1. The COMMON_CFG register-offset constants match Virtio 1.1
//      §4.1.5.1 byte-for-byte.
//   2. `ParseVirtioCaps` correctly turns a `[]VirtioPCICap` (the
//      output of WalkVirtioPCICaps) into a populated
//      VirtioModernConfig, surfacing the right errors when required
//      caps are absent or too short.
//   3. `PerQueueNotifyOffset` arithmetic matches the spec's
//      `cap.offset + queue_notify_off * multiplier` formula.
//
// Live `InitVirtioModernConfig` + the per-register accessors are
// tested by the M2 probe binary itself — they call into
// PciIo.Mem.Read/Write which has no host-side mock here (each
// register access would need a 6-arg efiCall stub, deferred to the
// live boot).

package uefiboard

import (
	"errors"
	"testing"
)

func TestCommonCfgRegisterOffsets(t *testing.T) {
	// Virtio 1.1 §4.1.5.1 table 4.1.5.1.1 byte offsets.
	cases := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"DeviceFeatureSelect", VirtioCfgDeviceFeatureSelect, 0x00},
		{"DeviceFeature", VirtioCfgDeviceFeature, 0x04},
		{"DriverFeatureSelect", VirtioCfgDriverFeatureSelect, 0x08},
		{"DriverFeature", VirtioCfgDriverFeature, 0x0c},
		{"MsixConfig", VirtioCfgMsixConfig, 0x10},
		{"NumQueues", VirtioCfgNumQueues, 0x12},
		{"DeviceStatus", VirtioCfgDeviceStatus, 0x14},
		{"ConfigGeneration", VirtioCfgConfigGeneration, 0x15},
		{"QueueSelect", VirtioCfgQueueSelect, 0x16},
		{"QueueSize", VirtioCfgQueueSize, 0x18},
		{"QueueMsixVector", VirtioCfgQueueMsixVector, 0x1a},
		{"QueueEnable", VirtioCfgQueueEnable, 0x1c},
		{"QueueNotifyOff", VirtioCfgQueueNotifyOff, 0x1e},
		{"QueueDesc", VirtioCfgQueueDesc, 0x20},
		{"QueueDriver", VirtioCfgQueueDriver, 0x28},
		{"QueueDevice", VirtioCfgQueueDevice, 0x30},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got 0x%x, want 0x%x", c.name, c.got, c.want)
		}
	}
	if VirtioCfgCommonCfgSize != 0x38 {
		t.Errorf("VirtioCfgCommonCfgSize: got 0x%x, want 0x38", VirtioCfgCommonCfgSize)
	}
}

// TestParseVirtioCaps_Happy verifies a QEMU-shaped cap list parses
// into a fully populated VirtioModernConfig.
func TestParseVirtioCaps_Happy(t *testing.T) {
	caps := []VirtioPCICap{
		// CommonCfg
		{
			CapID:          PCICapIDVendorSpecific,
			Next:           0x50,
			Len:            16,
			CfgType:        VirtioPCICapCommonCfg,
			BAR:            4,
			Offset:         0x0000,
			Length:         56,
			CfgSpaceOffset: 0x40,
		},
		// NotifyCfg
		{
			CapID:          PCICapIDVendorSpecific,
			Next:           0x60,
			Len:            20, // 16 + 4 for the multiplier
			CfgType:        VirtioPCICapNotifyCfg,
			BAR:            4,
			Offset:         0x1000,
			Length:         0x1000,
			CfgSpaceOffset: 0x50,
		},
		// ISRCfg
		{
			CapID:          PCICapIDVendorSpecific,
			Next:           0x70,
			Len:            16,
			CfgType:        VirtioPCICapISRCfg,
			BAR:            4,
			Offset:         0x2000,
			Length:         0x1000,
			CfgSpaceOffset: 0x60,
		},
		// DeviceCfg
		{
			CapID:          PCICapIDVendorSpecific,
			Next:           0x80,
			Len:            16,
			CfgType:        VirtioPCICapDeviceCfg,
			BAR:            4,
			Offset:         0x3000,
			Length:         12,
			CfgSpaceOffset: 0x70,
		},
		// PCICfg
		{
			CapID:          PCICapIDVendorSpecific,
			Next:           0,
			Len:            16,
			CfgType:        VirtioPCICapPCICfg,
			BAR:            0,
			Offset:         0,
			Length:         0,
			CfgSpaceOffset: 0x80,
		},
	}
	cfg, err := ParseVirtioCaps(caps)
	if err != nil {
		t.Fatalf("ParseVirtioCaps: %v", err)
	}
	if cfg.CommonCfgBAR != 4 || cfg.CommonCfgOffset != 0 {
		t.Errorf("CommonCfg: got (%d, 0x%x), want (4, 0x0)", cfg.CommonCfgBAR, cfg.CommonCfgOffset)
	}
	if !cfg.HasNotifyCfg() {
		t.Errorf("HasNotifyCfg = false, want true")
	}
	if cfg.NotifyCfgBAR != 4 || cfg.NotifyCfgOffset != 0x1000 || cfg.NotifyCfgLength != 0x1000 {
		t.Errorf("NotifyCfg: got (%d, 0x%x, 0x%x)", cfg.NotifyCfgBAR, cfg.NotifyCfgOffset, cfg.NotifyCfgLength)
	}
	if cfg.ISRCfgBAR != 4 || cfg.ISRCfgOffset != 0x2000 {
		t.Errorf("ISRCfg: got (%d, 0x%x)", cfg.ISRCfgBAR, cfg.ISRCfgOffset)
	}
	if !cfg.HasDeviceCfg() {
		t.Errorf("HasDeviceCfg = false, want true")
	}
	if cfg.DeviceCfgBAR != 4 || cfg.DeviceCfgOffset != 0x3000 || cfg.DeviceCfgLength != 12 {
		t.Errorf("DeviceCfg: got (%d, 0x%x, %d)", cfg.DeviceCfgBAR, cfg.DeviceCfgOffset, cfg.DeviceCfgLength)
	}
}

func TestParseVirtioCaps_VZShape_RM16a(t *testing.T) {
	// R-M1.6a: VZ ships DEVICE_CFG with length=17 (shorter than QEMU's).
	// Bounds checking is the caller's responsibility; here we just
	// verify ParseVirtioCaps stores the length correctly.
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapCommonCfg, BAR: 0, Offset: 0x40, Length: 56},
		{CfgType: VirtioPCICapNotifyCfg, BAR: 0, Offset: 0x80, Length: 0x100},
		{CfgType: VirtioPCICapDeviceCfg, BAR: 0, Offset: 0x8000, Length: 17},
	}
	cfg, err := ParseVirtioCaps(caps)
	if err != nil {
		t.Fatalf("ParseVirtioCaps: %v", err)
	}
	if cfg.DeviceCfgLength != 17 {
		t.Errorf("DeviceCfgLength: got %d, want 17 (R-M1.6a VZ shape)", cfg.DeviceCfgLength)
	}
}

func TestParseVirtioCaps_NoCommonCfg(t *testing.T) {
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapNotifyCfg, BAR: 0, Offset: 0x80, Length: 0x100},
	}
	_, err := ParseVirtioCaps(caps)
	if !errors.Is(err, ErrNoCommonCfg) {
		t.Errorf("ParseVirtioCaps: got %v, want ErrNoCommonCfg", err)
	}
}

func TestParseVirtioCaps_CommonCfgAtZeroOffset(t *testing.T) {
	// Edge case: a CommonCfg cap legitimately placed at BAR=0,
	// offset=0. The "unset pattern" detection in ParseVirtioCaps
	// must NOT confuse this for "no CommonCfg" — the second-pass
	// walk over the cap list resolves the ambiguity.
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapCommonCfg, BAR: 0, Offset: 0, Length: 56},
		{CfgType: VirtioPCICapNotifyCfg, BAR: 0, Offset: 0x80, Length: 0x100},
	}
	cfg, err := ParseVirtioCaps(caps)
	if err != nil {
		t.Fatalf("ParseVirtioCaps: %v", err)
	}
	if cfg.CommonCfgBAR != 0 || cfg.CommonCfgOffset != 0 {
		t.Errorf("CommonCfg at zero: got (%d, 0x%x)", cfg.CommonCfgBAR, cfg.CommonCfgOffset)
	}
}

func TestParseVirtioCaps_CommonCfgTooShort(t *testing.T) {
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapCommonCfg, BAR: 0, Offset: 0x40, Length: 32},
		{CfgType: VirtioPCICapNotifyCfg, BAR: 0, Offset: 0x80, Length: 0x100},
	}
	_, err := ParseVirtioCaps(caps)
	if !errors.Is(err, ErrCommonCfgTooShort) {
		t.Errorf("ParseVirtioCaps: got %v, want ErrCommonCfgTooShort", err)
	}
}

func TestParseVirtioCaps_NoNotifyCfg(t *testing.T) {
	caps := []VirtioPCICap{
		{CfgType: VirtioPCICapCommonCfg, BAR: 0, Offset: 0x40, Length: 56},
		{CfgType: VirtioPCICapDeviceCfg, BAR: 0, Offset: 0x8000, Length: 12},
	}
	_, err := ParseVirtioCaps(caps)
	if !errors.Is(err, ErrNoNotifyCfg) {
		t.Errorf("ParseVirtioCaps: got %v, want ErrNoNotifyCfg", err)
	}
}

func TestPerQueueNotifyOffset(t *testing.T) {
	cfg := &VirtioModernConfig{
		NotifyCfgOffset:     0x1000,
		NotifyOffMultiplier: 4,
	}
	// Per Virtio 1.1 §4.1.4.4:
	//   addr = cap.offset + queue_notify_off * multiplier
	if got := cfg.PerQueueNotifyOffset(0); got != 0x1000 {
		t.Errorf("queue 0: got 0x%x, want 0x1000", got)
	}
	if got := cfg.PerQueueNotifyOffset(1); got != 0x1004 {
		t.Errorf("queue 1: got 0x%x, want 0x1004", got)
	}
	if got := cfg.PerQueueNotifyOffset(10); got != 0x1028 {
		t.Errorf("queue 10: got 0x%x, want 0x1028", got)
	}
	// Multiplier=0 (legacy NOTIFY_CFG without the extension): all
	// queues notify at the same offset.
	cfg.NotifyOffMultiplier = 0
	if got := cfg.PerQueueNotifyOffset(5); got != 0x1000 {
		t.Errorf("multiplier=0 queue 5: got 0x%x, want 0x1000", got)
	}
}

func TestNotifyOffMultiplierCfgOffset(t *testing.T) {
	// `notify_off_multiplier` lives 16 bytes past the cap's
	// CfgSpaceOffset (after the 16-byte virtio_pci_cap header).
	if got := notifyOffMultiplierCfgOffset(0x50); got != 0x60 {
		t.Errorf("notifyOffMultiplierCfgOffset(0x50): got 0x%x, want 0x60", got)
	}
	if got := notifyOffMultiplierCfgOffset(0xA0); got != 0xB0 {
		t.Errorf("notifyOffMultiplierCfgOffset(0xA0): got 0x%x, want 0xB0", got)
	}
}

func TestVirtioModernConfig_HasFlags(t *testing.T) {
	// HasNotifyCfg / HasDeviceCfg should be false on a default
	// (zero) struct.
	cfg := &VirtioModernConfig{}
	if cfg.HasNotifyCfg() {
		t.Errorf("default cfg: HasNotifyCfg = true, want false")
	}
	if cfg.HasDeviceCfg() {
		t.Errorf("default cfg: HasDeviceCfg = true, want false")
	}
	cfg.NotifyCfgLength = 0x10
	cfg.DeviceCfgLength = 0x10
	if !cfg.HasNotifyCfg() {
		t.Errorf("after Length=0x10: HasNotifyCfg = false, want true")
	}
	if !cfg.HasDeviceCfg() {
		t.Errorf("after Length=0x10: HasDeviceCfg = false, want true")
	}
}

func TestStatusBits(t *testing.T) {
	// Sanity-check the canonical Virtio 1.1 §2.1 status bit values.
	if VirtioStatusAcknowledge != 0x01 {
		t.Errorf("ACKNOWLEDGE: got 0x%x, want 0x01", VirtioStatusAcknowledge)
	}
	if VirtioStatusDriver != 0x02 {
		t.Errorf("DRIVER: got 0x%x, want 0x02", VirtioStatusDriver)
	}
	if VirtioStatusDriverOK != 0x04 {
		t.Errorf("DRIVER_OK: got 0x%x, want 0x04", VirtioStatusDriverOK)
	}
	if VirtioStatusFeaturesOK != 0x08 {
		t.Errorf("FEATURES_OK: got 0x%x, want 0x08", VirtioStatusFeaturesOK)
	}
	if VirtioStatusNeedsReset != 0x40 {
		t.Errorf("NEEDS_RESET: got 0x%x, want 0x40", VirtioStatusNeedsReset)
	}
	if VirtioStatusFailed != 0x80 {
		t.Errorf("FAILED: got 0x%x, want 0x80", VirtioStatusFailed)
	}
}

func TestFeatureBits(t *testing.T) {
	// VIRTIO_NET_F_MAC = bit 5
	if VirtioNetFeatureMAC != (1 << 5) {
		t.Errorf("VIRTIO_NET_F_MAC: got 0x%x, want 0x%x", VirtioNetFeatureMAC, uint64(1<<5))
	}
	// VIRTIO_NET_F_STATUS = bit 16
	if VirtioNetFeatureStatus != (1 << 16) {
		t.Errorf("VIRTIO_NET_F_STATUS: got 0x%x, want 0x%x", VirtioNetFeatureStatus, uint64(1<<16))
	}
	// VIRTIO_F_VERSION_1 = bit 32
	if VirtioFeatureVersion1 != (1 << 32) {
		t.Errorf("VIRTIO_F_VERSION_1: got 0x%x, want 0x%x", VirtioFeatureVersion1, uint64(1<<32))
	}
}
