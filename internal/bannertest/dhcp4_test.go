// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Banner-rodata regression for the M4 DHCPv4 acquire probe binaries.
// Same shape as banner_test.go / ministack_test.go but iterates the
// BOOT*-DHCP4.EFI artifacts produced by the `dhcp4:efi:*` Taskfile
// targets.

package bannertest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDHCP4BannerRodataPerArch(t *testing.T) {
	cases := []struct {
		efi  string
		arch string
	}{
		{"BOOTX64-DHCP4.EFI", "amd64"},
		{"BOOTAA64-DHCP4.EFI", "arm64"},
		{"BOOTRISCV64-DHCP4.EFI", "riscv64"},
		{"BOOTLOONGARCH64-DHCP4.EFI", "loong64"},
	}

	root := repoRoot(t)

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			path := filepath.Join(root, tc.efi)
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("%s not present — run `task dhcp4:efi:%s` first", tc.efi, tc.arch)
				}
				t.Fatalf("read %s: %v", path, err)
			}

			wantBanner := []byte("hello from cloud-boot tamago/" + tc.arch + " UEFI board")
			if !bytes.Contains(data, wantBanner) {
				t.Errorf("%s: missing banner %q", tc.efi, wantBanner)
			}

			// The M4 probe banner — must be present.
			wantProbe := []byte("phase2-dhcp4:")
			if !bytes.Contains(data, wantProbe) {
				t.Errorf("%s: missing probe banner %q (was phase2_dhcp4_acquire tag set?)", tc.efi, wantProbe)
			}

			// And the *other* archs' banners must NOT appear.
			for _, other := range cases {
				if other.arch == tc.arch {
					continue
				}
				wrong := []byte("hello from cloud-boot tamago/" + other.arch + " UEFI board")
				if bytes.Contains(data, wrong) {
					t.Errorf("%s: rodata contains a banner for %s — runtime.GOARCH was constant-folded to %s instead of %s",
						tc.efi, other.arch, other.arch, tc.arch)
				}
			}
		})
	}
}
