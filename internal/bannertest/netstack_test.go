// Per-arch banner-rodata smoke test for the Phase-2 M3
// netstack-ping EFIs (BOOT*-NETSTACK.EFI).
//
// Same regression seam as the default-build banner test: assert
// that each per-arch ELF contains the matching
// `runtime.GOARCH` rodata constant. Catches the same family of
// "wrong GOARCH env at build time" bugs we caught at Phase 1.
//
// Skipped silently if the BOOT*-NETSTACK.EFI artefact isn't
// present (run `task netstack:all` first). Skipped specifically
// for loong64 — see R-M3'b in the design doc; tamago-pie ships
// no `zsyscall_tamago_loong64.go` so the gvisor-bearing M3
// binary cannot link on that arch. The other three archs are
// expected to ship a BOOT*-NETSTACK.EFI.

package bannertest

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestNetstackPingBannerRodataPerArch(t *testing.T) {
	cases := []struct {
		efi  string
		arch string
	}{
		{"BOOTX64-NETSTACK.EFI", "amd64"},
		{"BOOTAA64-NETSTACK.EFI", "arm64"},
		{"BOOTRISCV64-NETSTACK.EFI", "riscv64"},
		// loong64 omitted — R-M3'b: tamago-pie's loong64 syscall
		// overlay is incomplete; the M3 binary cannot link.
	}

	root := repoRoot(t)

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			path := filepath.Join(root, tc.efi)
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("%s not present — run `task netstack:all` first", tc.efi)
				}
				t.Fatalf("read %s: %v", path, err)
			}

			wantBanner := []byte("hello from cloud-boot tamago/" + tc.arch + " UEFI board")
			if !bytes.Contains(data, wantBanner) {
				t.Errorf("%s: missing banner %q (runtime.GOARCH was probably "+
					"constant-folded to the wrong value at compile time)",
					tc.efi, wantBanner)
			}

			// The probe's identifying log line should be present.
			wantProbe := []byte("phase2-netstack-ping: M3 — gvisor netstack over virtio-net")
			if !bytes.Contains(data, wantProbe) {
				t.Errorf("%s: missing probe banner %q (build-tag wiring may be off)",
					tc.efi, wantProbe)
			}

			// Wrong-arch banner must NOT appear in this EFI.
			for _, other := range cases {
				if other.arch == tc.arch {
					continue
				}
				wrong := []byte("hello from cloud-boot tamago/" + other.arch + " UEFI board")
				if bytes.Contains(data, wrong) {
					t.Errorf("%s: rodata contains a banner for %s (cross-arch leak)",
						tc.efi, other.arch)
				}
			}
		})
	}
}
