// Package bannertest is a host-side regression test for the multi-arch
// TamaGo UEFI build. It loads each produced BOOT*.EFI and asserts that
// `runtime.GOARCH` was constant-folded to the right value at compile
// time — i.e. that the per-arch ELF was built with the matching
// `GOARCH=...` env var and not with a stale value.
//
// Why a separate package: `main.go` imports `uefiboard`, which is gated
// on `//go:build tamago`. Under the host `go test` (darwin/amd64,
// linux/amd64, …) the uefiboard package compiles to nothing, which
// breaks any test that lives in `package main`. Putting the test under
// `internal/bannertest` sidesteps that.
//
// History: at one point BOOTRISCV64.EFI shipped with the correct
// RISC-V PE machine type and RISC-V .text, but with the rodata banner
// `hello from cloud-boot tamago/amd64 UEFI board` and a second
// `GOOS=tamago GOARCH=amd64` string. Root cause: the per-arch build
// invocation didn't set `GOARCH=riscv64`, so the Go compiler folded
// the `"hello from cloud-boot tamago/" + runtime.GOARCH + " UEFI
// board"` expression to the host's GOARCH. The Taskfile now pins
// every env var explicitly per target; this test guards against the
// regression.
package bannertest

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// repoRoot returns the absolute path to the tamago-uefi repo root,
// computed from this file's compiled-in location so the test works
// regardless of `go test`'s working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// .../tamago-uefi/internal/bannertest/banner_test.go → .../tamago-uefi
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func TestBannerRodataPerArch(t *testing.T) {
	cases := []struct {
		efi  string
		arch string
	}{
		{"BOOTX64.EFI", "amd64"},
		{"BOOTAA64.EFI", "arm64"},
		{"BOOTRISCV64.EFI", "riscv64"},
		{"BOOTLOONGARCH64.EFI", "loong64"},
	}

	root := repoRoot(t)

	for _, tc := range cases {
		t.Run(tc.arch, func(t *testing.T) {
			path := filepath.Join(root, tc.efi)
			data, err := os.ReadFile(path)
			if err != nil {
				if os.IsNotExist(err) {
					t.Skipf("%s not present — run `task all` first", tc.efi)
				}
				t.Fatalf("read %s: %v", path, err)
			}

			wantBanner := []byte("hello from cloud-boot tamago/" + tc.arch + " UEFI board")
			if !bytes.Contains(data, wantBanner) {
				t.Errorf("%s: missing banner %q (runtime.GOARCH was probably "+
					"constant-folded to the wrong value at compile time)",
					tc.efi, wantBanner)
			}

			wantGOARCH := []byte("GOOS=tamago GOARCH=" + tc.arch)
			if !bytes.Contains(data, wantGOARCH) {
				t.Errorf("%s: missing %q in rodata", tc.efi, wantGOARCH)
			}

			// And the *other* archs' GOARCH strings must NOT appear as a
			// banner — that's the exact regression we're guarding.
			for _, other := range cases {
				if other.arch == tc.arch {
					continue
				}
				wrong := []byte("hello from cloud-boot tamago/" + other.arch + " UEFI board")
				if bytes.Contains(data, wrong) {
					t.Errorf("%s: rodata contains a banner for %s — runtime.GOARCH "+
						"was constant-folded to %s instead of %s",
						tc.efi, other.arch, other.arch, tc.arch)
				}
			}
		})
	}
}
