# extractufs — real FreeBSD UFS2 fixture for cloud-boot

This package produces a real-world UFS2 partition image consumable by
[`go-filesystems/ufs`][gofs-ufs] so that Phase 3 sprint 2C (live
FreeBSD boot via `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL`) has a kernel
sitting on a real on-disk root.

[gofs-ufs]: https://github.com/go-filesystems/ufs

## Approach

The original brief considered booting the
`FreeBSD-14.3-RELEASE-amd64-bootonly.iso` installer in QEMU, running
`bsdinstall script` with a scripted config, powering down, and `dd`-ing
out the freebsd-ufs partition. We chose the FAST PATH instead:
**download FreeBSD release engineering's pre-built raw VM image** and
extract its rootfs partition. The pre-built artifact already passes
through the bsdinstall process upstream, so reusing it is strictly
cheaper and avoids the macOS + QEMU + serial-console install plumbing.

The bsdinstall fallback path is still documented and a sample
`bsdinstall.cfg` is checked in next to `install.sh`, in case upstream
ever stops publishing the raw image.

## Provenance

| Field | Value |
| --- | --- |
| FreeBSD release | 14.3-RELEASE-amd64 |
| Upstream URL | <https://download.freebsd.org/releases/VM-IMAGES/14.3-RELEASE/amd64/Latest/FreeBSD-14.3-RELEASE-amd64.raw.xz> |
| Compressed size | 807 MiB |
| Decompressed raw disk | 6 GiB (sparse: 3.5 GiB on-disk) |
| GPT scheme | bootfs (61 KiB) + efiesp (32.5 MiB) + swapfs (1 GiB) + **rootfs (5 GiB)** |
| rootfs partition GUID | `516E7CB6-6ECF-11D6-8FF8-00022D09712B` (FreeBSD UFS) |
| rootfs filesystem | UFS2 (FFSv2), `bsize=32768`, `fsize=4096`, 9 cylinder groups |
| Extracted partition size | 5.0 GiB exact (10 485 760 × 512-byte sectors) |

## Layout

```
extractufs/
├── README.md                  this file
├── install.sh                 download + decompress raw VM image
├── extract_ufs.sh             dd the FreeBSD UFS partition out
├── minimize_fixture.sh        export /boot + prune to virtio subset
├── bsdinstall.cfg             scripted config (fallback, unused)
├── loader.conf                synthetic /boot/loader.conf
├── verify/                    Go verifier using go-filesystems/ufs
│   ├── go.mod                 standalone module (GOWORK=off)
│   ├── _ufs_at_head/          snapshot of go-filesystems/ufs @ sprint 2A
│   ├── verify.go              opens image, checks /boot/kernel/kernel
│   ├── inspect_boot.go        (-tags inspect) walks /boot, prints sizes
│   └── export_boot.go         (-tags export) copies /boot to host tree
├── freebsd-ufs2-full.img      ← generated, .gitignored, 5 GiB
├── freebsd-ufs2-min.img       ← generated symlink → full (until genufs)
├── bootroot/                  ← generated, .gitignored, ~30 MiB
└── bootroot.tar               ← generated, ingested by sibling genufs
```

## End-to-end build

```sh
./install.sh           # one-shot download + decompress (cached in /tmp/fbsd)
./extract_ufs.sh       # carve UFS partition into freebsd-ufs2-full.img (5 GiB)
./minimize_fixture.sh  # export /boot, prune kmods, emit bootroot.tar (30 MiB)
./verify/verify -img ./freebsd-ufs2-full.img
```

Expected verify output:

```
superblock: bsize=32768 fsize=4096 ncg=9 magic=ok
/boot/kernel: 851 entries
/boot/kernel/kernel: size=29185072 bytes mode=0100444
/boot/loader.conf: not present (ufs: path not found: boot/loader.conf) — fine for fixture
OK — go-filesystems/ufs successfully read the extracted partition
```

## Sprint 2C integration

- **`freebsd-ufs2-full.img`** is the real-world UFS2 fixture sprint 2C
  consumes via `go-filesystems/ufs` + sprint 2B's
  `EFI_SIMPLE_FILE_SYSTEM_PROTOCOL` shim. It contains the real
  `/boot/kernel/kernel` (29 MiB) plus 851 kernel modules.
- **`freebsd-ufs2-min.img`** is reserved for the streaming-from-ttl.sh
  live test (target <100 MiB). Today it is a symlink to the full
  image; once Agent 2C-C's [`genufs`][genufs] lands, replace the
  symlink with `genufs pack bootroot.tar -o freebsd-ufs2-min.img`.
  `bootroot.tar` is already 30 MiB and contains the pruned virtio-only
  boot subset.

[genufs]: ../genufs/

## Why is the binary blob .gitignored?

The full UFS2 image is 5 GiB on the wire and ~3.5 GiB on disk —
unacceptable for a Git repository. It is fully regeneratable in
~30 seconds from `install.sh + extract_ufs.sh` and is byte-identical
across runs (deterministic upstream VM image). Tests and tooling refer
to it by local path; CI rebuilds it from scratch.

## sgdisk dependency

`extract_ufs.sh` uses `sgdisk` from `gptfdisk` (`brew install gptfdisk`
on macOS). It is the only non-standard CLI dependency; everything else
(dd, awk, curl, xz) is in base Darwin or pkgx.
