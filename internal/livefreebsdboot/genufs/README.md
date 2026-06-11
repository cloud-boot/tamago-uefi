# genufs — fresh UFS2 oracle for live-FreeBSD-boot

Phase-3 sprint-2C helper that builds a brand-new FreeBSD-flavored
UFS2 disk image populated with a real FreeBSD kernel + minimal
`/boot/loader.conf` + `/etc/fstab`. The output serves two purposes:

1. **Gold oracle for `go-filesystems/ufs`.** The image is written
   by an *independent* FreeBSD-compatible writer; if our pure-Go
   reader (`go-filesystems/ufs`) can open it cleanly, the reader
   is bit-compatible with a real implementation of the on-disk
   format — independent of whatever the parallel
   `go-filesystems/ufs Mkfs` agent (sprint 2C-A) emits.
2. **Working fixture for the live FreeBSD boot test.** Drops into
   `internal/livefreebsdboot/run.sh` as a root-fs candidate for
   `loader.efi` to chain into.

The image is intentionally *not committed* (see `.gitignore`); it
is rebuildable in seconds via `bash genufs.sh`.

## Files

| File | What it is |
|---|---|
| `genufs.sh` | shell driver: detect tool option, stage tree, run makefs, verify magic |
| `Dockerfile.makefs` | builds `cloudboot/makefs:freebsd`, a debian:bookworm-slim image wrapping `kusumi/makefs` (FreeBSD makefs ported to Linux) |
| `genufs.go` | thin Go wrapper around `genufs.sh` so `run.sh` and Go tests can invoke `Refresh()` |
| `genufs_test.go` | 100%-covered unit tests for the Go wrapper (no docker, no ISO) |
| `verify/main.go` | CLI that opens the produced image via `go-filesystems/ufs` and asserts the writer-vs-reader contract end to end |

## Tool selection (option matrix)

The script probes three options in priority order; the first that
works wins.

| Option | Tool | Status as of 2026-06-11 |
|---|---|---|
| A | `pkgx makefs` | pkgx pantry does not ship a `makefs` recipe (CmdNotFound). Skipped. |
| B | docker + `kusumi/makefs` (FreeBSD makefs ported to Linux) | **WORKS**. Used in this build. |
| C | `bsdtar` / libarchive | Rejected — libarchive can pack into many formats but does not emit a FreeBSD-layout UFS2 superblock. |

### Why not Debian's apt `makefs` package directly?

Debian ships *NetBSD's* `makefs` 20190105-3, which writes its UFS2
superblock at byte 8192 (NetBSD's historical `SBLOCK_UFS2`).
FreeBSD's `loader.efi` and our `go-filesystems/ufs` reader expect
byte **65536** (FreeBSD's `SBLOCK_UFS2`). The two on-disk layouts
are otherwise interoperable, but a primary superblock at the
wrong offset is unreadable by FreeBSD-side consumers.

`kusumi/makefs` (BSD-2-Clause) is FreeBSD's own `usr.sbin/makefs`
ported to Linux/*BSD; it preserves the FreeBSD offset and is
actively maintained. We pin neither source SHA nor a release tag
here because the upstream is mature and the integration test
catches any byte-level drift loudly. Sources:
<https://github.com/kusumi/makefs>.

## Provenance of the kernel

The script extracts `/boot/kernel/kernel` (29 185 072 bytes for
FreeBSD 14.3-RELEASE-amd64) from
`$GENUFS_FREEBSD_ISO` (default
`/tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso`) using
`xorriso -osirrox`. The ISO itself is downloaded by the cloud-boot
project once (~412 MiB) and cached out-of-tree — re-download per
run would saturate the network.

## Outputs

| Path | Size | Notes |
|---|---:|---|
| `/tmp/genufs/stage/` | ~30 MiB | staging tree handed to `makefs`; rebuilt every run unless `GENUFS_KEEP_STAGE=1` |
| `/tmp/genufs/ufs2-fresh.img` | 64 MiB | the produced UFS2 image; magic 0x19540119 at byte 65536+1372 |

## Verification

After `genufs.sh` finishes, run:

```bash
go run ./internal/livefreebsdboot/genufs/verify
```

which performs eight checks against the freshly-built image:

1. `ufs.OpenFile` succeeds (superblock decodes, magic OK)
2. Volume label matches `--label` (default `rootfs`)
3-5. `ListDir("/")`, `ListDir("/boot")`, `ListDir("/boot/kernel")`
     contain the expected entries
6. `Stat("/boot/kernel/kernel").Size()` equals the staging-tree
   kernel size
7. `ReadFile("/boot/loader.conf")` contains `boot_mfsroot="NO"`
8. `ReadFile("/etc/fstab")` references `UFS:<label>`

Exit code 0 → reader and writer agree on every byte that matters.

## Cloud-boot integration

`run.sh` (and any future Go-side runner) refreshes the image via:

```go
import "github.com/cloud-boot/tamago-uefi/internal/livefreebsdboot/genufs"

func setupRootFS() (string, error) {
    return genufs.Refresh() // returns /tmp/genufs/ufs2-fresh.img
}
```

`Refresh()` streams the script's stdout / stderr through the
calling process so live progress is visible and CI failures
preserve diagnostics verbatim.

## Tunables

All driven by environment variables (see `genufs.sh` header for
the canonical list):

| var | default | purpose |
|---|---|---|
| `GENUFS_OUT` | `/tmp/genufs/ufs2-fresh.img` | output image path |
| `GENUFS_STAGE` | `/tmp/genufs/stage` | staging tree path |
| `GENUFS_SIZE` | `64m` | image size (k/m/g suffix) |
| `GENUFS_LABEL` | `rootfs` | UFS volume label (also referenced from `/etc/fstab`) |
| `GENUFS_FREEBSD_ISO` | `/tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso` | source ISO for `/boot/kernel/kernel` |
| `GENUFS_DOCKER_IMG` | `cloudboot/makefs:freebsd` | image tag for option B |
| `GENUFS_KEEP_STAGE` | `0` | `1` to keep the staging tree across runs (faster iteration) |

## Out of scope

- A pure-Go UFS2 writer — that's `go-filesystems/ufs Mkfs` in
  sprint 2C-A.
- Extracting and re-packing an existing FreeBSD UFS — that's
  `internal/livefreebsdboot/extractufs/` in sprint 2C-B.
- Composing the UFS partition with an ESP into a single GPT
  image — that's the sprint-2C integration job.
