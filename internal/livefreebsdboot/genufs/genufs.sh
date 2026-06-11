#!/usr/bin/env bash
# Copyright 2026 The cloud-boot Authors.
# SPDX-License-Identifier: BSD-3-Clause
#
# genufs.sh — produce a freshly-generated FreeBSD-flavored UFS2
# image populated with a FreeBSD kernel + minimal /etc and
# /boot/loader.conf, intended as the gold-oracle fixture for
# Phase-3 sprint-2C live-FreeBSD-boot.
#
# Output: /tmp/genufs/ufs2-fresh.img  (UFS2 / FFS2, SBLOCK at 65536)
#
# Strategy — see README.md for the full discussion. Summary:
#
#   Option A : pkgx makefs                  — pantry does not ship makefs
#                                             (CmdNotFound). Skipped.
#   Option B : docker + Linux-ported FreeBSD makefs (kusumi/makefs)
#                                           — THE chosen path. Built once
#                                             into local image cloudboot/makefs:freebsd
#                                             via the sibling Dockerfile.makefs.
#   Option C : bsdtar / libarchive          — does NOT emit UFS2 at all;
#                                             documented for completeness.
#
# Why not Debian's apt `makefs` package directly?
#   It ships NetBSD's makefs 20190105, which lays the UFS2 superblock
#   at byte 8192 (NetBSD SBLOCK_UFS2). FreeBSD's loader.efi + our
#   go-filesystems/ufs reader expect byte 65536 (FreeBSD SBLOCK_UFS2).
#   The kusumi/makefs port preserves the FreeBSD offset.
#
# The image is NEVER committed; it is rebuildable any time with:
#
#     bash internal/livefreebsdboot/genufs/genufs.sh
#
# Environment overrides:
#
#   GENUFS_OUT        : output image path   (default /tmp/genufs/ufs2-fresh.img)
#   GENUFS_STAGE      : staging tree path   (default /tmp/genufs/stage)
#   GENUFS_SIZE       : image size  k/m/g   (default 64m)
#   GENUFS_LABEL      : UFS volume label    (default rootfs)
#   GENUFS_FREEBSD_ISO: source ISO for /boot/kernel/kernel
#                       (default /tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso)
#   GENUFS_DOCKER_IMG : docker image tag    (default cloudboot/makefs:freebsd)
#   GENUFS_KEEP_STAGE : 1 → keep stage tree across runs (default: nuke + rebuild)
#
# Exit codes:
#
#   0 : image written and superblock magic verified
#   1 : a required host tool is missing
#   2 : kernel could not be extracted from the FreeBSD ISO
#   3 : makefs failed inside the container
#   4 : output magic check failed (image probably unreadable by ufs)

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"

GENUFS_OUT="${GENUFS_OUT:-/tmp/genufs/ufs2-fresh.img}"
GENUFS_STAGE="${GENUFS_STAGE:-/tmp/genufs/stage}"
GENUFS_SIZE="${GENUFS_SIZE:-64m}"
GENUFS_LABEL="${GENUFS_LABEL:-rootfs}"
GENUFS_FREEBSD_ISO="${GENUFS_FREEBSD_ISO:-/tmp/fbsd/FreeBSD-14.3-RELEASE-amd64-bootonly.iso}"
GENUFS_DOCKER_IMG="${GENUFS_DOCKER_IMG:-cloudboot/makefs:freebsd}"
GENUFS_KEEP_STAGE="${GENUFS_KEEP_STAGE:-0}"

OUT_DIR="$(dirname "$GENUFS_OUT")"

log() { printf '[genufs] %s\n' "$*" >&2; }
die() { log "ERROR: $*"; exit "${2:-1}"; }

# --- host-tool probing ------------------------------------------------------

detect_option() {
    # Option A — pkgx makefs.
    #
    # `pkgx +foo --help` exits 0 even when foo doesn't exist (it
    # prints pkgx's own usage). We have to invoke the actual binary
    # under +foo to get a real CmdNotFound. As of 2026-06 pantry
    # ships no makefs recipe.
    if command -v pkgx >/dev/null 2>&1; then
        if pkgx +makefs makefs --help >/dev/null 2>&1; then
            echo "A"
            return 0
        fi
    fi
    # Option B — docker (with the kusumi/makefs image, built locally
    # via Dockerfile.makefs; auto-built on first use).
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        echo "B"
        return 0
    fi
    # Option C — bsdtar / libarchive.  We deliberately do NOT
    # auto-select C even when bsdtar is present, because libarchive
    # cannot emit a FreeBSD-flavored UFS2 — auto-selecting it would
    # always end in the C builder's "rejected" error and obscure
    # the real diagnosis (docker daemon down, etc). The user can
    # still force C with GENUFS_FORCE_OPTION=C to see the explicit
    # rejection message.
    if [[ "${GENUFS_FORCE_OPTION:-}" == "C" ]] && command -v bsdtar >/dev/null 2>&1; then
        echo "C"
        return 0
    fi
    return 1
}

# --- staging tree -----------------------------------------------------------

build_stage() {
    log "staging tree: $GENUFS_STAGE"
    if [[ "$GENUFS_KEEP_STAGE" != "1" ]]; then
        chmod -R u+rwX "$GENUFS_STAGE" 2>/dev/null || true
        rm -rf "$GENUFS_STAGE"
    fi
    mkdir -p "$GENUFS_STAGE/boot/kernel"
    mkdir -p "$GENUFS_STAGE/etc"

    # /boot/kernel/kernel — extracted from the FreeBSD bootonly ISO.
    if [[ ! -r "$GENUFS_FREEBSD_ISO" ]]; then
        die "FreeBSD ISO not found at $GENUFS_FREEBSD_ISO (override with GENUFS_FREEBSD_ISO)" 2
    fi
    if [[ ! -e "$GENUFS_STAGE/boot/kernel/kernel" ]]; then
        if ! command -v xorriso >/dev/null 2>&1; then
            die "xorriso required to extract /boot/kernel/kernel from the ISO" 1
        fi
        log "extracting /boot/kernel/kernel from $(basename "$GENUFS_FREEBSD_ISO")"
        xorriso -osirrox on \
                -indev "$GENUFS_FREEBSD_ISO" \
                -extract /boot/kernel/kernel "$GENUFS_STAGE/boot/kernel/kernel" \
                >/dev/null 2>&1 \
            || die "xorriso extract of /boot/kernel/kernel failed" 2
        # xorriso preserves the original mode bits (often 0444) which
        # make `rm -rf` complain on the next rebuild. Re-chmod so the
        # staging dir is fully owned-and-writable by us.
        chmod -R u+rw "$GENUFS_STAGE"
    fi

    local ksz
    ksz=$(stat -f%z "$GENUFS_STAGE/boot/kernel/kernel" 2>/dev/null \
          || stat -c%s "$GENUFS_STAGE/boot/kernel/kernel")
    log "kernel size: $ksz bytes"

    # /boot/loader.conf — minimal verbose-boot config.
    cat > "$GENUFS_STAGE/boot/loader.conf" <<'LOADER'
boot_mfsroot="NO"
verbose_loading="YES"
boot_verbose="YES"
LOADER

    # /etc/fstab — UFS:<label> at /.
    cat > "$GENUFS_STAGE/etc/fstab" <<FSTAB
# Device         Mountpoint  FStype  Options Dump    Pass#
UFS:$GENUFS_LABEL       /           ufs     ro      1       1
FSTAB
}

# --- builders ---------------------------------------------------------------

ensure_docker_image() {
    if docker image inspect "$GENUFS_DOCKER_IMG" >/dev/null 2>&1; then
        return 0
    fi
    log "image $GENUFS_DOCKER_IMG not present — building from Dockerfile.makefs"
    docker build \
        -t "$GENUFS_DOCKER_IMG" \
        -f "$SCRIPT_DIR/Dockerfile.makefs" \
        "$SCRIPT_DIR" \
        >&2 \
        || die "docker build of $GENUFS_DOCKER_IMG failed" 1
}

build_with_makefs_local() {
    # Option A — only reached if pkgx makefs ever lands. We pass
    # the FreeBSD-flavored options even though pantry has not chosen
    # which port to ship; if it ships NetBSD's the magic check at
    # the end will detect the wrong offset and exit nonzero.
    log "building UFS2 via host (pkgx) makefs"
    pkgx +makefs makefs -t ffs -o "version=2,label=$GENUFS_LABEL" -s "$GENUFS_SIZE" \
        "$GENUFS_OUT" "$GENUFS_STAGE" \
        || die "makefs (host) failed" 3
}

build_with_docker() {
    # Option B — local cloudboot/makefs:freebsd image wraps
    # kusumi/makefs (FreeBSD makefs ported to Linux). Output lives
    # in the SBLOCK_UFS2 = 65536 layout, label stamped via -o label=.
    ensure_docker_image
    log "building UFS2 via $GENUFS_DOCKER_IMG"
    docker run --rm \
        -v "$GENUFS_STAGE":/stage:ro \
        -v "$OUT_DIR":/out \
        "$GENUFS_DOCKER_IMG" \
        -t ffs \
        -o "version=2,label=$GENUFS_LABEL" \
        -s "$GENUFS_SIZE" \
        "/out/$(basename "$GENUFS_OUT")" \
        /stage \
        || die "makefs (docker) failed" 3
}

build_with_bsdtar() {
    die "Option C (bsdtar/libarchive) cannot emit FreeBSD-UFS2; pick A or B" 1
}

# --- verification -----------------------------------------------------------

verify_image() {
    # UFS2 superblock at byte 65536, magic field at +1372 = 0x19540119
    # (little-endian on disk -> "19 01 54 19").  We use a portable
    # shell + od probe so we do NOT need python on the host.
    local magic_hex
    magic_hex=$(dd if="$GENUFS_OUT" bs=1 skip=$((65536 + 1372)) count=4 status=none \
                 | od -An -tx1 \
                 | tr -d ' \n')
    if [[ "$magic_hex" != "19015419" ]]; then
        die "UFS2 magic check failed at byte 65536+1372 (got 0x$magic_hex, want 0x19015419)" 4
    fi
    local sz
    sz=$(stat -f%z "$GENUFS_OUT" 2>/dev/null || stat -c%s "$GENUFS_OUT")
    log "verified FreeBSD UFS2 magic 0x19540119 at byte 65536+1372"
    log "output: $GENUFS_OUT ($sz bytes)"
}

# --- driver -----------------------------------------------------------------

main() {
    mkdir -p "$OUT_DIR"
    rm -f "$GENUFS_OUT"

    local opt
    if ! opt=$(detect_option); then
        die "no UFS2-builder option available on this host (need pkgx makefs OR docker OR bsdtar)" 1
    fi
    log "selected option: $opt"

    build_stage

    case "$opt" in
        A) build_with_makefs_local ;;
        B) build_with_docker       ;;
        C) build_with_bsdtar       ;;
        *) die "internal: unknown option $opt" 1 ;;
    esac

    verify_image
    log "done"
}

main "$@"
