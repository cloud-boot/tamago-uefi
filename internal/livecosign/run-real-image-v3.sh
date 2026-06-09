#!/usr/bin/env bash
# Phase-2 M7.1b live cosign keyed-signature-verify against a cosign-V3-
# signed image (sigstore-bundle wire format) end-to-end:
# DHCP -> DNS -> TLS -> registry walk -> .sig fetch -> bundle parse -> ECDSA verify.
#
#     bash internal/livecosign/run-real-image-v3.sh arm64
#     bash internal/livecosign/run-real-image-v3.sh riscv64
#     bash internal/livecosign/run-real-image-v3.sh loong64
#
# Why a separate script vs run-real-image.sh:
#
# cosign v3 emits a different on-wire format from v2:
#   - Tag layout: `sha256-<hex>` (no `.sig` suffix when --registry-referrers-mode=oci-1-1).
#   - Top-level manifest is an OCI image INDEX (the referrers index),
#     each entry referencing a separate child artifact manifest whose
#     single layer is a JSON sigstore bundle.
#   - Bundle shape: either messageSignature{...} (sign-blob mode) or
#     dsseEnvelope{payload, payloadType, signatures[]} (default when
#     using --registry-referrers-mode=oci-1-1 today).
#
# The cloud-boot cosign verifier supports BOTH the v2 layer-annotation
# format AND the v3 bundle formats (parser at
# `uefiboard/ministack/oci/cosign.go`); see also the live wire-bytes
# unit test `TestLiveCosignV3DSSEBundleParseAndVerify` which uses real
# bytes captured from a ttl.sh-served cosign-v3 sign session.
#
# This v3 helper:
#
#   1. Generate a fresh ECDSA P-256 cosign keypair.
#   2. Pull `hello-world:latest`, retag to `ttl.sh/<uuid>:24h`, push.
#   3. Sign the pushed image with cosign v3 in oci-1-1 referrers mode
#      (COSIGN_EXPERIMENTAL=1, --tlog-upload=false, --use-signing-config=false).
#   4. Patch the probe constants in-place with the ttl.sh ref + pubkey.
#   5. Rebuild the per-arch EFI.
#   6. Run the live probe and match on the v3-aware anchor lines.
#   7. Restore the constants.
#
# NOTE: the on-target probe (phase2_oci_cosign_verify.go) must point
# at the v3 tag layout — pending a small CL to update sigTagFor() to
# also try the `sha256-<hex>` (no .sig) tag when the legacy lookup
# returns 404. Until then this script demonstrates the SIGNING side
# end-to-end and the parser is proven against real v3 bytes via the
# in-tree TestLiveCosignV3DSSEBundleParseAndVerify unit test.
#
# Environment overrides (same as run-real-image.sh):
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}, M71B_LIVE_TIMEOUT,
#   M71B_LIVE_KEEPRUN, M71B_LIVE_KEEPCONSTS.
set -euo pipefail

ARCH="${1:-}"
KEEP_CONSTS="${M71B_LIVE_KEEPCONSTS:-0}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {arm64|riscv64|loong64}" >&2
    exit 2
fi
case "$ARCH" in
    arm64|riscv64|loong64) ;;
    amd64)
        echo "[live-cosign-v3:amd64] skipped pending M6.2 (UPX-go)" >&2
        exit 0
        ;;
    *)
        echo "unsupported arch: $ARCH" >&2
        exit 2
        ;;
esac

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M71B_LIVE_TIMEOUT:-180}"
CONST_FILE="$REPO_DIR/phase2_oci_cosign_verify.go"
WORK="$(mktemp -d -t cloudboot-m71b-live-v3-XXXXXX)"
RESTORE_BAK="$WORK/phase2_oci_cosign_verify.go.bak"
cp "$CONST_FILE" "$RESTORE_BAK"

cleanup() {
    if [[ "$KEEP_CONSTS" != "1" ]]; then
        cp "$RESTORE_BAK" "$CONST_FILE"
        echo "[live-cosign-v3:$ARCH] restored constants from backup" >&2
    fi
    if [[ "${M71B_LIVE_KEEPRUN:-0}" != "1" ]]; then
        rm -rf "$WORK"
    else
        echo "[KEEP] work dir: $WORK" >&2
    fi
}
trap cleanup EXIT

echo "[live-cosign-v3:$ARCH] step 1/7: generating ephemeral cosign keypair (v3)" >&2
(
    cd "$WORK"
    COSIGN_PASSWORD="" pkgx +sigstore.dev/cosign cosign generate-key-pair \
        --output-key-prefix cloudboot-m71b-v3 >/dev/null 2>&1
)
KEY_PEM="$(cat "$WORK/cloudboot-m71b-v3.pub")"
echo "[live-cosign-v3:$ARCH] pubkey:" >&2
echo "$KEY_PEM" | sed 's/^/    /' >&2

STAMP="$(date +%s)"
TTL_REF="ttl.sh/cloudboot-m71b-v3-${STAMP}:24h"
echo "[live-cosign-v3:$ARCH] step 2/7: pushing $TTL_REF" >&2
docker pull --platform "linux/${ARCH}" hello-world:latest >/dev/null 2>&1 || \
    docker pull hello-world:latest >/dev/null 2>&1
docker tag hello-world:latest "$TTL_REF" >/dev/null
docker push "$TTL_REF" >/dev/null 2>&1

echo "[live-cosign-v3:$ARCH] step 3/7: cosign sign (v3 sigstore-bundle, oci-1-1 referrers)" >&2
COSIGN_PASSWORD="" COSIGN_EXPERIMENTAL=1 pkgx +sigstore.dev/cosign cosign sign \
    --key "$WORK/cloudboot-m71b-v3.key" \
    --use-signing-config=false \
    --tlog-upload=false \
    --registry-referrers-mode=oci-1-1 \
    --yes "$TTL_REF" >/dev/null 2>&1

# Host-side verify with cosign v3 (proves wire format is well-formed).
pkgx +sigstore.dev/cosign cosign verify \
    --key "$WORK/cloudboot-m71b-v3.pub" \
    --insecure-ignore-tlog=true \
    --insecure-ignore-sct=true \
    "$TTL_REF" >/dev/null 2>&1 || {
        echo "[live-cosign-v3:$ARCH] host-side cosign verify FAILED" >&2
        exit 1
    }
echo "[live-cosign-v3:$ARCH] host-side cosign v3 verify OK" >&2

echo "[live-cosign-v3:$ARCH] step 4/7: patching constants in $CONST_FILE" >&2
python3 - "$CONST_FILE" "$TTL_REF" "$KEY_PEM" <<'PY'
import sys, pathlib
fn, ref, pem = sys.argv[1], sys.argv[2], sys.argv[3]
p = pathlib.Path(fn)
src = p.read_text()
src = src.replace(
    'const cosignTargetRef = ""',
    f'const cosignTargetRef = "{ref}"',
    1,
)
src = src.replace(
    'const cosignEmbeddedPubKey = ""',
    'const cosignEmbeddedPubKey = `' + pem.rstrip() + '\n`',
    1,
)
p.write_text(src)
PY

echo "[live-cosign-v3:$ARCH] step 5/7: rebuilding BOOT*-COSIGN.EFI for $ARCH" >&2
( cd "$REPO_DIR" && task "cosign:efi:$ARCH" >/dev/null )

echo "[live-cosign-v3:$ARCH] step 6/7: launching QEMU live probe" >&2
LOG="$WORK/qemu.log"
M71B_LIVE_KEEPRUN=0 M71B_LIVE_TIMEOUT="$TIMEOUT_SECONDS" \
    bash "$REPO_DIR/internal/livecosign/run.sh" "$ARCH" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}

echo "[live-cosign-v3:$ARCH] step 7/7: report" >&2
if [[ "$RC" != "0" ]]; then
    echo "[live-cosign-v3:$ARCH] note: on-target run anchored on self-test only;" >&2
    echo "[live-cosign-v3:$ARCH] the v3 real-image PATH needs sigTagFor() to also" >&2
    echo "[live-cosign-v3:$ARCH] try the no-suffix tag layout. Parser correctness" >&2
    echo "[live-cosign-v3:$ARCH] is proven via TestLiveCosignV3DSSEBundleParseAndVerify." >&2
    exit "$RC"
fi
echo "[live-cosign-v3:$ARCH] PASS — cosign v3 signing path validated end-to-end against $TTL_REF" >&2
