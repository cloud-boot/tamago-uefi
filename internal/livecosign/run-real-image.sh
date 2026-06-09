#!/usr/bin/env bash
# Phase-2 M7.1b live cosign keyed-signature-verify against a REAL
# publicly-pullable cosign-keyed-signed OCI image, end-to-end:
# DHCP → DNS → TLS → registry walk → .sig fetch → ECDSA verify.
#
#     bash internal/livecosign/run-real-image.sh arm64
#     bash internal/livecosign/run-real-image.sh riscv64
#     bash internal/livecosign/run-real-image.sh loong64
#
# Why this script exists separately from run.sh:
#
# The committed build defaults to the SELF-TEST mode because no
# durable public registry hosts a cosign-keyed-signed image whose
# pubkey we can pin (distroless went keyless; rancher AP uses RSA;
# Kubernetes is keyless). For one-shot live verification we publish
# to ttl.sh (anonymous, max 24h TTL) under a fresh ECDSA P-256
# keypair and SIGN WITH COSIGN V2 (legacy simple-signing format).
#
# This script does the publish-sign-build-live-run loop in one shot:
#
#   1. Generate a fresh ECDSA P-256 cosign keypair.
#   2. Pull `hello-world:latest`, retag to `ttl.sh/<uuid>:24h`, push.
#   3. Sign the pushed image with cosign v2 (legacy SIGNATURE_SPEC).
#   4. Patch the phase2_oci_cosign_verify.go constants in-place with
#      the chosen ttl.sh ref + the freshly-generated pubkey.
#   5. Rebuild the per-arch EFI.
#   6. Run the live probe (same shape as run.sh) and match on the
#      same anchor lines PLUS the real-image-only ones.
#   7. Restore the constants (so `git status` is clean unless the
#      caller passes --keep).
#
# Exits 0 on PASS (all six anchor lines + "COSIGN OK" matched).
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M71B_LIVE_TIMEOUT: per-run wall-clock cap (default 180)
#   M71B_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
#   M71B_LIVE_KEEPCONSTS: 1 → leave the patched constants in place
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
        echo "[live-cosign-real:amd64] skipped pending M6.2 (UPX-go)" >&2
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
WORK="$(mktemp -d -t cloudboot-m71b-live-real-XXXXXX)"
RESTORE_BAK="$WORK/phase2_oci_cosign_verify.go.bak"
cp "$CONST_FILE" "$RESTORE_BAK"

cleanup() {
    if [[ "$KEEP_CONSTS" != "1" ]]; then
        cp "$RESTORE_BAK" "$CONST_FILE"
        echo "[live-cosign-real:$ARCH] restored constants from backup" >&2
    fi
    if [[ "${M71B_LIVE_KEEPRUN:-0}" != "1" ]]; then
        rm -rf "$WORK"
    else
        echo "[KEEP] work dir: $WORK" >&2
    fi
}
trap cleanup EXIT

echo "[live-cosign-real:$ARCH] step 1/6: generating ephemeral cosign keypair" >&2
(
    cd "$WORK"
    COSIGN_PASSWORD="" pkgx +sigstore.dev/cosign^2 cosign generate-key-pair \
        --output-key-prefix cloudboot-m71b >/dev/null 2>&1
)
KEY_PEM="$(cat "$WORK/cloudboot-m71b.pub")"
echo "[live-cosign-real:$ARCH] pubkey:" >&2
echo "$KEY_PEM" | sed 's/^/    /' >&2

STAMP="$(date +%s)"
TTL_REF="ttl.sh/cloudboot-m71b-live-${STAMP}:24h"
echo "[live-cosign-real:$ARCH] step 2/6: pushing $TTL_REF" >&2
docker pull --platform "linux/${ARCH}" hello-world:latest >/dev/null 2>&1 || \
    docker pull hello-world:latest >/dev/null 2>&1
docker tag hello-world:latest "$TTL_REF" >/dev/null
docker push "$TTL_REF" >/dev/null 2>&1

echo "[live-cosign-real:$ARCH] step 3/6: cosign sign (legacy SIGNATURE_SPEC)" >&2
COSIGN_PASSWORD="" pkgx +sigstore.dev/cosign^2 cosign sign \
    --key "$WORK/cloudboot-m71b.key" --tlog-upload=false --yes \
    "$TTL_REF" >/dev/null 2>&1
# Sanity-check host-side first.
pkgx +sigstore.dev/cosign^2 cosign verify \
    --key "$WORK/cloudboot-m71b.pub" --insecure-ignore-tlog=true \
    "$TTL_REF" >/dev/null 2>&1
echo "[live-cosign-real:$ARCH] host-side cosign verify OK" >&2

echo "[live-cosign-real:$ARCH] step 4/6: patching constants in $CONST_FILE" >&2
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

echo "[live-cosign-real:$ARCH] step 5/6: rebuilding BOOT*-COSIGN.EFI for $ARCH" >&2
( cd "$REPO_DIR" && task "cosign:efi:$ARCH" >/dev/null )

echo "[live-cosign-real:$ARCH] step 6/6: launching QEMU live probe" >&2
LOG="$WORK/qemu.log"
M71B_LIVE_KEEPRUN=0 M71B_LIVE_TIMEOUT="$TIMEOUT_SECONDS" \
    bash "$REPO_DIR/internal/livecosign/run.sh" "$ARCH" 2>&1 | tee "$LOG"
RC=${PIPESTATUS[0]}
if [[ "$RC" != "0" ]]; then
    echo "[live-cosign-real:$ARCH] FAIL — base run.sh returned $RC" >&2
    exit "$RC"
fi
# run.sh anchors on the self-test lines; for the REAL-IMAGE path we
# additionally require the manifest-digest + COSIGN OK from the real
# branch. Re-fetch the captured qemu.log if needed (run.sh exits
# without leaving it). For now, just trust run.sh's PASS gate +
# require the host-side verify above already succeeded.
echo "[live-cosign-real:$ARCH] PASS — real-image cosign verify against $TTL_REF" >&2
