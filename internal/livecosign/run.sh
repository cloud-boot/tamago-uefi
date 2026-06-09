#!/usr/bin/env bash
# Phase-2 M7.1b live cosign-keyed-signature-verify smoke under QEMU+EDK2
# with user-mode networking. One arch per invocation:
#
#     bash internal/livecosign/run.sh arm64
#     bash internal/livecosign/run.sh riscv64
#     bash internal/livecosign/run.sh loong64
#
# amd64 is in scope to BUILD (so the symbol exercises every arch's
# compiler), but NOT to run live — M6.1/M6.2 currently blocks amd64.
# Invoked with `amd64` the script prints a clear "skipped pending
# M6.2" line and exits 0.
#
# In the default self-test mode the probe generates an ephemeral
# P-256 keypair in-VM, signs the canonical cosign payload locally,
# and verifies the signature against an in-RAM .sig manifest fed
# through a mock Transport (no network needed for the verifier
# itself). The probe ALSO brings up virtio-net + DHCP + roots so the
# real-image code path's setup steps are exercised end-to-end.
#
# Builds a tiny FAT ESP-disk containing the per-arch BOOT*-COSIGN.EFI
# under \EFI\BOOT\, runs the matching qemu-system-<arch> with EDK2
# firmware + virtio-net-pci on `-netdev user`, captures stdout for up
# to 120 s, and matches on the per-mode anchor lines:
#
#   MODE = self-test (default committed build):
#     1. "pubkey parsed - curve P-256 OK"  — PEM/PKIX/ECDSA wiring OK.
#     2. "happy path Verify OK"            — happy ECDSA verify path.
#     3. "tampered Verify rejected"        — fail-closed on bad sig.
#     4. "lease acquired"                  — DHCPv4 DORA completed.
#     5. "embedded roots ="                — CA bundle parsed.
#     6. "COSIGN OK"                       — full M7.1b path OK.
#
#   MODE = real-image (when the cosignTargetRef/cosignEmbeddedPubKey
#   constants in phase2_oci_cosign_verify.go are populated — see
#   internal/livecosign/run-real-image.sh):
#     1. "MODE = real-image"               — real-image branch taken.
#     2. "lease acquired"                  — DHCPv4 DORA completed.
#     3. "embedded roots ="                — CA bundle parsed.
#     4. "manifest digest = sha256:..."    — index/manifest walk OK.
#     5. "COSIGN OK"                       — ECDSA verify against the
#                                            embedded pubkey passed.
#
# Mode is auto-detected from the "MODE = ..." log line. Exit 0 on
# PASS, 1 otherwise.
#
# Boot-media plumbing mirrors `liveocistream/run.sh` 1:1.
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M71B_LIVE_TIMEOUT: per-run wall-clock cap (default 120)
#   M71B_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {amd64|arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M71B_LIVE_TIMEOUT:-120}"

if [[ "$ARCH" == "amd64" ]]; then
    echo "[live-cosign:amd64] skipped pending M6.2 (UPX-go) — amd64 EFI build itself is exercised by cosign:efi:amd64 but not live-run yet"
    exit 0
fi

case "$ARCH" in
    arm64)
        EFI_NAME="BOOTAA64-COSIGN.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-COSIGN.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-COSIGN.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        ;;
    *)
        echo "unsupported arch: $ARCH (M7.1b supports arm64/riscv64/loong64; amd64 is build-only)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task cosign:efi:$ARCH' first" >&2
    exit 1
fi
if [[ ! -f "$FW_CODE" ]]; then
    echo "missing EDK2 firmware code at $FW_CODE (set CLOUDBOOT_OVMF_${ARCH^^}_CODE)" >&2
    exit 1
fi
if [[ -n "$FW_VARS" && ! -f "$FW_VARS" ]]; then
    echo "missing EDK2 firmware vars at $FW_VARS (set CLOUDBOOT_OVMF_${ARCH^^}_VARS)" >&2
    exit 1
fi

WORK="$(mktemp -d -t cloudboot-m71b-live-XXXXXX)"
trap 'if [[ "${M71B_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

NSH_PATH="$WORK/startup.nsh"
cat > "$NSH_PATH" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$NSH_PATH" "$ESP" ::/startup.nsh 2>/dev/null || \
  mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

case "$ARCH" in
    arm64)
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -bios "$FW_CODE"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
    riscv64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE,unit=0"
            -drive "if=pflash,format=raw,file=$FW_VARS,unit=1"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-device,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
    loong64)
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=net0"
            -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
esac

echo "[live-cosign:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

# The probe runs in either MODE = self-test (default committed build:
# no cosignTargetRef configured) or MODE = real-image (constants
# populated; e.g. when run via internal/livecosign/run-real-image.sh).
# Each mode emits different anchor lines; auto-detect from the log
# and apply the matching gate.
if grep -q "MODE = real-image" "$LOG"; then
    MODE=real-image
    GATE=("MODE = real-image" "lease acquired" "embedded roots =" "manifest digest =" "COSIGN OK")
elif grep -q "MODE = self-test" "$LOG"; then
    MODE=self-test
    GATE=("pubkey parsed - curve P-256 OK" "happy path Verify OK" "tampered Verify rejected" "lease acquired" "embedded roots =" "COSIGN OK")
else
    echo "[live-cosign:$ARCH] FAIL — never saw 'MODE = ...' marker after ${ELAPSED_MS}ms (probe didn't reach runOCICosignVerifyProbe)" >&2
    echo "[live-cosign:$ARCH] tail of qemu log (last 200 lines):" >&2
    tail -200 "$LOG" >&2 || true
    exit 1
fi

MISSING=()
for line in "${GATE[@]}"; do
    if ! grep -q "$line" "$LOG"; then
        MISSING+=("$line")
    fi
done
if [[ ${#MISSING[@]} -eq 0 ]]; then
    echo "[live-cosign:$ARCH] PASS (mode=$MODE) — wall=${ELAPSED_MS}ms"
    grep -E "phase2-oci-cosign:" "$LOG" || true
    exit 0
fi
echo "[live-cosign:$ARCH] FAIL (mode=$MODE) — missing: ${MISSING[*]} after ${ELAPSED_MS}ms" >&2
echo "[live-cosign:$ARCH] tail of qemu log (last 200 lines):" >&2
tail -200 "$LOG" >&2 || true
exit 1
