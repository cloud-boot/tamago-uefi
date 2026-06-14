#!/usr/bin/env bash
# Copyright (c) 2026 cloud-boot contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# R-doom1e — empirical verification that DOOM's interactive input path
# end-to-ends through the virtio-input -> InputAdapter -> Frontend.GetKey
# -> engine pipeline. The proof is a *frame divergence* measurement, NOT
# a "no error on key inject" success. Per personal feedback note
# feedback-autonomous-visual-verification.md: visual claims require
# programmatic capture (QMP screendump + pixel histogram) — never
# extrapolate from "API returned nil".
#
# Test protocol
# -------------
#
#   1. Baseline run: launch DOOM for 60s, NO key injection. Capture
#      QMP `screendump` PPMs at t=15s, 30s, 45s, 60s. The engine has a
#      time-driven intro/demo cycle, so the baseline frames change on
#      their own — that's the *control* signal we have to beat.
#
#   2. Keypress run: launch DOOM for 60s. At t=15s (well past
#      engine init), inject `send-key ret`, then `esc`+`down`+`ret` over
#      the next few seconds to navigate the main menu (option select).
#      Capture PPMs at the same timepoints + one immediately after the
#      keypress.
#
#   3. Compare: for each timepoint, compute distinct-color count + a
#      simple RGB histogram on the centered 320x200 DOOM canvas
#      (rows 300-499, cols 480-799 in the 1280x800 framebuffer — same
#      slice the R-doom1c timing curve used). Divergence between
#      baseline and keypress AT THE SAME TIMEPOINT, with the
#      divergence growing AFTER the keypress, is the empirical signal.
#
#   4. Verdict: PASS if post-keypress divergence (chi-square per
#      timepoint or simple top-color delta) is materially larger than
#      pre-keypress divergence. FAIL if no measurable change — and in
#      that case the script dumps both PPM sets so the operator can
#      eyeball them.
#
# Output goes to ${WORK} (kept on disk for inspection if
# DOOMBOOT_LIVE_KEEPRUN=1).

set -euo pipefail

ARCH="${1:-amd64}"
if [[ "$ARCH" != "amd64" ]]; then
    echo "verify_input: only amd64 is wired (mirrors run.sh)" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${DOOMBOOT_LIVE_TIMEOUT:-60}"

EFI_NAME="BOOTX64-DOOMBOOT.EFI"
EFI_BOOT_NAME="BOOTX64.EFI"
QEMU_BIN="qemu-system-x86_64"

# Pick the same firmware preference order as run.sh.
if [[ -f "$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd" ]]; then
    FW_CODE_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/tianocore.org/v0.0.0-stable202605/share/qemu/edk2-i386-vars.fd"
else
    FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-x86_64-code.fd"
    FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-i386-vars.fd"
fi
FW_CODE="${CLOUDBOOT_OVMF_AMD64_CODE:-$FW_CODE_DEFAULT}"
FW_VARS="${CLOUDBOOT_OVMF_AMD64_VARS:-$FW_VARS_DEFAULT}"

EFI_PATH="$REPO_DIR/$EFI_NAME"
[[ -f "$EFI_PATH" ]] || { echo "missing $EFI_PATH; run 'task doomboot:efi:amd64' first" >&2; exit 1; }
[[ -f "$FW_CODE" ]] || { echo "missing EDK2 firmware code at $FW_CODE" >&2; exit 1; }
[[ -f "$FW_VARS" ]] || { echo "missing EDK2 firmware vars at $FW_VARS" >&2; exit 1; }

WORK="$(mktemp -d -t cloudboot-doomboot-verify-XXXXXX)"
trap 'if [[ "${DOOMBOOT_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# macOS unix sockets are limited to 104 bytes. mktemp under TMPDIR
# blows past that for QMP socket paths, so keep them under /tmp/.
SOCK_DIR="$(mktemp -d -p /tmp doomb.XXXXXX 2>/dev/null || mktemp -d /tmp/doomb.XXXXXX)"
trap 'if [[ "${DOOMBOOT_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK" "$SOCK_DIR"; else echo "[KEEP] work dir: $WORK  sock dir: $SOCK_DIR" >&2; fi' EXIT

ESP="$WORK/esp.img"
dd if=/dev/zero of="$ESP" bs=1m count=128 status=none
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

# Send one QMP command to a unix socket and discard the reply.
# Reply lines are accumulated then dropped — we only care that the
# socket is drained so subsequent commands don't see stale buffer.
qmp_send() {
    local sock="$1" cmd="$2"
    {
        printf '%s\n' '{"execute":"qmp_capabilities"}'
        sleep 0.2
        printf '%s\n' "$cmd"
        sleep 0.2
    } | nc -U "$sock" >/dev/null 2>&1 || true
}

# Launch one DOOM run. Args:
#   $1 = run label (baseline | keypress)
#   $2 = path to a script file containing one `send-key qcode` per
#        timestamp (format: `seconds:qcode` per line, comments ok).
#        Empty/missing = no key injection (baseline).
#
# Always captures PPMs at t=15, 16, 30, 45, 60s into $WORK/$label/.
run_doom() {
    local label="$1" key_script="${2:-}"
    local out_dir="$WORK/$label"
    mkdir -p "$out_dir"
    local vars="$out_dir/vars.fd"
    cp "$FW_VARS" "$vars"

    local qmp_sock="$SOCK_DIR/$label.sock"
    local log="$out_dir/qemu.log"
    rm -f "$qmp_sock"

    local qemu_args=(
        -machine q35 -cpu max -m 2048
        -display none -no-reboot
        -vga none
        -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
        -drive "if=pflash,format=raw,file=$vars"
        -drive "file=$ESP,format=raw,if=none,id=esp,media=disk"
        -device "ide-hd,drive=esp"
        -device "virtio-gpu-pci"
        -device "virtio-sound-pci,audiodev=snd0"
        -audiodev "none,id=snd0"
        -device "virtio-keyboard-pci"
        -serial "file:$log"
        -qmp "unix:$qmp_sock,server=on,wait=off"
    )

    echo "[verify_input:$label] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
    "$QEMU_BIN" "${qemu_args[@]}" >"$out_dir/stdout.log" 2>"$out_dir/stderr.log" &
    local qemu_pid=$!

    # Wait for QMP socket to appear (firmware boot can take a few s).
    local waited=0
    while [[ ! -S "$qmp_sock" && $waited -lt 10 ]]; do
        sleep 0.5
        waited=$((waited + 1))
    done
    if [[ ! -S "$qmp_sock" ]]; then
        kill -KILL "$qemu_pid" 2>/dev/null || true
        echo "[verify_input:$label] QMP socket never appeared" >&2
        return 1
    fi

    # Compose the event timeline: (t_seconds, action)
    # action = "shot:NAME" or "key:QCODE"
    local timeline=(
        "15:shot:t15"
        "15:keys"
        "16:shot:t16"
        "30:shot:t30"
        "45:shot:t45"
        "60:shot:t60"
    )

    local start_ts
    start_ts="$(date +%s)"
    for evt in "${timeline[@]}"; do
        local target_t="${evt%%:*}"
        local rest="${evt#*:}"
        local now elapsed sleep_s
        now="$(date +%s)"
        elapsed=$((now - start_ts))
        sleep_s=$((target_t - elapsed))
        if [[ $sleep_s -gt 0 ]]; then
            sleep "$sleep_s"
        fi
        case "$rest" in
            shot:*)
                local name="${rest#shot:}"
                local ppm="$out_dir/$name.ppm"
                qmp_send "$qmp_sock" \
                    "{\"execute\":\"screendump\",\"arguments\":{\"filename\":\"$ppm\",\"format\":\"ppm\"}}"
                echo "[verify_input:$label] t=${target_t}s screendump -> $(basename "$ppm")" >&2
                ;;
            keys)
                if [[ -n "$key_script" && -f "$key_script" ]]; then
                    while IFS= read -r line; do
                        # Strip comments / empty.
                        line="${line%%#*}"
                        line="${line## }"
                        [[ -z "$line" ]] && continue
                        local q="$line"
                        echo "[verify_input:$label] t=${target_t}s send-key $q" >&2
                        qmp_send "$qmp_sock" \
                            "{\"execute\":\"send-key\",\"arguments\":{\"keys\":[{\"type\":\"qcode\",\"data\":\"$q\"}]}}"
                        sleep 0.5
                    done <"$key_script"
                fi
                ;;
        esac
    done

    # Tear the VM down.
    qmp_send "$qmp_sock" '{"execute":"quit"}'
    sleep 1
    kill -TERM "$qemu_pid" 2>/dev/null || true
    sleep 1
    kill -KILL "$qemu_pid" 2>/dev/null || true
    wait "$qemu_pid" 2>/dev/null || true
    return 0
}

# Build the key script for the keypress run. The qcode strings come
# straight from QEMU's qapi-events.json / qcode enum.
KEYS_FILE="$WORK/keys.txt"
cat >"$KEYS_FILE" <<'EOF'
# Advance past the gore engine intro / select first menu option.
ret
esc
down
ret
EOF

# === Run 1: baseline (no input) ============================================
run_doom baseline ""

# === Run 2: keypress =======================================================
run_doom keypress "$KEYS_FILE"

# === Histogram + divergence analysis =======================================
ANALYZE_PY="$WORK/analyze.py"
cat >"$ANALYZE_PY" <<'PYEOF'
"""R-doom1e frame analyzer (stdlib-only — no PIL).

For each timepoint, parse the baseline + keypress PPMs, slice the
centered 320x200 DOOM canvas (rows 300..499, cols 480..799 in the
1280x800 framebuffer), and report:

  - non-black pixel count
  - distinct chromatic color count (R != G or G != B)
  - top-5 chromatic colors
  - chi-square distance between baseline and keypress on the top-32
    chromatic colors (union)
  - top-color delta (Jaccard-like)

Exit status: 0 always (the bash wrapper makes the PASS/FAIL call from
the printed JSON record on the last line).
"""
import json
import os
import sys
from collections import Counter


def parse_ppm(path: str):
    """Parse a binary PPM (P6) into (width, height, bytes-RGB)."""
    with open(path, "rb") as fh:
        data = fh.read()
    # Header: "P6\n<w> <h>\n<maxval>\n" with optional comment lines.
    i = 0

    def read_token():
        nonlocal i
        # Skip whitespace + comments.
        while i < len(data):
            c = data[i:i + 1]
            if c in (b" ", b"\t", b"\n", b"\r"):
                i += 1
                continue
            if c == b"#":
                while i < len(data) and data[i:i + 1] != b"\n":
                    i += 1
                continue
            break
        start = i
        while i < len(data) and data[i:i + 1] not in (b" ", b"\t", b"\n", b"\r"):
            i += 1
        return data[start:i]

    magic = read_token()
    if magic != b"P6":
        raise ValueError(f"{path}: not a P6 PPM (got {magic!r})")
    w = int(read_token())
    h = int(read_token())
    maxval = int(read_token())
    # Skip exactly one whitespace byte after maxval.
    i += 1
    if maxval != 255:
        raise ValueError(f"{path}: only maxval=255 supported, got {maxval}")
    pixels = data[i:i + w * h * 3]
    if len(pixels) != w * h * 3:
        raise ValueError(
            f"{path}: short pixel payload ({len(pixels)} != {w * h * 3})"
        )
    return w, h, pixels


def canvas_pixels(w: int, h: int, pix: bytes, row0=300, row1=500, col0=480, col1=800):
    """Yield (r, g, b) for each pixel in the DOOM canvas slice."""
    row1 = min(row1, h)
    col1 = min(col1, w)
    stride = w * 3
    for r in range(row0, row1):
        base = r * stride + col0 * 3
        end = r * stride + col1 * 3
        row = pix[base:end]
        for j in range(0, len(row), 3):
            yield row[j], row[j + 1], row[j + 2]


def histogram(path: str):
    w, h, pix = parse_ppm(path)
    nonblack = 0
    chromatic_total = 0
    chrom = Counter()
    for r, g, b in canvas_pixels(w, h, pix):
        if r or g or b:
            nonblack += 1
        if r != g or g != b:
            chromatic_total += 1
            chrom[(r, g, b)] += 1
    top = chrom.most_common(32)
    return {
        "path": os.path.basename(path),
        "canvas_px": (500 - 300) * (800 - 480),
        "nonblack_px": nonblack,
        "distinct_chromatic": len(chrom),
        "chromatic_px": chromatic_total,
        "top_chromatic": [
            {"rgb": list(rgb), "count": c} for rgb, c in top[:5]
        ],
        "_top32_dict": {f"{r},{g},{b}": c for (r, g, b), c in top},
    }


def chi_square(a: dict, b: dict) -> float:
    """Pearson chi-square on the union of top keys, dropping the _top32_dict
    marker. Larger = more divergent."""
    ka = a["_top32_dict"]
    kb = b["_top32_dict"]
    keys = set(ka) | set(kb)
    total = 0.0
    for k in keys:
        x = ka.get(k, 0)
        y = kb.get(k, 0)
        denom = x + y
        if denom == 0:
            continue
        total += ((x - y) ** 2) / denom
    return total


def topcolor_delta(a: dict, b: dict) -> float:
    """1.0 = top-5 sets disjoint; 0.0 = identical."""
    sa = {tuple(c["rgb"]) for c in a["top_chromatic"]}
    sb = {tuple(c["rgb"]) for c in b["top_chromatic"]}
    if not sa and not sb:
        return 0.0
    inter = sa & sb
    union = sa | sb
    if not union:
        return 0.0
    return 1.0 - len(inter) / len(union)


def main():
    baseline_dir = sys.argv[1]
    keypress_dir = sys.argv[2]
    timepoints = ["t15", "t16", "t30", "t45", "t60"]

    print(f"{'time':<6} {'side':<10} "
          f"{'nonblk':>7} {'distC':>6} "
          f"{'top1_rgb':>16} {'top1_n':>6}")
    print("-" * 64)
    per_t = {}
    for tp in timepoints:
        bp = os.path.join(baseline_dir, f"{tp}.ppm")
        kp = os.path.join(keypress_dir, f"{tp}.ppm")
        if not (os.path.exists(bp) and os.path.exists(kp)):
            print(f"{tp:<6} MISSING  baseline={os.path.exists(bp)} keypress={os.path.exists(kp)}")
            continue
        hb = histogram(bp)
        hk = histogram(kp)
        for side, h in (("baseline", hb), ("keypress", hk)):
            top1 = h["top_chromatic"][0] if h["top_chromatic"] else {"rgb": [0, 0, 0], "count": 0}
            print(f"{tp:<6} {side:<10} "
                  f"{h['nonblack_px']:>7} {h['distinct_chromatic']:>6} "
                  f"{str(tuple(top1['rgb'])):>16} {top1['count']:>6}")
        chi = chi_square(hb, hk)
        delta = topcolor_delta(hb, hk)
        per_t[tp] = {"chi2": chi, "top_delta": delta}
        print(f"{tp:<6} {'CHI2/Δ':<10} {chi:>12.1f}   top-set Δ={delta:.2f}")
        print()

    pre = per_t.get("t15", {"chi2": 0.0})["chi2"]
    posts = [per_t[t]["chi2"] for t in ("t16", "t30", "t45", "t60") if t in per_t]
    post_max = max(posts) if posts else 0.0

    print(f"PRE-keypress  chi2 (t15)         = {pre:.1f}")
    print(f"POST-keypress chi2 (max t16-60)  = {post_max:.1f}")
    if pre <= 0:
        ratio = float("inf") if post_max > 0 else 0.0
    else:
        ratio = post_max / pre
    print(f"POST / PRE ratio                 = {ratio:.2f}")

    result = {
        "pre_chi2": pre,
        "post_chi2_max": post_max,
        "ratio": None if ratio == float("inf") else ratio,
        "per_timepoint": per_t,
    }
    print("RESULT_JSON=" + json.dumps(result))


main()
PYEOF

echo "" >&2
echo "[verify_input] === histogram analysis ===" >&2
ANALYSIS_OUT="$WORK/analysis.txt"
python3 "$ANALYZE_PY" "$WORK/baseline" "$WORK/keypress" | tee "$ANALYSIS_OUT"

# Extract JSON line + verdict.
RESULT_JSON="$(grep '^RESULT_JSON=' "$ANALYSIS_OUT" | tail -1 | sed 's/^RESULT_JSON=//')"

PRE="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d['pre_chi2'])" "$RESULT_JSON")"
POST="$(python3 -c "import json,sys; d=json.loads(sys.argv[1]); print(d['post_chi2_max'])" "$RESULT_JSON")"

# PASS criterion: the maximum chi-square between baseline and keypress
# at any POST-keypress timepoint (t16, t30, t45, t60) must materially
# exceed the PRE-keypress chi-square at t15 (where both runs had the
# same input history — namely none — so divergence should be near
# zero apart from natural engine non-determinism).
#
#   - Strict: post_max > 2 * pre AND post_max > 1000 (raw chi2 scale on
#     ~64k canvas pixels; an engine state change moves easily 10000+).
#   - Lenient (engine state changed but pre baseline noisier than
#     expected): post_max > 5 * pre.
#
# Either is empirical evidence that the keypress propagated.
python3 - "$RESULT_JSON" <<'VERDICT'
import json, sys
d = json.loads(sys.argv[1])
pre = d["pre_chi2"]
post = d["post_chi2_max"]
strict = (post > 2 * pre) and (post > 1000)
lenient = (post > 5 * pre) and (post > 200)
if strict:
    verdict = "PASS-STRICT"
elif lenient:
    verdict = "PASS-LENIENT"
else:
    verdict = "FAIL"
print(f"VERDICT={verdict} pre_chi2={pre:.1f} post_chi2_max={post:.1f}")
sys.exit(0 if verdict.startswith("PASS") else 1)
VERDICT
RC=$?

if [[ $RC -eq 0 ]]; then
    echo "[verify_input] PASS — keypress propagation empirically observed" >&2
    exit 0
fi
echo "[verify_input] FAIL — no measurable frame divergence after keypress" >&2
echo "[verify_input] keep PPMs for inspection: DOOMBOOT_LIVE_KEEPRUN=1 bash $0" >&2
exit 1
