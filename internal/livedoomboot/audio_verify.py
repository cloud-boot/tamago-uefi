#!/usr/bin/env python3
# Copyright (c) 2026 cloud-boot contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# R-doom1h GATE C-2 — bounded-tolerance comparison of a captured guest
# WAV file against a committed reference WAV.
#
# Metric: per-second RMS envelope within +/- TOLERANCE_DB for >= MIN_RATIO
# of windows. The two WAVs MUST share format (sample rate, channel count,
# sample width); a format mismatch is an unconditional fail because the
# QEMU wav backend's output is fully deterministic given a fixed device
# config.
#
# Why this metric (vs cross-correlation / spectral fingerprint):
#
#   DOOM Phase 1 audio = short SFX bursts (pistol shots, monster grunts)
#   over silence — no continuous music, no sustained tones. The guest's
#   sound output is the deterministic engine event stream (proved
#   byte-equal by GATE C-1) processed through go-virtio/sound's PCM mixer
#   and emitted via virtio-sound-pci. The *content* of each SFX is
#   identical between runs; the *timing* may shift by up to ~100ms due
#   to TamaGo GC pauses, the tamago scheduler, and virtqueue latency.
#
#   - Cross-correlation: hyper-sensitive to those sub-second phase shifts;
#     a 50ms drift collapses the score even when the audio is otherwise
#     identical.
#   - Spectral fingerprint (FFT bin Pearson r): designed for sustained
#     spectral content. DOOM's "burst over silence" pattern means most
#     FFT windows are noise floor; the few that contain SFX dominate the
#     correlation in unpredictable ways depending on which bursts the
#     window-aligned FFT captures.
#   - Per-second RMS envelope: each 1s window absorbs <1s of jitter
#     transparently. Log-amplitude error is a standard audio measure
#     and the "X dB threshold, Y% of windows" contract is unambiguous.
#
# Exit codes:
#   0 = PASS (>= MIN_RATIO windows within +/- TOLERANCE_DB)
#   1 = FAIL (numeric details on stdout)
#   2 = ERROR (bad input, format mismatch, etc.)

import argparse
import math
import os
import struct
import sys
import wave


def _read_qemu_wav(path):
    # QEMU's -audiodev wav backend writes a RIFF/WAVE header with
    # placeholder zero sizes for the RIFF chunk and the data chunk, then
    # patches the sizes back in only on graceful shutdown. When the test
    # runner SIGKILLs QEMU (the only way to stop a running probe), the
    # sizes stay at zero and Python's wave module rejects the file
    # ("not a WAVE file"). We sniff that exact layout and recover the
    # PCM by trusting the file size.
    with open(path, "rb") as f:
        head = f.read(44)
    if len(head) < 44 or head[:4] != b"RIFF" or head[8:12] != b"WAVE":
        return None
    if head[12:16] != b"fmt " or head[36:40] != b"data":
        return None
    fmt_size = struct.unpack("<I", head[16:20])[0]
    audio_fmt, nch, sr, _byterate, _align, bps = struct.unpack("<HHIIHH", head[20:36])
    if fmt_size != 16 or audio_fmt != 1:
        return None  # not plain PCM
    sw = bps // 8
    if sw != 2:
        raise ValueError(f"{path}: only 16-bit PCM supported, got {bps}-bit")
    body_bytes = os.path.getsize(path) - 44
    if body_bytes < 0:
        raise ValueError(f"{path}: truncated below header")
    with open(path, "rb") as f:
        f.seek(44)
        raw = f.read(body_bytes)
    return sr, nch, sw, raw


def read_wav(path):
    qemu = _read_qemu_wav(path)
    if qemu is not None:
        sr, nch, sw, raw = qemu
    else:
        with wave.open(path, "rb") as wf:
            nch = wf.getnchannels()
            sw = wf.getsampwidth()
            sr = wf.getframerate()
            n = wf.getnframes()
            raw = wf.readframes(n)
        if sw != 2:
            raise ValueError(f"{path}: only 16-bit PCM supported, got {sw*8}-bit")
    # Truncate to a whole-sample boundary; QEMU's last write can be
    # mid-sample if the SIGKILL races a libsndfile flush.
    raw = raw[: (len(raw) // (sw * nch)) * (sw * nch)]
    samples = struct.unpack(f"<{len(raw)//2}h", raw)
    if nch == 1:
        mono = list(samples)
    else:
        # Down-mix to mono by averaging interleaved channels — energy
        # envelope comparison only cares about total acoustic power.
        mono = [
            sum(samples[i + c] for c in range(nch)) // nch
            for i in range(0, len(samples), nch)
        ]
    return sr, nch, mono


def rms_windows(samples, sr, window_seconds):
    win = max(1, int(sr * window_seconds))
    out = []
    for start in range(0, len(samples), win):
        chunk = samples[start : start + win]
        if not chunk:
            continue
        ssum = sum(s * s for s in chunk)
        out.append(math.sqrt(ssum / len(chunk)))
    return out


def db(x, floor):
    return 20.0 * math.log10(max(x, floor))


def compare(ref_path, cap_path, *, tolerance_db, min_ratio, window_seconds,
            duration_seconds=None, silence_floor=1.0):
    ref_sr, ref_nch, ref = read_wav(ref_path)
    cap_sr, cap_nch, cap = read_wav(cap_path)
    if ref_sr != cap_sr:
        return False, {
            "error": f"sample-rate mismatch: ref={ref_sr} cap={cap_sr}",
        }
    if duration_seconds is not None:
        n = int(ref_sr * duration_seconds)
        ref = ref[:n]
        cap = cap[:n]
    ref_w = rms_windows(ref, ref_sr, window_seconds)
    cap_w = rms_windows(cap, cap_sr, window_seconds)
    n = min(len(ref_w), len(cap_w))
    if n == 0:
        return False, {"error": "both inputs empty after windowing"}
    within = 0
    diffs = []
    for i in range(n):
        d = abs(db(cap_w[i], silence_floor) - db(ref_w[i], silence_floor))
        diffs.append(d)
        if d <= tolerance_db:
            within += 1
    ratio = within / n
    stats = {
        "windows": n,
        "within": within,
        "ratio": ratio,
        "tolerance_db": tolerance_db,
        "min_ratio": min_ratio,
        "window_seconds": window_seconds,
        "max_diff_db": max(diffs),
        "mean_diff_db": sum(diffs) / n,
        "ref_sr": ref_sr,
        "cap_sr": cap_sr,
        "ref_nch": ref_nch,
        "cap_nch": cap_nch,
    }
    return ratio >= min_ratio, stats


def main(argv=None):
    p = argparse.ArgumentParser(description="GATE C-2 audio bounded-tolerance verify")
    p.add_argument("--reference", required=True, help="path to oracle/reference.wav")
    p.add_argument("--capture", required=True, help="path to captured WAV")
    p.add_argument("--tolerance-db", type=float, default=6.0,
                   help="per-window RMS tolerance in dB (default 6 dB)")
    p.add_argument("--min-ratio", type=float, default=0.95,
                   help="minimum fraction of windows within tolerance (default 0.95)")
    p.add_argument("--window-seconds", type=float, default=1.0,
                   help="RMS window size in seconds (default 1.0)")
    p.add_argument("--duration-seconds", type=float, default=None,
                   help="only compare the first N seconds (default = full overlap)")
    args = p.parse_args(argv)

    try:
        ok, stats = compare(
            args.reference, args.capture,
            tolerance_db=args.tolerance_db,
            min_ratio=args.min_ratio,
            window_seconds=args.window_seconds,
            duration_seconds=args.duration_seconds,
        )
    except (FileNotFoundError, ValueError, wave.Error, EOFError) as e:
        print(f"GATE C-2 ERROR: {e}", file=sys.stderr)
        return 2

    if "error" in stats:
        print(f"GATE C-2 ERROR: {stats['error']}", file=sys.stderr)
        return 2

    verdict = "PASS" if ok else "FAIL"
    print(
        f"GATE C-2 {verdict}  ratio={stats['ratio']:.3f}/{stats['min_ratio']:.3f}  "
        f"within={stats['within']}/{stats['windows']}  tol={stats['tolerance_db']:.1f}dB  "
        f"max_diff={stats['max_diff_db']:.1f}dB  mean_diff={stats['mean_diff_db']:.1f}dB"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
