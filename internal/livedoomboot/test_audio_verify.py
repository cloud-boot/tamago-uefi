#!/usr/bin/env python3
# Copyright (c) 2026 cloud-boot contributors
# SPDX-License-Identifier: BSD-3-Clause
#
# Self-contained smoke tests for audio_verify.py. Runs against synthetic
# WAVs (no DOOM needed). Use:
#
#     python3 -m unittest test_audio_verify
#
# Or just:
#
#     python3 test_audio_verify.py

import math
import os
import struct
import sys
import tempfile
import unittest
import wave

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import audio_verify  # noqa: E402


def write_wav(path, samples, sr=44100, nch=1):
    with wave.open(path, "wb") as wf:
        wf.setnchannels(nch)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        raw = struct.pack(f"<{len(samples)}h",
                          *(max(-32768, min(32767, int(s))) for s in samples))
        wf.writeframes(raw)


def tone(seconds, freq, sr=44100, amp=10000):
    n = int(seconds * sr)
    return [amp * math.sin(2 * math.pi * freq * i / sr) for i in range(n)]


def silence(seconds, sr=44100):
    return [0] * int(seconds * sr)


class CompareTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_identical_passes(self):
        s = tone(3.0, 440) + silence(2.0) + tone(2.0, 880)
        write_wav(self.path("a.wav"), s)
        write_wav(self.path("b.wav"), s)
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0)
        self.assertTrue(ok, stats)
        self.assertEqual(stats["within"], stats["windows"])

    def test_silence_only_within_floor(self):
        write_wav(self.path("a.wav"), silence(3.0))
        write_wav(self.path("b.wav"), silence(3.0))
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=6.0, min_ratio=0.95, window_seconds=1.0)
        self.assertTrue(ok)

    def test_grossly_different_fails(self):
        write_wav(self.path("a.wav"), tone(5.0, 440, amp=20000))
        write_wav(self.path("b.wav"), silence(5.0))
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0)
        self.assertFalse(ok)
        self.assertGreater(stats["max_diff_db"], 30.0)

    def test_small_timing_jitter_passes(self):
        # 100 ms shift — the GC-stutter the metric is designed to
        # tolerate. Same tone, just offset.
        base = silence(0.5) + tone(2.0, 440) + silence(2.5)
        shift = silence(0.6) + tone(2.0, 440) + silence(2.4)
        write_wav(self.path("a.wav"), base)
        write_wav(self.path("b.wav"), shift)
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=6.0, min_ratio=0.95, window_seconds=1.0)
        self.assertTrue(ok, stats)

    def test_format_mismatch_errors(self):
        write_wav(self.path("a.wav"), tone(1.0, 440), sr=44100)
        write_wav(self.path("b.wav"), tone(1.0, 440), sr=22050)
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0)
        self.assertFalse(ok)
        self.assertIn("error", stats)

    def test_duration_limit(self):
        # First 2 s identical, then divergence. With duration_seconds=2
        # the divergence is excluded → PASS.
        a = tone(2.0, 440) + tone(3.0, 880)
        b = tone(2.0, 440) + silence(3.0)
        write_wav(self.path("a.wav"), a)
        write_wav(self.path("b.wav"), b)
        ok, _ = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0,
            duration_seconds=2.0)
        self.assertTrue(ok)

    def test_stereo_downmix(self):
        # Stereo input with same content in each channel — must compare
        # equal to a mono copy.
        mono = tone(2.0, 440)
        stereo = []
        for s in mono:
            stereo.extend([s, s])
        write_wav(self.path("mono.wav"), mono, nch=1)
        write_wav(self.path("stereo.wav"), stereo, nch=2)
        ok, _ = audio_verify.compare(
            self.path("mono.wav"), self.path("stereo.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0)
        self.assertTrue(ok)

    def test_empty_after_windowing_errors(self):
        write_wav(self.path("a.wav"), [])
        write_wav(self.path("b.wav"), [])
        ok, stats = audio_verify.compare(
            self.path("a.wav"), self.path("b.wav"),
            tolerance_db=3.0, min_ratio=0.95, window_seconds=1.0)
        self.assertFalse(ok)
        self.assertIn("error", stats)


class QEMUWavTests(unittest.TestCase):
    """The QEMU -audiodev wav backend leaves zeroed RIFF/data sizes when
    the runner SIGKILLs the VM. read_wav must recover from that."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def _qemu_wav(self, path, samples, sr=44100, nch=2, sw=2):
        # Construct a RIFF/WAVE header with zeroed sizes (the QEMU bug).
        bps = sw * 8
        align = nch * sw
        byterate = sr * align
        with open(path, "wb") as f:
            f.write(b"RIFF\x00\x00\x00\x00WAVEfmt ")
            f.write(struct.pack("<I", 16))
            f.write(struct.pack("<HHIIHH", 1, nch, sr, byterate, align, bps))
            f.write(b"data\x00\x00\x00\x00")
            f.write(struct.pack(f"<{len(samples)}h",
                                *(max(-32768, min(32767, int(s))) for s in samples)))

    def test_qemu_zero_sized_recovered(self):
        # Interleave L/R as identical samples to make a true stereo stream.
        mono_in = tone(2.0, 440)
        stereo = []
        for s in mono_in:
            stereo.extend([s, s])
        self._qemu_wav(self.path("q.wav"), stereo, nch=2)
        sr, nch, mono = audio_verify.read_wav(self.path("q.wav"))
        self.assertEqual(sr, 44100)
        self.assertEqual(nch, 2)
        # Stereo down-mixed to mono → one sample per frame.
        self.assertAlmostEqual(len(mono), int(2.0 * 44100), delta=10)

    def test_qemu_8bit_rejected(self):
        # Build a zeroed-size header with sample width = 1 (8-bit).
        with open(self.path("q.wav"), "wb") as f:
            f.write(b"RIFF\x00\x00\x00\x00WAVEfmt ")
            f.write(struct.pack("<I", 16))
            f.write(struct.pack("<HHIIHH", 1, 1, 44100, 44100, 1, 8))
            f.write(b"data\x00\x00\x00\x00")
            f.write(b"\x80" * 100)
        with self.assertRaises(ValueError):
            audio_verify.read_wav(self.path("q.wav"))

    def test_non_qemu_path_still_works(self):
        # A properly-finalised wave file must still parse via the wave module
        # branch.
        write_wav(self.path("ok.wav"), tone(1.0, 440))
        sr, nch, mono = audio_verify.read_wav(self.path("ok.wav"))
        self.assertEqual(sr, 44100)
        self.assertEqual(nch, 1)
        self.assertEqual(len(mono), 44100)

    def test_too_short_header_falls_back(self):
        with open(self.path("tiny.wav"), "wb") as f:
            f.write(b"RIFF")
        # Either wave.Error or EOFError is acceptable — the point is that
        # the QEMU fast-path bails and the wave module's stricter parser
        # rejects it.
        with self.assertRaises((wave.Error, EOFError)):
            audio_verify.read_wav(self.path("tiny.wav"))

    def test_non_pcm_format_falls_back(self):
        # audio_fmt != 1 → _read_qemu_wav returns None, wave module then
        # rejects (it doesn't know the codec either).
        with open(self.path("alaw.wav"), "wb") as f:
            f.write(b"RIFF\x00\x00\x00\x00WAVEfmt ")
            f.write(struct.pack("<I", 16))
            f.write(struct.pack("<HHIIHH", 6, 1, 44100, 44100, 1, 8))
            f.write(b"data\x00\x00\x00\x00")
            f.write(b"\x80" * 100)
        with self.assertRaises(wave.Error):
            audio_verify.read_wav(self.path("alaw.wav"))

    def test_bad_fmt_chunk_falls_back(self):
        with open(self.path("badfmt.wav"), "wb") as f:
            f.write(b"RIFF\x00\x00\x00\x00WAVE")
            f.write(b"XXXX" + b"\x00" * 100)
        with self.assertRaises(wave.Error):
            audio_verify.read_wav(self.path("badfmt.wav"))


class CLITests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def path(self, name):
        return os.path.join(self.tmp.name, name)

    def test_main_pass(self):
        s = tone(3.0, 440)
        write_wav(self.path("ref.wav"), s)
        write_wav(self.path("cap.wav"), s)
        rc = audio_verify.main([
            "--reference", self.path("ref.wav"),
            "--capture", self.path("cap.wav"),
            "--tolerance-db", "3",
            "--min-ratio", "0.95",
        ])
        self.assertEqual(rc, 0)

    def test_main_fail(self):
        write_wav(self.path("ref.wav"), tone(3.0, 440, amp=20000))
        write_wav(self.path("cap.wav"), silence(3.0))
        rc = audio_verify.main([
            "--reference", self.path("ref.wav"),
            "--capture", self.path("cap.wav"),
        ])
        self.assertEqual(rc, 1)

    def test_main_missing_file(self):
        rc = audio_verify.main([
            "--reference", self.path("nope.wav"),
            "--capture", self.path("nope.wav"),
        ])
        self.assertEqual(rc, 2)

    def test_main_bad_format(self):
        # Write a non-WAV file.
        with open(self.path("junk.wav"), "wb") as f:
            f.write(b"not a wav")
        rc = audio_verify.main([
            "--reference", self.path("junk.wav"),
            "--capture", self.path("junk.wav"),
        ])
        self.assertEqual(rc, 2)

    def test_main_format_mismatch(self):
        write_wav(self.path("a.wav"), tone(1.0, 440), sr=44100)
        write_wav(self.path("b.wav"), tone(1.0, 440), sr=22050)
        rc = audio_verify.main([
            "--reference", self.path("a.wav"),
            "--capture", self.path("b.wav"),
        ])
        self.assertEqual(rc, 2)

    def test_main_unsupported_sample_width(self):
        # 8-bit PCM must be rejected.
        with wave.open(self.path("a.wav"), "wb") as wf:
            wf.setnchannels(1)
            wf.setsampwidth(1)
            wf.setframerate(44100)
            wf.writeframes(b"\x80" * 100)
        rc = audio_verify.main([
            "--reference", self.path("a.wav"),
            "--capture", self.path("a.wav"),
        ])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
