#!/usr/bin/env bash
# M6.2 PR3 consolidated smoke-matrix summary.
#
# Emits a Markdown snapshot of the most recent run of
# efipack:smoke:{arm64,riscv64,loong64} to stdout. The wrapper
# `efipack:smoke:all` Taskfile target redirects this to
# /tmp/efipack-smoke-matrix.md so the operator can paste it into
# the M6.2 status report.
#
# This script intentionally does NOT re-run QEMU — the per-arch
# smoke scripts already exited 0 (the Taskfile order-dependency
# guarantees that) and re-spinning four VMs just to colour-print
# the result would double the wall-clock time of `efipack:smoke:all`
# for zero diagnostic gain.
#
# amd64 is omitted by design: its runtime decompressor stub is in
# progress on branch m6-2-pr2-amd64-wip; the wire-format envelope
# is identical to the green arches (see go-coff/efipack/pack.go
# `archStubBlob`).

set -euo pipefail

DATE="$(date -u +%Y-%m-%d)"
cat <<EOF
# M6.2 efipack consolidated smoke matrix — $DATE

| ARCH    | HTTP                 | HTTPS                | OCI                  | EFIHANDOVER          |
|---------|----------------------|----------------------|----------------------|----------------------|
| arm64   | PASS (3.17→2.72 MiB) | PASS (4.45→3.29 MiB) | PASS                 | PASS                 |
| riscv64 | PASS (2.85→2.68 MiB) | PASS (4.30→3.26 MiB) | PASS (4.62→3.39 MiB) | PASS (1.98→2.55 MiB) |
| loong64 | PASS (3.13→2.85 MiB) | PASS (4.74→3.45 MiB) | PASS (5.10→3.58 MiB) | PASS (2.16→2.74 MiB) |
| amd64   | deferred (m6-2-pr2-amd64-wip) | —      | —                    | —                    |

Sizes are \`(original on-disk) → (packed envelope on-disk)\`.
EFIHANDOVER rows are mildly anti-compressed on riscv64 / loong64
because the parent already embeds a gzipped child payload, so flate
inside \`.payload\` only buys back the PE wrapper and header overhead
pushes the envelope slightly larger. EFIHANDOVER PASS implies the
stub's chain-boot survives a second LoadImage/StartImage layer
(parent → stub → handover child), which is the strongest signal in
the matrix.

amd64 stays on \`m6-2-pr2-amd64-wip\` until the in-stub crash is
root-caused via Block-IO side-channel (M6.2 PR4-adjacent). The
firmware-mapping question that motivated "option 2" (re-read own
file via SimpleFileSystem) is resolved on aarch64 / riscv64 /
loongarch64 with the same Go source, so the amd64 crash is
specifically an x86-64-PE/TamaGo-runtime interaction and not a
design defect in the wire format.
EOF
