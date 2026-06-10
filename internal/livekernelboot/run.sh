#!/usr/bin/env bash
# Phase-2 M8.1-minimal live smoke under QEMU+EDK2. One arch per
# invocation:
#
#     bash internal/livekernelboot/run.sh arm64
#     bash internal/livekernelboot/run.sh riscv64
#     bash internal/livekernelboot/run.sh loong64
#
# (amd64 deferred to its own debug sprint per the M8.1 brief —
# blocked behind the M6.1 OVMF >4 MiB threshold + parallel amd64
# debug sprint on the m6-2-pr2-amd64-wip branch.)
#
# Builds a tiny FAT ESP-disk containing the per-arch
# BOOT*-KERNELBOOT.EFI under \EFI\BOOT\, runs the matching
# qemu-system-<arch> with EDK2 firmware (no networking required in
# MODE B — the default in this build — because the in-process
# oci.Transport serves the embedded chained EFI bytes), captures
# stdout for up to 120 s, and matches on:
#   1. "phase2-oci-kernel-boot: synthetic descriptor digest =" — descriptor built.
#   2. "phase2-oci-kernel-boot: streaming blob via in-process Transport (MODE B)"
#                                                              — streaming leg entered.
#   3. "phase2-oci-kernel-boot: streamed N bytes; SHA-256 verified OK"
#                                                              — streaming + digest check passed.
#   4. "phase2-oci-kernel-boot: LoadImage OK"                  — firmware parsed PE32+.
#   5. "phase2-oci-kernel-boot: StartImage entering loaded image"
#                                                              — about to jump.
#   6. ">>> M8.0 chained payload -- Hello from <ARCH> <<<"     — loaded image banner.
#   7. "phase2-oci-kernel-boot: KERNEL-BOOT OK"                — full mechanism proven.
# Exit 0 on PASS (all seven matched); 1 otherwise.
#
# Per the brief: the timeout cap is intentionally larger (120s) than
# the M8.0 efihandover runner's 30s — a real Linux EFI-stub on MODE A
# might take 30+ s just to print its banner. MODE B is sub-10s on
# every arch but we leave headroom for MODE A drop-in.
#
# Boot-media plumbing mirrors `liveefihandover/run.sh` 1:1:
#   - arm64    → virtio-blk-pci
#   - riscv64  → virtio-blk-device
#   - loong64  → virtio-blk-pci
#
# Environment overrides:
#
#   CLOUDBOOT_OVMF_<ARCH>_{CODE,VARS}: EDK2 .fd paths
#   M81_LIVE_TIMEOUT: per-run wall-clock cap (default 120)
#   M81_LIVE_KEEPRUN: 1 → keep ESP + qemu logs in /tmp
set -euo pipefail

ARCH="${1:-}"
if [[ -z "$ARCH" ]]; then
    echo "usage: $0 {arm64|riscv64|loong64}" >&2
    exit 2
fi

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TIMEOUT_SECONDS="${M81_LIVE_TIMEOUT:-180}"

case "$ARCH" in
    arm64)
        EFI_NAME="BOOTAA64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTAA64.EFI"
        QEMU_BIN="qemu-system-aarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-aarch64-code.fd"
        FW_CODE="${CLOUDBOOT_OVMF_ARM64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS=""
        BANNER_ARCH="arm64"
        ;;
    riscv64)
        EFI_NAME="BOOTRISCV64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTRISCV64.EFI"
        QEMU_BIN="qemu-system-riscv64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="riscv64"
        ;;
    loong64)
        EFI_NAME="BOOTLOONGARCH64-KERNELBOOT.EFI"
        EFI_BOOT_NAME="BOOTLOONGARCH64.EFI"
        QEMU_BIN="qemu-system-loongarch64"
        FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-code.fd"
        FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-loongarch64-vars.fd"
        FW_CODE="${CLOUDBOOT_OVMF_LOONG64_CODE:-$FW_CODE_DEFAULT}"
        FW_VARS="${CLOUDBOOT_OVMF_LOONG64_VARS:-$FW_VARS_DEFAULT}"
        BANNER_ARCH="loong64"
        ;;
    *)
        echo "unsupported arch: $ARCH (M8.1 minimal supports arm64/riscv64/loong64; amd64 deferred)" >&2
        exit 2
        ;;
esac

EFI_PATH="$REPO_DIR/$EFI_NAME"
if [[ ! -f "$EFI_PATH" ]]; then
    echo "missing $EFI_PATH; run 'task kernelboot:efi:$ARCH' first" >&2
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

WORK="$(mktemp -d -t cloudboot-m81-live-XXXXXX)"
trap 'if [[ "${M81_LIVE_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a 16-MiB FAT ESP-disk with \EFI\BOOT\<EFI_BOOT_NAME>.
ESP="$WORK/esp.img"
ESP_SIZE_MB=16
dd if=/dev/zero of="$ESP" bs=1m count="$ESP_SIZE_MB" status=none
# NOTE: do NOT pass `-F` — at 16 MiB the volume is too small for a
# valid FAT32 layout, EDK2 refuses to mount it, and BDS falls back
# to PXE. Let mformat pick FAT12/16 automatically.
mformat -i "$ESP" ::
mmd -i "$ESP" ::/EFI ::/EFI/BOOT
mcopy -i "$ESP" "$EFI_PATH" "::/EFI/BOOT/$EFI_BOOT_NAME"

# Drop a startup.nsh at the FAT root that the EDK2 Internal Shell
# auto-runs. Same shape as the other live runners.
NSH_PATH="$WORK/startup.nsh"
cat > "$NSH_PATH" <<EOF
@echo -off
fs0:
\\EFI\\BOOT\\$EFI_BOOT_NAME
EOF
mcopy -i "$ESP" "$NSH_PATH" "::/startup.nsh"

case "$ARCH" in
    arm64)
        # M8.3: arm64 runs MODE C (real-registry streaming) and needs
        # outbound networking to ghcr.io. The other arches stay on
        # MODE B (self-test) and don't need a netdev.
        #
        # M8.10 (R-M8.9a) ROOT CAUSE for post-EBS silence (2026-06-10)
        #
        # After M8.9 closed the pre-EBS Data Abort, the EFI-stub
        # reached a clean "Exiting boot services and installing
        # virtual address map..." then ZERO bytes — not a glyph,
        # not an ANSI escape. `-d int,unimp,guest_errors` showed
        # the CPU stuck in a tight IRQ loop with every timer tick
        # vectored to EDK2's stale IVT at EL1 PC 0x13fd5f280,
        # never reaching the kernel's exception vectors.
        #
        # Bisected by booting the same kernel directly via QEMU
        # `-kernel` (bypassing our EFI loader entirely). Same
        # silence. The kernel's `-cpu` choice was the variable:
        #
        #   -cpu max         : ZERO output post-Booting Linux.
        #   -cpu cortex-a57  : 517 lines of clean kernel log.
        #
        # The Talos kernel pinned by the OCI ref
        # ghcr.io/siderolabs/kernel:v0.6.0-alpha.0-1-ge8ed5bc is
        # Linux 5.10.29 (from 2021-05-14). `-cpu max` on QEMU 9.x
        # exposes CPU features (SVE2, FEAT_RNG, FEAT_HCX, …) that
        # this old kernel doesn't know how to gate, and it crashes
        # in very early head.S before VBAR_EL1 is set up. The
        # stale firmware IVT then loops on every timer tick.
        #
        # Fix: pin `-cpu cortex-a72` — a real-world arm64 SoC
        # CPU that the 5.10 kernel was actually tested against
        # (Raspberry Pi 4, AWS Graviton 1 family), present in
        # QEMU since forever, and exposes no surprise features.
        # cortex-a57 also works but a72 is closer to what real
        # Talos arm64 deployments target.
        QEMU_ARGS=(
            -machine virt -cpu cortex-a72 -m 4096
            -display none -no-reboot
            -bios "$FW_CODE"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=n0"
            -device "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off"
            -chardev "stdio,id=char0,mux=off,signal=off"
            -serial "chardev:char0"
        )
        ;;
    riscv64)
        # M8.4 self-publish: riscv64 also runs MODE C now (ttl.sh
        # self-published EFI-stub kernel from cloudboot-oci-extract);
        # therefore needs the same outbound netdev as arm64.
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE,unit=0"
            -drive "if=pflash,format=raw,file=$FW_VARS,unit=1"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-device,drive=esp"
            -netdev "user,id=n0"
            -device "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
    loong64)
        # M8.4 self-publish: loong64 also runs MODE C now (ttl.sh
        # self-published EFI-stub kernel from cloudboot-oci-extract);
        # therefore needs the same outbound netdev as arm64.
        cp "$FW_VARS" "$WORK/vars.fd"
        QEMU_ARGS=(
            -machine virt -cpu max -m 4096
            -display none -no-reboot
            -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE"
            -drive "if=pflash,format=raw,file=$WORK/vars.fd"
            -drive "file=$ESP,format=raw,if=none,id=esp"
            -device "virtio-blk-pci,drive=esp"
            -netdev "user,id=n0"
            -device "virtio-net-pci,netdev=n0,disable-legacy=on,disable-modern=off"
            -serial stdio
        )
        ;;
esac

echo "[live-kernelboot:$ARCH] launching $QEMU_BIN (timeout ${TIMEOUT_SECONDS}s)" >&2
LOG="$WORK/qemu.log"
START_NS="$(date +%s%N)"
# Run QEMU under a wall-clock cap. macOS doesn't ship GNU coreutils
# `timeout`, so we drive the cap with a background sleep killer.
# NOTE: do NOT pipe through `tee` — $! returns tee's PID, not
# QEMU's, and the watchdog ends up killing tee while QEMU keeps
# running forever (same bug as previous live runners).
"$QEMU_BIN" "${QEMU_ARGS[@]}" >"$LOG" 2>&1 &
QEMU_PID=$!
( sleep "$TIMEOUT_SECONDS" && kill -TERM "$QEMU_PID" 2>/dev/null && sleep 1 && kill -KILL "$QEMU_PID" 2>/dev/null ) &
KILLER_PID=$!
# Poll for QEMU exit (kill -0 probe) — `wait` may not work when
# the shell loses job-control tracking under task/interactive
# contexts.
while kill -0 "$QEMU_PID" 2>/dev/null; do sleep 1; done
kill "$KILLER_PID" 2>/dev/null || true
END_NS="$(date +%s%N)"
ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))

PASS=1
case "$ARCH" in
    arm64|riscv64|loong64)
        # M8.4 MODE C — real-registry kernel streaming + DTB probe +
        # initrd publish + EFI-stub handoff. Acceptance gate covers
        # both the framework's reach (DHCP, HTTPS, OCI manifest walk,
        # layer stream) AND the new M8.4 plumbing (DTB probe fires,
        # PublishInitrd succeeds, EFI-stub reaches initramfs unpack).
        #
        # riscv64 + loong64 joined MODE C in M8.4 self-publish
        # (2026-06-10) — kernels extracted from Debian linux-image /
        # linux-binary .deb and re-published to ttl.sh by the
        # cmd/cloudboot-oci-extract tool.
        grep -q "phase2-oci-kernel-boot: MODE = C" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: device UP" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: lease acquired" "$LOG" || PASS=0
        # Manifest pick: multi-arch index emits "picked per-arch
        # manifest" + then a digest line; single-arch manifest (the
        # M8.4 self-publish shape) skips the pick and goes straight to
        # "streaming layer digest". Either path is acceptable.
        grep -qE "phase2-oci-kernel-boot: (picked per-arch manifest|streaming layer digest)" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: streaming layer digest" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: extracting boot/vmlinuz" "$LOG" || PASS=0
        # M8.4 additions: DTB probe walks ConfigurationTable, and
        # PublishInitrd installs the embedded minimal initramfs
        # under LINUX_EFI_INITRD_MEDIA_GUID. Both must fire.
        grep -q "phase2-oci-kernel-boot: DTB probe:" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: PublishInitrd OK" "$LOG" || PASS=0
        # M8.4 self-publish (2026-06-10): require post-StartImage
        # kernel-side proof. The Linux EFI-stub prints either
        # "EFI stub: Booting Linux Kernel..." (arm64/rv64) or jumps
        # straight to the post-decompress "Linux version N.N..." line
        # (loong64 — its EFI-stub is quieter). Either is acceptable
        # proof the OCI-streamed kernel ran.
        grep -qE "(EFI stub: Booting Linux Kernel|Linux version )" "$LOG" || PASS=0
        # M8.6 additions (arm64 only — closes R-M8.5a):
        # PublishDTB installs the embedded arm64-virt DTB via
        # gBS->InstallConfigurationTable. The Linux EFI-stub then
        # picks it up via "Using DTB from configuration table".
        # Without this the empty-DTB fallback null-derefs on EDK2
        # arm64 (which publishes ACPI + SMBIOS but no DTB).
        if [[ "$ARCH" == "arm64" ]]; then
            grep -q "phase2-oci-kernel-boot: DTB published" "$LOG" || PASS=0
            grep -q "EFI stub: Using DTB from configuration table" "$LOG" || PASS=0
            # M8.10 closure (R-M8.9a): FIRST FULL END-TO-END
            # KERNEL BOOT — the Linux EFI-stub now reaches
            # ExitBootServices, the kernel proper takes over,
            # runs through head.S + start_kernel, mounts the
            # initramfs as / and execs our /init. The Path D
            # banner is the load-bearing proof.
            grep -q "Run /init as init process" "$LOG" || PASS=0
            grep -q "cloud-boot/openweft Phase 2 Path D" "$LOG" || PASS=0
            grep -q "reboot: Power down" "$LOG" || PASS=0
        fi
        ;;
    *)
        # Other arches stay on MODE B self-test (chainedhello payload).
        EXPECT_BANNER=">>> M8.0 chained payload -- Hello from ${BANNER_ARCH} <<<"
        grep -q "phase2-oci-kernel-boot: synthetic descriptor digest" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: streaming blob via in-process Transport" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: streamed .*SHA-256 verified OK" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: LoadImage OK" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: StartImage entering loaded image" "$LOG" || PASS=0
        grep -qF "$EXPECT_BANNER" "$LOG" || PASS=0
        grep -q "phase2-oci-kernel-boot: KERNEL-BOOT OK" "$LOG" || PASS=0
        ;;
esac

if [[ "$PASS" -eq 1 ]]; then
    echo "[live-kernelboot:$ARCH] PASS — wall=${ELAPSED_MS}ms"
    grep -E "phase2-oci-kernel-boot:|M8\.0 chained payload|EFI stub:|Booting Linux|Linux version|EFI v[0-9]+|Unpacking initramfs|cloud-boot-m83|Kernel panic|Attempted to kill init|Run /init as init process|Path D|Pseudo-filesystem|Kernel cmdline|Kernel: |Total RAM|reboot: Power down" "$LOG" || true
    exit 0
fi
echo "[live-kernelboot:$ARCH] FAIL — missing one of the expected markers after ${ELAPSED_MS}ms" >&2
echo "[live-kernelboot:$ARCH] tail of qemu log (last 200 lines):" >&2
tail -200 "$LOG" >&2 || true
exit 1
