#!/usr/bin/env bash
# M6.2 PR2 riscv64 efipack smoke matrix.
#
# For each of {HTTP, HTTPS, OCI, EFIHANDOVER}:
#   1. Pack BOOTRISCV64-<NAME>.EFI via go-coff/efipack (compress/flate).
#   2. Boot the packed PE under qemu-system-riscv64 + EDK2 RISC-V OVMF
#      (virt machine, edk2-riscv-code.fd) with virtio-blk-device +
#      user-mode networking on a virtio-net-pci, mirroring livehttp's
#      riscv64 setup.
#   3. Match the same PASS pattern the per-protocol live runner uses.
#
# Prints a clean table on stdout and exits 0 iff every row passes.
#
# Usage:
#     bash internal/efipacksmoke/run_riscv64.sh
#
# Env overrides:
#     EFIPACK_TIMEOUT          per-row wall-clock cap in seconds (default 120)
#     EFIPACK_ROWS             space-separated row names (default: HTTP HTTPS OCI EFIHANDOVER)
#     EFIPACK_DIR              repo path to go-coff/efipack
#                              (default: ../../../go-coff/efipack)
#     CLOUDBOOT_OVMF_RISCV64_CODE / _VARS  as in livehttp/run.sh

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
EFIPACK_DIR="${EFIPACK_DIR:-$REPO_DIR/../../go-coff/efipack}"
TIMEOUT="${EFIPACK_TIMEOUT:-120}"

FW_CODE_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-code.fd"
FW_VARS_DEFAULT="$HOME/.pkgx/qemu.org/v9.2.0/share/qemu/edk2-riscv-vars.fd"
FW_CODE="${CLOUDBOOT_OVMF_RISCV64_CODE:-$FW_CODE_DEFAULT}"
FW_VARS="${CLOUDBOOT_OVMF_RISCV64_VARS:-$FW_VARS_DEFAULT}"

[[ -f "$FW_CODE" ]] || { echo "missing EDK2 code fd at $FW_CODE" >&2; exit 2; }
[[ -f "$FW_VARS" ]] || { echo "missing EDK2 vars fd at $FW_VARS" >&2; exit 2; }
[[ -d "$EFIPACK_DIR" ]] || { echo "missing efipack at $EFIPACK_DIR" >&2; exit 2; }

# Each row: NAME EFI_INPUT_FILENAME PASS_GREP_REGEX
ROWS=(
    "HTTP|BOOTRISCV64-HTTP.EFI|HTTP-GET OK"
    "HTTPS|BOOTRISCV64-HTTPS.EFI|HTTPS-GET OK"
    "OCI|BOOTRISCV64-OCI.EFI|OCI-FETCH OK"
    "EFIHANDOVER|BOOTRISCV64-EFIHANDOVER.EFI|phase2-efi-handover: StartImage entering child"
)
if [[ -n "${EFIPACK_ROWS:-}" ]]; then
    FILTERED=()
    for r in "${ROWS[@]}"; do
        name="${r%%|*}"
        for want in $EFIPACK_ROWS; do
            if [[ "$name" == "$want" ]]; then FILTERED+=("$r"); fi
        done
    done
    ROWS=("${FILTERED[@]}")
fi

WORK="$(mktemp -d -t efipack-smoke-riscv64-XXXXXX)"
trap 'if [[ "${EFIPACK_KEEPRUN:-0}" != "1" ]]; then rm -rf "$WORK"; else echo "[KEEP] work dir: $WORK" >&2; fi' EXIT

# Build a tiny Go program that packs an input EFI via efipack.Pack.
PACKBIN="$WORK/packer"
mkdir -p "$WORK/packer.src"
cat > "$WORK/packer.src/go.mod" <<EOF
module efipacksmoke_pack_riscv64
go 1.25
replace github.com/go-coff/efipack => $EFIPACK_DIR
replace github.com/go-coff/peln   => $EFIPACK_DIR/../peln
require github.com/go-coff/efipack v0.0.0
require github.com/go-coff/peln v0.0.0
EOF
cat > "$WORK/packer.src/main.go" <<'EOG'
package main
import (
    "fmt"
    "os"
    "github.com/go-coff/efipack"
)
func main() {
    if len(os.Args) != 3 { fmt.Fprintln(os.Stderr, "usage: packer IN OUT"); os.Exit(2) }
    in, err := os.Open(os.Args[1]); if err != nil { panic(err) }; defer in.Close()
    out, err := os.Create(os.Args[2]); if err != nil { panic(err) }; defer out.Close()
    r, err := efipack.Pack(in, out, efipack.Options{Compressor: efipack.Flate})
    if err != nil { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
    fmt.Printf("orig=%d packed=%d\n", r.OriginalSize, r.PackedSize)
}
EOG
(cd "$WORK/packer.src" && go mod tidy >/dev/null 2>&1 && go build -o "$PACKBIN" . >/dev/null) || {
    echo "packer build failed" >&2; exit 2;
}

run_one() {
    local name="$1" input="$2" pattern="$3" mode="$4"
    local efi_path="$REPO_DIR/$input"
    if [[ ! -f "$efi_path" ]]; then
        printf "%-12s %-40s NOT_BUILT\n" "$name" "$input"
        return 2
    fi
    local orig_sz packed_path packed_sz log esp work vars
    orig_sz=$(stat -f %z "$efi_path" 2>/dev/null || stat -c %s "$efi_path")
    work="$WORK/$name-$mode"; mkdir -p "$work"
    if [[ "$mode" == "packed" ]]; then
        packed_path="$work/boot.efi"
        "$PACKBIN" "$efi_path" "$packed_path" >/dev/null
        packed_sz=$(stat -f %z "$packed_path" 2>/dev/null || stat -c %s "$packed_path")
    else
        packed_path="$efi_path"
        packed_sz="$orig_sz"
    fi
    esp="$work/esp.img"
    dd if=/dev/zero of="$esp" bs=1m count=24 status=none
    mformat -i "$esp" ::
    mmd -i "$esp" ::/EFI ::/EFI/BOOT
    mcopy -i "$esp" "$packed_path" "::/EFI/BOOT/BOOTRISCV64.EFI"
    {
        printf "@echo -off\nfs0:\n\\\\EFI\\\\BOOT\\\\BOOTRISCV64.EFI\n"
    } > "$work/startup.nsh"
    mcopy -i "$esp" "$work/startup.nsh" "::/startup.nsh"
    vars="$work/vars.fd"
    cp "$FW_VARS" "$vars"
    log="$work/qemu.log"
    qemu-system-riscv64 \
        -machine virt -m 4096 \
        -display none -no-reboot \
        -drive "if=pflash,format=raw,readonly=on,file=$FW_CODE,unit=0" \
        -drive "if=pflash,format=raw,file=$vars,unit=1" \
        -drive "file=$esp,format=raw,if=none,id=esp" \
        -device "virtio-blk-device,drive=esp" \
        -netdev "user,id=net0" \
        -device "virtio-net-pci,netdev=net0,disable-legacy=on,disable-modern=off" \
        -serial stdio >"$log" 2>&1 &
    local qpid=$!
    ( sleep "$TIMEOUT" && kill -TERM "$qpid" 2>/dev/null && sleep 1 && kill -KILL "$qpid" 2>/dev/null ) &
    local kpid=$!
    while kill -0 "$qpid" 2>/dev/null; do sleep 1; done
    kill "$kpid" 2>/dev/null || true
    local result="FAIL"
    if grep -q "CpuPageTableLib" "$log"; then result="FAIL_GP"
    elif grep -q "Synchronous Exception" "$log"; then result="FAIL_SE"
    elif grep -q "$pattern" "$log"; then result="PASS"
    fi
    printf "%-12s %-10s size=%-10s %s\n" "$name" "$mode" "$packed_sz" "$result"
    if [[ "$result" == "FAIL" || "$result" == "FAIL_GP" || "$result" == "FAIL_SE" ]]; then
        echo "    log tail:"; tail -20 "$log" | sed 's/^/    | /'
    fi
}

echo "=== M6.2 PR2 riscv64 efipack smoke matrix ==="
printf "%-12s %-10s %-15s %s\n" "ROW" "MODE" "SIZE" "RESULT"
RC=0
for r in "${ROWS[@]}"; do
    IFS='|' read -r name input pattern <<<"$r"
    run_one "$name" "$input" "$pattern" "original" || RC=$?
    run_one "$name" "$input" "$pattern" "packed"   || RC=$?
done
exit $RC
