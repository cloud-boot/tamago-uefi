# cloud-boot/tamago-amd64-uefi

A pure-Go bare-metal **UEFI** application for **amd64**, built on the standard
Go runtime via [TamaGo](https://github.com/usbarmory/tamago) (`GOOS=tamago
GOARCH=amd64`) and packaged to PE32+/EFI with cloud-boot's own pure-Go tooling
([go-coff `peln`/`pectl`](https://github.com/go-coff)) — **no go-boot, no
external linker, `CGO_ENABLED=0`**.

This is Phase 0 of cloud-boot's TamaGo UEFI work: it proves the firmware entry,
runtime bring-up and console on the real Go runtime (GC, scheduler, goroutines).
It prints over the UEFI ConOut and halts; `ExitBootServices` and the full loader
come later.

## Our own UEFI board (`uefiboard/`)

We reuse the TamaGo framework's `amd64` CPU package (SSE enable, TSC timer,
RDRAND, `RamStackOffset`, `Hwinit0`) and override only the UEFI-specific
`runtime/goos` hooks:

| file | role |
| --- | --- |
| `cpuinit_amd64.s` | PE entry (`-E cpuinit`): captures `ImageHandle`/`SystemTable` (MS x64 ABI), enables SSE, sets `RamStart`, hands off to `runtime.rt0_amd64_tamago` |
| `eficall_amd64.s` | MS x64 firmware-call thunk (RCX/RDX/R8/R9, 32-byte shadow space, indirect `CALL (AX)`) |
| `board_amd64.go` | `Printk` via ConOut, `Nanotime`, `Hwinit1`, `RamSize`, the captured handoff vars |

Built with `-tags linkcpuinit,linkramstart` (excludes the framework's bare-metal
`cpuinit` / default `RamStart` so ours win).

## Build & boot

Requires a TamaGo `tamago-go` toolchain with the cloud-boot-local PIE overlay
applied (see `cloud-boot/docs/tamago-loong64-pie.patch`), the TamaGo framework,
and `go-coff/pectl`.

```sh
# 1. ELF (PIE) on the TamaGo runtime
GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=amd64 \
  <tamago-go>/bin/go build -tags linkcpuinit,linkramstart -trimpath \
  -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

# 2. PIE ELF -> PE32+/EFI (pure-Go, no binutils)
pectl link-pie -o BOOTX64.EFI app.elf

# 3. boot under QEMU/OVMF (needs RDRAND + enough RAM for RamSize)
#    place BOOTX64.EFI at \EFI\BOOT\BOOTX64.EFI on a FAT ESP, then:
qemu-system-x86_64 -machine q35 -cpu max -m 2048 -nographic \
  -drive if=pflash,format=raw,readonly=on,file=edk2-x86_64-code.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -drive format=raw,file=esp.img
```

Expected output:

```
hello from cloud-boot tamago/amd64 UEFI board
runtime: go1.26.3 GOOS=tamago GOARCH=amd64
goroutine sum: 499500
DONE
```

## Status / follow-ups

- `RamSize` is a coarse 704 MiB bound; reconcile against the UEFI memory map
  (`GetMemoryMap`) post-World, as go-boot does.
- `go.mod` uses a local `replace` for the TamaGo framework during development.
- Next: factor an arch-neutral board core + per-arch entry shims (arm64,
  riscv64, loong64), then assemble a multi-arch ISO.

## License

BSD 3-Clause.
