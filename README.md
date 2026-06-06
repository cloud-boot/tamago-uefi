# cloud-boot/tamago-uefi

A pure-Go bare-metal **UEFI** application targeting **multiple CPU
architectures** on the standard Go runtime via
[TamaGo](https://github.com/usbarmory/tamago) (`GOOS=tamago`), packaged to
PE32+/EFI with cloud-boot's own pure-Go tooling
([go-coff `peln`/`pectl`](https://github.com/go-coff)) — **no go-boot, no
external linker, `CGO_ENABLED=0`**.

This is Phase 1 of cloud-boot's TamaGo UEFI work: a multi-arch board that
proves firmware entry, runtime bring-up and console on the real Go runtime
(GC, scheduler, goroutines). It prints over the UEFI ConOut and halts;
`ExitBootServices` and the full loader come later.

## Status

| arch | toolchain PIE | board files | builds | image loads | runtime bring-up | hello |
| --- | --- | --- | --- | --- | --- | --- |
| **amd64** | ✅ | ✅ | ✅ | ✅ (OVMF q35) | ✅ | **✅** |
| **arm64** | ✅ | ✅ | ✅ | ✅ (AAVMF virt) | ⚠️ fault in `schedinit` (see below) | ❌ |

The arm64 leg's `cpuinit` shim runs to completion (verified with serial
markers on the QEMU virt PL011) and the firmware loads/starts the image.
A focused debug pass — temporary PL011 marker writes after each `BL` in
`sys_tamago_arm64.s` plus markers around `goos.Hwinit0()` in
`runtime.hwinit0` — pinned the bring-up failure down to two distinct
issues:

1. **Framework `arm64.Init()` is incompatible with UEFI.** Despite being
   named `Init()` (and exposed as `runtime/goos.Hwinit0` via linkname),
   the framework function calls `cpu.InitMMU()`, which builds new EL1
   page tables on the bare-metal assumption that "all memory is mapped as
   device memory at start". Under UEFI the firmware has already
   identity-mapped RAM (Normal/Cacheable) + MMIO (Device) — rebuilding
   the MMU clobbers those mappings and the bring-up never returns.
   Worked around by patching the local clone of
   `github.com/usbarmory/tamago/arm64/init.go` to skip the `InitMMU()`
   call. **TODO upstream**: gate it behind a build tag (e.g.
   `!linkhwinit0`, mirroring `!linkcpuinit`/`!linkramstart`) so consumers
   like `tamago-uefi` can opt out without forking the framework.

2. **`runtime.schedinit` triggers a permission fault.** With (1) worked
   around, the runtime progresses through `hwinit0` → `check` →
   `osinit` and faults inside `schedinit`: ESR=`0x9600004F`
   (EC 0x25, ISS 0x4F = *Data abort: Permission fault, third level*) at
   FAR=`0x13C69D000`. The faulting address sits in a page the UEFI
   image-protection policy mapped read-only (likely an image data region
   that EDK2 marks RO at load time); the runtime tries to write there
   during scheduler init. Closing this needs either a UEFI-aware MMU
   re-map (analogue of `InitMMU()` that preserves firmware's MMIO
   mappings) or an image-protection-policy adjustment.

Treat arm64 as Phase 1.5; the toolchain, packaging and entry shim are all
in place. Closing the remaining schedinit perm-fault is the last
blocker, and it's bounded — single page, single PC, well-characterised.

## Our own UEFI board (`uefiboard/`)

We reuse the TamaGo framework's per-arch CPU package (timer,
`RamStackOffset` on amd64, `Hwinit0`, …) and override only the
UEFI-specific `runtime/goos` hooks. The board is split into an
arch-neutral core plus per-arch entry shims and Go hooks.

| file | role | scope |
| --- | --- | --- |
| `board.go` | UEFI handoff vars, `RamStart` placeholder, ConOut `Printk`, `efiCall` declaration | arch-neutral |
| `cpuinit_amd64.s` | PE entry (MS x64 ABI: `RCX`=ImageHandle, `RDX`=SystemTable), SSE enable, RamStart, hand-off to `runtime.rt0_amd64_tamago` | amd64 |
| `eficall_amd64.s` | MS x64 thunk: `RCX/RDX/R8/R9` args, 32-byte shadow space, indirect `CALL (AX)` | amd64 |
| `board_amd64.go` | `CPU = &amd64.CPU{}`, `Nanotime`, `Hwinit1`, `RamSize=704 MiB` | amd64 |
| `cpuinit_arm64.s` | PE entry (AAPCS64: `X0`=ImageHandle, `X1`=SystemTable), `SCTLR_EL1.A` clear, `CPACR_EL1.FPEN`, RamStart, hand-off to `_rt0_tamago_start` | arm64 |
| `eficall_arm64.s` | AAPCS64 thunk: `X0..X3` args, no shadow space, indirect `BL (R9)` | arm64 |
| `board_arm64.go` | `CPU = &arm64.CPU{}`, `Nanotime`, `Hwinit1` (no-op under UEFI), `RamSize=32 MiB`, `RamStackOffset`, RNG stubs | arm64 |

Built with `-tags linkcpuinit,linkramstart`: these exclude the framework's
bare-metal `cpuinit` (so ours wins) and, on amd64, the framework's
default `RamStart`. On arm64 the framework ships neither symbol so the
tags are no-ops there.

## Build & boot

Requires the TamaGo `tamago-go` toolchain with the cloud-boot-local PIE
overlay applied (see `cloud-boot/docs/tamago-loong64-pie.patch`), the
TamaGo framework, and `go-coff/pectl`.

```sh
# 1. ELF (PIE) on the TamaGo runtime
GOOS=tamago GOOSPKG=github.com/usbarmory/tamago GOARCH=<arch> \
  <tamago-go>/bin/go build -tags linkcpuinit,linkramstart -trimpath \
  -buildmode=pie -ldflags "-E cpuinit" -o app.elf .

# 2. PIE ELF -> PE32+/EFI (pure-Go, no binutils)
pectl link-pie -o BOOT<ARCH>.EFI app.elf

# 3. assemble a bootable ISO (cloud-boot iso uses the same shape)
cloud-boot iso --uki linux/<arch>=BOOT<ARCH>.EFI -o boot-<arch>.iso

# 4. boot under QEMU/OVMF (amd64) — verified bootable end-to-end
qemu-system-x86_64 -machine q35 -cpu max -m 2048 -nographic \
  -drive if=pflash,format=raw,readonly=on,file=edk2-x86_64-code.fd \
  -drive if=pflash,format=raw,file=vars.fd \
  -cdrom boot-amd64.iso

# 4'. boot under QEMU/AAVMF (arm64) — image loads + runs cpuinit; runtime hangs (see Status)
qemu-system-aarch64 -machine virt -cpu max -m 4096 -nographic \
  -bios edk2-aarch64-code.fd \
  -drive format=raw,file=boot-arm64.iso,if=none,id=cd \
  -device virtio-blk-pci,drive=cd
```

amd64 expected output:

```text
hello from cloud-boot tamago/amd64 UEFI board
runtime: go1.26.3 GOOS=tamago GOARCH=amd64
goroutine sum: 499500
DONE
```

## Follow-ups

- Finish arm64 runtime bring-up under UEFI (Phase 1.5).
- Reconcile `RamSize` against the UEFI memory map post-World
  (`GetMemoryMap` + `AllocatePages`) instead of the per-arch hardcoded
  bound; same approach go-boot uses on amd64.
- Add the riscv64 and loong64 legs once arm64 lands (toolchain PIE +
  `peln` already cover all four machines).
- `go.mod` uses a local `replace` for the TamaGo framework during
  development.

## License

BSD 3-Clause.
