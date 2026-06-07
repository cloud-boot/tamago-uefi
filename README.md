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
| **arm64** | ✅ | ✅ | ✅ | ✅ (AAVMF virt) | ✅ | **✅** |
| **riscv64** | ✅ | ✅ | ✅ | ✅ (EDK2 RiscVVirt) | ✅ | **✅** |
| **loong64** | ✅ | ✅ | ✅ | ✅ (EDK2 LoongArch virt) | ✅ | **✅** |

All four legs reach the `main` hello print and the goroutine-channel
smoke test (verified end-to-end under `-nographic` boot with
`qemu-system-{x86_64,aarch64,riscv64,loongarch64}` against the
pkgx-pinned `edk2-stable202408` firmware, see `cloud-boot/uki`'s
`task test:multiarch:boot`).

Two issues blocked bring-up earlier, both resolved:

1. **Framework `arm64.Init()` was incompatible with UEFI.** The
   framework function (linkname'd `runtime/goos.Hwinit0`) called
   `cpu.InitMMU()`, which builds new EL1 page tables on the bare-metal
   assumption that "all memory is mapped as device memory at start".
   Under UEFI the firmware has already identity-mapped RAM
   (Normal/Cacheable) + MMIO (Device) — rebuilding the MMU clobbered
   those mappings and the bring-up never returned. Fix: the board no
   longer imports the framework's arm64 package at all; it implements
   the small set of hooks it needs (Nanotime via the Generic Timer
   CSRs, RamSize, RamStackOffset, RNG, empty Hwinit0/1) directly in
   `board_arm64.go` + `board_arm64.s`. Same shape as the riscv64 leg.

2. **Heap allocation crashed the very first sbrk pass with a
   permission fault.** The earlier shim set `goos.RamStart = &runtime.text + 2 MiB`
   and left `goos.Bloc` unset, so the runtime's sbrk allocator
   defaulted `bloc = firstmoduledata.end` (mid-`.data` BSS) and grew
   upward. Once it crossed the end of our PE image into the
   adjacent page, it tripped an L3 permission fault (ESR `0x9600004F`
   = *Data abort, permission fault level 3*, FAR one page past
   `SizeOfImage`). EDK2 marks unrelated firmware modules' `.text` RO
   and they happen to be packed right after ours by AllocateAnyPages,
   so the page next to us is generically unsafe. Fix: cpuinit_arm64.s
   now calls `gBS->AllocatePages(AllocateAnyPages, EfiLoaderData, RamSize/4096, &heapBase)`
   to obtain a guaranteed-writable contiguous chunk, sets
   `goos.RamStart = goos.Bloc = heapBase`, points SP at its top, and
   only then enters `_rt0_tamago_start`. The runtime never touches
   memory outside that chunk.

The loong64 leg had the same root cause for its silent-hang state
(heap memclr running into adjacent RO pages); the same AllocatePages
fix in `cpuinit_loong64.s` resolved it. The 'A' UART marker still
fires; the runtime then proceeds all the way to the goroutine sum and
DONE prints over ConOut. The previously-feared "csrwr R19, EUEN"
instruction-non-defined exception did NOT recur in the final
configuration — empirically firmware *does* hand us a disabled FPU,
re-arming it via `csrwr R19, 0x2` (CSR.EUEN.FPE) is required and
works.

The **riscv64** leg now boots end-to-end on the same `edk2-stable202408`
firmware shipped by pkgx `qemu.org/v9.2.0`. An earlier revision of this
README claimed a deterministic firmware fault in
`SetUefiImageMemoryAttributes` blocking before our `cpuinit`; under
the current toolchain + board + OVMF combination that fault does not
reproduce. The image loads, the three image-protection calls succeed,
control reaches our `cpuinit`, the runtime brings itself up, the
goroutine-channel smoke test completes, and `DONE` prints over ConOut
— same shape as amd64 / arm64 / loong64.

One known cosmetic issue remains: the banner reads `tamago/amd64`
instead of `tamago/riscv64`. The PE machine type is RISC-V (`0x5064`),
the instructions are riscv64, and the runtime executes correctly on
riscv64; only the `runtime.GOARCH` string baked into rodata is wrong.
This is a build-pipeline mislabel, not a runtime defect, and is being
tracked as a follow-up.

While auditing the page-table mutation path during the earlier
investigation, we found one real latent defect in
`UefiCpuPkg/Library/BaseRiscVMmuLib/BaseRiscVMmuLib.c`:
`SetPpnToPte`'s bounds-check assert uses bitwise `~` where it should
use logical `!` (the mirror call in `RiscVMmuSetSatpMode` uses the
correct `!`). The assert is dead in `RELEASE` builds and semantically
wrong in `DEBUG`. A one-character fix is staged at
`cloud-boot/docs/edk2-riscv64-protection-fix.patch` with the analysis
at `cloud-boot/docs/riscv64-edk2-protection-fix.md`, awaiting upstream
submission to `devel@edk2.groups.io`.

The **loong64** leg is the highest-risk one because the upstream port
is itself still in flight: `usbarmory/tamago-go#17` (toolchain
instruction-set wireup, PIE-free) is still open and the framework
proposal `usbarmory/tamago#70` is design-only — there is no
`usbarmory/tamago/loong64/` directory upstream yet. Both pieces are
staged locally:

- the tamago-go fork patch (`cloud-boot/docs/tamago-loong64-fork.patch`)
  plus the cloud-boot-local PIE overlay
  (`cloud-boot/docs/tamago-loong64-pie.patch`) on top of
  `~/Documents/VCS/GIT/localhost/tamago-pie/`, and
- a local `usbarmory/tamago/loong64/` package + `goos/goos_loong64.s`
  trampoline mirroring the riscv64 / arm64 shape (`loong64.go`,
  `loong64.s`, `init.{go,s}`, `timer.{go,s}`, `rng.go`, `exception.{go,s}`).

These local additions are NOT pushed upstream. Track upstream:
[`usbarmory/tamago-go#17`](https://github.com/usbarmory/tamago-go/pull/17),
[`usbarmory/tamago#70`](https://github.com/usbarmory/tamago/issues/70).

The bring-up status is now the same as arm64 — end-to-end:

1. **Toolchain + PE wrapping work end-to-end.** A 1.6 MB TamaGo
   loong64 PIE (`ET_DYN`, ~3800 `R_LARCH_RELATIVE` relocs) round-trips
   through `pectl link-pie` to a 1.1 MB `BOOTLOONGARCH64.EFI`
   (PE32+, machine `0x6264`, subsystem 10, ~3800 `IMAGE_REL_BASED_DIR64`
   base relocs). EDK2 LoongArch under QEMU `virt -cpu max -m 4096`
   loads the image and transfers control to our `cpuinit`.

2. **`cpuinit_loong64.s` allocates a heap chunk via Boot Services.**
   The 'A' UART marker fires first (`THR @ 0x1FE001E0`), then the
   shim captures ImageHandle/SystemTable/ConOut, calls
   `gBS->AllocatePages(AllocateAnyPages, EfiLoaderData,
   RamSize/4096, &heapBase)`, re-arms `CSR.EUEN.FPE` (the EDK2
   LoongArch boot env hands us a disabled FPU), and points SP at
   `heapBase + RamSize - StackOffset`. Tail-call to
   `_rt0_tamago_start`.

3. **Runtime reaches `main` and prints over ConOut.** The 'A' marker
   is followed by the standard hello banner, the goroutine-channel
   sum, and `DONE`. Same shape as arm64 and amd64.

### Upstream PRs that would close gaps

- `usbarmory/tamago-go#17` — merge the loong64 toolchain port (already
  open). Cloud-boot's PIE overlay is intentionally kept out of that PR.
- `usbarmory/tamago#70` — open the `usbarmory/tamago/loong64/` package
  upstream once the design discussion concludes; cloud-boot's local
  files (`loong64.{go,s}`, `init.{go,s}`, `timer.{go,s}`, `rng.go`,
  `exception.{go,s}`) are ready to seed that PR.
- A small `peln` improvement (track in
  [`go-coff/peln`](https://github.com/go-coff/peln)) to surface load-bias
  diagnostics on `loongarch64` would have shortened our debug.
- A framework-side `!linkhwinit0` build tag gating `arm64.Init()`'s
  `InitMMU()` call — would let UEFI consumers reuse the framework's
  arm64 CPU package without forking. The cloud-boot board sidesteps
  this by simply not importing the framework's arm64 package.

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
| `cpuinit_arm64.s` | PE entry (AAPCS64: `X0`=ImageHandle, `X1`=SystemTable), `gBS->AllocatePages` for heap, `SCTLR_EL1.A` clear, `CPACR_EL1.FPEN`, RamStart, hand-off to `_rt0_tamago_start` | arm64 |
| `eficall_arm64.s` | AAPCS64 thunk: `X0..X3` args, no shadow space, indirect `BL (R9)` | arm64 |
| `board_arm64.go` | Self-contained (no framework arm64 import), `Nanotime` via CNTPCT_EL0 / CNTFRQ_EL0, `Hwinit0/1` (no-op under UEFI), `RamSize=32 MiB`, `RamStackOffset`, RNG stubs | arm64 |
| `board_arm64.s` | `rdcntpct()` / `rdcntfrq()` via `MRS CNTPCT_EL0` / `MRS CNTFRQ_EL0` | arm64 |
| `cpuinit_riscv64.s` | PE entry (LP64: `A0`=ImageHandle, `A1`=SystemTable), `gBS->AllocatePages` for heap, `SSTATUS.FS=Initial` for FPU, RamStart, hand-off to `_rt0_tamago_start` | riscv64 |
| `eficall_riscv64.s` | LP64 thunk: `A0..A3` args, no shadow space, indirect `JALR (T1)` | riscv64 |
| `board_riscv64.go` | self-contained (no framework dep), `Nanotime` via `rdtime` (TIME CSR), `Hwinit0/1` no-ops under UEFI, `RamSize=32 MiB`, `RamStackOffset`, xorshift RNG stubs | riscv64 |
| `board_riscv64.s` | `rdtime()` via raw `csrrs t0, time, zero` (`WORD $0xc01022f3`) | riscv64 |
| `cpuinit_loong64.s` | PE entry (LoongArch LP64: `R4`=ImageHandle, `R5`=SystemTable), early `'A'` UART marker, `gBS->AllocatePages` for heap, `csrwr CSR.EUEN.FPE`, RamStart, hand-off to `_rt0_tamago_start` | loong64 |
| `eficall_loong64.s` | LoongArch LP64 thunk: `R4..R7` args, no shadow space, indirect `JAL (R13)` via `R23`-stashed RA | loong64 |
| `board_loong64.go` | Self-contained (no framework loong64 import), `Nanotime` via stable-timer + CPUCFG, `Hwinit0/1` (no-op under UEFI), `RamSize=64 MiB`, `RamStackOffset`, splitmix64 RNG seeded from the stable-timer | loong64 |
| `board_loong64.s` | `rdStableCounter()` / `rdCPUCFG()` via `RDTIMED` / `CPUCFG` | loong64 |

Built with `-tags linkcpuinit,linkramstart`: these exclude the framework's
bare-metal `cpuinit` (so ours wins) and, on amd64, the framework's
default `RamStart`. On arm64 the framework ships neither symbol so the
tags are no-ops there. On riscv64 `linkcpuinit` excludes
`tamago/riscv64/init.s`'s bare-metal `cpuinit` trampoline; the board
deliberately does not import the framework's `riscv64` package at all
(see `board_riscv64.go` file header) — its IRQ asm uses `X3` directly
and the patched tamago-go riscv64 assembler now rejects that
("illegal or missing addressing mode for symbol X3"), and its
`CPU.Init()` writes M-mode CSRs that would trap under UEFI's S-mode.

## Build & boot

Requires the TamaGo `tamago-go` toolchain with the cloud-boot-local PIE
overlay applied (see `cloud-boot/docs/tamago-loong64-pie.patch`), the
TamaGo framework, and `go-coff/pectl`.

The per-arch build pipeline is captured in `Taskfile.yaml` — `task all`
builds the four EFIs in one shot, `task test` rebuilds them and asserts
that `runtime.GOARCH` got constant-folded to the right value in each PE's
rodata (regression guard for the now-fixed `BOOTRISCV64.EFI` banner that
used to read `tamago/amd64` despite carrying RISC-V machine code — root
cause was a stray host `GOARCH` leaking into the riscv64 invocation).
Overridable env: `TAMAGO=...` for the `tamago-go` toolchain, `PECTL_DIR=...`
for the `pectl` source dir.

Equivalent shell pipeline, per arch:

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

# 4''. boot under QEMU/EDK2-RiscV (riscv64) — boots end-to-end
qemu-system-riscv64 -machine virt -m 4096 -nographic \
  -drive if=pflash,format=raw,unit=0,file=edk2-riscv-code.fd \
  -drive if=pflash,format=raw,unit=1,file=edk2-riscv-vars.fd \
  -drive file=fat:rw:esp-riscv64,format=raw,if=none,id=esp \
  -device virtio-blk-device,drive=esp

# 4'''. boot under QEMU/EDK2-LoongArch (loong64) — boots end-to-end
qemu-system-loongarch64 -machine virt -cpu max -m 4096 -nographic \
  -bios edk2-loongarch64-code.fd \
  -drive format=raw,file=boot-loong64.iso,if=none,id=cd \
  -device virtio-blk-pci,drive=cd
```

Expected output (per arch — `<arch>` ∈ {`amd64`, `arm64`, `riscv64`,
`loong64`}):

```text
hello from cloud-boot tamago/<arch> UEFI board
runtime: go1.26.3 GOOS=tamago GOARCH=<arch>
goroutine sum: 499500
DONE
```

## Follow-ups

- Submit the `BaseRiscVMmuLib.c` `~`/`!` assert-typo patch (staged at
  `cloud-boot/docs/edk2-riscv64-protection-fix.patch`) to
  `devel@edk2.groups.io`.
- Upstream the local `usbarmory/tamago/loong64/` package
  (cf. `usbarmory/tamago#70`) and the toolchain port
  (cf. `usbarmory/tamago-go#17`). The cloud-boot-local PIE overlay
  (`tamago-loong64-pie.patch`) stays out of the upstream PR per the
  maintainer's request — track it here.
- Reconcile `RamSize` against the UEFI memory map post-World
  (`GetMemoryMap` + `AllocatePages`) instead of the per-arch hardcoded
  bound; same approach go-boot uses on amd64.
- `go.mod` uses a local `replace` for the TamaGo framework during
  development.

## License

BSD 3-Clause.
