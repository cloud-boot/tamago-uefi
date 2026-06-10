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
pkgx-pinned `edk2-stable202408` firmware, see `cloud-boot/iso`'s
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

An earlier revision of this README documented a build-pipeline
mislabel — `BOOTRISCV64.EFI` rodata contained `tamago/amd64` instead
of `tamago/riscv64`. The root cause was a stale host `GOARCH=amd64`
leaking into the riscv64 `go build` invocation, so the riscv64 ELF
was emitted with RISC-V codegen but amd64 internal constants. Fixed
in `Taskfile.yaml`: each arch's `elf:`/`efi:` task pins its full env
(`GOOS`, `GOARCH`, `GOOSPKG`, `CGO_ENABLED`, `GOWORK`) inside the
task's `env:` block, eliminating cross-arch env bleed. A new
`internal/bannertest` regression test loads each `BOOT<ARCH>.EFI` and
asserts its rodata contains the matching `GOOS=tamago GOARCH=<arch>`
strings and no other arch's banner.

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

# 4'. boot under QEMU/AAVMF (arm64) — boots end-to-end
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

## Phase 2 — pure-Go bare-metal UEFI loader (live Linux userspace on all 4 arches)

Phase 2 turns this image into a PXE-class pre-boot agent that runs
inside UEFI Boot Services, fetches a `kernel + initrd` OCI artifact
over HTTPS, verifies a cosign signature, and chain-boots the Linux
kernel via `LoadImage` + `StartImage` — replacing the historical
`PXE + iPXE + systemd-boot` chain with a single statically-linked
pure-Go application on the real Go runtime.

Design doc:
[`cloud-boot/docs/tamago-uefi-phase2-oci-loader.md`](https://github.com/cloud-boot/docs/blob/main/tamago-uefi-phase2-oci-loader.md)
— the milestone-by-milestone design log, continuously updated.

Architectural pivot (2026-06-07, ref design doc §2): the original
"Path X = drive `EFI_HTTP_PROTOCOL` + `EFI_DHCP4_PROTOCOL` + `EFI_TLS_PROTOCOL`"
plan was abandoned after Apple `Virtualization.framework`'s firmware
was confirmed to expose only `BlockIO` / `SFS` / `SimpleNetwork`
(no `HTTP` / `TCP4` / `DHCP4` / `DNS4`) and virtio-net rejects
`FEATURES_OK` from any UEFI-context client. Phase 2 adopted
**Path Y = pure-Go network + crypto stack on top of virtio-net via
`EFI_PCI_IO_PROTOCOL`**, which doesn't need any networking protocol
from the firmware. Same loader now boots under QEMU/OVMF, Apple VZ,
and EDK2 hardware.

### End-to-end pipeline

```text
PCI walk -> virtio-net -> DHCPv4 -> DNS -> TLS (CCADB roots) -> HTTPS
  -> OCI Distribution v2 walk -> multi-arch index -> manifest
  -> streaming blob fetch -> SHA-256 verify -> cosign keyed verify
  -> LoadImage -> SetLoadOptions(cmdline) -> PublishDTB -> PublishInitrd
  -> PublishRNG -> StartImage -> Linux EFI-stub
  -> "Booting Linux Kernel..." -> real distro kernel
```

### Milestones shipped

| ID | Scope | Status |
| -- | ----- | ------ |
| **M0**     | Design doc, type surface, `GetMemoryMap` probe                                                                  | SHIPPED |
| **M1..M3** | virtio-net device discovery, init, gvisor `netstack` `LinkEndpoint` (ARP + IPv4 + ICMP echo)                    | SHIPPED |
| **M4**     | pure-Go DHCPv4 client                                                                                            | SHIPPED 2026-06-08 |
| **M5**     | pure-Go DNS + HTTP GET over the ministack                                                                        | SHIPPED 2026-06-08 |
| **M6**     | TLS + HTTPS GET via stdlib `crypto/tls` over the ministack (CCADB roots)                                         | SHIPPED 2026-06-08 |
| **M6.1**   | EDK2 OVMF image-protection bug ID'd + 3 upstream commits (`5ccb5fff02`, `867fad874a`, `b5bab75e58`) — fix lands in `edk2-stable202511`+ ; pantry recipe in [pkgxdev/pantry#13239](https://github.com/pkgxdev/pantry/pull/13239) | SHIPPED |
| **M6.2**   | [`go-coff/efipack`](https://github.com/go-coff/efipack) — PE32+ self-extracting compressor (flate + LZFSE, host-side + per-arch stubs) ; M6.2 PR2 GREEN on arm64 + riscv64 + loong64 | SHIPPED |
| **M7**     | pure-Go OCI Distribution v2 registry client                                                                      | SHIPPED 2026-06-08 |
| **M7.1a**  | streaming OCI blob fetch                                                                                         | SHIPPED 2026-06-09 |
| **M7.1b**  | cosign keyed signature verification                                                                              | SHIPPED 2026-06-09 |
| **M7-alt** | `oras-go` POC evaluated and parked — `net/http.Client.Do` deadlocks under the TamaGo + UEFI scheduler            | PARKED  |
| **M8.0**   | `LoadImage` + `StartImage` chain-boot mechanism                                                                  | SHIPPED 2026-06-09 |
| **M8.1**   | Minimal end-to-end MODE B (streaming OCI fetch -> LoadImage -> StartImage on 3/4 arches)                         | SHIPPED 2026-06-09 |
| **M8.2**   | Framework : `SetLoadOptions` + `PublishInitrd`                                                                    | SHIPPED 2026-06-09 |
| **M8.3**   | Live MODE C kernel boot via OCI — arm64 against `ghcr.io/siderolabs/kernel` ; riscv64 + loong64 self-published via `cmd/cloudboot-oci-extract` (Debian linux-image .deb → tar.gz → ttl.sh, nightly cron) | SHIPPED 2026-06-10 |
| **M8.4**   | DTB `ConfigurationTable` probe + per-arch `LoadFile2` trampoline (all 4 arches)                                  | SHIPPED 2026-06-10 |
| **M8.5**   | Real-ELF `/init` in embedded initramfs (573 KiB cpio.gz, pure-Go arm64) — R-M8.5a CLOSED by M8.6                 | SHIPPED 2026-06-10 |
| **M8.6**   | `PublishDTB` via `gBS->InstallConfigurationTable` + embedded arm64-virt DTB — R-M8.5a CLOSED                     | SHIPPED 2026-06-10 |
| **M8.7**   | `PublishRNG` + cmdline `nokaslr random.trust_bootloader=0 random.trust_cpu=0` — R-M8.6a CLOSED                   | SHIPPED 2026-06-10 |
| **M8.8**   | Post-EBS pl011 serial routing cmdline cleanup (drop `acpi=force`, add `keep_bootcon` + `earlyprintk=keep` + `printk.time=y`) | SHIPPED 2026-06-10 |
| **M8.9..M8.12** | riscv64 + loong64 + amd64 live kernel boot bring-up (Debian 6.12.90 / 7.0.12) ; smoke matrix 8/8 GREEN | SHIPPED 2026-06-10 |
| **M8.13**  | Debian 13 unified across all four arches                                                                         | SHIPPED 2026-06-10 |
| **M8.14**  | `R-amd64j` CLOSED — EDK2 OVMF amd64 `LoadFile2` quirk worked around via `initrd=` kernel cmdline + ESP `SimpleFileSystem` file + `InheritParentDeviceHandle` ; amd64 lands in Linux userspace | SHIPPED 2026-06-10 |
| **M9.0..M9.2** | Interactive boot menu (selector + cmdline editor + persistence) shipped                                      | SHIPPED 2026-06-10 |
| **R-M9.1a** | virtio-console firmware handoff — pre-EBS console rerouting under EDK2                                          | next |
| **R-M9.2a** | `time.Sleep` under TamaGo+UEFI — preemption-edge timer-wheel residency                                          | next |

### Live status per arch (2026-06-10)

All four arches reach a real Debian 13 userspace end-to-end from a
cold DHCP lease against a public OCI registry. Wall-clock numbers
are the firmware-to-`/sbin/init` interval observed under QEMU on
the standard `task test:phase2:*` harness.

| arch    | M0..M7 | M8.0 chain-boot | Live Linux userspace | Wall-clock | Kernel | Initrd handoff |
| ------- | ------ | --------------- | -------------------- | ---------- | ------ | -------------- |
| **arm64**   | ✅ | ✅ | ✅ | 17.1 s | Debian 6.12.90 | `LoadFile2` |
| **amd64**   | ✅ | ✅ | ✅ | 16.1 s | Debian 6.12.90 | `initrd=` cmdline (ESP `SimpleFileSystem` + `InheritParentDeviceHandle`) |
| **riscv64** | ✅ | ✅ | ✅ | 18.1 s | Debian 6.12.90 | `LoadFile2` |
| **loong64** | ✅ | ✅ | ✅ | 17.1 s | Debian 7.0.12 | `LoadFile2` |

amd64 closed on 2026-06-10 via the `R-amd64a..j` cleanup chain :

- `R-amd64a..e` : EDK2 firmware `CpuPageTableLib` bug chase ; fix
  landed upstream.
- `R-amd64f..g` : TamaGo cpuinit `.bss` heap zero pass + an explicit
  `goos.Bloc` `MOVQ` write the other three arches had always emitted
  but amd64 was the outlier on.
- `R-amd64h` : `rxLoop` allocation churn (async-preemption
  side-effect) — surfaced as `runtime: cannot allocate memory`.
- `R-amd64i` : `dialTLSOnce` deadline-math bug.
- `R-amd64j` : EDK2 OVMF amd64 `LoadFile2` quirk — the firmware
  silently mis-handles the protocol the kernel uses to fetch its
  initrd, so the loader on amd64 falls back to the long-standing
  `initrd=<filename>` kernel-cmdline path. The initrd is published
  as an ESP file via `SimpleFileSystem` and the loaded kernel
  inherits the parent image's `DeviceHandle` so the cmdline path
  resolves against the same FS the kernel was loaded from. The
  other three arches retain the `LoadFile2` protocol path.

The amd64 smoke matrix is 8/8 GREEN post-`R-amd64j` (R-amd64a..j
saga closed). A nightly cron re-publishes a fresh `vmlinuz` for
each of the four arches.

Known sharp edges still tracked :

- `R-M9.1a` — virtio-console firmware handoff under EDK2 (pre-EBS
  console rerouting path).
- `R-M9.2a` — `time.Sleep` under TamaGo + UEFI (preemption-edge
  timer-wheel residency).

### M0 probe (historical reference)

`uefiboard/` gained the M0 type surface :

- `ebs.go` — `ExitBootServices(mapKey)` thunk.
- `memorymap.go` + `memorymap_tamago.go` — `MemoryDescriptor` type +
  `GetMemoryMap()` wrapper (stride-aware ; firmware reports
  `DescriptorSize=48`).
- `http_protocol.go` — GUIDs and Go struct shapes (kept for
  diagnostic builds ; the live Phase 2 loader doesn't use them).

A `-tags phase2_probe` build of `main.go` calls `GetMemoryMap`,
prints `descriptors=`, `descriptorSize=`, `mapKey=` and per-type RAM
totals to ConOut, then halts. The default build keeps Phase 1's
banner-only behaviour bit-for-bit.

Build the probe EFIs :

```sh
task probe:memory:all          # all four arches
task probe:memory:amd64        # one arch
```

Host-side unit tests cover the parser + GUID byte layouts :

```sh
task uefiboard:test
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
