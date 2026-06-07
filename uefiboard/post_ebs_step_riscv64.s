// cloud-boot UEFI board — riscv64 post-EBS interrupt mask (M2-B).
//
// `postEBSDisableInterrupts` clears SSTATUS.SIE (bit 1) — the
// supervisor-mode interrupt-enable bit. We're in S-mode at UEFI
// entry (M-mode belongs to OpenSBI) so SSTATUS is the right CSR.
//
// Reference: RISC-V Privileged Spec v1.12 §4.1.1 "Supervisor Status
// Register (sstatus)" — bit 1 = SIE. Clearing it via `csrrc` is the
// canonical interrupt-mask sequence (also matches what Linux
// arch/riscv/include/asm/csr.h does with `csr_clear(CSR_SSTATUS,
// SR_SIE)`).
//
// Note: M2-B runs riscv64 only as a no-op cell (the §3 M2 capability
// matrix has riscv64 firmware not publishing a modern virtio-net cap;
// the M2-B probe will surface "no virtio-net" cleanly before EBS
// even gets a chance to run). This file exists so the package
// compiles cleanly on riscv64, not because the riscv64 cell is
// expected to exercise it.

#include "textflag.h"

TEXT ·postEBSDisableInterrupts(SB),NOSPLIT|NOFRAME,$0
	// csrrc x0, sstatus, 0x2 → clear SIE, discard old value.
	// Encoding: CSRRC rd=x0, rs1=imm(0x2), csr=0x100 (sstatus).
	// The Go asm idiom mirrors the riscv64 framework's existing
	// CSR-clear pattern (see cpuinit_riscv64.s lines around CSRRS).
	MOV	$2, T0
	CSRRC	T0, SSTATUS, ZERO
	RET
