// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — LoongArch64 firmware->Go callback trampolines
// for the published EFI_SIMPLE_FILE_SYSTEM_PROTOCOL + EFI_FILE_PROTOCOL
// (Phase 3 sprint 2B, multi-arch port — companion to
// sfs_publish_amd64.s).
//
// Eleven reverse-direction trampolines (firmware -> us, LP64 ->
// Go ABI0), one per spec method. See sfs_publish_amd64.s for the
// per-method (this, ...) parameter shapes; this file mirrors that
// 1:1 in the LoongArch LP64 ABI.
//
// Same shape as block_io_publish_loong64.s + rng_protocol_loong64.s.
// R22 is the Go g register — DO NOT touch.
// R30 is the Go assembler scratch register — DO NOT touch.
//
// Uniform 240-byte frame across all 11 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 = reserved saved-LR
// slot). Ret-slot offset varies per arity:
//
//   1 arg : ret at SP+16
//   2 args: ret at SP+24
//   3 args: ret at SP+32
//   4 args: ret at SP+40
//   5 args: ret at SP+48
//
// Frame layout (post-prologue SP / R3):
//   SP+0     reserved (Go ABI0 saved-LR slot)
//   SP+8..40 args  (up to 5 slots; lower-arity ret goes earlier)
//   SP+48    ret slot for 5-arg form
//   SP+56    saved R1  (RA)
//   SP+64    saved R23 (S0)
//   SP+72    saved R24 (S1)
//   SP+80    saved R25 (S2)
//   SP+88    saved R26 (S3)
//   SP+96    saved R27 (S4)
//   SP+104   saved R28 (S5)
//   SP+112   saved R29 (S6)
//   SP+120   saved R31 (S8)
//   SP+128   padding
//   SP+136   padding
//   SP+144..200 saved F24..F31 (FS0..FS7)
//   SP+208..239 padding

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────

TEXT ·sfs_open_volume_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_open_volume_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_open_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_open_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_close_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_close_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_delete_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_delete_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_read_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_read_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_write_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_write_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_getpos_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_getpos_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_setpos_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_setpos_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_getinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_getinfo_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_setinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_setinfo_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

TEXT ·sfs_file_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOVV	$·sfs_file_flush_trampoline(SB), R4
	MOVV	R4, ret+0(FP)
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_open_volume_trampoline — OpenVolume(this, *Root) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_open_volume_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	JAL	·sfsOpenVolumeGo(SB)
	MOVV	24(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_open_trampoline — Open(this, *new, name, mode, attr) — 5 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_open_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)
	MOVV	R8, 40(R3)
	JAL	·sfsFileOpenGo(SB)
	MOVV	48(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_close_trampoline — Close(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_close_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	JAL	·sfsFileCloseGo(SB)
	MOVV	16(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_delete_trampoline — Delete(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_delete_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	JAL	·sfsFileDeleteGo(SB)
	MOVV	16(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_read_trampoline — Read(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	JAL	·sfsFileReadGo(SB)
	MOVV	32(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_write_trampoline — Write(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	JAL	·sfsFileWriteGo(SB)
	MOVV	32(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getpos_trampoline — GetPosition(this, *pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	JAL	·sfsFileGetPositionGo(SB)
	MOVV	24(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setpos_trampoline — SetPosition(this, pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	JAL	·sfsFileSetPositionGo(SB)
	MOVV	24(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getinfo_trampoline — GetInfo(this, *type, *size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)
	JAL	·sfsFileGetInfoGo(SB)
	MOVV	40(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setinfo_trampoline — SetInfo(this, *type, size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	MOVV	R5, 16(R3)
	MOVV	R6, 24(R3)
	MOVV	R7, 32(R3)
	JAL	·sfsFileSetInfoGo(SB)
	MOVV	40(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_flush_trampoline — Flush(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADDV	$-240, R3
	MOVV	R1, 56(R3)
	MOVV	R23, 64(R3)
	MOVV	R24, 72(R3)
	MOVV	R25, 80(R3)
	MOVV	R26, 88(R3)
	MOVV	R27, 96(R3)
	MOVV	R28, 104(R3)
	MOVV	R29, 112(R3)
	MOVV	R31, 120(R3)
	MOVD	F24, 144(R3)
	MOVD	F25, 152(R3)
	MOVD	F26, 160(R3)
	MOVD	F27, 168(R3)
	MOVD	F28, 176(R3)
	MOVD	F29, 184(R3)
	MOVD	F30, 192(R3)
	MOVD	F31, 200(R3)
	MOVV	R4, 8(R3)
	JAL	·sfsFileFlushGo(SB)
	MOVV	16(R3), R4
	MOVD	144(R3), F24
	MOVD	152(R3), F25
	MOVD	160(R3), F26
	MOVD	168(R3), F27
	MOVD	176(R3), F28
	MOVD	184(R3), F29
	MOVD	192(R3), F30
	MOVD	200(R3), F31
	MOVV	56(R3), R1
	MOVV	64(R3), R23
	MOVV	72(R3), R24
	MOVV	80(R3), R25
	MOVV	88(R3), R26
	MOVV	96(R3), R27
	MOVV	104(R3), R28
	MOVV	112(R3), R29
	MOVV	120(R3), R31
	ADDV	$240, R3
	RET
