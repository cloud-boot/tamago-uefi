// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — RISC-V 64 firmware->Go callback trampolines
// for the published EFI_SIMPLE_FILE_SYSTEM_PROTOCOL + EFI_FILE_PROTOCOL
// (Phase 3 sprint 2B, multi-arch port — companion to
// sfs_publish_amd64.s).
//
// Eleven reverse-direction trampolines (firmware -> us, LP64D ->
// Go ABI0), one per spec method. See sfs_publish_amd64.s for the
// per-method (this, ...) parameter shapes; this file mirrors that
// 1:1 in the RISC-V psABI.
//
// Same shape as block_io_publish_riscv64.s + rng_protocol_riscv64.s.
// X27 (S11) is the Go g register — DO NOT touch.
//
// Uniform 288-byte frame across all 11 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 = reserved saved-LR
// slot). Ret-slot offset varies per arity:
//
//   1 arg : ret at SP+16
//   2 args: ret at SP+24
//   3 args: ret at SP+32
//   4 args: ret at SP+40
//   5 args: ret at SP+48
//
// Frame layout (post-prologue SP / X2):
//   SP+0     reserved (Go ABI0 saved-LR slot)
//   SP+8..40 args  (up to 5 slots; lower-arity ret goes earlier)
//   SP+48    ret slot for 5-arg form
//   SP+56    saved RA  (X1)
//   SP+64    saved S0  (X8)
//   SP+72    saved S1  (X9)
//   SP+80    saved S2  (X18)
//   SP+88    saved S3  (X19)
//   SP+96    saved S4  (X20)
//   SP+104   saved S5  (X21)
//   SP+112   saved S6  (X22)
//   SP+120   saved S7  (X23)
//   SP+128   saved S8  (X24)
//   SP+136   saved S9  (X25)
//   SP+144   saved S10 (X26)
//                       // X27 (S11) is g — DO NOT touch.
//   SP+152   padding
//   SP+160..248  saved FS0..FS11 (F8, F9, F18..F27)
//   SP+256..287  padding

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────

TEXT ·sfs_open_volume_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_open_volume_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_open_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_open_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_close_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_close_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_delete_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_delete_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_read_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_read_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_write_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_write_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_getpos_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_getpos_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_setpos_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_setpos_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_getinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_getinfo_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_setinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_setinfo_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

TEXT ·sfs_file_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOV	$·sfs_file_flush_trampoline(SB), A0
	MOV	A0, ret+0(FP)
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_open_volume_trampoline — OpenVolume(this, *Root) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_open_volume_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	CALL	·sfsOpenVolumeGo(SB)
	MOV	24(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_open_trampoline — Open(this, *new, name, mode, attr) — 5 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_open_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	MOV	A3, 32(X2)
	MOV	A4, 40(X2)
	CALL	·sfsFileOpenGo(SB)
	MOV	48(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_close_trampoline — Close(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_close_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	CALL	·sfsFileCloseGo(SB)
	MOV	16(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_delete_trampoline — Delete(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_delete_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	CALL	·sfsFileDeleteGo(SB)
	MOV	16(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_read_trampoline — Read(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	CALL	·sfsFileReadGo(SB)
	MOV	32(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_write_trampoline — Write(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	CALL	·sfsFileWriteGo(SB)
	MOV	32(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getpos_trampoline — GetPosition(this, *pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	CALL	·sfsFileGetPositionGo(SB)
	MOV	24(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setpos_trampoline — SetPosition(this, pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	CALL	·sfsFileSetPositionGo(SB)
	MOV	24(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getinfo_trampoline — GetInfo(this, *type, *size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	MOV	A3, 32(X2)
	CALL	·sfsFileGetInfoGo(SB)
	MOV	40(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setinfo_trampoline — SetInfo(this, *type, size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	MOV	A1, 16(X2)
	MOV	A2, 24(X2)
	MOV	A3, 32(X2)
	CALL	·sfsFileSetInfoGo(SB)
	MOV	40(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_flush_trampoline — Flush(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	ADD	$-288, X2
	MOV	X1, 56(X2)
	MOV	X8, 64(X2)
	MOV	X9, 72(X2)
	MOV	X18, 80(X2)
	MOV	X19, 88(X2)
	MOV	X20, 96(X2)
	MOV	X21, 104(X2)
	MOV	X22, 112(X2)
	MOV	X23, 120(X2)
	MOV	X24, 128(X2)
	MOV	X25, 136(X2)
	MOV	X26, 144(X2)
	MOVD	F8,  160(X2)
	MOVD	F9,  168(X2)
	MOVD	F18, 176(X2)
	MOVD	F19, 184(X2)
	MOVD	F20, 192(X2)
	MOVD	F21, 200(X2)
	MOVD	F22, 208(X2)
	MOVD	F23, 216(X2)
	MOVD	F24, 224(X2)
	MOVD	F25, 232(X2)
	MOVD	F26, 240(X2)
	MOVD	F27, 248(X2)
	MOV	A0, 8(X2)
	CALL	·sfsFileFlushGo(SB)
	MOV	16(X2), A0
	MOVD	160(X2), F8
	MOVD	168(X2), F9
	MOVD	176(X2), F18
	MOVD	184(X2), F19
	MOVD	192(X2), F20
	MOVD	200(X2), F21
	MOVD	208(X2), F22
	MOVD	216(X2), F23
	MOVD	224(X2), F24
	MOVD	232(X2), F25
	MOVD	240(X2), F26
	MOVD	248(X2), F27
	MOV	56(X2), X1
	MOV	64(X2), X8
	MOV	72(X2), X9
	MOV	80(X2), X18
	MOV	88(X2), X19
	MOV	96(X2), X20
	MOV	104(X2), X21
	MOV	112(X2), X22
	MOV	120(X2), X23
	MOV	128(X2), X24
	MOV	136(X2), X25
	MOV	144(X2), X26
	ADD	$288, X2
	RET
