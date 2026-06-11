// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — aarch64 firmware->Go callback trampolines
// for the published EFI_SIMPLE_FILE_SYSTEM_PROTOCOL + EFI_FILE_PROTOCOL
// (Phase 3 sprint 2B, multi-arch port — companion to
// sfs_publish_amd64.s).
//
// Eleven reverse-direction trampolines (firmware -> us, AAPCS64 ->
// Go ABI0), one per spec method (UEFI 2.10 §13.4-§13.5):
//
//   sfs_open_volume_trampoline  -> ·sfsOpenVolumeGo(SB)       (2 args)
//   sfs_file_open_trampoline    -> ·sfsFileOpenGo(SB)         (5 args)
//   sfs_file_close_trampoline   -> ·sfsFileCloseGo(SB)        (1 arg)
//   sfs_file_delete_trampoline  -> ·sfsFileDeleteGo(SB)       (1 arg)
//   sfs_file_read_trampoline    -> ·sfsFileReadGo(SB)         (3 args)
//   sfs_file_write_trampoline   -> ·sfsFileWriteGo(SB)        (3 args)
//   sfs_file_getpos_trampoline  -> ·sfsFileGetPositionGo(SB)  (2 args)
//   sfs_file_setpos_trampoline  -> ·sfsFileSetPositionGo(SB)  (2 args)
//   sfs_file_getinfo_trampoline -> ·sfsFileGetInfoGo(SB)      (4 args)
//   sfs_file_setinfo_trampoline -> ·sfsFileSetInfoGo(SB)      (4 args)
//   sfs_file_flush_trampoline   -> ·sfsFileFlushGo(SB)        (1 arg)
//
// Mirrors block_io_publish_arm64.s and rng_protocol_arm64.s for the
// ABI bridging conventions — same AAPCS64 callee-saved integer set
// (X19..X25 + X29/X30) and callee-saved FP set (D8..D15). AAPCS64
// passes the first 8 args in X0..X7, so the 5-arg shapes (Open) get
// all five args directly in registers — no shadow-space dance needed.
//
// Uniform 224-byte frame across all 11 trampolines. Go ABI0 lays
// args + ret contiguously starting at SP+8 (SP+0 is the reserved
// saved-LR slot), so the ret-slot offset varies per arity:
//
//   1 arg : ret at SP+16
//   2 args: ret at SP+24
//   3 args: ret at SP+32
//   4 args: ret at SP+40
//   5 args: ret at SP+48
//
// Frame layout (post-prologue SP):
//   SP+0     reserved (Go ABI0 saved-LR slot)
//   SP+8..40 args  (up to 5 slots; lower-arity ret goes earlier)
//   SP+48    ret slot for 5-arg form
//   SP+56    X29
//   SP+64    X30
//   SP+72    X19
//   SP+80    X20
//   SP+88    X21
//   SP+96    X22
//   SP+104   X23
//   SP+112   X24
//   SP+120   X25
//   SP+128   D8
//   SP+136   D9
//   SP+144   D10
//   SP+152   D11
//   SP+160   D12
//   SP+168   D13
//   SP+176   D14
//   SP+184   D15
//   SP+192..223 padding

#include "textflag.h"

// ───────────────────────────────────────────────────────────────────
// Entry-PC helpers — return the .abi0 entry PC of each trampoline.
// ───────────────────────────────────────────────────────────────────

TEXT ·sfs_open_volume_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_open_volume_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_open_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_open_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_close_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_close_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_delete_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_delete_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_read_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_read_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_write_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_write_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_getpos_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_getpos_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_setpos_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_setpos_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_getinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_getinfo_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_setinfo_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_setinfo_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

TEXT ·sfs_file_flush_trampolinePC(SB),NOSPLIT,$0-8
	MOVD	$·sfs_file_flush_trampoline(SB), R0
	MOVD	R0, ret+0(FP)
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_open_volume_trampoline — OpenVolume(this, *Root) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_open_volume_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	BL	·sfsOpenVolumeGo(SB)
	MOVD	24(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_open_trampoline — Open(this, *new, name, mode, attr) — 5 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_open_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	MOVD	R3, 32(RSP)
	MOVD	R4, 40(RSP)
	BL	·sfsFileOpenGo(SB)
	MOVD	48(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_close_trampoline — Close(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_close_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	BL	·sfsFileCloseGo(SB)
	MOVD	16(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_delete_trampoline — Delete(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_delete_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	BL	·sfsFileDeleteGo(SB)
	MOVD	16(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_read_trampoline — Read(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_read_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	BL	·sfsFileReadGo(SB)
	MOVD	32(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_write_trampoline — Write(this, *size, buf) — 3 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_write_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	BL	·sfsFileWriteGo(SB)
	MOVD	32(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getpos_trampoline — GetPosition(this, *pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	BL	·sfsFileGetPositionGo(SB)
	MOVD	24(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setpos_trampoline — SetPosition(this, pos) — 2 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setpos_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	BL	·sfsFileSetPositionGo(SB)
	MOVD	24(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_getinfo_trampoline — GetInfo(this, *type, *size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_getinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	MOVD	R3, 32(RSP)
	BL	·sfsFileGetInfoGo(SB)
	MOVD	40(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_setinfo_trampoline — SetInfo(this, *type, size, buf) — 4 args
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_setinfo_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	MOVD	R1, 16(RSP)
	MOVD	R2, 24(RSP)
	MOVD	R3, 32(RSP)
	BL	·sfsFileSetInfoGo(SB)
	MOVD	40(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET

// ───────────────────────────────────────────────────────────────────
// sfs_file_flush_trampoline — Flush(this) — 1 arg
// ───────────────────────────────────────────────────────────────────
TEXT ·sfs_file_flush_trampoline(SB),NOSPLIT|NOFRAME,$0
	SUB	$224, RSP
	MOVD	R29, 56(RSP)
	MOVD	R30, 64(RSP)
	MOVD	R19, 72(RSP)
	MOVD	R20, 80(RSP)
	MOVD	R21, 88(RSP)
	MOVD	R22, 96(RSP)
	MOVD	R23, 104(RSP)
	MOVD	R24, 112(RSP)
	MOVD	R25, 120(RSP)
	FMOVD	F8,  128(RSP)
	FMOVD	F9,  136(RSP)
	FMOVD	F10, 144(RSP)
	FMOVD	F11, 152(RSP)
	FMOVD	F12, 160(RSP)
	FMOVD	F13, 168(RSP)
	FMOVD	F14, 176(RSP)
	FMOVD	F15, 184(RSP)
	MOVD	R0, 8(RSP)
	BL	·sfsFileFlushGo(SB)
	MOVD	16(RSP), R0
	FMOVD	128(RSP), F8
	FMOVD	136(RSP), F9
	FMOVD	144(RSP), F10
	FMOVD	152(RSP), F11
	FMOVD	160(RSP), F12
	FMOVD	168(RSP), F13
	FMOVD	176(RSP), F14
	FMOVD	184(RSP), F15
	MOVD	56(RSP), R29
	MOVD	64(RSP), R30
	MOVD	72(RSP), R19
	MOVD	80(RSP), R20
	MOVD	88(RSP), R21
	MOVD	96(RSP), R22
	MOVD	104(RSP), R23
	MOVD	112(RSP), R24
	MOVD	120(RSP), R25
	ADD	$224, RSP
	RET
