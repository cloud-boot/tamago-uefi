// cloud-boot UEFI board — amd64 post-EBS interrupt mask (M2-B).
//
// `postEBSDisableInterrupts` clears the IF (interrupt-enable) bit of
// the RFLAGS register via the single-byte CLI instruction (Intel SDM
// Vol 2A §3.2 — opcode 0xFA).
//
// At EBS-success the firmware's IDT is still installed but its
// vector handlers point at code we no longer own; a spurious legacy
// device interrupt (e.g. a 8254 timer tick on some platforms) could
// dispatch into a torn-down handler and fault. Masking IF defensively
// stops that.

#include "textflag.h"

TEXT ·postEBSDisableInterrupts(SB),NOSPLIT|NOFRAME,$0
	BYTE	$0xFA  // CLI
	RET
