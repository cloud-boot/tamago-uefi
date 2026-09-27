package uefiboard

import (
	"unsafe"
)

// ⛔ A uintptr TO A LOCAL IS NOT AN ADDRESS THAT STAYS PUT.
//
// These tests call the trampoline handlers the way firmware does: the
// out-parameter arrives as a uintptr. Firmware hands over a real address that
// nothing in Go owns, so the handlers are right to take one. A TEST that
// writes
//
//	var fh uintptr
//	rc := sfsFileOpenGo(root, uintptr(unsafe.Pointer(&fh)), …)
//
// is doing something else entirely, and Go says so: converting a Pointer to a
// uintptr yields a number with no pointer semantics, keeping nothing alive and
// pinning nothing. The callee here is not firmware — it is Go, it allocates,
// and it can grow the goroutine stack. A growing stack is COPIED, so the
// handler's
//
//	*(*uintptr)(unsafe.Pointer(outNew)) = …
//
// writes to the address the local used to have. The test then reads the local
// at its new address and finds zero, while the call reported EFI_SUCCESS.
//
// It had been true for as long as the tests existed and it surfaced on
// 2026-09-23 as a red arm64 lane in CI, amd64 green. Measured on 2026-09-27:
//
//	go test -count=1   passes
//	go test -count=3   passes
//	go test -count=5   FAILS at the fourth iteration
//	adding one t.Logf  passes again, 5 of 5
//	adding an unrelated, UNRUN test function to the file  flips which one fails
//
// Nothing about that is random. The verdict tracks the stack frame layout,
// which is why the two architectures disagreed and why the bug reads as a
// flake. A package-level cell lives in the data segment, and the data segment
// does not move: 100 of 100 with the same body.
//
// Production code passes these same uintptrs to firmware through assembly. No
// Go frame grows between taking the address and the callee writing, so that
// side is not this defect — and none of it is changed here.

// escapeSink is what makes pin() work: assigning a pointer to a package-level
// variable is an escape the compiler cannot analyse away, so the pointee is
// heap-allocated and its address does not move when a goroutine stack grows.
//
// It is deliberately never read. `new(uintptr)` is NOT enough on its own --
// escape analysis is free to keep it on the stack, because a conversion to
// uintptr does not count as the pointer escaping. That was measured: a
// `new(uintptr)` variant of the failing test failed just as the local did.
var escapeSink unsafe.Pointer

// pin returns v, having forced whatever it points at onto the heap.
//
// Written as one token at the call site -- addr(pin(&fh)) rather than
// uintptr(unsafe.Pointer(&fh)) -- so the fix does not reshape the tests it
// repairs, and so every place that needs it looks the same.
func pin[T any](v *T) *T {
	escapeSink = unsafe.Pointer(v)
	return v
}

// addr is the ONE place a stable cell becomes a uintptr, so the unsafe
// conversion is written once and reviewed once.
func addr[T any](p *T) uintptr { return uintptr(unsafe.Pointer(p)) }
