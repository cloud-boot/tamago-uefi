// cloud-boot — TamaGo UEFI Phase-1 proof of life (multi-arch).
//
// A pure-Go bare-metal UEFI application built on the standard Go runtime
// via TamaGo (GOOS=tamago, GOARCH=amd64/arm64/loong64/riscv64). It uses
// cloud-boot's OWN UEFI
// board (package uefiboard) — NOT go-boot — for the firmware entry, the
// MS x64 service-call thunk, and ConOut wiring. This first milestone only
// proves the entry + runtime bring-up + console: it prints over the UEFI
// ConOut and halts (ExitBootServices and the real loader come later).
package main

import (
	"runtime"

	_ "github.com/cloud-boot/tamago-uefi/uefiboard"
)

func main() {
	println("hello from cloud-boot tamago/" + runtime.GOARCH + " UEFI board")
	println("runtime:", runtime.Version(), "GOOS="+runtime.GOOS+" GOARCH="+runtime.GOARCH)

	// goroutine + channel smoke test (proves the real scheduler is up,
	// the whole point of TamaGo over TinyGo).
	done := make(chan int, 1)
	go func() {
		sum := 0
		for i := 0; i < 1000; i++ {
			sum += i
		}
		done <- sum
	}()
	println("goroutine sum:", <-done)

	println("DONE — halting")
	for {
		// spin; nothing to exit to yet.
	}
}
