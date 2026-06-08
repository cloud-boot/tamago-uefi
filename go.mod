module github.com/cloud-boot/tamago-uefi

go 1.26.3

require github.com/usbarmory/tamago v0.0.0

require (
	golang.org/x/exp v0.0.0-20250711185948-6ae5c78190dc // indirect
	golang.org/x/sys v0.43.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gvisor.dev/gvisor v0.0.0-20260604230326-c7dbb92365cd // indirect
)

replace github.com/usbarmory/tamago => ../../usbarmory/tamago
