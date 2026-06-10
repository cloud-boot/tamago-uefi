module github.com/cloud-boot/tamago-uefi

go 1.26.3

require (
	github.com/go-virtio/common v0.1.0
	github.com/go-virtio/net v0.1.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/ulikunitz/xz v0.5.15
	github.com/usbarmory/tamago v0.0.0
	oras.land/oras-go/v2 v2.6.1
)

require golang.org/x/sync v0.20.0 // indirect

replace github.com/usbarmory/tamago => ../../usbarmory/tamago
