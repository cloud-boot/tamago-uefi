module github.com/cloud-boot/tamago-uefi

go 1.26.3

require (
	github.com/go-virtio/common v0.0.0-00010101000000-000000000000
	github.com/go-virtio/net v0.0.0-00010101000000-000000000000
	github.com/usbarmory/tamago v0.0.0
)

replace github.com/usbarmory/tamago => ../../usbarmory/tamago

// During the migration, the go-virtio modules live as siblings of
// cloud-boot. Once the first tagged releases are published these
// replace directives can be removed in favour of versioned requires.
replace github.com/go-virtio/common => ../../go-virtio/common

replace github.com/go-virtio/net => ../../go-virtio/net
