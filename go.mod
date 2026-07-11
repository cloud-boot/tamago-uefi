module github.com/cloud-boot/tamago-uefi

go 1.26.3

require (
	github.com/cloud-boot/godoom v0.0.0
	github.com/go-compressions/lz4 v0.1.1
	github.com/go-compressions/lzfse v0.2.0
	github.com/go-filesystems/interface v0.0.0
	github.com/go-filesystems/ufs v0.0.0
	github.com/go-tpm2/common v0.1.0
	github.com/go-tpm2/efitcg2 v0.2.0
	github.com/go-tpm2/tpm2 v0.5.0
	github.com/go-virtio/common v0.1.5
	github.com/go-virtio/console v0.1.0
	github.com/go-virtio/gpu v0.0.0
	github.com/go-virtio/input v0.0.0
	github.com/go-virtio/net v0.1.0
	github.com/go-virtio/sound v0.0.0
	github.com/hashicorp/hcl/v2 v2.24.0
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/ulikunitz/xz v0.5.15
	github.com/usbarmory/tamago v0.0.0
	oras.land/oras-go/v2 v2.6.1
)

require (
	github.com/agext/levenshtein v1.2.1 // indirect
	github.com/apparentlymart/go-textseg/v15 v15.0.0 // indirect
	github.com/go-simd/matchlen v0.3.1 // indirect
	github.com/go-tpm2/attest v0.2.2
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/zclconf/go-cty v1.16.3 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
)

replace github.com/usbarmory/tamago => ../../usbarmory/tamago

replace github.com/go-filesystems/interface => ../../go-filesystems/interface

replace github.com/go-filesystems/ufs => ../../go-filesystems/ufs

// Phase-3 DOOM bare-metal demo (phase3_oci_doom_boot tag) — local
// godoom + go-virtio gpu / sound / input clones. Pinned to local paths
// so the bring-up sprint can iterate without tagged releases.
replace github.com/cloud-boot/godoom => ../godoom

replace github.com/go-virtio/common => ../../go-virtio/common

replace github.com/go-virtio/gpu => ../../go-virtio/gpu

replace github.com/go-virtio/input => ../../go-virtio/input

replace github.com/go-virtio/sound => ../../go-virtio/sound
