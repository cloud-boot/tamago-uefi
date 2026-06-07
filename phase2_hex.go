// Pure host-buildable hex stringifiers shared by every Phase-2
// probe binary that needs them. Avoids pulling fmt into the EFI
// binary (dep-light, matching the rest of the probe's print idioms).
//
// Gated on the union of probe build tags so the symbols are linked
// in any probe binary, but absent from a default (Phase-1) build.
// Each Phase-2 probe binary that uses these helpers ALSO carries
// its own build-tag for the live probe body, so this file's
// `package main` symbols are consistent.

//go:build phase2_pcienum || phase2_snpenum || phase2_blkprintk || phase2_virtionet_tx

package main

// hex8 stringifies a uint8 in 0x-prefixed 2-digit hex.
func hex8(v uint8) string {
	const digits = "0123456789abcdef"
	var buf [4]byte
	buf[0] = '0'
	buf[1] = 'x'
	buf[2] = digits[(v>>4)&0xF]
	buf[3] = digits[v&0xF]
	return string(buf[:])
}

// hex32 stringifies a uint32 in 0x-prefixed 8-digit hex.
func hex32(v uint32) string {
	const digits = "0123456789abcdef"
	var buf [10]byte
	buf[0] = '0'
	buf[1] = 'x'
	for i := 0; i < 8; i++ {
		buf[9-i] = digits[v&0xF]
		v >>= 4
	}
	return string(buf[:])
}

// hex16 stringifies a uint16 in 0x-prefixed 4-digit hex.
func hex16(v uint16) string {
	const digits = "0123456789abcdef"
	var buf [6]byte
	buf[0] = '0'
	buf[1] = 'x'
	buf[2] = digits[(v>>12)&0xF]
	buf[3] = digits[(v>>8)&0xF]
	buf[4] = digits[(v>>4)&0xF]
	buf[5] = digits[v&0xF]
	return string(buf[:])
}

// hexU64 stringifies a uint64 in 0x-prefixed hex (minimum 1 digit;
// no leading zero pad). Mirrors `uefiboard.hexU64`'s shape so
// callers don't see a difference in output.
func hexU64(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0x0"
	}
	var buf [18]byte
	i := len(buf)
	for v != 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	i--
	buf[i] = 'x'
	i--
	buf[i] = '0'
	return string(buf[i:])
}
