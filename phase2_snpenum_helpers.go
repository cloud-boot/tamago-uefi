// Pure host-buildable helpers used by the M1.5 SNP probe. Kept in
// their own file (separate from phase2_snpenum.go) so the host test
// at phase2_snpenum_test.go can exercise them without needing the
// `tamago` build tag (which would pull in efiCall, which only links
// on the firmware target).
//
// Build tag: `phase2_snpenum`. The host test file uses the same tag,
// so `go test -tags phase2_snpenum` picks up both — no `tamago`
// required for the host run.

//go:build phase2_snpenum

package main

// macHex formats `b` as a colon-separated hex MAC string. Avoids
// pulling fmt into the EFI binary (dep-light, matching the rest of
// the probe's print idioms).
func macHex(b []uint8) string {
	const digits = "0123456789abcdef"
	if len(b) == 0 {
		return "<empty>"
	}
	// Each byte → 2 hex chars; separators are colons. 6-byte MAC = 17.
	out := make([]byte, 0, 3*len(b))
	for i, v := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, digits[(v>>4)&0xF], digits[v&0xF])
	}
	return string(out)
}
