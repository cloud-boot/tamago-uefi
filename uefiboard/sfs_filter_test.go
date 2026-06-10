// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause

package uefiboard

import "testing"

// Helpers to hand-craft device-path byte sequences for the tests.
// Each node is `type, subtype, lengthLE...payload`. The END node is
// always `0x7F 0xFF 0x04 0x00`.

func endNode() []byte {
	return []byte{devPathTypeEnd, devPathSubTypeEndWhole, 0x04, 0x00}
}

// node builds a single device-path node with the given type/subtype
// and an arbitrary payload. Length is computed from len(payload)+4.
func node(t, st byte, payload ...byte) []byte {
	ln := uint16(len(payload) + 4)
	out := []byte{t, st, byte(ln), byte(ln >> 8)}
	out = append(out, payload...)
	return out
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestDevicePathPrefix_StrictChild(t *testing.T) {
	// Parent: PCI(0x3,0) -> END
	parent := concat(
		node(0x01, 0x01, 0x00, 0x03),
		endNode(),
	)
	// Child:  PCI(0x3,0) -> HD(1,GPT,...) -> END
	child := concat(
		node(0x01, 0x01, 0x00, 0x03),
		node(0x04, 0x01, // MEDIA_HARDDRIVE_DP
			0x01, 0x00, 0x00, 0x00, // PartitionNumber=1
			0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, // PartitionStart
			0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, // PartitionSize
			0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0, // Signature
			0x02, // MBRType=GPT
			0x02, // SignatureType=GUID
		),
		endNode(),
	)
	if !devicePathPrefix(parent, child) {
		t.Fatalf("expected parent to be a strict prefix of child")
	}
}

func TestDevicePathPrefix_ExactMatchRejected(t *testing.T) {
	// `prefix` == `full` (minus the END differences): strictly NOT a
	// prefix of itself — a child must have at least one additional
	// node beyond the parent.
	parent := concat(
		node(0x01, 0x01, 0x00, 0x03),
		endNode(),
	)
	if devicePathPrefix(parent, parent) {
		t.Fatalf("identical paths must not be considered a parent-child relationship")
	}
}

func TestDevicePathPrefix_SiblingRejected(t *testing.T) {
	// Parent: PCI(0x3,0) -> END
	parent := concat(
		node(0x01, 0x01, 0x00, 0x03),
		endNode(),
	)
	// Sibling: PCI(0x4,0) -> HD(...) -> END  (different PCI device)
	sibling := concat(
		node(0x01, 0x01, 0x00, 0x04),
		node(0x04, 0x01, 0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x02, 0x02),
		endNode(),
	)
	if devicePathPrefix(parent, sibling) {
		t.Fatalf("PCI(0x3) parent must not match PCI(0x4) sibling")
	}
}

func TestDevicePathPrefix_NonNodeAlignedRejected(t *testing.T) {
	// A byte-wise prefix that doesn't align with node boundaries must
	// fail. We construct a parent whose END node truncates mid-payload
	// of the child's first node.
	parent := []byte{
		0x01, 0x01, 0x06, 0x00, 0xAA, 0xBB, // PCI node, 6 bytes
		devPathTypeEnd, devPathSubTypeEndWhole, 0x04, 0x00,
	}
	// Child: a single 7-byte PCI node followed by END. The parent's
	// 6-byte first node has a different Length field than the child's,
	// so the node-aligned compare must reject it.
	child := []byte{
		0x01, 0x01, 0x07, 0x00, 0xAA, 0xBB, 0xCC,
		0x04, 0x01, 0x04, 0x00,
		devPathTypeEnd, devPathSubTypeEndWhole, 0x04, 0x00,
	}
	if devicePathPrefix(parent, child) {
		t.Fatalf("mismatched first-node lengths must be rejected")
	}
}

func TestDevicePathPrefix_UnterminatedPrefixRejected(t *testing.T) {
	// `prefix` without an END node — defensive rejection so callers
	// can't pass partial paths through.
	prefix := node(0x01, 0x01, 0x00, 0x03)
	child := concat(
		node(0x01, 0x01, 0x00, 0x03),
		node(0x04, 0x01, 0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0x02, 0x02),
		endNode(),
	)
	if devicePathPrefix(prefix, child) {
		t.Fatalf("unterminated prefix must be rejected")
	}
}

func TestDevicePathPrefix_EmptyInputs(t *testing.T) {
	if devicePathPrefix(nil, nil) {
		t.Fatalf("nil inputs must yield false")
	}
	if devicePathPrefix(endNode(), endNode()) {
		t.Fatalf("two bare END paths must not be in a parent-child relationship")
	}
}

func TestDevicePathPrefix_MalformedLengthZero(t *testing.T) {
	// A node with Length=0 would loop forever if we didn't guard.
	bad := []byte{0x01, 0x01, 0x00, 0x00, devPathTypeEnd, devPathSubTypeEndWhole, 0x04, 0x00}
	full := concat(node(0x01, 0x01, 0x00, 0x03), node(0x04, 0x01, 0xAA), endNode())
	if devicePathPrefix(bad, full) {
		t.Fatalf("Length=0 node must be rejected")
	}
}
