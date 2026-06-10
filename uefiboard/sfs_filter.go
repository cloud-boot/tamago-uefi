// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// SFS-parent device-path filter — picks, among ALL handles publishing
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL, the one whose backing storage is
// the synthetic Block IO we just published via PublishBlockIO.
//
// Why this exists
// ---------------
// After ConnectController(blkHandle) the firmware's PartitionDxe +
// FatDxe load and create one or more child handles. On a typical EDK2
// boot OVMF's BdsDxe ALSO connects every other Block IO device on the
// platform (the firmware's stock ESP, the virtio-blk if present, the
// IDE disk we use as our own startup vehicle, ...). So a blind
// LocateHandleBuffer(SFS_GUID) returns every FAT volume the firmware
// knows about — not just the one rooted on our synthetic disk.
//
// The right filter is the device-path parent chain. EDK2's
// PartitionDxe creates the partition-child handle with device path =
// parent.devicePath ++ HD(...) node. So our target SFS handle's
// device path begins with our blkHandle's device path. The bytes-wise
// prefix match (node-aligned, see devicePathPrefix below) catches it.
//
// Reference: UEFI 2.10 §10.3 (Device Path), §13.7 (Driver Binding),
// MdeModulePkg/Universal/Disk/PartitionDxe/Partition.c
// PartitionInstallChildHandle().
//
// Sprint 3 (Windows) note: the same filter pattern works for NTFS
// child handles once a NTFS driver is loaded — only the partition
// type GUID changes, not the parent-device-path relationship.

package uefiboard

import "errors"

// ErrNoMatchingSFS is returned by FindSFSChildOf when no SFS handle's
// device path begins with the parent handle's device path. Possible
// causes:
//   - ConnectController didn't run, so PartitionDxe never bound;
//   - The synthetic image doesn't contain a recognised partition table
//     (PartitionDxe rejects unknown PMBR / GPT signatures); or
//   - The partition is not FAT (FatDxe didn't bind, so no SFS handle).
//
// All three are diagnostic-grade — see the live runner's failure
// banner table for the troubleshooting checklist.
var ErrNoMatchingSFS = errors.New("uefi: no SimpleFileSystem handle has the given Block IO handle as a device-path parent")

// devicePathPrefix returns true iff `prefix` (a complete device-path
// byte sequence WITH its END node) is a node-aligned prefix of `full`
// — i.e. dropping the END node from `prefix` yields the leading
// bytes of `full` AND `full` continues with at least one more
// non-END node.
//
// We compare node-by-node so a coincidental byte match in the middle
// of a node doesn't trigger a false positive.
//
// Host-buildable: a pure function over byte slices so unit tests can
// hand-craft synthetic device-paths without dragging the firmware
// surface in.
func devicePathPrefix(prefix, full []byte) bool {
	// Trim END node from prefix (header is 4 bytes).
	if len(prefix) < 4 {
		return false
	}
	endIdx := len(prefix) - 4
	if prefix[endIdx] != devPathTypeEnd || prefix[endIdx+1] != devPathSubTypeEndWhole {
		// Caller passed a non-terminated path; reject so we don't trip
		// on garbage in the trailing bytes.
		return false
	}
	body := prefix[:endIdx]
	if len(body) >= len(full) {
		return false
	}
	// Walk nodes in body, ensuring each matches the corresponding bytes
	// of full.
	p := 0
	for p < len(body) {
		if p+4 > len(body) || p+4 > len(full) {
			return false
		}
		ln := int(uint16(body[p+2]) | uint16(body[p+3])<<8)
		if ln < 4 {
			return false
		}
		if p+ln > len(body) || p+ln > len(full) {
			return false
		}
		// Compare node bytes 1:1.
		for i := 0; i < ln; i++ {
			if body[p+i] != full[p+i] {
				return false
			}
		}
		p += ln
	}
	// `full` must have at least one more non-END node after the prefix.
	if p+4 > len(full) {
		return false
	}
	if full[p] == devPathTypeEnd && full[p+1] == devPathSubTypeEndWhole {
		// `full` ends right after the prefix — not a strict child.
		return false
	}
	return true
}
