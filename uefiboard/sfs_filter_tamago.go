// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// Tamago-side live wiring for the SFS-parent filter — pulls device
// paths off firmware handles and calls FindSFSChildOf-friendly
// helpers. See sfs_filter.go for the pure-data helpers and the
// architectural rationale.

//go:build tamago && (amd64 || arm64 || loong64 || riscv64)

package uefiboard

import (
	"errors"
	"unsafe"
)

// devicePathBytes pulls the bytes of an EFI_DEVICE_PATH_PROTOCOL from
// the firmware. The protocol is just a sequence of EFI_DEVICE_PATH
// nodes terminated by an END_ENTIRE node (type 0x7F, subtype 0xFF,
// length 4) — so we walk forward node by node, accumulating bytes,
// stopping at (but INCLUDING) the END node.
//
// Returns a Go-owned byte slice. Safe to share across calls.
func devicePathBytes(handle uint64) ([]byte, error) {
	if handle == 0 {
		return nil, errors.New("uefi: devicePathBytes called with zero handle")
	}
	iface, err := HandleProtocol(handle, &EFIDevicePathProtocolGUID)
	if err != nil {
		return nil, err
	}
	if iface == 0 {
		return nil, errors.New("uefi: handle does not publish DevicePath")
	}
	// Walk node by node. A node header is 4 bytes (Type, SubType,
	// Length[2] LE); Length is the TOTAL bytes of that node header
	// + payload. The END node has Type=0x7F and Length=4 (header only).
	var out []byte
	p := uintptr(iface)
	for {
		if p == 0 {
			return nil, errors.New("uefi: DevicePath walk hit NULL")
		}
		t := *(*byte)(unsafe.Pointer(p))
		st := *(*byte)(unsafe.Pointer(p + 1))
		ln := *(*uint16)(unsafe.Pointer(p + 2))
		if ln < 4 {
			return nil, errors.New("uefi: DevicePath node length < 4 (malformed)")
		}
		seg := unsafe.Slice((*byte)(unsafe.Pointer(p)), int(ln))
		out = append(out, seg...)
		if t == devPathTypeEnd && st == devPathSubTypeEndWhole {
			return out, nil
		}
		p += uintptr(ln)
		// Defensive cap so a malformed path can't trap us in an infinite
		// loop. 64 KiB of device path is already comically deep — real
		// paths are 10-200 bytes.
		if len(out) > 65536 {
			return nil, errors.New("uefi: DevicePath grew past 64 KiB without END node")
		}
	}
}

// FindSFSChildOf scans every handle that publishes
// EFI_SIMPLE_FILE_SYSTEM_PROTOCOL and returns the first whose device
// path begins with the device path of `parentHandle` (the Block IO
// handle returned by PublishBlockIO).
//
// Returns the child handle (the one to LoadImage from) and the bytes
// of its device path (handy for downstream LoadImage device-path
// construction — see EFI_LOADED_IMAGE.FilePath).
//
// If no matching SFS handle exists, returns ErrNoMatchingSFS. See the
// error doc-comment in sfs_filter.go for diagnostic interpretation.
func FindSFSChildOf(parentHandle uintptr) (uint64, []byte, error) {
	if parentHandle == 0 {
		return 0, nil, errors.New("uefi: FindSFSChildOf called with zero parent handle")
	}
	parentDP, err := devicePathBytes(uint64(parentHandle))
	if err != nil {
		return 0, nil, err
	}
	sfsHandles, err := LocateHandleBuffer(&EFISimpleFileSystemProtocolGUID)
	if err != nil {
		return 0, nil, err
	}
	for _, h := range sfsHandles {
		childDP, err := devicePathBytes(h)
		if err != nil {
			// Skip handles that don't publish a device path — there
			// shouldn't be any in practice, but the spec doesn't strictly
			// require it.
			continue
		}
		if devicePathPrefix(parentDP, childDP) {
			return h, childDP, nil
		}
	}
	return 0, nil, ErrNoMatchingSFS
}
