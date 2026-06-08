// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// cloud-boot UEFI board — LoadImage / StartImage / UnloadImage / Exit
// offsets + sentinel errors (Phase 2, M8.0).
//
// Holds the type surface (offsets + ErrLoadImageNoSource) that both
// the host build (loadimage_host.go) and the tamago build
// (loadimage_tamago.go) share.
//
// Wraps the image-services subset of EFI_BOOT_SERVICES (UEFI 2.10
// §7.4):
//
//	EFI_STATUS LoadImage(
//	    IN  BOOLEAN                   BootPolicy,
//	    IN  EFI_HANDLE                ParentImageHandle,
//	    IN  EFI_DEVICE_PATH_PROTOCOL  *DevicePath, OPTIONAL
//	    IN  VOID                      *SourceBuffer,  OPTIONAL
//	    IN  UINTN                     SourceSize,
//	    OUT EFI_HANDLE                *ImageHandle );
//
//	EFI_STATUS StartImage(
//	    IN  EFI_HANDLE                ImageHandle,
//	    OUT UINTN                     *ExitDataSize, OPTIONAL
//	    OUT CHAR16                    **ExitData     OPTIONAL );
//
//	EFI_STATUS UnloadImage(
//	    IN  EFI_HANDLE                ImageHandle );
//
//	EFI_STATUS Exit(
//	    IN  EFI_HANDLE                ImageHandle,
//	    IN  EFI_STATUS                ExitStatus,
//	    IN  UINTN                     ExitDataSize,
//	    IN  CHAR16                    *ExitData      OPTIONAL );

package uefiboard

import "errors"

// EFI_BOOT_SERVICES image-services function-pointer offsets (UEFI 2.10
// §4.2 table 4.2 + MdePkg/Include/Uefi/UefiSpec.h struct order). The
// image-services block starts at offset 200 (one full slot after
// CalculateCrc32 = 192):
//
//	200 LoadImage              <-- here
//	208 StartImage             <-- here
//	216 Exit                   <-- here
//	224 UnloadImage            <-- here
//	232 ExitBootServices       (matches memorymap.go's efiBSExitBootServices)
const (
	efiBSLoadImage   = 200
	efiBSStartImage  = 208
	efiBSExit        = 216
	efiBSUnloadImage = 224
)

// ErrLoadImageNoSource is returned by LoadImage when the supplied
// source buffer is nil/empty. UEFI's LoadImage tolerates a NULL
// SourceBuffer only if a DevicePath is supplied; the M8.0 wrapper
// always uses SourceBuffer mode (DevicePath = NULL), so an empty
// buffer is unambiguously a caller error and is rejected before the
// firmware ever sees it.
var ErrLoadImageNoSource = errors.New("uefi: LoadImage source buffer is empty")
