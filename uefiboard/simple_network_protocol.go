// cloud-boot UEFI board — EFI_SIMPLE_NETWORK_PROTOCOL type surface (M1.5).
//
// Pure type + GUID + offset surface for EFI_SIMPLE_NETWORK_PROTOCOL
// (UEFI 2.10 §24.1 — "Simple Network Protocol"). M1.5 ONLY uses the
// pieces required for handle enumeration + a read-only peek at
// `*This->Mode`: the protocol GUID, the offset of the `Mode` pointer
// inside the protocol struct, and the layout of the
// `EFI_SIMPLE_NETWORK_MODE` block itself.
//
// **No driver implementation here.** Start/Stop/Initialize/Receive/
// Transmit and the rest of the entry table are deliberately out of
// scope — the M1.5 probe only needs the MAC byte string and the
// media-state booleans. A future M-step (a VZ-only Simple-Network
// LinkEndpoint adapter that wraps this protocol) would add the function
// thunks; today we keep the surface minimal.
//
// Upstream reference (read before changing layouts):
//
//   - MdePkg/Include/Protocol/SimpleNetwork.h (edk2.git stable/202408)
//     — GUID + protocol struct + `EFI_SIMPLE_NETWORK_MODE` definition.
//   - MdePkg/Include/Uefi/UefiBaseType.h — `EFI_MAC_ADDRESS` as
//     `typedef struct { UINT8 Addr[32]; }`.
//   - UEFI 2.10 §24.1 — protocol semantics.
//
// Host-buildable (no //go:build tamago): the GUID round-trip + the
// `EFI_SIMPLE_NETWORK_MODE` struct-layout assertions run under host
// `go test`.

package uefiboard

// EFI_SIMPLE_NETWORK_PROTOCOL_GUID
//
//	A19832B9-AC25-11D3-9A2D-0090273FC14D
//
// Source: MdePkg/Include/Protocol/SimpleNetwork.h (edk2.git
// stable/202408, line 23):
//
//	#define EFI_SIMPLE_NETWORK_PROTOCOL_GUID \
//	  { 0xA19832B9, 0xAC25, 0x11D3,
//	    { 0x9A, 0x2D, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D } }
var EFISimpleNetworkProtocolGUID = EFIGUID{
	Data1: 0xa19832b9,
	Data2: 0xac25,
	Data3: 0x11d3,
	Data4: [8]uint8{0x9a, 0x2d, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d},
}

// EFI_SIMPLE_NETWORK_PROTOCOL struct layout (UEFI 2.10 §24.1, mirrored
// against `MdePkg/Include/Protocol/SimpleNetwork.h` lines 643..671):
//
//	struct _EFI_SIMPLE_NETWORK_PROTOCOL {
//	    UINT64                                Revision;          //   0
//	    EFI_SIMPLE_NETWORK_START              Start;             //   8
//	    EFI_SIMPLE_NETWORK_STOP               Stop;              //  16
//	    EFI_SIMPLE_NETWORK_INITIALIZE         Initialize;        //  24
//	    EFI_SIMPLE_NETWORK_RESET              Reset;             //  32
//	    EFI_SIMPLE_NETWORK_SHUTDOWN           Shutdown;          //  40
//	    EFI_SIMPLE_NETWORK_RECEIVE_FILTERS    ReceiveFilters;    //  48
//	    EFI_SIMPLE_NETWORK_STATION_ADDRESS    StationAddress;    //  56
//	    EFI_SIMPLE_NETWORK_STATISTICS         Statistics;        //  64
//	    EFI_SIMPLE_NETWORK_MCAST_IP_TO_MAC    MCastIpToMac;      //  72
//	    EFI_SIMPLE_NETWORK_NVDATA             NvData;            //  80
//	    EFI_SIMPLE_NETWORK_GET_STATUS         GetStatus;         //  88
//	    EFI_SIMPLE_NETWORK_TRANSMIT           Transmit;          //  96
//	    EFI_SIMPLE_NETWORK_RECEIVE            Receive;           // 104
//	    EFI_EVENT                             WaitForPacket;     // 112
//	    EFI_SIMPLE_NETWORK_MODE              *Mode;              // 120
//	};
//
// All function-pointer slots are sizeof(void*) on a 64-bit UEFI image;
// `EFI_EVENT` and `EFI_SIMPLE_NETWORK_MODE *` are also 8 bytes. M1.5
// only references `snpModeOffset` (read-only peek at `*Mode`); the
// other entries are named for future thunks but unused here.
const (
	snpRevisionOffset       = 0
	snpStartOffset          = 8
	snpStopOffset           = 16
	snpInitializeOffset     = 24
	snpResetOffset          = 32
	snpShutdownOffset       = 40
	snpReceiveFiltersOffset = 48
	snpStationAddressOffset = 56
	snpStatisticsOffset     = 64
	snpMCastIpToMacOffset   = 72
	snpNvDataOffset         = 80
	snpGetStatusOffset      = 88
	snpTransmitOffset       = 96
	snpReceiveOffset        = 104
	snpWaitForPacketOffset  = 112
	snpModeOffset           = 120
)

// EFISimpleNetworkState mirrors EFI_SIMPLE_NETWORK_STATE (UEFI 2.10
// §24.1, `MdePkg/Include/Protocol/SimpleNetwork.h` lines 143..148).
// Stored as `UINT32` in `EFI_SIMPLE_NETWORK_MODE.State` — see below.
type EFISimpleNetworkState uint32

const (
	EFISimpleNetworkStopped      EFISimpleNetworkState = 0
	EFISimpleNetworkStarted      EFISimpleNetworkState = 1
	EFISimpleNetworkInitialized  EFISimpleNetworkState = 2
	EFISimpleNetworkMaxState     EFISimpleNetworkState = 3
)

// MaxMCastFilterCount is the spec-fixed size of the multicast filter
// array (`MdePkg/Include/Protocol/SimpleNetwork.h` line 161).
const MaxMCastFilterCount = 16

// EFIMACAddress mirrors EFI_MAC_ADDRESS — a fixed 32-byte buffer
// (`MdePkg/Include/Uefi/UefiBaseType.h` lines 95..97). Only the first
// HwAddressSize bytes (typically 6 for Ethernet) carry MAC data; the
// remainder is zero-padded by the firmware.
//
// We expose the raw 32 bytes so the probe can slice the meaningful
// prefix without having to know `HwAddressSize` ahead of time.
type EFIMACAddress struct {
	Addr [32]uint8
}

// EFISimpleNetworkMode mirrors EFI_SIMPLE_NETWORK_MODE (UEFI 2.10
// §24.1, `MdePkg/Include/Protocol/SimpleNetwork.h` lines 162..242).
//
// On-the-wire layout (Edk2 packs `BOOLEAN` as `UINT8`):
//
//	  0  UINT32   State
//	  4  UINT32   HwAddressSize
//	  8  UINT32   MediaHeaderSize
//	 12  UINT32   MaxPacketSize
//	 16  UINT32   NvRamSize
//	 20  UINT32   NvRamAccessSize
//	 24  UINT32   ReceiveFilterMask
//	 28  UINT32   ReceiveFilterSetting
//	 32  UINT32   MaxMCastFilterCount
//	 36  UINT32   MCastFilterCount
//	 40  EFI_MAC_ADDRESS  MCastFilter[16]  (16 * 32 = 512 bytes; ends at 552)
//	552  EFI_MAC_ADDRESS  CurrentAddress     (32 bytes; ends at 584)
//	584  EFI_MAC_ADDRESS  BroadcastAddress   (32 bytes; ends at 616)
//	616  EFI_MAC_ADDRESS  PermanentAddress   (32 bytes; ends at 648)
//	648  UINT8            IfType
//	649  BOOLEAN (UINT8)  MacAddressChangeable
//	650  BOOLEAN (UINT8)  MultipleTxSupported
//	651  BOOLEAN (UINT8)  MediaPresentSupported
//	652  BOOLEAN (UINT8)  MediaPresent
//
// Total size: 656 bytes (no trailing padding required at struct end on
// any of our 4 LE64 arches; the byte tail aligns naturally on the next
// struct boundary). The host test `TestSNPModeLayout` pins each of the
// per-field offsets explicitly so a typo here is caught at `go test`.
type EFISimpleNetworkMode struct {
	State                 uint32
	HwAddressSize         uint32
	MediaHeaderSize       uint32
	MaxPacketSize         uint32
	NvRamSize             uint32
	NvRamAccessSize       uint32
	ReceiveFilterMask     uint32
	ReceiveFilterSetting  uint32
	MaxMCastFilterCount   uint32
	MCastFilterCount      uint32
	MCastFilter           [MaxMCastFilterCount]EFIMACAddress
	CurrentAddress        EFIMACAddress
	BroadcastAddress      EFIMACAddress
	PermanentAddress      EFIMACAddress
	IfType                uint8
	MacAddressChangeable  uint8
	MultipleTxSupported   uint8
	MediaPresentSupported uint8
	MediaPresent          uint8
}

// efiSimpleNetworkModeSize is the Go-side `unsafe.Sizeof` of
// EFI_SIMPLE_NETWORK_MODE. The on-the-wire EDK2 layout ends 653 bytes
// past the struct start (last `BOOLEAN` at offset 652); Go pads to the
// struct's own alignment (4-byte from the leading UINT32 fields), so
// `unsafe.Sizeof` returns 656. Pinned by `TestSNPModeLayout` so a
// reordering or alignment mistake in the struct fields above shows up
// at `go test` rather than blowing up live.
const (
	efiSimpleNetworkModeWireEnd = 653 // last meaningful byte (MediaPresent) + 1
	efiSimpleNetworkModeSize    = 656 // unsafe.Sizeof — wire-end + 3 bytes alignment pad
)
