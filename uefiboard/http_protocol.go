// cloud-boot UEFI board — EFI HTTP Protocol type surface (Phase 2, M0).
//
// Pure type + GUID surface for the EFI_HTTP_PROTOCOL family
// (UEFI 2.10 §29 — HTTP Protocol). NO method calls yet; M1 wires
// the request/response state machine on top of this.
//
// Upstream references (read for M1):
//   - MdePkg/Include/Protocol/Http.h           (struct + GUID source)
//   - MdePkg/Include/IndustryStandard/Http11.h (header-field constants)
//   - NetworkPkg/HttpDxe/HttpImpl.c            (state machine reference)
//
// This file is host-buildable (no //go:build tamago) so the round-trip
// GUID-layout tests can run under host `go test`.

package uefiboard

// EFI_GUID layout (UEFI 2.10 §2.3.1 / RFC 4122 mixed-endian):
//
//	typedef struct {
//	    UINT32  Data1;     // little-endian
//	    UINT16  Data2;     // little-endian
//	    UINT16  Data3;     // little-endian
//	    UINT8   Data4[8];  // raw bytes
//	} EFI_GUID;
//
// The textual form "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" maps to:
// Data1 = first 32 bits (big-endian text → little-endian wire),
// Data2 = next 16 bits, Data3 = next 16 bits, Data4 = last 8 bytes
// in textual order (big-endian to wire).
type EFIGUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]uint8
}

// EFI_HTTP_SERVICE_BINDING_PROTOCOL_GUID
//
//	bdc8e6af-d9bc-4379-a72a-e0c4e75dae1c
//
// Source: MdePkg/Include/Protocol/Http.h (edk2.git).
var EFIHTTPServiceBindingProtocolGUID = EFIGUID{
	Data1: 0xbdc8e6af,
	Data2: 0xd9bc,
	Data3: 0x4379,
	Data4: [8]uint8{0xa7, 0x2a, 0xe0, 0xc4, 0xe7, 0x5d, 0xae, 0x1c},
}

// EFI_HTTP_PROTOCOL_GUID
//
//	7a59b29b-910b-4171-8242-a85a0df25b5b
//
// Source: MdePkg/Include/Protocol/Http.h (edk2.git).
var EFIHTTPProtocolGUID = EFIGUID{
	Data1: 0x7a59b29b,
	Data2: 0x910b,
	Data3: 0x4171,
	Data4: [8]uint8{0x82, 0x42, 0xa8, 0x5a, 0x0d, 0xf2, 0x5b, 0x5b},
}

// EFI_HTTP_VERSION enum (UEFI 2.10 §29.4.3).
type EFIHTTPVersion uint32

const (
	EFIHTTPVersion10 EFIHTTPVersion = 0
	EFIHTTPVersion11 EFIHTTPVersion = 1
	// HttpVersionUnsupported / sentinel — followed by HTTP/2, HTTP/3 in
	// future UEFI revisions; track via the official enum if M1+ need
	// them.
	EFIHTTPVersionUnsupported EFIHTTPVersion = 2
)

// EFI_HTTP_METHOD enum (UEFI 2.10 §29.4.3). Order MUST match
// `MdePkg/Include/Protocol/Http.h`.
type EFIHTTPMethod uint32

const (
	EFIHTTPMethodGet EFIHTTPMethod = iota
	EFIHTTPMethodPost
	EFIHTTPMethodPatch
	EFIHTTPMethodOptions
	EFIHTTPMethodConnect
	EFIHTTPMethodHead
	EFIHTTPMethodPut
	EFIHTTPMethodDelete
	EFIHTTPMethodTrace
	EFIHTTPMethodMax
)

// EFI_HTTP_STATUS_CODE enum (UEFI 2.10 §29.4.3). Numeric range mirrors
// the IANA HTTP status code registry; the enum names follow the spec.
// Defined as uint32 to match edk2's `typedef enum`.
type EFIHTTPStatusCode uint32

// EFI_HTTPv4_ACCESS_POINT (UEFI 2.10 §29.4 — Http4Node sub-struct):
//
//	typedef struct {
//	    BOOLEAN          UseDefaultAddress;
//	    EFI_IPv4_ADDRESS LocalAddress;    // [4]UINT8
//	    EFI_IPv4_ADDRESS LocalSubnet;     // [4]UINT8
//	    UINT16           LocalPort;
//	} EFI_HTTPv4_ACCESS_POINT;
type EFIHTTPv4AccessPoint struct {
	UseDefaultAddress uint8 // BOOLEAN (UEFI 2.10 §2.3.1: 1 byte)
	_pad              [3]uint8
	LocalAddress      [4]uint8
	LocalSubnet       [4]uint8
	LocalPort         uint16
	_pad2             [2]uint8
}

// EFI_HTTPv6_ACCESS_POINT (UEFI 2.10 §29.4):
//
//	typedef struct {
//	    EFI_IPv6_ADDRESS LocalAddress;  // [16]UINT8
//	    UINT16           LocalPort;
//	} EFI_HTTPv6_ACCESS_POINT;
type EFIHTTPv6AccessPoint struct {
	LocalAddress [16]uint8
	LocalPort    uint16
	_pad         [2]uint8
}

// EFI_HTTP_CONFIG_DATA (UEFI 2.10 §29.4.2). The AccessPoint union is
// flattened here as a pointer field carrying either an
// EFI_HTTPv4_ACCESS_POINT* or EFI_HTTPv6_ACCESS_POINT* depending on
// LocalAddressIsIPv6. M1 picks IPv4 by default.
//
//	typedef struct {
//	    EFI_HTTP_VERSION  HttpVersion;
//	    UINT32            TimeOutMillisec;
//	    BOOLEAN           LocalAddressIsIPv6;
//	    union {
//	      EFI_HTTPv4_ACCESS_POINT *IPv4Node;
//	      EFI_HTTPv6_ACCESS_POINT *IPv6Node;
//	    } AccessPoint;
//	} EFI_HTTP_CONFIG_DATA;
type EFIHTTPConfigData struct {
	HTTPVersion        EFIHTTPVersion
	TimeOutMillisec    uint32
	LocalAddressIsIPv6 uint8 // BOOLEAN
	_pad               [7]uint8
	AccessPoint        uint64 // pointer to either v4 or v6 access point
}

// EFI_HTTP_REQUEST_DATA (UEFI 2.10 §29.4.3):
//
//	typedef struct {
//	    EFI_HTTP_METHOD  Method;
//	    CHAR16          *Url;
//	} EFI_HTTP_REQUEST_DATA;
type EFIHTTPRequestData struct {
	Method EFIHTTPMethod
	_pad   uint32
	URL    uint64 // CHAR16*
}

// EFI_HTTP_RESPONSE_DATA (UEFI 2.10 §29.4.3):
//
//	typedef struct {
//	    EFI_HTTP_STATUS_CODE  StatusCode;
//	} EFI_HTTP_RESPONSE_DATA;
type EFIHTTPResponseData struct {
	StatusCode EFIHTTPStatusCode
	_pad       uint32
}

// EFI_HTTP_HEADER (UEFI 2.10 §29.4.3):
//
//	typedef struct {
//	    CHAR8  *FieldName;
//	    CHAR8  *FieldValue;
//	} EFI_HTTP_HEADER;
//
// FieldName and FieldValue are CHAR8 (ASCII) — RFC 7230's field-name +
// field-value byte sequences, NUL-terminated.
type EFIHTTPHeader struct {
	FieldName  uint64 // CHAR8*
	FieldValue uint64 // CHAR8*
}

// EFI_HTTP_MESSAGE (UEFI 2.10 §29.4.3):
//
//	typedef struct {
//	    union {
//	      EFI_HTTP_REQUEST_DATA   *Request;
//	      EFI_HTTP_RESPONSE_DATA  *Response;
//	    } Data;
//	    UINTN            HeaderCount;
//	    EFI_HTTP_HEADER *Headers;
//	    UINTN            BodyLength;
//	    VOID            *Body;
//	} EFI_HTTP_MESSAGE;
//
// Data union flattened to a single uint64 pointer — interpretation is
// driven by caller (request vs response context).
type EFIHTTPMessage struct {
	Data        uint64 // *EFIHTTPRequestData OR *EFIHTTPResponseData
	HeaderCount uint64 // UINTN
	Headers     uint64 // *EFIHTTPHeader
	BodyLength  uint64 // UINTN
	Body        uint64 // VOID*
}

// EFI_HTTP_TOKEN (UEFI 2.10 §29.4.3):
//
//	typedef struct {
//	    EFI_EVENT          Event;
//	    EFI_STATUS         Status;
//	    EFI_HTTP_MESSAGE  *Message;
//	} EFI_HTTP_TOKEN;
type EFIHTTPToken struct {
	Event   uint64 // EFI_EVENT (firmware handle)
	Status  uint64 // EFI_STATUS (UINTN; high-bit error marker)
	Message uint64 // *EFIHTTPMessage
}
