// Copyright 2026 The cloud-boot Authors.
// SPDX-License-Identifier: BSD-3-Clause
//
// DHCPv4 client (RFC 2131 + RFC 2132) for ministack.
//
// We implement the canonical four-way DORA exchange:
//
//   DISCOVER (broadcast UDP 0.0.0.0:68 → 255.255.255.255:67)
//     ← OFFER (from a DHCP server)
//   REQUEST (broadcast — RFC 2131 §3.1 client should keep using
//            255.255.255.255 until the lease is fully acquired)
//     ← ACK
//
// Wire format per RFC 2131 §2:
//
//   - 240-byte fixed BOOTP-shaped header (op, htype, hlen, hops, xid,
//     secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr[16],
//     sname[64], file[128]).
//   - 4-byte magic cookie (0x63 0x82 0x53 0x63).
//   - Variable-length options (RFC 2132). Each option is
//     [tag(1)][len(1)][value(len)]. Tag 0xFF (End) terminates.
//
// Options ministack handles:
//
//   - 53 (DHCP Message Type) — REQUIRED on every DHCP message.
//   - 50 (Requested IP)      — sent in REQUEST.
//   - 51 (Lease Time)        — extracted from ACK.
//   - 54 (Server Identifier) — extracted from OFFER, echoed in REQUEST.
//   - 55 (Parameter Request List) — sent in DISCOVER + REQUEST,
//     requesting 1 (subnet) / 3 (router) / 6 (DNS) / 51 (lease).
//   - 61 (Client Identifier) — sent as 0x01 || our MAC.
//   - 1 (Subnet Mask)        — extracted from ACK.
//   - 3 (Router)             — extracted from ACK (default gateway).
//   - 6 (DNS Server)         — extracted from ACK (up to 4 entries).
//   - 67 (Bootfile-Name)     — extracted from ACK as a UTF-8 string
//     (RFC 2132 §9.5). M9.0 carries an OCI ref here (e.g.
//     "ghcr.io/myorg/bootconfig:v1.0") for the DHCP-discovered OCI
//     boot-menu path.
//   - 255 (End)              — terminator.
//
// The xid (transaction identifier) is generated from a deterministic
// seed XOR'd with the MAC address — fine for a one-shot DHCP exchange
// in a UEFI boot context. We don't need cryptographic randomness here;
// we just need the OFFER/ACK matching to be reliable across the four
// messages of the DORA.
//
// State machine:
//
//   acquire()
//     → buildDiscover() → WriteTo(255.255.255.255:67)
//     → waitFor(OFFER, xid, deadline)
//     → buildRequest(yiaddr, serverID) → WriteTo(255.255.255.255:67)
//     → waitFor(ACK, xid, deadline)
//     → parseLease(ACK) → return DHCP4Lease
//
// On any timeout / unparseable reply / NAK we surface ErrDHCP4*
// errors. Retransmission is intentionally out of scope for M4 — boot
// runs are one-shot under QEMU; if a packet drops we fail loudly.

package ministack

import (
	"encoding/binary"
	"errors"
	"net"
	"time"
)

// DHCP4 client constants.
const (
	dhcp4ClientPort       uint16 = 68
	dhcp4ServerPort       uint16 = 67
	dhcp4HeaderLen               = 240
	dhcp4MagicCookie             = 0x63825363
	dhcp4FlagBroadcast    uint16 = 0x8000
	dhcp4BootRequest      uint8  = 1
	dhcp4BootReply        uint8  = 2
	dhcp4HTypeEthernet    uint8  = 1
	dhcp4HLenEthernet     uint8  = 6
	dhcp4OptionsBufferLen        = 312 // typical client-side option budget
)

// DHCP message type codes (RFC 2132 §9.6).
const (
	dhcp4MsgDiscover uint8 = 1
	dhcp4MsgOffer    uint8 = 2
	dhcp4MsgRequest  uint8 = 3
	dhcp4MsgDecline  uint8 = 4 //nolint:unused
	dhcp4MsgAck      uint8 = 5
	dhcp4MsgNak      uint8 = 6
)

// DHCP option codes ministack knows about.
const (
	dhcp4OptPad            uint8 = 0
	dhcp4OptSubnetMask     uint8 = 1
	dhcp4OptRouter         uint8 = 3
	dhcp4OptDNS            uint8 = 6
	dhcp4OptRequestedIP    uint8 = 50
	dhcp4OptLeaseTime      uint8 = 51
	dhcp4OptMessageType    uint8 = 53
	dhcp4OptServerID       uint8 = 54
	dhcp4OptParameterList  uint8 = 55
	dhcp4OptClientID       uint8 = 61
	dhcp4OptBootfileName   uint8 = 67
	dhcp4OptEnd            uint8 = 255
)

// Errors emitted by DHCP4Acquire.
var (
	ErrDHCP4Timeout       = errors.New("ministack: DHCP4 timed out waiting for reply")
	ErrDHCP4MissingOption = errors.New("ministack: DHCP4 response missing required option")
	ErrDHCP4UnexpectedMsg = errors.New("ministack: DHCP4 unexpected message type")
	ErrDHCP4Nak           = errors.New("ministack: DHCP4 server responded with NAK")
	ErrDHCP4BadFormat     = errors.New("ministack: DHCP4 reply malformed")
)

// DHCP4Lease describes a successful DHCPv4 acquisition. All IP /
// IPMask slices are 4-byte canonical values; DNS holds 0..4 servers
// (RFC 2132 limits option 6 to a multiple of 4 bytes; we cap at 4 to
// keep the API small).
type DHCP4Lease struct {
	IP       net.IP
	Mask     net.IPMask
	Gateway  net.IP
	DNS      []net.IP
	Server   net.IP
	Duration time.Duration

	// BootfileName is the value of DHCP option 67 (Bootfile-Name,
	// RFC 2132 §9.5) from the DHCPACK, decoded as a UTF-8 string with
	// any trailing NUL bytes trimmed. Empty when the option was not
	// present in the ACK.
	//
	// For the cloud-boot M9 "DHCP-discovered OCI boot menu" path this
	// field carries an OCI ref (e.g. "ghcr.io/myorg/bootconfig:v1.0")
	// — cloud-boot then walks the OCI distribution v2 spec to fetch
	// the HCL boot-config artifact and renders / dispatches a menu.
	BootfileName string

	// Parameter Request List members 1/3/6/51 are the only ones
	// ministack actively consumes; 67 was added in M9.0 (DHCP option
	// 67 extraction for the OCI-boot-menu path) and is requested in
	// the parameter list so RFC-compliant servers will include it
	// even when not configured as a default.
}

// dhcp4Options is a parsed option set. Each value is the raw bytes
// (independent copy) from the wire. The dispatcher only ever inspects
// options it knows about; unknowns are kept for diagnostics but never
// consulted.
type dhcp4Options map[uint8][]byte

// MarshalDHCP4Options serialises `opts` into a TLV byte stream
// terminated by option 255 (End). Order is insertion-order; for
// reproducibility tests we recommend feeding entries in a canonical
// sequence.
func marshalDHCP4Options(entries []dhcp4OptionEntry) []byte {
	out := make([]byte, 0, dhcp4OptionsBufferLen)
	for _, e := range entries {
		out = append(out, e.tag, byte(len(e.value)))
		out = append(out, e.value...)
	}
	out = append(out, dhcp4OptEnd)
	return out
}

// dhcp4OptionEntry is the input form for marshalDHCP4Options: a tag +
// the raw value bytes. Tag 255 (End) is NOT included — the marshaller
// always appends it.
type dhcp4OptionEntry struct {
	tag   uint8
	value []byte
}

// parseDHCP4Options decodes a DHCPv4 option TLV stream into a map
// keyed by tag. Padding bytes (tag 0) are skipped. Parsing stops at
// the End option (255). Returns ErrDHCP4BadFormat on truncated input.
func parseDHCP4Options(buf []byte) (dhcp4Options, error) {
	out := make(dhcp4Options)
	i := 0
	for i < len(buf) {
		tag := buf[i]
		i++
		if tag == dhcp4OptEnd {
			return out, nil
		}
		if tag == dhcp4OptPad {
			continue
		}
		if i >= len(buf) {
			return nil, ErrDHCP4BadFormat
		}
		l := int(buf[i])
		i++
		if i+l > len(buf) {
			return nil, ErrDHCP4BadFormat
		}
		v := append([]byte(nil), buf[i:i+l]...)
		out[tag] = v
		i += l
	}
	// No End option seen — accept the truncation but report what we got.
	return out, nil
}

// buildDHCP4Message composes a complete BOOTP+DHCP message (240-byte
// header + magic + options). `op` is dhcp4BootRequest for client→server.
// `mac` is exactly 6 bytes; copied into chaddr[0:6], the trailing 10
// chaddr bytes left zero. `ciaddr` is 0.0.0.0 (we don't renew leases
// in M4). The broadcast flag is set so the server uses the L2 broadcast
// in its reply rather than ARPing for our (as-yet-unassigned) IP.
func buildDHCP4Message(xid uint32, mac net.HardwareAddr, opts []byte) ([]byte, error) {
	if len(mac) != 6 {
		return nil, ErrInvalidMAC
	}
	buf := make([]byte, dhcp4HeaderLen+4+len(opts))
	buf[0] = dhcp4BootRequest
	buf[1] = dhcp4HTypeEthernet
	buf[2] = dhcp4HLenEthernet
	buf[3] = 0 // hops
	binary.BigEndian.PutUint32(buf[4:8], xid)
	binary.BigEndian.PutUint16(buf[8:10], 0) // secs
	binary.BigEndian.PutUint16(buf[10:12], dhcp4FlagBroadcast)
	// ciaddr / yiaddr / siaddr / giaddr all zero in DISCOVER/REQUEST.
	// chaddr starts at offset 28; 16 bytes wide.
	copy(buf[28:34], mac)
	// sname (64 B) at 44, file (128 B) at 108 — both left zero.
	binary.BigEndian.PutUint32(buf[236:240], dhcp4MagicCookie)
	copy(buf[240:], opts)
	return buf, nil
}

// parseDHCP4Message verifies the magic cookie + decodes the
// dhcp4Options. Returns yiaddr (the "your IP" the server assigned) +
// xid + opts. Caller validates the message type via opts[53].
func parseDHCP4Message(buf []byte) (xid uint32, yiaddr net.IP, opts dhcp4Options, err error) {
	if len(buf) < dhcp4HeaderLen+4 {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	if buf[0] != dhcp4BootReply {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	if binary.BigEndian.Uint32(buf[236:240]) != dhcp4MagicCookie {
		return 0, nil, nil, ErrDHCP4BadFormat
	}
	xid = binary.BigEndian.Uint32(buf[4:8])
	yiaddr = append(net.IP(nil), buf[16:20]...)
	opts, err = parseDHCP4Options(buf[240:])
	if err != nil {
		return 0, nil, nil, err
	}
	return xid, yiaddr, opts, nil
}

// dhcp4ClientIDFromMAC encodes a MAC as DHCP option 61's value: a
// single type byte (0x01 = Ethernet) followed by the 6-byte MAC.
func dhcp4ClientIDFromMAC(mac net.HardwareAddr) []byte {
	out := make([]byte, 1+6)
	out[0] = 0x01
	copy(out[1:], mac)
	return out
}

// dhcp4ParameterRequestList is the option-55 value: a list of option
// codes the client wants the server to include in its OFFER/ACK. The
// Bootfile-Name (option 67) was added in M9.0 to enable the
// DHCP-discovered OCI boot-menu path — RFC 2131 §3.5 requires a
// compliant server to honour a Parameter Request List entry, so
// servers configured with `bootfile-name` (ISC dhcpd) or QEMU's
// `-netdev user,bootfile=...` will include it in the ACK.
func dhcp4ParameterRequestList() []byte {
	return []byte{
		dhcp4OptSubnetMask,
		dhcp4OptRouter,
		dhcp4OptDNS,
		dhcp4OptLeaseTime,
		dhcp4OptBootfileName,
	}
}

// dhcp4XIDFromMAC produces a 32-bit transaction ID from the MAC + a
// 32-bit nonce. Deterministic so tests can pin xid generation.
func dhcp4XIDFromMAC(mac net.HardwareAddr, seed uint32) uint32 {
	if len(mac) < 6 {
		return seed
	}
	macHi := binary.BigEndian.Uint32(append([]byte{0, 0}, mac[0:2]...))
	macLo := binary.BigEndian.Uint32(mac[2:6])
	return seed ^ macLo ^ macHi
}

// parseDHCP4MessageType returns the DHCP message type byte stamped in
// option 53. Returns ErrDHCP4MissingOption if not present, or
// ErrDHCP4BadFormat if the option value isn't exactly 1 byte.
func parseDHCP4MessageType(opts dhcp4Options) (uint8, error) {
	v, ok := opts[dhcp4OptMessageType]
	if !ok {
		return 0, ErrDHCP4MissingOption
	}
	if len(v) != 1 {
		return 0, ErrDHCP4BadFormat
	}
	return v[0], nil
}

// dhcp4LeaseFromOptions extracts the addresses + duration from an ACK
// option block + yiaddr. Missing options yield zero values; an absent
// option 51 (lease time) is tolerated (we map it to 0). The DNS option
// is capped at 4 servers.
func dhcp4LeaseFromOptions(yiaddr net.IP, opts dhcp4Options) DHCP4Lease {
	lease := DHCP4Lease{IP: append(net.IP(nil), yiaddr...)}
	if m, ok := opts[dhcp4OptSubnetMask]; ok && len(m) == 4 {
		lease.Mask = net.IPMask(append([]byte(nil), m...))
	}
	if r, ok := opts[dhcp4OptRouter]; ok && len(r) >= 4 {
		lease.Gateway = append(net.IP(nil), r[0:4]...)
	}
	if d, ok := opts[dhcp4OptDNS]; ok {
		// Each DNS entry is 4 bytes; floor-divide to skip any
		// trailing partial entry (shouldn't happen but defensively
		// handle).
		n := len(d) / 4
		if n > 4 {
			n = 4
		}
		for i := 0; i < n; i++ {
			lease.DNS = append(lease.DNS, append(net.IP(nil), d[i*4:i*4+4]...))
		}
	}
	if s, ok := opts[dhcp4OptServerID]; ok && len(s) == 4 {
		lease.Server = append(net.IP(nil), s...)
	}
	if l, ok := opts[dhcp4OptLeaseTime]; ok && len(l) == 4 {
		secs := binary.BigEndian.Uint32(l)
		lease.Duration = time.Duration(secs) * time.Second
	}
	if bf, ok := opts[dhcp4OptBootfileName]; ok {
		// Per RFC 2132 §9.5 the option value is a sequence of bytes
		// representing the file name. Some servers (notably ISC dhcpd
		// when the value is set via a string literal) trail a NUL
		// terminator to fill the 128-byte sname/file BOOTP field;
		// strip any trailing NULs so the OCI ref parser sees a clean
		// UTF-8 string.
		end := len(bf)
		for end > 0 && bf[end-1] == 0 {
			end--
		}
		lease.BootfileName = string(bf[:end])
	}
	return lease
}

// dhcp4XIDSeedDefault is the seed we mix with the MAC for the xid when
// the caller doesn't override (i.e. always, in M4 — tests override it
// via the internal acquire helper).
const dhcp4XIDSeedDefault uint32 = 0x4E45_5453 // "NETS"

// DHCP4Acquire runs a complete DHCPv4 DORA exchange and returns the
// resulting lease. `timeout` is the total wall-clock cap on the whole
// exchange. Caller is responsible for applying the lease back to the
// Stack (SetIPv4Address + SetDefaultGateway).
func (s *Stack) DHCP4Acquire(timeout time.Duration) (DHCP4Lease, error) {
	return s.dhcp4Acquire(timeout, dhcp4XIDSeedDefault)
}

// dhcp4Acquire is the internal worker — exposed only to the tests so
// they can pin the xid seed for deterministic packet bytes.
func (s *Stack) dhcp4Acquire(timeout time.Duration, xidSeed uint32) (DHCP4Lease, error) {
	mac := s.link.MAC()
	xid := dhcp4XIDFromMAC(mac, xidSeed)

	conn, err := s.OpenUDP4(dhcp4ClientPort)
	if err != nil {
		return DHCP4Lease{}, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	bcast := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: int(dhcp4ServerPort)}

	// --- DISCOVER -------------------------------------------------
	discoverOpts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgDiscover}},
		{tag: dhcp4OptClientID, value: dhcp4ClientIDFromMAC(mac)},
		{tag: dhcp4OptParameterList, value: dhcp4ParameterRequestList()},
	})
	discoverMsg, err := buildDHCP4Message(xid, mac, discoverOpts)
	if err != nil {
		return DHCP4Lease{}, err
	}
	if err := conn.WriteTo(discoverMsg, bcast); err != nil {
		return DHCP4Lease{}, err
	}

	// --- WAIT FOR OFFER -------------------------------------------
	offerYIAddr, offerOpts, err := dhcp4WaitFor(conn, xid, dhcp4MsgOffer, deadline)
	if err != nil {
		return DHCP4Lease{}, err
	}
	serverID, ok := offerOpts[dhcp4OptServerID]
	if !ok || len(serverID) != 4 {
		return DHCP4Lease{}, ErrDHCP4MissingOption
	}

	// --- REQUEST --------------------------------------------------
	requestOpts := marshalDHCP4Options([]dhcp4OptionEntry{
		{tag: dhcp4OptMessageType, value: []byte{dhcp4MsgRequest}},
		{tag: dhcp4OptClientID, value: dhcp4ClientIDFromMAC(mac)},
		{tag: dhcp4OptRequestedIP, value: append([]byte(nil), offerYIAddr[0:4]...)},
		{tag: dhcp4OptServerID, value: append([]byte(nil), serverID...)},
		{tag: dhcp4OptParameterList, value: dhcp4ParameterRequestList()},
	})
	requestMsg, err := buildDHCP4Message(xid, mac, requestOpts)
	if err != nil {
		return DHCP4Lease{}, err
	}
	if err := conn.WriteTo(requestMsg, bcast); err != nil {
		return DHCP4Lease{}, err
	}

	// --- WAIT FOR ACK ---------------------------------------------
	ackYIAddr, ackOpts, err := dhcp4WaitFor(conn, xid, dhcp4MsgAck, deadline)
	if err != nil {
		return DHCP4Lease{}, err
	}
	return dhcp4LeaseFromOptions(ackYIAddr, ackOpts), nil
}

// dhcp4WaitFor blocks (subject to deadline) until a DHCP message of
// the wantType for our xid arrives, or the deadline elapses. Messages
// whose xid doesn't match, or whose type isn't OFFER/ACK/NAK, are
// silently consumed and the loop continues. A NAK matching our xid
// returns ErrDHCP4Nak.
func dhcp4WaitFor(conn *UDP4Conn, wantXID uint32, wantType uint8, deadline time.Time) (net.IP, dhcp4Options, error) {
	// Compute timeout once. The deadlineChecker honors both wall-clock
	// (host) and iter-count (tamago) caps, same pattern as resolveARP
	// / PingOnce / UDP4Conn.ReadFrom.
	timeout := time.Until(deadline)
	if timeout <= 0 {
		timeout = 1 * time.Second
	}
	outer := newDeadlineChecker(timeout)
	buf := make([]byte, 1500)
	for !outer.expired() {
		outer.tick()
		conn.SetReadDeadline(deadline)
		n, _, err := conn.ReadFrom(buf)
		if err == ErrUDP4ReadTimeout {
			return nil, nil, ErrDHCP4Timeout
		}
		if err != nil {
			return nil, nil, err
		}
		gotXID, gotYI, gotOpts, err := parseDHCP4Message(buf[:n])
		if err != nil {
			// Malformed reply: ignore and continue. A real
			// DHCP server on QEMU never sends garbage; this is
			// defensive against the very-improbable case where
			// we receive stray UDP/68 traffic from elsewhere.
			continue
		}
		if gotXID != wantXID {
			continue
		}
		mtype, err := parseDHCP4MessageType(gotOpts)
		if err != nil {
			continue
		}
		switch mtype {
		case wantType:
			return gotYI, gotOpts, nil
		case dhcp4MsgNak:
			return nil, nil, ErrDHCP4Nak
		default:
			// Wrong type (e.g. an unexpected duplicate
			// OFFER while we were waiting for ACK).
			continue
		}
	}
	return nil, nil, ErrDHCP4Timeout
}
