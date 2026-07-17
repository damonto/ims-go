// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import (
	"encoding/binary"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
)

const (
	versTCFL = 0
	// IPv6PayloadLenOffset is the offset of the PayloadLength field in
	// IPv6 header.
	IPv6PayloadLenOffset = 4
	// IPv6NextHeaderOffset is the offset of the NextHeader field in
	// IPv6 header.
	IPv6NextHeaderOffset = 6
	hopLimit             = 7
	v6SrcAddr            = 8
	v6DstAddr            = v6SrcAddr + IPv6AddressSize

	// IPv6FixedHeaderSize is the size of the fixed header.
	IPv6FixedHeaderSize = v6DstAddr + IPv6AddressSize
)

// IPv6Fields contains the fields of an IPv6 packet. It is used to describe the
// fields of a packet that needs to be encoded.
type IPv6Fields struct {
	// TrafficClass is the "traffic class" field of an IPv6 packet.
	TrafficClass uint8

	// FlowLabel is the "flow label" field of an IPv6 packet.
	FlowLabel uint32

	// PayloadLength is the "payload length" field of an IPv6 packet, including
	// the length of all extension headers.
	PayloadLength uint16

	// TransportProtocol is the transport layer protocol number. Serialized in the
	// last "next header" field of the IPv6 header + extension headers.
	TransportProtocol tcpip.TransportProtocolNumber

	// HopLimit is the "Hop Limit" field of an IPv6 packet.
	HopLimit uint8

	// SrcAddr is the "source ip address" of an IPv6 packet.
	SrcAddr tcpip.Address

	// DstAddr is the "destination ip address" of an IPv6 packet.
	DstAddr tcpip.Address

	// ExtensionHeaders are the extension headers following the IPv6 header.
	ExtensionHeaders IPv6ExtHdrSerializer
}

// IPv6 represents an ipv6 header stored in a byte array.
// Most of the methods of IPv6 access to the underlying slice without
// checking the boundaries and could panic because of 'index out of range'.
// Always call IsValid() to validate an instance of IPv6 before using other methods.
type IPv6 []byte

const (
	// IPv6MinimumSize is the minimum size of a valid IPv6 packet.
	IPv6MinimumSize = IPv6FixedHeaderSize

	// IPv6AddressSize is the size, in bytes, of an IPv6 address.
	IPv6AddressSize = 16

	// IPv6AddressSizeBits is the size, in bits, of an IPv6 address.
	IPv6AddressSizeBits = 128

	// IPv6MaximumPayloadSize is the maximum size of a valid IPv6 payload per
	// RFC 8200 Section 4.5.
	IPv6MaximumPayloadSize = 65535

	// IPv6ProtocolNumber is IPv6's network protocol number.
	IPv6ProtocolNumber tcpip.NetworkProtocolNumber = 0x86dd

	// IPv6Version is the version of the ipv6 protocol.
	IPv6Version = 6

	// IPv6MinimumMTU is the minimum MTU required by IPv6, per RFC 8200,
	// section 5:
	//   IPv6 requires that every link in the Internet have an MTU of 1280 octets
	//   or greater.  This is known as the IPv6 minimum link MTU.
	IPv6MinimumMTU = 1280

	// ipv6MulticastAddressScopeByteIdx is the byte where the scope (scop) field
	// is located within a multicast IPv6 address, as per RFC 4291 section 2.7.
	ipv6MulticastAddressScopeByteIdx = 1

	// ipv6MulticastAddressScopeMask is the mask for the scope (scop) field,
	// within the byte holding the field, as per RFC 4291 section 2.7.
	ipv6MulticastAddressScopeMask = 0xF
)

var (
	// IPv6AllNodesMulticastAddress is a link-local multicast group that
	// all IPv6 nodes MUST join, as per RFC 4291, section 2.8. Packets
	// destined to this address will reach all nodes on a link.
	//
	// The address is ff02::1.
	IPv6AllNodesMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	// IPv6AllRoutersInterfaceLocalMulticastAddress is an interface-local
	// multicast group that all IPv6 routers MUST join, as per RFC 4291, section
	// 2.8. Packets destined to this address will reach the router on an
	// interface.
	//
	// The address is ff01::2.
	IPv6AllRoutersInterfaceLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	// IPv6AllRoutersLinkLocalMulticastAddress is a link-local multicast group
	// that all IPv6 routers MUST join, as per RFC 4291, section 2.8. Packets
	// destined to this address will reach all routers on a link.
	//
	// The address is ff02::2.
	IPv6AllRoutersLinkLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	// IPv6AllRoutersSiteLocalMulticastAddress is a site-local multicast group
	// that all IPv6 routers MUST join, as per RFC 4291, section 2.8. Packets
	// destined to this address will reach all routers in a site.
	//
	// The address is ff05::2.
	IPv6AllRoutersSiteLocalMulticastAddress = tcpip.AddrFrom16([16]byte{0xff, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02})

	// IPv6Loopback is the IPv6 Loopback address.
	IPv6Loopback = tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})

	// IPv6Any is the non-routable IPv6 "any" meta address. It is also
	// known as the unspecified address.
	IPv6Any = tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
)

// IPv6EmptySubnet is the empty IPv6 subnet. It may also be known as the
// catch-all or wildcard subnet. That is, all IPv6 addresses are considered to
// be contained within this subnet.
var IPv6EmptySubnet = tcpip.AddressWithPrefix{
	Address:   IPv6Any,
	PrefixLen: 0,
}.Subnet()

// IPv4MappedIPv6Subnet is the prefix for an IPv4 mapped IPv6 address as defined
// by RFC 4291 section 2.5.5.
var IPv4MappedIPv6Subnet = tcpip.AddressWithPrefix{
	Address:   tcpip.AddrFrom16([16]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}),
	PrefixLen: 96,
}.Subnet()

// IPv6LinkLocalPrefix is the prefix for IPv6 link-local addresses, as defined
// by RFC 4291 section 2.5.6.
//
// The prefix is fe80::/64
var IPv6LinkLocalPrefix = tcpip.AddressWithPrefix{
	Address:   tcpip.AddrFrom16([16]byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
	PrefixLen: 64,
}

// PayloadLength returns the value of the "payload length" field of the ipv6
// header.
func (b IPv6) PayloadLength() uint16 {
	return binary.BigEndian.Uint16(b[IPv6PayloadLenOffset:])
}

// HopLimit returns the value of the "Hop Limit" field of the ipv6 header.
func (b IPv6) HopLimit() uint8 {
	return b[hopLimit]
}

// NextHeader returns the value of the "next header" field of the ipv6 header.
func (b IPv6) NextHeader() uint8 {
	return b[IPv6NextHeaderOffset]
}

// TransportProtocol implements Network.TransportProtocol.
//
// Deprecated: Use TryParseTransportProtocol instead.
// This function does not parse extension headers and returns the next header
// field of the IPv6 header as the transport
// protocol which may not be the actual transport protocol.
// Use TryParseTransportProtocol to get the transport protocol correctly.
func (b IPv6) TransportProtocol() tcpip.TransportProtocolNumber {
	return tcpip.TransportProtocolNumber(b.NextHeader())
}

// IsExtensionHeader returns true if the next header is a known extension header.
func IsExtensionHeader(nextHdr uint8) bool {
	extType := IPv6ExtensionHeaderIdentifier(nextHdr)
	switch extType {
	case IPv6HopByHopOptionsExtHdrIdentifier, IPv6RoutingExtHdrIdentifier, IPv6FragmentExtHdrIdentifier, IPv6DestinationOptionsExtHdrIdentifier, IPv6AuthenticationExtHdrIdentifier, IPv6NoNextHeaderIdentifier:
		return true
	default:
		return false
	}
}

// TryParseTransportProtocol parses the IPv6 header and extension headers to get the
// transport protocol.
// Reference: net/ipv6/exthdrs_core.c:ipv6_skip_exthdr.
// Returns the transport protocol and a boolean indicating if the transport
// protocol parsing was successful.
func (b IPv6) TryParseTransportProtocol() (tcpip.TransportProtocolNumber, bool) {
	if len(b) < IPv6MinimumSize {
		return 0, false
	}
	data := []byte(b[IPv6MinimumSize:])
	nxtHdr := b.NextHeader()
	maybeProto := tcpip.TransportProtocolNumber(nxtHdr)
	for IsExtensionHeader(nxtHdr) {
		dataLen := len(data)
		if dataLen < 2 {
			return maybeProto, false
		}
		currHdrLen := 0
		switch IPv6ExtensionHeaderIdentifier(nxtHdr) {
		case IPv6FragmentExtHdrIdentifier:
			// Fragment extension header is always 8 bytes long.
			if dataLen < 8 {
				return maybeProto, false
			}
			// Get the fragment offset from the fragment extension header.
			fragOffset := binary.BigEndian.Uint16(data[2:4]) & ^uint16(0x7)
			if fragOffset != 0 {
				return tcpip.TransportProtocolNumber(data[0]), false
			}
			currHdrLen = 8
		case IPv6HopByHopOptionsExtHdrIdentifier, IPv6RoutingExtHdrIdentifier, IPv6DestinationOptionsExtHdrIdentifier:
			currHdrLen = int(data[1]+1) * 8
		case IPv6AuthenticationExtHdrIdentifier:
			// Authentication extension header length calculation is different from
			// other extension headers.
			currHdrLen = int(data[1]+2) * 4
		default:
			// IPv6NoNextHeaderIdentifier or any unknown extension header.
			return maybeProto, false
		}
		if currHdrLen > len(data) {
			return maybeProto, false
		}
		nxtHdr = data[0]
		maybeProto = tcpip.TransportProtocolNumber(nxtHdr)
		data = data[currHdrLen:]
	}
	if len(data) == 0 {
		return maybeProto, false
	}
	return maybeProto, true
}

// Payload implements Network.Payload.
func (b IPv6) Payload() []byte {
	return b[IPv6MinimumSize:][:b.PayloadLength()]
}

// SourceAddress returns the "source address" field of the ipv6 header.
func (b IPv6) SourceAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(b[v6SrcAddr:][:IPv6AddressSize]))
}

// DestinationAddress returns the "destination address" field of the ipv6
// header.
func (b IPv6) DestinationAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(b[v6DstAddr:][:IPv6AddressSize]))
}

// SourceAddressSlice returns the "source address" field of the ipv6 header as a
// byte slice.
func (b IPv6) SourceAddressSlice() []byte {
	return []byte(b[v6SrcAddr:][:IPv6AddressSize])
}

// DestinationAddressSlice returns the "destination address" field of the ipv6
// header as a byte slice.
func (b IPv6) DestinationAddressSlice() []byte {
	return []byte(b[v6DstAddr:][:IPv6AddressSize])
}

// Checksum implements Network.Checksum. Given that IPv6 doesn't have a
// checksum, it just returns 0.
func (IPv6) Checksum() uint16 {
	return 0
}

// TOS returns the "traffic class" and "flow label" fields of the ipv6 header.
func (b IPv6) TOS() (uint8, uint32) {
	v := binary.BigEndian.Uint32(b[versTCFL:])
	return uint8(v >> 20), v & 0xfffff
}

// SetTOS sets the "traffic class" and "flow label" fields of the ipv6 header.
func (b IPv6) SetTOS(t uint8, l uint32) {
	vtf := (6 << 28) | (uint32(t) << 20) | (l & 0xfffff)
	binary.BigEndian.PutUint32(b[versTCFL:], vtf)
}

// SetPayloadLength sets the "payload length" field of the ipv6 header.
func (b IPv6) SetPayloadLength(payloadLength uint16) {
	binary.BigEndian.PutUint16(b[IPv6PayloadLenOffset:], payloadLength)
}

// SetSourceAddress sets the "source address" field of the ipv6 header.
func (b IPv6) SetSourceAddress(addr tcpip.Address) {
	copy(b[v6SrcAddr:][:IPv6AddressSize], addr.AsSlice())
}

// SetDestinationAddress sets the "destination address" field of the ipv6
// header.
func (b IPv6) SetDestinationAddress(addr tcpip.Address) {
	copy(b[v6DstAddr:][:IPv6AddressSize], addr.AsSlice())
}

// SetHopLimit sets the value of the "Hop Limit" field.
func (b IPv6) SetHopLimit(v uint8) {
	b[hopLimit] = v
}

// SetNextHeader sets the value of the "next header" field of the ipv6 header.
func (b IPv6) SetNextHeader(v uint8) {
	b[IPv6NextHeaderOffset] = v
}

// SetChecksum implements Network.SetChecksum. Given that IPv6 doesn't have a
// checksum, it is empty.
func (IPv6) SetChecksum(uint16) {
}

// Encode encodes all the fields of the ipv6 header.
func (b IPv6) Encode(i *IPv6Fields) {
	extHdr := b[IPv6MinimumSize:]
	b.SetTOS(i.TrafficClass, i.FlowLabel)
	b.SetPayloadLength(i.PayloadLength)
	b[hopLimit] = i.HopLimit
	b.SetSourceAddress(i.SrcAddr)
	b.SetDestinationAddress(i.DstAddr)
	nextHeader, _ := i.ExtensionHeaders.Serialize(i.TransportProtocol, extHdr)
	b[IPv6NextHeaderOffset] = nextHeader
}

// IsValid performs basic validation on the packet.
func (b IPv6) IsValid(pktSize int) bool {
	if len(b) < IPv6MinimumSize {
		return false
	}

	dlen := int(b.PayloadLength())
	if dlen > pktSize-IPv6MinimumSize {
		return false
	}

	if IPVersion(b) != IPv6Version {
		return false
	}

	return true
}

// IsV4MappedAddress determines if the provided address is an IPv4 mapped
// address by checking if its prefix is 0:0:0:0:0:ffff::/96.
func IsV4MappedAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}

	return IPv4MappedIPv6Subnet.Contains(addr)
}

// IsV6MulticastAddress determines if the provided address is an IPv6
// multicast address (anything starting with FF).
func IsV6MulticastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}
	return addr.As16()[0] == 0xff
}

// IsV6UnicastAddress determines if the provided address is a valid IPv6
// unicast (and specified) address. That is, IsV6UnicastAddress returns
// true if addr contains IPv6AddressSize bytes, is not the unspecified
// address and is not a multicast address.
func IsV6UnicastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}

	// Must not be unspecified
	if addr == IPv6Any {
		return false
	}

	// Return if not a multicast.
	return addr.As16()[0] != 0xff
}

// IsV6LinkLocalUnicastAddress returns true iff the provided address is an IPv6
// link-local unicast address, as defined by RFC 4291 section 2.5.6.
func IsV6LinkLocalUnicastAddress(addr tcpip.Address) bool {
	if addr.BitLen() != IPv6AddressSizeBits {
		return false
	}
	addrBytes := addr.As16()
	return addrBytes[0] == 0xfe && (addrBytes[1]&0xc0) == 0x80
}

// IsV6LoopbackAddress returns true iff the provided address is an IPv6 loopback
// address, as defined by RFC 4291 section 2.5.3.
func IsV6LoopbackAddress(addr tcpip.Address) bool {
	return addr == IPv6Loopback
}

// IsV6LinkLocalMulticastAddress returns true iff the provided address is an
// IPv6 link-local multicast address, as defined by RFC 4291 section 2.7.
func IsV6LinkLocalMulticastAddress(addr tcpip.Address) bool {
	return IsV6MulticastAddress(addr) && V6MulticastScope(addr) == IPv6LinkLocalMulticastScope
}

// IPv6AddressScope is the scope of an IPv6 address.
type IPv6AddressScope int

const (
	// LinkLocalScope indicates a link-local address.
	LinkLocalScope IPv6AddressScope = iota

	// GlobalScope indicates a global address.
	GlobalScope
)

// ScopeForIPv6Address returns the scope for an IPv6 address.
func ScopeForIPv6Address(addr tcpip.Address) (IPv6AddressScope, tcpip.Error) {
	if addr.BitLen() != IPv6AddressSizeBits {
		return GlobalScope, &tcpip.ErrBadAddress{}
	}

	switch {
	case IsV6LinkLocalMulticastAddress(addr):
		return LinkLocalScope, nil

	case IsV6LinkLocalUnicastAddress(addr):
		return LinkLocalScope, nil

	default:
		return GlobalScope, nil
	}
}

// IPv6MulticastScope is the scope of a multicast IPv6 address, as defined by
// RFC 7346 section 2.
type IPv6MulticastScope uint8

// The various values for IPv6 multicast scopes, as per RFC 7346 section 2:
//
//	+------+--------------------------+-------------------------+
//	| scop | NAME                     | REFERENCE               |
//	+------+--------------------------+-------------------------+
//	|  0   | Reserved                 | [RFC4291], RFC 7346     |
//	|  1   | Interface-Local scope    | [RFC4291], RFC 7346     |
//	|  2   | Link-Local scope         | [RFC4291], RFC 7346     |
//	|  3   | Realm-Local scope        | [RFC4291], RFC 7346     |
//	|  4   | Admin-Local scope        | [RFC4291], RFC 7346     |
//	|  5   | Site-Local scope         | [RFC4291], RFC 7346     |
//	|  6   | Unassigned               |                         |
//	|  7   | Unassigned               |                         |
//	|  8   | Organization-Local scope | [RFC4291], RFC 7346     |
//	|  9   | Unassigned               |                         |
//	|  A   | Unassigned               |                         |
//	|  B   | Unassigned               |                         |
//	|  C   | Unassigned               |                         |
//	|  D   | Unassigned               |                         |
//	|  E   | Global scope             | [RFC4291], RFC 7346     |
//	|  F   | Reserved                 | [RFC4291], RFC 7346     |
//	+------+--------------------------+-------------------------+
const (
	IPv6Reserved0MulticastScope         = IPv6MulticastScope(0x0)
	IPv6InterfaceLocalMulticastScope    = IPv6MulticastScope(0x1)
	IPv6LinkLocalMulticastScope         = IPv6MulticastScope(0x2)
	IPv6RealmLocalMulticastScope        = IPv6MulticastScope(0x3)
	IPv6AdminLocalMulticastScope        = IPv6MulticastScope(0x4)
	IPv6SiteLocalMulticastScope         = IPv6MulticastScope(0x5)
	IPv6OrganizationLocalMulticastScope = IPv6MulticastScope(0x8)
	IPv6GlobalMulticastScope            = IPv6MulticastScope(0xE)
	IPv6ReservedFMulticastScope         = IPv6MulticastScope(0xF)
)

// V6MulticastScope returns the scope of a multicast address.
func V6MulticastScope(addr tcpip.Address) IPv6MulticastScope {
	addrBytes := addr.As16()
	return IPv6MulticastScope(addrBytes[ipv6MulticastAddressScopeByteIdx] & ipv6MulticastAddressScopeMask)
}
