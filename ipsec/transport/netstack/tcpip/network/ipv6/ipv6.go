// Copyright 2020 The gVisor Authors.
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

// Package ipv6 contains the implementation of the ipv6 network protocol.
package ipv6

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"sync/atomic"
	"time"

	"sync"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header/parse"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/network/fragmentation"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/network/ip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

const (
	// ReassembleTimeout controls how long a fragment will be held.
	// As per RFC 8200 section 4.5:
	//
	//   If insufficient fragments are received to complete reassembly of a packet
	//   within 60 seconds of the reception of the first-arriving fragment of that
	//   packet, reassembly of that packet must be abandoned.
	//
	// Linux also uses 60 seconds for reassembly timeout:
	// https://github.com/torvalds/linux/blob/47ec5303d73ea344e84f46660fff693c57641386/include/net/ipv6.h#L456
	ReassembleTimeout = 60 * time.Second

	// ProtocolNumber is the ipv6 protocol number.
	ProtocolNumber = header.IPv6ProtocolNumber

	// maxPayloadSize is the maximum size that can be encoded in the 16-bit
	// PayloadLength field of the ipv6 header.
	maxPayloadSize = 0xffff

	// DefaultTTL is the default hop limit for IPv6 Packets egressed by
	// Netstack.
	DefaultTTL = 64
)

const (
	forwardingDisabled = 0
	forwardingEnabled  = 1
)

// policyTable is the default policy table defined in RFC 6724 section 2.1.
//
// A more human-readable version:
//
//	Prefix        Precedence Label
//	::1/128               50     0
//	::/0                  40     1
//	::ffff:0:0/96         35     4
//	2002::/16             30     2
//	2001::/32              5     5
//	fc00::/7               3    13
//	::/96                  1     3
//	fec0::/10              1    11
//	3ffe::/16              1    12
//
// The table is sorted by prefix length so longest-prefix match can be easily
// achieved.
//
// We willingly left out ::/96, fec0::/10 and 3ffe::/16 since those prefix
// assignments are deprecated.
//
// As per RFC 4291 section 2.5.5.1 (for ::/96),
//
//	The "IPv4-Compatible IPv6 address" is now deprecated because the
//	current IPv6 transition mechanisms no longer use these addresses.
//	New or updated implementations are not required to support this
//	address type.
//
// As per RFC 3879 section 4 (for fec0::/10),
//
//	This document formally deprecates the IPv6 site-local unicast prefix
//	defined in [RFC3513], i.e., 1111111011 binary or FEC0::/10.
//
// As per RFC 3701 section 1 (for 3ffe::/16),
//
//	As clearly stated in [TEST-NEW], the addresses for the 6bone are
//	temporary and will be reclaimed in the future. It further states
//	that all users of these addresses (within the 3FFE::/16 prefix) will
//	be required to renumber at some time in the future.
//
// and section 2,
//
//	Thus after the pTLA allocation cutoff date January 1, 2004, it is
//	REQUIRED that no new 6bone 3FFE pTLAs be allocated.
//
// MUST NOT BE MODIFIED.
var policyTable = [...]struct {
	subnet tcpip.Subnet

	label uint8
}{
	// ::1/128
	{
		subnet: header.IPv6Loopback.WithPrefix().Subnet(),
		label:  0,
	},
	// ::ffff:0:0/96
	{
		subnet: header.IPv4MappedIPv6Subnet,
		label:  4,
	},
	// 2001::/32 (Teredo prefix as per RFC 4380 section 2.6).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 32,
		}.Subnet(),
		label: 5,
	},
	// 2002::/16 (6to4 prefix as per RFC 3056 section 2).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 16,
		}.Subnet(),
		label: 2,
	},
	// fc00::/7 (Unique local addresses as per RFC 4193 section 3.1).
	{
		subnet: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom16([16]byte{0xfc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			PrefixLen: 7,
		}.Subnet(),
		label: 13,
	},
	// ::/0
	{
		subnet: header.IPv6EmptySubnet,
		label:  1,
	},
}

func getLabel(addr tcpip.Address) uint8 {
	for _, p := range policyTable {
		if p.subnet.Contains(addr) {
			return p.label
		}
	}

	panic(fmt.Sprintf("should have a label for address = %s", addr))
}

var _ stack.ForwardingNetworkEndpoint = (*endpoint)(nil)
var _ stack.AddressableEndpoint = (*endpoint)(nil)
var _ stack.NetworkEndpoint = (*endpoint)(nil)

type endpointMu struct {
	sync.RWMutex

	addressableEndpointState stack.AddressableEndpointState
}

type endpoint struct {
	nic        stack.NetworkInterface
	dispatcher stack.TransportDispatcher
	protocol   *protocol
	stats      sharedStats

	// enabled is set to 1 when the endpoint is enabled and 0 when it is
	// disabled.
	enabled atomic.Uint32

	// forwarding is set to forwardingEnabled when the endpoint has forwarding
	// enabled and forwardingDisabled when it is disabled.
	forwarding atomic.Uint32

	mu endpointMu
}

// Forwarding implements stack.ForwardingNetworkEndpoint.
func (e *endpoint) Forwarding() bool {
	return e.forwarding.Load() == forwardingEnabled
}

// setForwarding sets the forwarding status for the endpoint.
//
// Returns the previous forwarding status.
func (e *endpoint) setForwarding(v bool) bool {
	forwarding := uint32(forwardingDisabled)
	if v {
		forwarding = forwardingEnabled
	}

	return e.forwarding.Swap(forwarding) != forwardingDisabled
}

// SetForwarding implements stack.ForwardingNetworkEndpoint.
func (e *endpoint) SetForwarding(forwarding bool) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.setForwarding(forwarding)
}

// Enable implements stack.NetworkEndpoint.
func (e *endpoint) Enable() tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.nic.Enabled() {
		return &tcpip.ErrNotPermitted{}
	}
	if !e.setEnabled(true) {
		return nil
	}
	e.mu.addressableEndpointState.OnNetworkEndpointEnabledChanged()
	return nil
}

// Enabled implements stack.NetworkEndpoint.
func (e *endpoint) Enabled() bool {
	return e.nic.Enabled() && e.isEnabled()
}

// isEnabled returns true if the endpoint is enabled, regardless of the
// enabled status of the NIC.
func (e *endpoint) isEnabled() bool {
	return e.enabled.Load() == 1
}

// setEnabled sets the enabled status for the endpoint.
//
// Returns true if the enabled status was updated.
func (e *endpoint) setEnabled(v bool) bool {
	if v {
		return e.enabled.Swap(1) == 0
	}
	return e.enabled.Swap(0) == 1
}

// Disable implements stack.NetworkEndpoint.
func (e *endpoint) Disable() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.disableLocked()
}

func (e *endpoint) disableLocked() {
	if !e.Enabled() {
		return
	}
	if !e.setEnabled(false) {
		panic("should have only done work to disable the endpoint if it was enabled")
	}
	e.mu.addressableEndpointState.OnNetworkEndpointEnabledChanged()
}

// DefaultTTL is the default hop limit for this endpoint.
func (e *endpoint) DefaultTTL() uint8 {
	return e.protocol.DefaultTTL()
}

// MTU implements stack.NetworkEndpoint. It returns the link-layer MTU minus the
// network layer max header length.
func (e *endpoint) MTU() uint32 {
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), header.IPv6MinimumSize)
	if err != nil {
		return 0
	}
	return networkMTU
}

// EndpointHeaderSize returns the size necessary for the IPv6 header.
func (e *endpoint) EndpointHeaderSize() uint32 {
	return header.IPv6MinimumSize
}

// MaxHeaderLength returns the maximum length needed by ipv6 headers (and
// underlying protocols).
func (e *endpoint) MaxHeaderLength() uint16 {
	// TODO(gvisor.dev/issues/5035): The maximum header length returned here does
	// not open the possibility for the caller to know about size required for
	// extension headers.
	return e.nic.MaxHeaderLength() + header.IPv6MinimumSize
}

func addIPHeader(srcAddr, dstAddr tcpip.Address, pkt *stack.PacketBuffer, params stack.NetworkHeaderParams, extensionHeaders header.IPv6ExtHdrSerializer) tcpip.Error {
	if params.ExperimentOptionValue != 0 {
		extensionHeaders = append(extensionHeaders, &header.IPv6ExperimentExtHdr{Value: params.ExperimentOptionValue})
	}
	extHdrsLen := extensionHeaders.Length()
	length := pkt.Size() + extensionHeaders.Length()
	if length > math.MaxUint16 {
		return &tcpip.ErrMessageTooLong{}
	}
	header.IPv6(pkt.NetworkHeader().Push(header.IPv6MinimumSize + extHdrsLen)).Encode(&header.IPv6Fields{
		PayloadLength:     uint16(length),
		TransportProtocol: params.Protocol,
		HopLimit:          params.TTL,
		TrafficClass:      params.TOS,
		SrcAddr:           srcAddr,
		DstAddr:           dstAddr,
		ExtensionHeaders:  extensionHeaders,
	})
	pkt.NetworkProtocolNumber = ProtocolNumber
	return nil
}

func packetMustBeFragmented(pkt *stack.PacketBuffer, networkMTU uint32) bool {
	payload := len(pkt.TransportHeader().Slice()) + pkt.Data().Size()
	return pkt.GSOOptions.Type == stack.GSONone && uint32(payload) > networkMTU
}

// handleFragments fragments pkt and calls the handler function on each
// fragment. It returns the number of fragments handled and the number of
// fragments left to be processed. The IP header must already be present in the
// original packet. The transport header protocol number is required to avoid
// parsing the IPv6 extension headers.
func (e *endpoint) handleFragments(networkMTU uint32, pkt *stack.PacketBuffer, transProto tcpip.TransportProtocolNumber, handler func(*stack.PacketBuffer) tcpip.Error) (int, int, tcpip.Error) {
	networkHeader := header.IPv6(pkt.NetworkHeader().Slice())

	// TODO(gvisor.dev/issue/3912): Once the Authentication or ESP Headers are
	// supported for outbound packets, their length should not affect the fragment
	// maximum payload length because they should only be transmitted once.
	fragmentPayloadLen := (networkMTU - header.IPv6FragmentHeaderSize) &^ 7
	if fragmentPayloadLen < header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit {
		// We need at least 8 bytes of space left for the fragmentable part because
		// the fragment payload must obviously be non-zero and must be a multiple
		// of 8 as per RFC 8200 section 4.5:
		//   Each complete fragment, except possibly the last ("rightmost") one, is
		//   an integer multiple of 8 octets long.
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	if fragmentPayloadLen < uint32(len(pkt.TransportHeader().Slice())) {
		// As per RFC 8200 Section 4.5, the Transport Header is expected to be small
		// enough to fit in the first fragment.
		return 0, 1, &tcpip.ErrMessageTooLong{}
	}

	pf := fragmentation.MakePacketFragmenter(pkt, fragmentPayloadLen, calculateFragmentReserve(pkt))
	defer pf.Release()
	id := e.getFragmentID()

	var n int
	for {
		fragPkt, more := buildNextFragment(&pf, networkHeader, transProto, id)
		err := handler(fragPkt)
		fragPkt.DecRef()
		if err != nil {
			return n, pf.RemainingFragmentCount() + 1, err
		}
		n++
		if !more {
			return n, pf.RemainingFragmentCount(), nil
		}
	}
}

// WritePacket writes a packet to the given destination address and protocol.
func (e *endpoint) WritePacket(r *stack.Route, params stack.NetworkHeaderParams, pkt *stack.PacketBuffer) tcpip.Error {
	dstAddr := r.RemoteAddress()
	if err := addIPHeader(r.LocalAddress(), dstAddr, pkt, params, nil /* extensionHeaders */); err != nil {
		return err
	}

	return e.writePacket(r, pkt, params.Protocol, false /* headerIncluded */)
}

func (e *endpoint) writePacket(r *stack.Route, pkt *stack.PacketBuffer, protocol tcpip.TransportProtocolNumber, headerIncluded bool) tcpip.Error {
	if r.Loop()&stack.PacketLoop != 0 {
		// If the packet was generated by the stack (not a raw/packet endpoint
		// where a packet may be written with the header included), then we can
		// safely assume the checksum is valid.
		e.handleLocalPacket(pkt, !headerIncluded /* canSkipRXChecksum */)
	}
	if r.Loop()&stack.PacketOut == 0 {
		return nil
	}

	stats := e.stats.ip
	networkMTU, err := calculateNetworkMTU(e.nic.MTU(), uint32(len(pkt.NetworkHeader().Slice())))
	if err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	if packetMustBeFragmented(pkt, networkMTU) {
		if pkt.NetworkPacketInfo.IsForwardedPacket {
			// As per RFC 2460, section 4.5:
			//   Unlike IPv4, fragmentation in IPv6 is performed only by source nodes,
			//   not by routers along a packet's delivery path.
			return &tcpip.ErrMessageTooLong{}
		}
		sent, remain, err := e.handleFragments(networkMTU, pkt, protocol, func(fragPkt *stack.PacketBuffer) tcpip.Error {
			// TODO(gvisor.dev/issue/3884): Evaluate whether we want to send each
			// fragment one by one using WritePacket() (current strategy) or if we
			// want to create a PacketBufferList from the fragments and feed it to
			// WritePackets(). It'll be faster but cost more memory.
			return e.nic.WritePacket(r, fragPkt)
		})
		stats.PacketsSent.IncrementBy(uint64(sent))
		stats.OutgoingPacketErrors.IncrementBy(uint64(remain))
		return err
	}

	if err := e.nic.WritePacket(r, pkt); err != nil {
		stats.OutgoingPacketErrors.Increment()
		return err
	}

	stats.PacketsSent.Increment()
	return nil
}

// WriteHeaderIncludedPacket implements stack.NetworkEndpoint.
func (e *endpoint) WriteHeaderIncludedPacket(r *stack.Route, pkt *stack.PacketBuffer) tcpip.Error {
	// The packet already has an IP header, but there are a few required checks.
	h, ok := pkt.Data().PullUp(header.IPv6MinimumSize)
	if !ok {
		return &tcpip.ErrMalformedHeader{}
	}
	ipH := header.IPv6(h)

	// Always set the payload length.
	pktSize := pkt.Data().Size()
	ipH.SetPayloadLength(uint16(pktSize - header.IPv6MinimumSize))

	// Set the source address when zero.
	if ipH.SourceAddress() == header.IPv6Any {
		ipH.SetSourceAddress(r.LocalAddress())
	}

	// Populate the packet buffer's network header and don't allow an invalid
	// packet to be sent.
	//
	// Note that parsing only makes sure that the packet is well formed as per the
	// wire format. We also want to check if the header's fields are valid before
	// sending the packet.
	proto, _, _, _, ok := parse.IPv6(pkt)
	if !ok || !header.IPv6(pkt.NetworkHeader().Slice()).IsValid(pktSize) {
		return &tcpip.ErrMalformedHeader{}
	}

	return e.writePacket(r, pkt, proto, true /* headerIncluded */)
}

func validateAddressesForForwarding(h header.IPv6) ip.ForwardingError {
	srcAddr := h.SourceAddress()

	// As per RFC 4291 section 2.5.2,
	//
	//   The address 0:0:0:0:0:0:0:0 is called the unspecified address. It
	//   must never be assigned to any node. It indicates the absence of an
	//   address. One example of its use is in the Source Address field of
	//   any IPv6 packets sent by an initializing host before it has learned
	//   its own address.
	//
	//   The unspecified address must not be used as the destination address
	//   of IPv6 packets or in IPv6 Routing headers. An IPv6 packet with a
	//   source address of unspecified must never be forwarded by an IPv6
	//   router.
	if srcAddr.Unspecified() {
		return &ip.ErrInitializingSourceAddress{}
	}

	// As per RFC 4291 section 2.5.6,
	//
	//   Routers must not forward any packets with Link-Local source or
	//   destination addresses to other links.
	if header.IsV6LinkLocalUnicastAddress(srcAddr) {
		return &ip.ErrLinkLocalSourceAddress{}
	}

	if dstAddr := h.DestinationAddress(); header.IsV6LinkLocalUnicastAddress(dstAddr) || header.IsV6LinkLocalMulticastAddress(dstAddr) {
		return &ip.ErrLinkLocalDestinationAddress{}
	}
	return nil
}

// forwardUnicastPacket attempts to forward a unicast packet to its final
// destination.
func (e *endpoint) forwardUnicastPacket(pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv6(pkt.NetworkHeader().Slice())

	if err := validateAddressesForForwarding(h); err != nil {
		return err
	}

	hopLimit := h.HopLimit()
	if hopLimit <= 1 {
		// As per RFC 4443 section 3.3,
		//
		//   If a router receives a packet with a Hop Limit of zero, or if a
		//   router decrements a packet's Hop Limit to zero, it MUST discard the
		//   packet and originate an ICMPv6 Time Exceeded message with Code 0 to
		//   the source of the packet.  This indicates either a routing loop or
		//   too small an initial Hop Limit value.
		//
		// We return the original error rather than the result of returning
		// the ICMP packet because the original error is more relevant to
		// the caller.
		return &ip.ErrTTLExceeded{}
	}

	stk := e.protocol.stack

	dstAddr := h.DestinationAddress()

	// Check if the destination is owned by the stack.
	if ep := e.protocol.findEndpointWithAddress(dstAddr); ep != nil {
		// The packet originally arrived on e so provide its NIC as the input NIC.
		ep.handleValidatedPacket(h, pkt)
		return nil
	}

	// Check extension headers for any errors requiring action during forwarding.
	if err := e.processExtensionHeaders(h, pkt, true /* forwarding */); err != nil {
		return &ip.ErrParameterProblem{}
	}

	r, err := stk.FindRoute(0, tcpip.Address{}, dstAddr, ProtocolNumber, false /* multicastLoop */)
	switch err.(type) {
	case nil:
	case *tcpip.ErrNetworkUnreachable:
		// We return the original error rather than the result of returning the
		// ICMP packet because the original error is more relevant to the caller.
		return &ip.ErrHostUnreachable{}
	default:
		return &ip.ErrOther{Err: err}
	}
	defer r.Release()

	return e.forwardPacketWithRoute(r, pkt)
}

// forwardPacketWithRoute emits the pkt using the provided route.
//
// This method should be invoked by the endpoint that received the pkt.
func (e *endpoint) forwardPacketWithRoute(route *stack.Route, pkt *stack.PacketBuffer) ip.ForwardingError {
	h := header.IPv6(pkt.NetworkHeader().Slice())
	hopLimit := h.HopLimit()

	// We need to do a deep copy of the IP packet because
	// WriteHeaderIncludedPacket takes ownership of the packet buffer, but we do
	// not own it.
	newPkt := pkt.DeepCopyForForwarding(int(route.MaxHeaderLength()))
	defer newPkt.DecRef()
	newHdr := header.IPv6(newPkt.NetworkHeader().Slice())

	// As per RFC 8200 section 3,
	//
	//   Hop Limit           8-bit unsigned integer. Decremented by 1 by
	//                       each node that forwards the packet.
	newHdr.SetHopLimit(hopLimit - 1)

	if route.RequiresTXTransportChecksum() {
		newPkt.CalculateTransportChecksum()
	}

	forwardToEp, ok := e.protocol.getEndpointForNIC(route.NICID())
	if !ok {
		// The interface was removed after we obtained the route.
		return &ip.ErrUnknownOutputEndpoint{}
	}

	switch err := forwardToEp.writePacket(route, newPkt, newPkt.TransportProtocolNumber, true /* headerIncluded */); err.(type) {
	case nil:
		return nil
	case *tcpip.ErrMessageTooLong:
		// As per RFC 4443, section 3.2:
		//   A Packet Too Big MUST be sent by a router in response to a packet that
		//   it cannot forward because the packet is larger than the MTU of the
		//   outgoing link.
		return &ip.ErrMessageTooLong{}
	case *tcpip.ErrNoBufferSpace:
		return &ip.ErrOutgoingDeviceNoBufferSpace{}
	default:
		return &ip.ErrOther{Err: err}
	}
}

// HandlePacket is called by the link layer when new ipv6 packets arrive for
// this endpoint.
func (e *endpoint) HandlePacket(pkt *stack.PacketBuffer) {
	stats := e.stats.ip

	stats.PacketsReceived.Increment()

	if !e.isEnabled() {
		stats.DisabledPacketsReceived.Increment()
		return
	}

	hView, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}
	defer hView.Release()
	h := header.IPv6(hView.AsSlice())

	if !checkV4Mapped(h, stats) {
		return
	}

	if !e.nic.IsLoopback() {
		if !e.protocol.options.AllowExternalLoopbackTraffic {
			if header.IsV6LoopbackAddress(h.SourceAddress()) {
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}

			if header.IsV6LoopbackAddress(h.DestinationAddress()) {
				stats.InvalidDestinationAddressesReceived.Increment()
				return
			}
		}

		stk := e.protocol.stack
		if stk.HandleLocal() {
			addressEndpoint := e.AcquireAssignedAddress(header.IPv6(pkt.NetworkHeader().Slice()).SourceAddress(), e.nic.Promiscuous(), stack.CanBePrimaryEndpoint, true /* readOnly */)
			if addressEndpoint != nil {
				// The source address is one of our own, so we never should have gotten
				// a packet like this unless HandleLocal is false or our NIC is the
				// loopback interface.
				stats.InvalidSourceAddressesReceived.Increment()
				return
			}
		}

	}
	e.handleValidatedPacket(h, pkt)
}

// handleLocalPacket handles a packet generated by this stack.
func (e *endpoint) handleLocalPacket(pkt *stack.PacketBuffer, canSkipRXChecksum bool) {
	stats := e.stats.ip
	stats.PacketsReceived.Increment()

	pkt = pkt.CloneToInbound()
	defer pkt.DecRef()
	pkt.RXChecksumValidated = canSkipRXChecksum

	hView, ok := e.protocol.parseAndValidate(pkt)
	if !ok {
		stats.MalformedPacketsReceived.Increment()
		return
	}
	defer hView.Release()
	h := header.IPv6(hView.AsSlice())

	if !checkV4Mapped(h, stats) {
		return
	}

	e.handleValidatedPacket(h, pkt)
}

func (e *endpoint) handleForwardingError(err ip.ForwardingError) {
	stats := e.stats.ip
	switch err := err.(type) {
	case nil:
		return
	case *ip.ErrInitializingSourceAddress:
		stats.Forwarding.InitializingSource.Increment()
	case *ip.ErrLinkLocalSourceAddress:
		stats.Forwarding.LinkLocalSource.Increment()
	case *ip.ErrLinkLocalDestinationAddress:
		stats.Forwarding.LinkLocalDestination.Increment()
	case *ip.ErrTTLExceeded:
		stats.Forwarding.ExhaustedTTL.Increment()
	case *ip.ErrHostUnreachable:
		stats.Forwarding.Unrouteable.Increment()
	case *ip.ErrParameterProblem:
		stats.Forwarding.ExtensionHeaderProblem.Increment()
	case *ip.ErrMessageTooLong:
		stats.Forwarding.PacketTooBig.Increment()
	case *ip.ErrNoMulticastPendingQueueBufferSpace:
		stats.Forwarding.NoMulticastPendingQueueBufferSpace.Increment()
	case *ip.ErrUnexpectedMulticastInputInterface:
		stats.Forwarding.UnexpectedMulticastInputInterface.Increment()
	case *ip.ErrUnknownOutputEndpoint:
		stats.Forwarding.UnknownOutputEndpoint.Increment()
	case *ip.ErrOutgoingDeviceNoBufferSpace:
		stats.Forwarding.OutgoingDeviceNoBufferSpace.Increment()
	case *ip.ErrOther:
		switch err := err.Err.(type) {
		case *tcpip.ErrClosedForSend:
			stats.Forwarding.OutgoingDeviceClosedForSend.Increment()
		default:
			panic(fmt.Sprintf("unrecognized tcpip forwarding error: %s", err))
		}
	default:
		panic(fmt.Sprintf("unrecognized forwarding error: %s", err))
	}
	stats.Forwarding.Errors.Increment()
}

func (e *endpoint) handleValidatedPacket(h header.IPv6, pkt *stack.PacketBuffer) {
	pkt.NICID = e.nic.ID()

	// Raw socket packets are delivered based solely on the transport protocol
	// number. We only require that the packet be valid IPv6.

	stats := e.stats.ip
	stats.ValidPacketsReceived.Increment()

	srcAddr := h.SourceAddress()
	dstAddr := h.DestinationAddress()

	// As per RFC 4291 section 2.7:
	//   Multicast addresses must not be used as source addresses in IPv6
	//   packets or appear in any Routing header.
	if header.IsV6MulticastAddress(srcAddr) {
		stats.InvalidSourceAddressesReceived.Increment()
		return
	}

	if header.IsV6MulticastAddress(dstAddr) {
		stats.InvalidDestinationAddressesReceived.Increment()
		return
	}

	// The destination address should be an address we own for us to receive the
	// packet. Otherwise, attempt to forward the packet.
	if addressEndpoint := e.AcquireAssignedAddress(dstAddr, e.nic.Promiscuous(), stack.CanBePrimaryEndpoint, true /* readOnly */); addressEndpoint != nil {
		e.deliverPacketLocally(h, pkt)
	} else if e.Forwarding() {
		e.handleForwardingError(e.forwardUnicastPacket(pkt))
	} else {
		stats.InvalidDestinationAddressesReceived.Increment()
	}
}

func (e *endpoint) deliverPacketLocally(h header.IPv6, pkt *stack.PacketBuffer) {
	// Any returned error is only useful for terminating execution early, but
	// we have nothing left to do, so we can drop it.
	_ = e.processExtensionHeaders(h, pkt, false /* forwarding */)
}

func (e *endpoint) processExtensionHeader(it *header.IPv6PayloadIterator, pkt **stack.PacketBuffer, h header.IPv6, routerAlert **header.IPv6RouterAlertOption, hasFragmentHeader *bool, forwarding bool) (bool, error) {
	stats := e.stats.ip
	dstAddr := h.DestinationAddress()
	// Keep track of the start of the previous header so we can report the
	// special case of a Hop by Hop at a location other than at the start.
	previousHeaderStart := it.HeaderOffset()
	extHdr, done, err := it.Next()
	if err != nil {
		stats.MalformedPacketsReceived.Increment()
		return true, err
	}
	if done {
		return true, nil
	}
	defer extHdr.Release()

	// As per RFC 8200, section 4:
	//
	//   Extension headers (except for the Hop-by-Hop Options header) are
	//   not processed, inserted, or deleted by any node along a packet's
	//   delivery path until the packet reaches the node identified in the
	//   Destination Address field of the IPv6 header.
	//
	// Furthermore, as per RFC 8200 section 4.1, the Hop By Hop extension
	// header is restricted to appear first in the list of extension headers.
	//
	// Therefore, we can immediately return once we hit any header other
	// than the Hop-by-Hop header while forwarding a packet.
	if forwarding {
		if _, ok := extHdr.(header.IPv6HopByHopOptionsExtHdr); !ok {
			return true, nil
		}
	}

	switch extHdr := extHdr.(type) {
	case header.IPv6HopByHopOptionsExtHdr:
		if err := e.processIPv6HopByHopOptionsExtHdr(&extHdr, it, *pkt, dstAddr, routerAlert, previousHeaderStart, forwarding); err != nil {
			return true, err
		}
	case header.IPv6RoutingExtHdr:
		if err := e.processIPv6RoutingExtHeader(&extHdr, it, *pkt); err != nil {
			return true, err
		}
	case header.IPv6FragmentExtHdr:
		*hasFragmentHeader = true
		if extHdr.IsAtomic() {
			// This fragment extension header indicates that this packet is an
			// atomic fragment. An atomic fragment is a fragment that contains
			// all the data required to reassemble a full packet. As per RFC 6946,
			// atomic fragments must not interfere with "normal" fragmented traffic
			// so we skip processing the fragment instead of feeding it through the
			// reassembly process below.
			return false, nil
		}

		if err := e.processFragmentExtHdr(&extHdr, it, pkt, h); err != nil {
			return true, err
		}
	case header.IPv6DestinationOptionsExtHdr:
		if err := e.processIPv6DestinationOptionsExtHdr(&extHdr, it, *pkt, dstAddr); err != nil {
			return true, err
		}
	case header.IPv6RawPayloadHeader:
		if err := e.processIPv6RawPayloadHeader(&extHdr, *pkt, *routerAlert, previousHeaderStart, *hasFragmentHeader); err != nil {
			return true, err
		}
	case header.IPv6ExperimentExtHdr:
	default:
		// Since the iterator returns IPv6RawPayloadHeader for unknown Extension
		// Header IDs this should never happen unless we missed a supported type
		// here.
		panic(fmt.Sprintf("unrecognized type from it.Next() = %T", extHdr))
	}
	return false, nil
}

// processExtensionHeaders processes the extension headers in the given packet.
// Returns an error if the processing of a header failed or if the packet should
// be discarded.
func (e *endpoint) processExtensionHeaders(h header.IPv6, pkt *stack.PacketBuffer, forwarding bool) error {
	// Create a VV to parse the packet. We don't plan to modify anything here.
	// vv consists of:
	//	- Any IPv6 header bytes after the first 40 (i.e. extensions).
	//	- The transport header, if present.
	//	- Any other payload data.
	v := pkt.NetworkHeader().View()
	if v != nil {
		v.TrimFront(header.IPv6MinimumSize)
	}
	buf := buffer.MakeWithView(v)
	buf.Append(pkt.TransportHeader().View())
	dataBuf := pkt.Data().ToBuffer()
	buf.Merge(&dataBuf)
	it := header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(h.NextHeader()), buf)

	// Clone the pkt here because fragment header processing can replace this
	// packet with a new one that has an extra reference. Cloning here
	// keeps it so this method owns the packet either way so the packet can always
	// be DecRef'd after processing is done.
	processingPkt := pkt.Clone()
	defer func() {
		processingPkt.DecRef()
		it.Release()
	}()

	var (
		hasFragmentHeader bool
		routerAlert       *header.IPv6RouterAlertOption
	)
	for {
		h := header.IPv6(pkt.NetworkHeader().Slice())
		if done, err := e.processExtensionHeader(&it, &processingPkt, h, &routerAlert, &hasFragmentHeader, forwarding); err != nil || done {
			return err
		}
	}
}

func (e *endpoint) processIPv6RawPayloadHeader(extHdr *header.IPv6RawPayloadHeader, pkt *stack.PacketBuffer, routerAlert *header.IPv6RouterAlertOption, previousHeaderStart uint32, hasFragmentHeader bool) error {
	stats := e.stats.ip
	// If the last header in the payload isn't a known IPv6 extension header,
	// handle it as if it is transport layer data.

	// Calculate the number of octets parsed from data. We want to consume all
	// the data except the unparsed portion located at the end, whose size is
	// extHdr.Buf.Size().
	trim := pkt.Data().Size() - int(extHdr.Buf.Size())

	// For unfragmented packets, extHdr still contains the transport header.
	// Consume that too.
	//
	// For reassembled fragments, pkt.TransportHeader is unset, so this is a
	// no-op and pkt.Data begins with the transport header.
	trim += len(pkt.TransportHeader().Slice())

	if _, ok := pkt.Data().Consume(trim); !ok {
		stats.MalformedPacketsReceived.Increment()
		return fmt.Errorf("could not consume %d bytes", trim)
	}

	proto := tcpip.TransportProtocolNumber(extHdr.Identifier)
	// If the packet was reassembled from a fragment, it will not have a
	// transport header set yet.
	if len(pkt.TransportHeader().Slice()) == 0 {
		e.protocol.parseTransport(pkt, proto)
	}

	stats.PacketsDelivered.Increment()
	if proto == 58 {
		pkt.TransportProtocolNumber = proto
		e.handleICMP(pkt)
		return nil
	}
	switch res := e.dispatcher.DeliverTransportPacket(proto, pkt); res {
	case stack.TransportPacketHandled:
		return nil
	case stack.TransportPacketDestinationPortUnreachable:
		// As per RFC 4443 section 3.1:
		//   A destination node SHOULD originate a Destination Unreachable
		//   message with Code 4 in response to a packet for which the
		//   transport protocol (e.g., UDP) has no listener, if that transport
		//   protocol has no alternative means to inform the sender.
		return fmt.Errorf("destination port unreachable")
	case stack.TransportPacketProtocolUnreachable:
		// As per RFC 8200 section 4. (page 7):
		//   Extension headers are numbered from IANA IP Protocol Numbers
		//   [IANA-PN], the same values used for IPv4 and IPv6.  When
		//   processing a sequence of Next Header values in a packet, the
		//   first one that is not an extension header [IANA-EH] indicates
		//   that the next item in the packet is the corresponding upper-layer
		//   header.
		// With more related information on page 8:
		//   If, as a result of processing a header, the destination node is
		//   required to proceed to the next header but the Next Header value
		//   in the current header is unrecognized by the node, it should
		//   discard the packet and send an ICMP Parameter Problem message to
		//   the source of the packet, with an ICMP Code value of 1
		//   ("unrecognized Next Header type encountered") and the ICMP
		//   Pointer field containing the offset of the unrecognized value
		//   within the original packet.
		//
		// Which when taken together indicate that an unknown protocol should
		// be treated as an unrecognized next header value.
		// The location of the Next Header field is in a different place in
		// the initial IPv6 header than it is in the extension headers so
		// treat it specially.
		return fmt.Errorf("transport protocol unreachable")
	default:
		panic(fmt.Sprintf("unrecognized result from DeliverTransportPacket = %d", res))
	}
}

func (e *endpoint) processIPv6RoutingExtHeader(extHdr *header.IPv6RoutingExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer) error {
	// As per RFC 8200 section 4.4, if a node encounters a routing header with
	// an unrecognized routing type value, with a non-zero Segments Left
	// value, the node must discard the packet and send an ICMP Parameter
	// Problem, Code 0 to the packet's Source Address, pointing to the
	// unrecognized Routing Type.
	//
	// If the Segments Left is 0, the node must ignore the Routing extension
	// header and process the next header in the packet.
	//
	// Note, the stack does not yet handle any type of routing extension
	// header, so we just make sure Segments Left is zero before processing
	// the next extension header.
	if extHdr.SegmentsLeft() == 0 {
		return nil
	}
	return fmt.Errorf("found unrecognized routing type with non-zero segments left in header = %#v", extHdr)
}

func (e *endpoint) processIPv6DestinationOptionsExtHdr(extHdr *header.IPv6DestinationOptionsExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer, dstAddr tcpip.Address) error {
	stats := e.stats.ip
	optsIt := extHdr.Iter()
	var uopt *header.IPv6UnknownExtHdrOption
	defer func() {
		if uopt != nil {
			uopt.Data.Release()
		}
	}()

	for {
		opt, done, err := optsIt.Next()
		if err != nil {
			stats.MalformedPacketsReceived.Increment()
			return err
		}
		if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
			uopt = uo
		}
		if done {
			break
		}

		// We currently do not support any IPv6 Destination extension header
		// options.
		switch opt.UnknownAction() {
		case header.IPv6OptionUnknownActionSkip:
		case header.IPv6OptionUnknownActionDiscard:
			return fmt.Errorf("found unknown destination header option = %#v with discard action", opt)
		case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
			if header.IsV6MulticastAddress(dstAddr) {
				if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
					uopt = uo
				}
				return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
			}
			fallthrough
		case header.IPv6OptionUnknownActionDiscardSendICMP:
			// This case satisfies a requirement of RFC 8200 section 4.2
			// which states that an unknown option starting with bits [10] should:
			//
			//    discard the packet and, regardless of whether or not the
			//    packet's Destination Address was a multicast address, send an
			//    ICMP Parameter Problem, Code 2, message to the packet's
			//    Source Address, pointing to the unrecognized Option Type.
			//
			return fmt.Errorf("found unknown destination header option %#v with discard action", opt)
		default:
			panic(fmt.Sprintf("unrecognized action for an unrecognized Destination extension header option = %#v", opt))
		}
		if uopt != nil {
			uopt.Data.Release()
			uopt = nil
		}
	}
	return nil
}

func (e *endpoint) processIPv6HopByHopOptionsExtHdr(extHdr *header.IPv6HopByHopOptionsExtHdr, it *header.IPv6PayloadIterator, pkt *stack.PacketBuffer, dstAddr tcpip.Address, routerAlert **header.IPv6RouterAlertOption, previousHeaderStart uint32, forwarding bool) error {
	stats := e.stats.ip
	// As per RFC 8200 section 4.1, the Hop By Hop extension header is
	// restricted to appear immediately after an IPv6 fixed header.
	if previousHeaderStart != 0 {
		return fmt.Errorf("found Hop-by-Hop header = %#v with non-zero previous header offset = %d", extHdr, previousHeaderStart)
	}

	optsIt := extHdr.Iter()
	var uopt *header.IPv6UnknownExtHdrOption
	defer func() {
		if uopt != nil {
			uopt.Data.Release()
		}
	}()

	for {
		opt, done, err := optsIt.Next()
		if err != nil {
			stats.MalformedPacketsReceived.Increment()
			return err
		}
		if uo, ok := opt.(*header.IPv6UnknownExtHdrOption); ok {
			uopt = uo
		}
		if done {
			break
		}

		switch opt := opt.(type) {
		case *header.IPv6RouterAlertOption:
			if *routerAlert != nil {
				// As per RFC 2711 section 3, there should be at most one Router
				// Alert option per packet.
				//
				//    There MUST only be one option of this type, regardless of
				//    value, per Hop-by-Hop header.
				stats.MalformedPacketsReceived.Increment()
				return fmt.Errorf("found multiple Router Alert options (%#v, %#v)", opt, *routerAlert)
			}
			*routerAlert = opt
			stats.OptionRouterAlertReceived.Increment()
		default:
			switch opt.UnknownAction() {
			case header.IPv6OptionUnknownActionSkip:
			case header.IPv6OptionUnknownActionDiscard:
				return fmt.Errorf("found unknown Hop-by-Hop header option = %#v with discard action", opt)
			case header.IPv6OptionUnknownActionDiscardSendICMPNoMulticastDest:
				if header.IsV6MulticastAddress(dstAddr) {
					return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
				}
				fallthrough
			case header.IPv6OptionUnknownActionDiscardSendICMP:
				// This case satisfies a requirement of RFC 8200 section 4.2 which
				// states that an unknown option starting with bits [10] should:
				//
				//    discard the packet and, regardless of whether or not the
				//    packet's Destination Address was a multicast address, send an
				//    ICMP Parameter Problem, Code 2, message to the packet's
				//    Source Address, pointing to the unrecognized Option Type.
				return fmt.Errorf("found unknown hop-by-hop header option = %#v with discard action", opt)
			default:
				panic(fmt.Sprintf("unrecognized action for an unrecognized Hop By Hop extension header option = %#v", opt))
			}
		}
		if uopt != nil {
			uopt.Data.Release()
			uopt = nil
		}
	}
	return nil
}

func (e *endpoint) processFragmentExtHdr(extHdr *header.IPv6FragmentExtHdr, it *header.IPv6PayloadIterator, pkt **stack.PacketBuffer, h header.IPv6) error {
	stats := e.stats.ip
	// Don't consume the iterator if we have the first fragment because we
	// will use it to validate that the first fragment holds the upper layer
	// header.
	rawPayload := it.AsRawHeader(extHdr.FragmentOffset() != 0 /* consume */)
	defer rawPayload.Release()

	if extHdr.FragmentOffset() == 0 {
		// Check that the iterator ends with a raw payload as the first fragment
		// should include all headers up to and including any upper layer
		// headers, as per RFC 8200 section 4.5; only upper layer data
		// (non-headers) should follow the fragment extension header.
		var lastHdr header.IPv6PayloadHeader

		for {
			it, done, err := it.Next()
			if err != nil {
				stats.MalformedPacketsReceived.Increment()
				stats.MalformedFragmentsReceived.Increment()
				return err
			}
			if done {
				break
			}
			it.Release()

			lastHdr = it
		}

		// If the last header is a raw header, then the last portion of the IPv6
		// payload is not a known IPv6 extension header. Note, this does not
		// mean that the last portion is an upper layer header or not an
		// extension header because:
		//  1) we do not yet support all extension headers
		//  2) we do not validate the upper layer header before reassembling.
		//
		// This check makes sure that a known IPv6 extension header is not
		// present after the Fragment extension header in a non-initial
		// fragment.
		//
		// TODO(#2196): Support IPv6 Authentication and Encapsulated
		// Security Payload extension headers.
		// TODO(#2333): Validate that the upper layer header is valid.
		switch lastHdr.(type) {
		case header.IPv6RawPayloadHeader:
		default:
			stats.MalformedPacketsReceived.Increment()
			stats.MalformedFragmentsReceived.Increment()
			return fmt.Errorf("known extension header = %#v present after fragment header in a non-initial fragment", lastHdr)
		}
	}

	fragmentPayloadLen := rawPayload.Buf.Size()
	if fragmentPayloadLen == 0 {
		// Drop the packet as it's marked as a fragment but has no payload.
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return fmt.Errorf("fragment has no payload")
	}

	// As per RFC 2460 Section 4.5:
	//
	//    If the length of a fragment, as derived from the fragment packet's
	//    Payload Length field, is not a multiple of 8 octets and the M flag
	//    of that fragment is 1, then that fragment must be discarded and an
	//    ICMP Parameter Problem, Code 0, message should be sent to the source
	//    of the fragment, pointing to the Payload Length field of the
	//    fragment packet.
	if extHdr.More() && fragmentPayloadLen%header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit != 0 {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return fmt.Errorf("found fragment length = %d that is not a multiple of 8 octets", fragmentPayloadLen)
	}

	// The packet is a fragment, let's try to reassemble it.
	start := extHdr.FragmentOffset() * header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit

	// As per RFC 2460 Section 4.5:
	//
	//    If the length and offset of a fragment are such that the Payload
	//    Length of the packet reassembled from that fragment would exceed
	//    65,535 octets, then that fragment must be discarded and an ICMP
	//    Parameter Problem, Code 0, message should be sent to the source of
	//    the fragment, pointing to the Fragment Offset field of the fragment
	//    packet.
	lengthAfterReassembly := int(start) + int(fragmentPayloadLen)
	if lengthAfterReassembly > header.IPv6MaximumPayloadSize {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return fmt.Errorf("determined that reassembled packet length = %d would exceed allowed length = %d", lengthAfterReassembly, header.IPv6MaximumPayloadSize)
	}

	// Note that pkt doesn't have its transport header set after reassembly,
	// and won't until DeliverNetworkPacket sets it.
	resPkt, proto, ready, err := e.protocol.fragmentation.Process(
		// IPv6 ignores the Protocol field since the ID only needs to be unique
		// across source-destination pairs, as per RFC 8200 section 4.5.
		fragmentation.FragmentID{
			Source:      h.SourceAddress(),
			Destination: h.DestinationAddress(),
			ID:          extHdr.ID(),
		},
		start,
		start+uint16(fragmentPayloadLen)-1,
		extHdr.More(),
		uint8(rawPayload.Identifier),
		*pkt,
	)
	if err != nil {
		stats.MalformedPacketsReceived.Increment()
		stats.MalformedFragmentsReceived.Increment()
		return err
	}

	if ready {
		// We create a new iterator with the reassembled packet because we could
		// have more extension headers in the reassembled payload, as per RFC
		// 8200 section 4.5. We also use the NextHeader value from the first
		// fragment.
		it.Release()
		*it = header.MakeIPv6PayloadIterator(header.IPv6ExtensionHeaderIdentifier(proto), resPkt.Data().ToBuffer())
		(*pkt).DecRef()
		*pkt = resPkt
	}
	return nil
}

// Close cleans up resources associated with the endpoint.
func (e *endpoint) Close() {
	e.mu.Lock()
	e.disableLocked()
	e.mu.addressableEndpointState.Cleanup()
	e.mu.Unlock()

	e.protocol.forgetEndpoint(e.nic.ID())
}

// NetworkProtocolNumber implements stack.NetworkEndpoint.
func (e *endpoint) NetworkProtocolNumber() tcpip.NetworkProtocolNumber {
	return e.protocol.Number()
}

// AddAndAcquirePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) AddAndAcquirePermanentAddress(addr tcpip.AddressWithPrefix, properties stack.AddressProperties) (stack.AddressEndpoint, tcpip.Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.AddAndAcquireAddress(addr, properties, stack.Permanent)
}

// RemovePermanentAddress implements stack.AddressableEndpoint.
func (e *endpoint) RemovePermanentAddress(addr tcpip.Address) tcpip.Error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.mu.addressableEndpointState.RemovePermanentAddress(addr)
}

// SetDeprecated implements stack.AddressableEndpoint.
func (e *endpoint) SetDeprecated(addr tcpip.Address, deprecated bool) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.SetDeprecated(addr, deprecated)
}

// SetLifetimes implements stack.AddressableEndpoint.
func (e *endpoint) SetLifetimes(addr tcpip.Address, lifetimes stack.AddressLifetimes) tcpip.Error {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.SetLifetimes(addr, lifetimes)
}

// MainAddress implements stack.AddressableEndpoint.
func (e *endpoint) MainAddress() tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.MainAddress()
}

// AcquireAssignedAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireAssignedAddress(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior, readOnly bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireAddressOrCreateTempLocked(localAddr, allowTemp, tempPEB, readOnly)
}

// acquireAddressOrCreateTempLocked is like AcquireAssignedAddress but with
// locking requirements.
//
// Precondition: e.mu must be write locked.
func (e *endpoint) acquireAddressOrCreateTempLocked(localAddr tcpip.Address, allowTemp bool, tempPEB stack.PrimaryEndpointBehavior, readOnly bool) stack.AddressEndpoint {
	return e.mu.addressableEndpointState.AcquireAssignedAddress(localAddr, allowTemp, tempPEB, readOnly)
}

// AcquireOutgoingPrimaryAddress implements stack.AddressableEndpoint.
func (e *endpoint) AcquireOutgoingPrimaryAddress(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint, allowExpired)
}

// acquireOutgoingPrimaryAddressRLocked is like AcquireOutgoingPrimaryAddress
// but with locking requirements.
//
// Precondition: e.mu must be read locked.
func (e *endpoint) acquireOutgoingPrimaryAddressRLocked(remoteAddr, srcHint tcpip.Address, allowExpired bool) stack.AddressEndpoint {
	// TODO(b/309216156): Support IPv6 hints.

	// addrCandidate is a candidate for Source Address Selection, as per
	// RFC 6724 section 5.
	type addrCandidate struct {
		addressEndpoint stack.AddressEndpoint
		addr            tcpip.Address
		scope           header.IPv6AddressScope

		label          uint8
		matchingPrefix uint8
	}

	if remoteAddr.BitLen() == 0 {
		return e.mu.addressableEndpointState.AcquireOutgoingPrimaryAddress(remoteAddr, srcHint, allowExpired)
	}

	// Create a candidate set of available addresses we can potentially use as a
	// source address.
	var cs []addrCandidate
	e.mu.addressableEndpointState.ForEachPrimaryEndpoint(func(addressEndpoint stack.AddressEndpoint) bool {
		// If r is not valid for outgoing connections, it is not a valid endpoint.
		if !addressEndpoint.IsAssigned(allowExpired) {
			return true
		}

		addr := addressEndpoint.AddressWithPrefix().Address
		scope, err := header.ScopeForIPv6Address(addr)
		if err != nil {
			// Should never happen as we got r from the primary IPv6 endpoint list and
			// ScopeForIPv6Address only returns an error if addr is not an IPv6
			// address.
			panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", addr, err))
		}

		cs = append(cs, addrCandidate{
			addressEndpoint: addressEndpoint,
			addr:            addr,
			scope:           scope,
			label:           getLabel(addr),
			matchingPrefix:  remoteAddr.MatchingPrefix(addr),
		})

		return true
	})

	remoteScope, err := header.ScopeForIPv6Address(remoteAddr)
	if err != nil {
		// primaryIPv6Endpoint should never be called with an invalid IPv6 address.
		panic(fmt.Sprintf("header.ScopeForIPv6Address(%s): %s", remoteAddr, err))
	}

	remoteLabel := getLabel(remoteAddr)

	// Sort the addresses as per RFC 6724 section 5 rules 1-3.
	//
	// TODO(b/146021396): Implement rules 4, 5 of RFC 6724 section 5.
	sort.Slice(cs, func(i, j int) bool {
		sa := cs[i]
		sb := cs[j]

		// Prefer same address as per RFC 6724 section 5 rule 1.
		if sa.addr == remoteAddr {
			return true
		}
		if sb.addr == remoteAddr {
			return false
		}

		// Prefer appropriate scope as per RFC 6724 section 5 rule 2.
		if sa.scope < sb.scope {
			return sa.scope >= remoteScope
		} else if sb.scope < sa.scope {
			return sb.scope < remoteScope
		}

		// Avoid deprecated addresses as per RFC 6724 section 5 rule 3.
		if saDep, sbDep := sa.addressEndpoint.Deprecated(), sb.addressEndpoint.Deprecated(); saDep != sbDep {
			// If sa is not deprecated, it is preferred over sb.
			return sbDep
		}

		// Prefer matching label as per RFC 6724 section 5 rule 6.
		if sa, sb := sa.label == remoteLabel, sb.label == remoteLabel; sa != sb {
			if sa {
				return true
			}
			if sb {
				return false
			}
		}

		// Prefer temporary addresses as per RFC 6724 section 5 rule 7.
		if saTemp, sbTemp := sa.addressEndpoint.Temporary(), sb.addressEndpoint.Temporary(); saTemp != sbTemp {
			return saTemp
		}

		// Use longest matching prefix as per RFC 6724 section 5 rule 8.
		if sa.matchingPrefix > sb.matchingPrefix {
			return true
		}
		if sb.matchingPrefix > sa.matchingPrefix {
			return false
		}

		// sa and sb are equal, return the endpoint that is closest to the front of
		// the primary endpoint list.
		return i < j
	})

	// Return the most preferred address that can have its reference count
	// incremented.
	for _, c := range cs {
		if c.addressEndpoint.TryIncRef() {
			return c.addressEndpoint
		}
	}

	return nil
}

// PrimaryAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PrimaryAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PrimaryAddresses()
}

// PermanentAddresses implements stack.AddressableEndpoint.
func (e *endpoint) PermanentAddresses() []tcpip.AddressWithPrefix {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.mu.addressableEndpointState.PermanentAddresses()
}

// Stats implements stack.NetworkEndpoint.
func (e *endpoint) Stats() stack.NetworkEndpointStats {
	return &e.stats.localStats
}

var _ stack.NetworkProtocol = (*protocol)(nil)
var _ fragmentation.TimeoutHandler = (*protocol)(nil)

type protocolMu struct {
	sync.RWMutex

	// eps is keyed by NICID to allow protocol methods to retrieve an endpoint
	// when handling a packet, by looking at which NIC handled the packet.
	eps map[tcpip.NICID]*endpoint
}

type protocol struct {
	stack   *stack.Stack
	options Options

	mu protocolMu

	// defaultTTL is the current default TTL for the protocol. Only the
	// uint8 portion of it is meaningful.
	defaultTTL atomic.Uint32

	fragmentation *fragmentation.Fragmentation
}

// Number returns the ipv6 protocol number.
func (p *protocol) Number() tcpip.NetworkProtocolNumber {
	return ProtocolNumber
}

// MinimumPacketSize returns the minimum valid ipv6 packet size.
func (p *protocol) MinimumPacketSize() int {
	return header.IPv6MinimumSize
}

// ParseAddresses implements stack.NetworkProtocol.
func (*protocol) ParseAddresses(b []byte) (src, dst tcpip.Address) {
	h := header.IPv6(b)
	return h.SourceAddress(), h.DestinationAddress()
}

// NewEndpoint creates a new ipv6 endpoint.
func (p *protocol) NewEndpoint(nic stack.NetworkInterface, dispatcher stack.TransportDispatcher) stack.NetworkEndpoint {
	e := &endpoint{nic: nic, dispatcher: dispatcher, protocol: p}
	e.mu.Lock()
	e.mu.addressableEndpointState.Init(e, stack.AddressableEndpointStateOptions{HiddenWhileDisabled: false})
	e.mu.Unlock()

	tcpip.InitStatCounters(reflect.ValueOf(&e.stats.localStats).Elem())
	stackStats := p.stack.Stats()
	e.stats.ip.Init(&e.stats.localStats.IP, &stackStats.IP)

	p.mu.Lock()
	p.mu.eps[nic.ID()] = e
	p.mu.Unlock()
	return e
}

func (p *protocol) findEndpointWithAddress(addr tcpip.Address) *endpoint {
	p.mu.RLock()
	defer p.mu.RUnlock()

	for _, e := range p.mu.eps {
		if addressEndpoint := e.AcquireAssignedAddress(addr, false /* allowTemp */, stack.NeverPrimaryEndpoint, true /* readOnly */); addressEndpoint != nil {
			return e
		}
	}

	return nil
}

func (p *protocol) getEndpointForNIC(id tcpip.NICID) (*endpoint, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ep, ok := p.mu.eps[id]
	return ep, ok
}

func (p *protocol) forgetEndpoint(nicID tcpip.NICID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.mu.eps, nicID)
}

// SetOption implements stack.NetworkProtocol.
func (p *protocol) SetOption(option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		p.SetDefaultTTL(uint8(*v))
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// Option implements stack.NetworkProtocol.
func (p *protocol) Option(option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	switch v := option.(type) {
	case *tcpip.DefaultTTLOption:
		*v = tcpip.DefaultTTLOption(p.DefaultTTL())
		return nil
	default:
		return &tcpip.ErrUnknownProtocolOption{}
	}
}

// SetDefaultTTL sets the default TTL for endpoints created with this protocol.
func (p *protocol) SetDefaultTTL(ttl uint8) {
	p.defaultTTL.Store(uint32(ttl))
}

// DefaultTTL returns the default TTL for endpoints created with this protocol.
func (p *protocol) DefaultTTL() uint8 {
	return uint8(p.defaultTTL.Load())
}

// Close implements stack.TransportProtocol.
func (p *protocol) Close() {
	p.fragmentation.Release()
}

// OnReassemblyTimeout drops incomplete fragmented packets.
func (*protocol) OnReassemblyTimeout(*stack.PacketBuffer) {}

// Wait implements stack.TransportProtocol.
func (*protocol) Wait() {}

// parseAndValidate parses the packet (including its transport layer header) and
// returns a view containing the parsed IP header. The caller is responsible
// for releasing the returned View.
//
// Returns true if the IP header was successfully parsed.
func (p *protocol) parseAndValidate(pkt *stack.PacketBuffer) (*buffer.View, bool) {
	transProtoNum, hasTransportHdr, ok := p.Parse(pkt)
	if !ok {
		return nil, false
	}

	h := header.IPv6(pkt.NetworkHeader().Slice())
	// Do not include the link header's size when calculating the size of the IP
	// packet.
	if !h.IsValid(pkt.Size() - len(pkt.LinkHeader().Slice())) {
		return nil, false
	}

	if hasTransportHdr {
		p.parseTransport(pkt, transProtoNum)
	}

	return pkt.NetworkHeader().View(), true
}

func (p *protocol) parseTransport(pkt *stack.PacketBuffer, transProtoNum tcpip.TransportProtocolNumber) {
	if transProtoNum == 58 {
		return
	}

	switch err := p.stack.ParsePacketBufferTransport(transProtoNum, pkt); err {
	case stack.ParsedOK:
	case stack.UnknownTransportProtocol, stack.TransportLayerParseError:
		// The transport layer will handle unknown protocols and transport layer
		// parsing errors.
	default:
		panic(fmt.Sprintf("unexpected error parsing transport header = %d", err))
	}
}

// Parse implements stack.NetworkProtocol.
func (*protocol) Parse(pkt *stack.PacketBuffer) (proto tcpip.TransportProtocolNumber, hasTransportHdr bool, ok bool) {
	proto, _, fragOffset, fragMore, ok := parse.IPv6(pkt)
	if !ok {
		return 0, false, false
	}

	return proto, !fragMore && fragOffset == 0, true
}

// calculateNetworkMTU calculates the network-layer payload MTU based on the
// link-layer payload MTU and the length of every IPv6 header.
// Note that this is different than the Payload Length field of the IPv6 header,
// which includes the length of the extension headers.
func calculateNetworkMTU(linkMTU, networkHeadersLen uint32) (uint32, tcpip.Error) {
	if linkMTU < header.IPv6MinimumMTU {
		return 0, &tcpip.ErrInvalidEndpointState{}
	}

	// As per RFC 7112 section 5, we should discard packets if their IPv6 header
	// is bigger than 1280 bytes (ie, the minimum link MTU) since we do not
	// support PMTU discovery:
	//   Hosts that do not discover the Path MTU MUST limit the IPv6 Header Chain
	//   length to 1280 bytes.  Limiting the IPv6 Header Chain length to 1280
	//   bytes ensures that the header chain length does not exceed the IPv6
	//   minimum MTU.
	if networkHeadersLen > header.IPv6MinimumMTU {
		return 0, &tcpip.ErrMalformedHeader{}
	}

	networkMTU := linkMTU - networkHeadersLen
	if networkMTU > maxPayloadSize {
		networkMTU = maxPayloadSize
	}
	return networkMTU, nil
}

// Options holds options to configure a new protocol.
type Options struct {
	AllowExternalLoopbackTraffic bool
}

// NewProtocolWithOptions returns an IPv6 network protocol.
func NewProtocolWithOptions(opts Options) stack.NetworkProtocolFactory {
	return func(s *stack.Stack) stack.NetworkProtocol {
		p := &protocol{
			stack:   s,
			options: opts,
		}
		p.fragmentation = fragmentation.NewFragmentation(header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit, fragmentation.HighFragThreshold, fragmentation.LowFragThreshold, ReassembleTimeout, s.Clock(), p)
		p.mu.eps = make(map[tcpip.NICID]*endpoint)
		p.SetDefaultTTL(DefaultTTL)
		return p
	}
}

// NewProtocol is equivalent to NewProtocolWithOptions with an empty Options.
func NewProtocol(s *stack.Stack) stack.NetworkProtocol {
	return NewProtocolWithOptions(Options{})(s)
}

func calculateFragmentReserve(pkt *stack.PacketBuffer) int {
	return pkt.AvailableHeaderBytes() + len(pkt.NetworkHeader().Slice()) + header.IPv6FragmentHeaderSize
}

// getFragmentID returns a random uint32 number (other than zero) to be used as
// fragment ID in the IPv6 header.
func (e *endpoint) getFragmentID() uint32 {
	rng := e.protocol.stack.SecureRNG()
	id := randomUint32(rng)
	for id == 0 {
		id = randomUint32(rng)
	}
	return id
}

func randomUint32(r io.Reader) uint32 {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		panic(fmt.Errorf("reading random IPv6 fragment ID: %w", err))
	}
	return binary.LittleEndian.Uint32(b[:])
}

func buildNextFragment(pf *fragmentation.PacketFragmenter, originalIPHeaders header.IPv6, transportProto tcpip.TransportProtocolNumber, id uint32) (*stack.PacketBuffer, bool) {
	fragPkt, offset, copied, more := pf.BuildNextFragment()
	fragPkt.NetworkProtocolNumber = ProtocolNumber

	originalIPHeadersLength := len(originalIPHeaders)

	s := header.IPv6ExtHdrSerializer{&header.IPv6SerializableFragmentExtHdr{
		FragmentOffset: uint16(offset / header.IPv6FragmentExtHdrFragmentOffsetBytesPerUnit),
		M:              more,
		Identification: id,
	}}

	fragmentIPHeadersLength := originalIPHeadersLength + s.Length()
	fragmentIPHeaders := header.IPv6(fragPkt.NetworkHeader().Push(fragmentIPHeadersLength))

	// Copy the IPv6 header and any extension headers already populated.
	if copied := copy(fragmentIPHeaders, originalIPHeaders); copied != originalIPHeadersLength {
		panic(fmt.Sprintf("wrong number of bytes copied into fragmentIPHeaders: got %d, want %d", copied, originalIPHeadersLength))
	}

	nextHeader, _ := s.Serialize(transportProto, fragmentIPHeaders[originalIPHeadersLength:])

	fragmentIPHeaders.SetNextHeader(nextHeader)
	fragmentIPHeaders.SetPayloadLength(uint16(copied + fragmentIPHeadersLength - header.IPv6MinimumSize))

	return fragPkt, more
}

func checkV4Mapped(h header.IPv6, stats ip.MultiCounterIPStats) bool {
	// Disallow IPv4-mapped addresses per RFC 6890 section 2.2.3.
	ret := true
	if header.IsV4MappedAddress(h.SourceAddress()) {
		stats.InvalidSourceAddressesReceived.Increment()
		ret = false
	}
	if header.IsV4MappedAddress(h.DestinationAddress()) {
		stats.InvalidDestinationAddressesReceived.Increment()
		ret = false
	}
	return ret
}
