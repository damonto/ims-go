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

// Package stack provides the glue between networking protocols and the
// consumers of the networking stack.
//
// For consumers, the only function of interest is New(), everything else is
// provided by the tcpip/public package.
package stack

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"io"
	"sync/atomic"
	"time"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/ports"
	"github.com/damonto/ims-go/ipsec/transport/netstack/waiter"
)

const (
	// DefaultTOS is the default type of service value for network endpoints.
	DefaultTOS = 0
)

type transportProtocolState struct {
	proto          TransportProtocol
	defaultHandler func(id TransportEndpointID, pkt *PacketBuffer) bool
}

// Stack is a networking stack, with all supported protocols, NICs, and route
// table.
//
// LOCK ORDERING: mu > routeMu.
type Stack struct {
	transportProtocols map[tcpip.TransportProtocolNumber]*transportProtocolState
	networkProtocols   map[tcpip.NetworkProtocolNumber]NetworkProtocol

	demux *transportDemuxer

	stats tcpip.Stats

	// routeMu protects annotated fields below.
	routeMu routeStackRWMutex

	// routeTable is a list of routes sorted by prefix length, longest (most specific) first.
	// +checklocks:routeMu
	routeTable tcpip.RouteList

	mu stackRWMutex
	// +checklocks:mu
	nics map[tcpip.NICID]*nic
	// +checklocks:mu
	loopbackNIC *nic
	// +checklocks:mu
	defaultForwardingEnabled map[tcpip.NetworkProtocolNumber]struct{}

	// nicIDGen is used to generate NIC IDs.
	nicIDGen atomic.Int32

	// cleanupEndpointsMu protects cleanupEndpoints.
	cleanupEndpointsMu cleanupEndpointsMutex
	// +checklocks:cleanupEndpointsMu
	cleanupEndpoints map[TransportEndpoint]struct{}

	*ports.PortManager

	// clock is used to generate user-visible times.
	clock tcpip.Clock

	// handleLocal allows non-loopback interfaces to loop packets.
	handleLocal bool

	// seed is a one-time random value initialized at stack startup.
	//
	// TODO(gvisor.dev/issue/940): S/R this field.
	seed maphash.Seed

	// secureRNG is a cryptographically secure random number generator.
	secureRNG io.Reader

	// sendBufferSize holds the min/default/max send buffer sizes for
	// endpoints other than TCP.
	sendBufferSize tcpip.SendBufferSizeOption

	// receiveBufferSize holds the min/default/max receive buffer sizes for
	// endpoints other than TCP.
	receiveBufferSize tcpip.ReceiveBufferSizeOption

	// tcpInvalidRateLimit is the maximal rate for sending duplicate
	// acknowledgements in response to incoming TCP packets that are for an existing
	// connection but that are invalid due to any of the following reasons:
	//
	//   a) out-of-window sequence number.
	//   b) out-of-window acknowledgement number.
	//   c) PAWS check failure (when implemented).
	//
	// This is required to prevent potential ACK loops.
	// Setting this to 0 will disable all rate limiting.
	tcpInvalidRateLimit time.Duration

	// tsOffsetSecret is the secret key for generating timestamp offsets
	// initialized at stack startup.
	tsOffsetSecret uint32
}

// NetworkProtocolFactory instantiates a network protocol.
//
// NetworkProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type NetworkProtocolFactory func(*Stack) NetworkProtocol

// TransportProtocolFactory instantiates a transport protocol.
//
// TransportProtocolFactory must not attempt to modify the stack, it may only
// query the stack.
type TransportProtocolFactory func(*Stack) TransportProtocol

// Options contains optional Stack configuration.
type Options struct {
	// NetworkProtocols lists the network protocols to enable.
	NetworkProtocols []NetworkProtocolFactory

	// TransportProtocols lists the transport protocols to enable.
	TransportProtocols []TransportProtocolFactory

	// Clock is an optional clock used for timekeeping.
	//
	// If Clock is nil, tcpip.NewStdClock() will be used.
	Clock tcpip.Clock

	// Stats are optional statistic counters.
	Stats tcpip.Stats

	// HandleLocal indicates whether packets destined to their source
	// should be handled by the stack internally (true) or outside the
	// stack (false).
	HandleLocal bool

	// SecureRNG is a cryptographically secure random number generator.
	SecureRNG io.Reader
}

// TransportEndpointInfo holds useful information about a transport endpoint
// which can be queried by monitoring tools.
type TransportEndpointInfo struct {
	// The following fields are initialized at creation time and are
	// immutable.

	NetProto   tcpip.NetworkProtocolNumber
	TransProto tcpip.TransportProtocolNumber

	// The following fields are protected by endpoint mu.

	ID TransportEndpointID
	// BindNICID and bindAddr are set via calls to Bind(). They are used to
	// reject attempts to send data or connect via a different NIC or
	// address
	BindNICID tcpip.NICID
	BindAddr  tcpip.Address
	// RegisterNICID is the default NICID registered as a side-effect of
	// connect or datagram write.
	RegisterNICID tcpip.NICID
}

// AddrNetProtoLocked unwraps the specified address if it is a V4-mapped V6
// address and returns the network protocol number to be used to communicate
// with the specified address. It returns an error if the passed address is
// incompatible with the receiver.
//
// Preconditon: the parent endpoint mu must be held while calling this method.
func (t *TransportEndpointInfo) AddrNetProtoLocked(addr tcpip.FullAddress, v6only bool, bind bool) (tcpip.FullAddress, tcpip.NetworkProtocolNumber, tcpip.Error) {
	netProto := t.NetProto
	switch addr.Addr.BitLen() {
	case header.IPv4AddressSizeBits:
		netProto = header.IPv4ProtocolNumber
	case header.IPv6AddressSizeBits:
		if header.IsV4MappedAddress(addr.Addr) {
			netProto = header.IPv4ProtocolNumber
			addr.Addr = tcpip.AddrFrom4Slice(addr.Addr.AsSlice()[header.IPv6AddressSize-header.IPv4AddressSize:])
			if addr.Addr == header.IPv4Any {
				addr.Addr = tcpip.Address{}
			}
		}
	}

	switch t.ID.LocalAddress.BitLen() {
	case header.IPv4AddressSizeBits:
		if addr.Addr.BitLen() == header.IPv6AddressSizeBits {
			return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
		}
	case header.IPv6AddressSizeBits:
		if addr.Addr.BitLen() == header.IPv4AddressSizeBits {
			return tcpip.FullAddress{}, 0, &tcpip.ErrNetworkUnreachable{}
		}
	}

	if !bind && addr.Addr.Unspecified() {
		// If the destination address isn't set, Linux sets it to the
		// source address. If a source address isn't set either, it
		// sets both to the loopback address.
		if t.ID.LocalAddress.Unspecified() {
			switch netProto {
			case header.IPv4ProtocolNumber:
				addr.Addr = header.IPv4Loopback
			case header.IPv6ProtocolNumber:
				addr.Addr = header.IPv6Loopback
			}
		} else {
			addr.Addr = t.ID.LocalAddress
		}
	}

	switch {
	case netProto == t.NetProto:
	case netProto == header.IPv4ProtocolNumber && t.NetProto == header.IPv6ProtocolNumber:
		if v6only {
			return tcpip.FullAddress{}, 0, &tcpip.ErrHostUnreachable{}
		}
	default:
		return tcpip.FullAddress{}, 0, &tcpip.ErrInvalidEndpointState{}
	}

	return addr, netProto, nil
}

// IsEndpointInfo is an empty method to implement the tcpip.EndpointInfo
// marker interface.
func (*TransportEndpointInfo) IsEndpointInfo() {}

// New allocates a new networking stack with only the requested networking and
// transport protocols configured with default options.
//
// Protocol options can be changed by calling the
// SetNetworkProtocolOption/SetTransportProtocolOption methods provided by the
// stack. Please refer to individual protocol implementations as to what options
// are supported.
func New(opts Options) *Stack {
	clock := opts.Clock
	if clock == nil {
		clock = tcpip.NewStdClock()
	}

	if opts.SecureRNG == nil {
		opts.SecureRNG = rand.Reader
	}
	secureRNG := opts.SecureRNG

	s := &Stack{
		transportProtocols:       make(map[tcpip.TransportProtocolNumber]*transportProtocolState),
		networkProtocols:         make(map[tcpip.NetworkProtocolNumber]NetworkProtocol),
		nics:                     make(map[tcpip.NICID]*nic),
		defaultForwardingEnabled: make(map[tcpip.NetworkProtocolNumber]struct{}),
		cleanupEndpoints:         make(map[TransportEndpoint]struct{}),
		PortManager:              ports.NewPortManager(),
		clock:                    clock,
		stats:                    opts.Stats.FillIn(),
		handleLocal:              opts.HandleLocal,
		seed:                     maphash.MakeSeed(),
		secureRNG:                secureRNG,
		sendBufferSize: tcpip.SendBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		receiveBufferSize: tcpip.ReceiveBufferSizeOption{
			Min:     MinBufferSize,
			Default: DefaultBufferSize,
			Max:     DefaultMaxBufferSize,
		},
		tcpInvalidRateLimit: defaultTCPInvalidRateLimit,
		tsOffsetSecret:      randomUint32(secureRNG),
	}

	// Add specified network protocols.
	for _, netProtoFactory := range opts.NetworkProtocols {
		netProto := netProtoFactory(s)
		s.networkProtocols[netProto.Number()] = netProto
	}

	// Add specified transport protocols.
	for _, transProtoFactory := range opts.TransportProtocols {
		transProto := transProtoFactory(s)
		s.transportProtocols[transProto.Number()] = &transportProtocolState{
			proto: transProto,
		}
	}

	// Create the global transport demuxer.
	s.demux = newTransportDemuxer(s)

	return s
}

func randomUint32(r io.Reader) uint32 {
	var b [4]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		panic(fmt.Errorf("reading random stack value: %w", err))
	}
	return binary.LittleEndian.Uint32(b[:])
}

// NextNICID allocates the next available NIC ID and returns it.
func (s *Stack) NextNICID() tcpip.NICID {
	next := s.nicIDGen.Add(1)
	if next < 0 {
		panic("NICID overflow")
	}
	return tcpip.NICID(next)
}

// SetNetworkProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetNetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.SettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.SetOption(option)
}

// NetworkProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation. E.g.:
//
//	var v ipv4.MyOption
//	err := s.NetworkProtocolOption(tcpip.IPv4ProtocolNumber, &v)
//	if err != nil {
//		...
//	}
func (s *Stack) NetworkProtocolOption(network tcpip.NetworkProtocolNumber, option tcpip.GettableNetworkProtocolOption) tcpip.Error {
	netProto, ok := s.networkProtocols[network]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return netProto.Option(option)
}

// SetTransportProtocolOption allows configuring individual protocol level
// options. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation or the provided value
// is incorrect.
func (s *Stack) SetTransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.SettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.SetOption(option)
}

// TransportProtocolOption allows retrieving individual protocol level option
// values. This method returns an error if the protocol is not supported or
// option is not supported by the protocol implementation.
//
//	var v tcp.SACKEnabled
//	if err := s.TransportProtocolOption(tcpip.TCPProtocolNumber, &v); err != nil {
//		...
//	}
func (s *Stack) TransportProtocolOption(transport tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	transProtoState, ok := s.transportProtocols[transport]
	if !ok {
		return &tcpip.ErrUnknownProtocol{}
	}
	return transProtoState.proto.Option(option)
}

// SendBufSizeProto is a protocol that can return its send buffer size.
type SendBufSizeProto interface {
	SendBufferSize() tcpip.TCPSendBufferSizeRangeOption
}

// TCPSendBufferLimits returns the TCP send buffer size limit.
func (s *Stack) TCPSendBufferLimits() tcpip.TCPSendBufferSizeRangeOption {
	return s.transportProtocols[header.TCPProtocolNumber].proto.(SendBufSizeProto).SendBufferSize()
}

// SetTransportProtocolHandler sets the per-stack default handler for the given
// protocol.
//
// It must be called only during initialization of the stack. Changing it as the
// stack is operating is not supported.
func (s *Stack) SetTransportProtocolHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	state := s.transportProtocols[p]
	if state != nil {
		state.defaultHandler = h
	}
}

// Clock returns the Stack's clock for retrieving the current time and
// scheduling work.
func (s *Stack) Clock() tcpip.Clock {
	return s.clock
}

// Stats returns a mutable copy of the current stats.
//
// This is not generally exported via the public interface, but is available
// internally.
func (s *Stack) Stats() tcpip.Stats {
	return s.stats
}

// SetNICForwarding enables or disables packet forwarding on the specified NIC
// for the passed protocol.
//
// Returns the previous configuration on the NIC.
func (s *Stack) SetNICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.setForwarding(protocol, enable)
}

// NICForwarding returns the forwarding configuration for the specified NIC.
func (s *Stack) NICForwarding(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false, &tcpip.ErrUnknownNICID{}
	}

	return nic.forwarding(protocol)
}

// SetForwardingDefaultAndAllNICs sets packet forwarding for all NICs for the
// passed protocol and sets the default setting for newly created NICs.
func (s *Stack) SetForwardingDefaultAndAllNICs(protocol tcpip.NetworkProtocolNumber, enable bool) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	doneOnce := false
	for id, nic := range s.nics {
		if _, err := nic.setForwarding(protocol, enable); err != nil {
			// Expect forwarding to be settable on all interfaces if it was set on
			// one.
			if doneOnce {
				panic(fmt.Sprintf("nic(id=%d).setForwarding(%d, %t): %s", id, protocol, enable, err))
			}

			return err
		}

		doneOnce = true
	}

	if enable {
		s.defaultForwardingEnabled[protocol] = struct{}{}
	} else {
		delete(s.defaultForwardingEnabled, protocol)
	}

	return nil
}

// PortRange returns the UDP and TCP inclusive range of ephemeral ports used in
// both IPv4 and IPv6.
func (s *Stack) PortRange() (uint16, uint16) {
	return s.PortManager.PortRange()
}

// SetPortRange sets the UDP and TCP IPv4 and IPv6 ephemeral port range
// (inclusive).
func (s *Stack) SetPortRange(start uint16, end uint16) tcpip.Error {
	return s.PortManager.SetPortRange(start, end)
}

// SetRouteTable assigns the route table to be used by this stack. It
// specifies which NIC to use for given destination address ranges.
//
// This method takes ownership of the table.
func (s *Stack) SetRouteTable(table []tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.routeTable.Reset()
	for _, r := range table {
		s.addRouteLocked(&r)
	}
}

// GetRouteTable returns the route table which is currently in use.
func (s *Stack) GetRouteTable() []tcpip.Route {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	table := make([]tcpip.Route, 0)
	for r := s.routeTable.Front(); r != nil; r = r.Next() {
		table = append(table, *r)
	}
	return table
}

// AddRoute appends a route to the route table.
func (s *Stack) AddRoute(route tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.addRouteLocked(&route)
}

// +checklocks:s.routeMu
func (s *Stack) addRouteLocked(route *tcpip.Route) {
	routePrefix := route.Destination.Prefix()
	n := s.routeTable.Front()
	for ; n != nil; n = n.Next() {
		if n.Destination.Prefix() < routePrefix {
			s.routeTable.InsertBefore(n, route)
			return
		}
	}
	s.routeTable.PushBack(route)
}

// RemoveRoutes removes matching routes from the route table, it
// returns the number of routes that are removed.
func (s *Stack) RemoveRoutes(match func(tcpip.Route) bool) int {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	return s.removeRoutesLocked(match)
}

// +checklocks:s.routeMu
func (s *Stack) removeRoutesLocked(match func(tcpip.Route) bool) int {
	count := 0
	for route := s.routeTable.Front(); route != nil; {
		next := route.Next()
		if match(*route) {
			s.routeTable.Remove(route)
			count++
		}
		route = next
	}
	return count
}

// ReplaceRoute replaces the route in the routing table which matches
// the lookup key for the routing table. If there is no match, the given
// route will still be added to the routing table.
// The lookup key consists of destination, ToS, scope and output interface.
func (s *Stack) ReplaceRoute(route tcpip.Route) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	s.removeRoutesLocked(func(rt tcpip.Route) bool {
		return rt.Equal(route)
	})
	s.addRouteLocked(&route)
}

// NewEndpoint creates a new transport layer endpoint of the given protocol.
func (s *Stack) NewEndpoint(transport tcpip.TransportProtocolNumber, network tcpip.NetworkProtocolNumber, waiterQueue *waiter.Queue) (tcpip.Endpoint, tcpip.Error) {
	t, ok := s.transportProtocols[transport]
	if !ok {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	return t.proto.NewEndpoint(network, waiterQueue)
}

// NICContext is an opaque pointer used to store client-supplied NIC metadata.
type NICContext any

// NICOptions specifies the configuration of a NIC as it is being created.
// The zero value creates an enabled, unnamed NIC.
type NICOptions struct {
	// Name specifies the name of the NIC.
	Name string

	// Disabled specifies whether to avoid calling Attach on the passed
	// LinkEndpoint.
	Disabled bool

	// Context specifies user-defined data that will be returned in stack.NICInfo
	// for the NIC. Clients of this library can use it to add metadata that
	// should be tracked alongside a NIC, to avoid having to keep a
	// map[tcpip.NICID]metadata mirroring stack.Stack's nic map.
	Context NICContext

	// QDisc is the queue discipline to use for this NIC.
	QDisc QueueingDiscipline

	// EnableExperimentIPOption specifies whether the NIC is responsible for
	// passing the experiment IP option.
	EnableExperimentIPOption bool
}

// GetNICByID return a network device associated with the specified ID.
func (s *Stack) GetNICByID(id tcpip.NICID) (*nic, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n, ok := s.nics[id]
	if !ok {
		return nil, &tcpip.ErrNoSuchFile{}
	}
	return n, nil
}

// CreateNICWithOptions creates a NIC with the provided id, LinkEndpoint, and
// NICOptions. See the documentation on type NICOptions for details on how
// NICs can be configured.
//
// LinkEndpoint.Attach will be called to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNICWithOptions(id tcpip.NICID, ep LinkEndpoint, opts NICOptions) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id == 0 {
		return &tcpip.ErrInvalidNICID{}
	}
	// Make sure id is unique.
	if _, ok := s.nics[id]; ok {
		return &tcpip.ErrDuplicateNICID{}
	}

	// Make sure name is unique, unless unnamed.
	if opts.Name != "" {
		for _, n := range s.nics {
			if n.Name() == opts.Name {
				return &tcpip.ErrDuplicateNICID{}
			}
		}
	}

	n := newNIC(s, id, ep, opts)
	for proto := range s.defaultForwardingEnabled {
		if _, err := n.setForwarding(proto, true); err != nil {
			panic(fmt.Sprintf("newNIC(%d, ...).setForwarding(%d, true): %s", id, proto, err))
		}
	}
	s.nics[id] = n
	if n.IsLoopback() {
		s.loopbackNIC = n
	}
	ep.SetOnCloseAction(func() {
		s.RemoveNIC(id)
	})
	if !opts.Disabled {
		return n.enable()
	}

	return nil
}

// CreateNIC creates a NIC with the provided id and LinkEndpoint and calls
// LinkEndpoint.Attach to bind ep with a NetworkDispatcher.
func (s *Stack) CreateNIC(id tcpip.NICID, ep LinkEndpoint) tcpip.Error {
	return s.CreateNICWithOptions(id, ep, NICOptions{})
}

// GetLinkEndpointByName gets the link endpoint specified by name.
func (s *Stack) GetLinkEndpointByName(name string) LinkEndpoint {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, nic := range s.nics {
		if nic.Name() == name {
			linkEP, ok := nic.NetworkLinkEndpoint.(LinkEndpoint)
			if !ok {
				panic(fmt.Sprintf("unexpected NetworkLinkEndpoint(%#v) is not a LinkEndpoint", nic.NetworkLinkEndpoint))
			}
			return linkEP
		}
	}
	return nil
}

// EnableNIC enables the given NIC so that the link-layer endpoint can start
// delivering packets to it.
func (s *Stack) EnableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.enable()
}

// DisableNIC disables the given NIC.
func (s *Stack) DisableNIC(id tcpip.NICID) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.disable()
	return nil
}

// CheckNIC checks if a NIC is usable.
func (s *Stack) CheckNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return false
	}

	return nic.Enabled()
}

// RemoveNIC removes NIC and all related routes from the network stack.
func (s *Stack) RemoveNIC(id tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	deferAct, err := s.removeNICLocked(id, true /* closeLinkEndpoint */)
	s.mu.Unlock()
	if deferAct != nil {
		deferAct()
	}
	return err
}

// removeNICLocked removes NIC and all related routes from the network stack.
//
// +checklocks:s.mu
func (s *Stack) removeNICLocked(id tcpip.NICID, closeLinkEndpoint bool) (func(), tcpip.Error) {
	nic, ok := s.nics[id]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}
	delete(s.nics, id)

	if nic.Primary != nil {
		b := nic.Primary.NetworkLinkEndpoint.(CoordinatorNIC)
		if err := b.DelNIC(nic); err != nil {
			return nil, err
		}
	}

	// Remove routes in-place. n tracks the number of routes written.
	s.routeMu.Lock()
	for r := s.routeTable.Front(); r != nil; {
		next := r.Next()
		if r.NIC == id {
			s.routeTable.Remove(r)
		}
		r = next
	}
	s.routeMu.Unlock()

	if s.loopbackNIC == nic {
		s.loopbackNIC = nil
	}
	return nic.remove(closeLinkEndpoint)
}

// GetNICCoordinatorID returns the ID of the coordinator device of a NIC.
func (s *Stack) GetNICCoordinatorID(id tcpip.NICID) (tcpip.NICID, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if nic, ok := s.nics[id]; ok {
		if nic.Primary != nil {
			return nic.Primary.id, true
		}
	}
	return 0, false
}

// SetNICCoordinator sets a coordinator device.
func (s *Stack) SetNICCoordinator(id tcpip.NICID, mid tcpip.NICID) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	// Setting a coordinator for a coordinator NIC is not allowed.
	if _, ok := nic.NetworkLinkEndpoint.(CoordinatorNIC); ok {
		return &tcpip.ErrNoSuchFile{}
	}
	m, ok := s.nics[mid]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	b, ok := m.NetworkLinkEndpoint.(CoordinatorNIC)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}
	if err := b.AddNIC(nic); err != nil {
		return err
	}
	nic.Primary = m
	return nil
}

// SetNICAddress sets the hardware address which is identified by the nic ID.
func (s *Stack) SetNICAddress(id tcpip.NICID, addr tcpip.LinkAddress) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.SetLinkAddress(addr)
	return nil
}

// SetNICName sets a NIC's name.
func (s *Stack) SetNICName(id tcpip.NICID, name string) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.name = name
	return nil
}

// SetNICMTU sets a NIC's MTU.
func (s *Stack) SetNICMTU(id tcpip.NICID, mtu uint32) tcpip.Error {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}
	nic.SetMTU(mtu)
	return nil
}

// NICInfo captures the name and addresses assigned to a NIC.
type NICInfo struct {
	Name              string
	LinkAddress       tcpip.LinkAddress
	ProtocolAddresses []tcpip.ProtocolAddress

	// Flags indicate the state of the NIC.
	Flags NICStateFlags

	// MTU is the maximum transmission unit.
	MTU uint32

	Stats tcpip.NICStats

	// NetworkStats holds the stats of each NetworkEndpoint bound to the NIC.
	NetworkStats map[tcpip.NetworkProtocolNumber]NetworkEndpointStats

	// Context is user-supplied data optionally supplied in CreateNICWithOptions.
	// See type NICOptions for more details.
	Context NICContext

	// Forwarding holds the forwarding status for each network endpoint that
	// supports forwarding.
	Forwarding map[tcpip.NetworkProtocolNumber]bool

	// Primary is the index of the main controlling interface in a bonded setup.
	Primary tcpip.NICID
}

// HasNIC returns true if the NICID is defined in the stack.
func (s *Stack) HasNIC(id tcpip.NICID) bool {
	s.mu.RLock()
	_, ok := s.nics[id]
	s.mu.RUnlock()
	return ok
}

type forwardingFn func(tcpip.NetworkProtocolNumber) (bool, tcpip.Error)

func forwardingValue(forwardingFn forwardingFn, proto tcpip.NetworkProtocolNumber, nicID tcpip.NICID, fnName string) (forward bool, ok bool) {
	switch forwarding, err := forwardingFn(proto); err.(type) {
	case nil:
		return forwarding, true
	case *tcpip.ErrUnknownProtocol:
		panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nicID))
	case *tcpip.ErrNotSupported:
		// Not all network protocols support forwarding.
	default:
		panic(fmt.Sprintf("nic(id=%d).%s(%d): %s", nicID, fnName, proto, err))
	}
	return false, false
}

// precondition: s.mu is held.
func (s *Stack) nicInfo(nic *nic, id tcpip.NICID) *NICInfo {
	flags := NICStateFlags{
		Up:          true, // Netstack interfaces are always up.
		Running:     nic.Enabled(),
		Promiscuous: nic.Promiscuous(),
		Loopback:    nic.IsLoopback(),
	}

	netStats := make(map[tcpip.NetworkProtocolNumber]NetworkEndpointStats)
	for proto, netEP := range nic.networkEndpoints {
		netStats[proto] = netEP.Stats()
	}

	info := NICInfo{
		Name:              nic.name,
		LinkAddress:       nic.LinkAddress(),
		ProtocolAddresses: nic.primaryAddresses(),
		Flags:             flags,
		MTU:               nic.MTU(),
		Stats:             nic.stats.local,
		NetworkStats:      netStats,
		Context:           nic.context,
		Forwarding:        make(map[tcpip.NetworkProtocolNumber]bool),
	}

	for proto := range s.networkProtocols {
		if forwarding, ok := forwardingValue(nic.forwarding, proto, id, "forwarding"); ok {
			info.Forwarding[proto] = forwarding
		}

	}

	if nic.Primary != nil {
		info.Primary = nic.Primary.id
	}

	return &info
}

// SingleNICInfo returns the NICInfo for the given NICID.
func (s *Stack) SingleNICInfo(id tcpip.NICID) (*NICInfo, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; !ok {
		return nil, false
	} else {
		return s.nicInfo(nic, id), true
	}
}

// NICInfo returns a map of NICIDs to their associated information.
func (s *Stack) NICInfo() map[tcpip.NICID]NICInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID]NICInfo)
	for id, nic := range s.nics {
		nics[id] = *s.nicInfo(nic, id)
	}
	return nics
}

// NICStateFlags holds information about the state of an NIC.
type NICStateFlags struct {
	// Up indicates whether the interface is running.
	Up bool

	// Running indicates whether resources are allocated.
	Running bool

	// Promiscuous indicates whether the interface is in promiscuous mode.
	Promiscuous bool

	// Loopback indicates whether the interface is a loopback.
	Loopback bool
}

// AddProtocolAddress adds an address to the specified NIC, possibly with extra
// properties.
func (s *Stack) AddProtocolAddress(id tcpip.NICID, protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	return nic.addAddress(protocolAddress, properties)
}

// RemoveAddress removes an existing network-layer address from the specified
// NIC.
func (s *Stack) RemoveAddress(id tcpip.NICID, addr tcpip.Address) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.removeAddress(addr)
	}

	return &tcpip.ErrUnknownNICID{}
}

// SetAddressLifetimes sets informational preferred and valid lifetimes, and
// whether the address should be preferred or deprecated.
func (s *Stack) SetAddressLifetimes(id tcpip.NICID, addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nic, ok := s.nics[id]; ok {
		return nic.setAddressLifetimes(addr, lifetimes)
	}

	return &tcpip.ErrUnknownNICID{}
}

// AllAddresses returns a map of NICIDs to their protocol addresses (primary
// and non-primary).
func (s *Stack) AllAddresses() map[tcpip.NICID][]tcpip.ProtocolAddress {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nics := make(map[tcpip.NICID][]tcpip.ProtocolAddress)
	for id, nic := range s.nics {
		nics[id] = nic.allPermanentAddresses()
	}
	return nics
}

// GetMainNICAddress returns the first non-deprecated primary address and prefix
// for the given NIC and protocol. If no non-deprecated primary addresses exist,
// a deprecated address will be returned. If no deprecated addresses exist, the
// zero value will be returned.
func (s *Stack) GetMainNICAddress(id tcpip.NICID, protocol tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownNICID{}
	}

	return nic.PrimaryAddress(protocol)
}

func (s *Stack) getAddressEP(nic *nic, localAddr, remoteAddr, srcHint tcpip.Address, netProto tcpip.NetworkProtocolNumber) AssignableAddressEndpoint {
	if localAddr.BitLen() == 0 {
		return nic.primaryEndpoint(netProto, remoteAddr, srcHint)
	}
	return nic.findEndpoint(netProto, localAddr, CanBePrimaryEndpoint)
}

// NewRouteForMulticast returns a Route that may be used to forward multicast
// packets.
//
// Returns nil if validation fails.
func (s *Stack) NewRouteForMulticast(nicID tcpip.NICID, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok || !nic.Enabled() {
		return nil
	}

	if addressEndpoint := s.getAddressEP(nic, tcpip.Address{} /* localAddr */, remoteAddr, tcpip.Address{} /* srcHint */, netProto); addressEndpoint != nil {
		return constructAndValidateRoute(netProto, addressEndpoint, nic, nic, tcpip.Address{} /* gateway */, tcpip.Address{} /* localAddr */, remoteAddr, s.handleLocal, false /* multicastLoop */, 0 /* mtu */)
	}
	return nil
}

// findLocalRouteFromNICRLocked is like findLocalRouteRLocked but finds a route
// from the specified NIC.
//
// +checklocksread:s.mu
func (s *Stack) findLocalRouteFromNICRLocked(localAddressNIC *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, false /* createTemp */, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	var outgoingNIC *nic
	// Prefer a local route to the same interface as the local address.
	if localAddressNIC.hasAddress(netProto, remoteAddr) {
		outgoingNIC = localAddressNIC
	}

	// If the remote address isn't owned by the local address's NIC, check all
	// NICs.
	if outgoingNIC == nil {
		for _, nic := range s.nics {
			if nic.hasAddress(netProto, remoteAddr) {
				outgoingNIC = nic
				break
			}
		}
	}

	// If the remote address is not owned by the stack, we can't return a local
	// route.
	if outgoingNIC == nil {
		localAddressEndpoint.DecRef()
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		outgoingNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

func (s *Stack) loopbackLocalRoute(localAddressNIC *nic, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	localAddressEndpoint := localAddressNIC.getAddressOrCreateTempInner(netProto, localAddr, true /* createTemp */, NeverPrimaryEndpoint)
	if localAddressEndpoint == nil {
		return nil
	}

	r := makeLocalRoute(
		netProto,
		localAddr,
		remoteAddr,
		localAddressNIC,
		localAddressNIC,
		localAddressEndpoint,
	)

	if r.IsOutboundBroadcast() {
		r.Release()
		return nil
	}

	return r
}

// findLocalRouteRLocked returns a local route.
//
// A local route is a route to some remote address which the stack owns. That
// is, a local route is a route where packets never have to leave the stack.
//
// +checklocksread:s.mu
func (s *Stack) findLocalRouteRLocked(localAddressNICID tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber) *Route {
	if localAddr.BitLen() == 0 {
		localAddr = remoteAddr
	}

	if localAddressNICID == 0 {
		if s.loopbackNIC != nil {
			// Send all packets directed to local ip addresses through the loopback device.
			for _, nic := range s.nics {
				if !nic.hasAddress(netProto, remoteAddr) {
					continue
				}
				if isSubnetBroadcastOnNIC(nic, netProto, remoteAddr) {
					break
				}
				if r := s.loopbackLocalRoute(s.loopbackNIC, localAddr, remoteAddr, netProto); r != nil {
					return r
				}
				break
			}
		}

		for _, localAddressNIC := range s.nics {
			if r := s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto); r != nil {
				return r
			}
		}

		return nil
	}

	if localAddressNIC, ok := s.nics[localAddressNICID]; ok {
		return s.findLocalRouteFromNICRLocked(localAddressNIC, localAddr, remoteAddr, netProto)
	}

	return nil
}

// HandleLocal returns true if non-loopback interfaces are allowed to loop packets.
func (s *Stack) HandleLocal() bool {
	return s.handleLocal
}

func isNICForwarding(nic *nic, proto tcpip.NetworkProtocolNumber) bool {
	switch forwarding, err := nic.forwarding(proto); err.(type) {
	case nil:
		return forwarding
	case *tcpip.ErrUnknownProtocol:
		panic(fmt.Sprintf("expected network protocol %d to be available on NIC %d", proto, nic.ID()))
	case *tcpip.ErrNotSupported:
		// Not all network protocols support forwarding.
		return false
	default:
		panic(fmt.Sprintf("nic(id=%d).forwarding(%d): %s", nic.ID(), proto, err))
	}
}

// findRouteWithLocalAddrFromAnyInterfaceRLocked returns a route to the given
// destination address, leaving through the given NIC.
//
// Rather than preferring to find a route that uses a local address assigned to
// the outgoing interface, it finds any NIC that holds a matching local address
// endpoint.
//
// +checklocksread:s.mu
func (s *Stack) findRouteWithLocalAddrFromAnyInterfaceRLocked(outgoingNIC *nic, localAddr, remoteAddr, srcHint, gateway tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool, mtu uint32) *Route {
	for _, aNIC := range s.nics {
		addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, srcHint, netProto)
		if addressEndpoint == nil {
			continue
		}

		if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, outgoingNIC, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, mtu); r != nil {
			return r
		}
	}
	return nil
}

// FindRoute creates a route to the given destination address, leaving through
// the given NIC and local address (if provided).
//
// If a NIC is not specified, the returned route will leave through the same
// NIC as the NIC that has the local address assigned when forwarding is
// disabled. If forwarding is enabled and the NIC is unspecified, the route may
// leave through any interface unless the route is link-local.
//
// If no local address is provided, the stack will select a local address. If no
// remote address is provided, the stack will use a remote address equal to the
// local address.
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (*Route, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Reject attempts to use unsupported protocols.
	if !s.CheckNetworkProtocol(netProto) {
		return nil, &tcpip.ErrUnknownProtocol{}
	}

	isLinkLocal := header.IsV6LinkLocalUnicastAddress(remoteAddr) || header.IsV6LinkLocalMulticastAddress(remoteAddr)
	isLocalBroadcast := remoteAddr == header.IPv4Broadcast
	isMulticast := header.IsV4MulticastAddress(remoteAddr) || header.IsV6MulticastAddress(remoteAddr)
	isLoopback := header.IsV4LoopbackAddress(remoteAddr) || header.IsV6LoopbackAddress(remoteAddr)
	needRoute := !isLocalBroadcast && !isMulticast && !isLinkLocal && !isLoopback

	if s.handleLocal && !isMulticast && !isLocalBroadcast {
		if r := s.findLocalRouteRLocked(id, localAddr, remoteAddr, netProto); r != nil {
			return r, nil
		}
	}

	// If the interface is specified and we do not need a route, return a route
	// through the interface if the interface is valid and enabled.
	if id != 0 && !needRoute {
		if nic, ok := s.nics[id]; ok && nic.Enabled() {
			if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, tcpip.Address{} /* srcHint */, netProto); addressEndpoint != nil {
				return makeRoute(
					netProto,
					tcpip.Address{}, /* gateway */
					localAddr,
					remoteAddr,
					nic, /* outgoingNIC */
					nic, /* localAddressNIC*/
					addressEndpoint,
					s.handleLocal,
					multicastLoop,
					0, /* mtu */
				), nil
			}
		}

		if isLoopback {
			return nil, &tcpip.ErrBadLocalAddress{}
		}
		return nil, &tcpip.ErrNetworkUnreachable{}
	}

	onlyGlobalAddresses := !header.IsV6LinkLocalUnicastAddress(localAddr) && !isLinkLocal

	// Find a route to the remote with the route table.
	var chosenRoute tcpip.Route
	if r := func() *Route {
		s.routeMu.RLock()
		defer s.routeMu.RUnlock()

		for route := s.routeTable.Front(); route != nil; route = route.Next() {
			if remoteAddr.BitLen() != 0 && !route.Destination.Contains(remoteAddr) {
				continue
			}

			nic, ok := s.nics[route.NIC]
			if !ok || !nic.Enabled() {
				continue
			}

			if id == 0 || id == route.NIC {
				if addressEndpoint := s.getAddressEP(nic, localAddr, remoteAddr, route.SourceHint, netProto); addressEndpoint != nil {
					var gateway tcpip.Address
					if needRoute {
						gateway = route.Gateway
					}
					r := constructAndValidateRoute(netProto, addressEndpoint, nic /* outgoingNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, route.MTU)
					if r == nil {
						panic(fmt.Sprintf("non-forwarding route validation failed with route table entry = %#v, id = %d, localAddr = %s, remoteAddr = %s", route, id, localAddr, remoteAddr))
					}
					return r
				}
			}

			// If the stack has forwarding enabled, we haven't found a valid route to
			// the remote address yet, and we are routing locally generated traffic,
			// keep track of the first valid route. We keep iterating because we
			// prefer routes that let us use a local address that is assigned to the
			// outgoing interface. There is no requirement to do this from any RFC
			// but simply a choice made to better follow a strong host model which
			// the netstack follows at the time of writing.
			//
			// Note that for incoming traffic that we are forwarding (for which the
			// NIC and local address are unspecified), we do not keep iterating, as
			// there is no reason to prefer routes that let us use a local address
			// when routing forwarded (as opposed to locally-generated) traffic.
			locallyGenerated := (id != 0 || localAddr != tcpip.Address{})
			if onlyGlobalAddresses && chosenRoute.Equal(tcpip.Route{}) && isNICForwarding(nic, netProto) {
				if locallyGenerated {
					chosenRoute = *route
					continue
				}

				if r := s.findRouteWithLocalAddrFromAnyInterfaceRLocked(nic, localAddr, remoteAddr, route.SourceHint, route.Gateway, netProto, multicastLoop, route.MTU); r != nil {
					return r
				}
			}
		}

		return nil
	}(); r != nil {
		return r, nil
	}

	if !chosenRoute.Equal(tcpip.Route{}) {
		// At this point we know the stack has forwarding enabled since chosenRoute is
		// only set when forwarding is enabled.
		nic, ok := s.nics[chosenRoute.NIC]
		if !ok {
			// If the route's NIC was invalid, we should not have chosen the route.
			panic(fmt.Sprintf("chosen route must have a valid NIC with ID = %d", chosenRoute.NIC))
		}

		var gateway tcpip.Address
		if needRoute {
			gateway = chosenRoute.Gateway
		}

		// Use the specified NIC to get the local address endpoint.
		if id != 0 {
			if aNIC, ok := s.nics[id]; ok {
				if addressEndpoint := s.getAddressEP(aNIC, localAddr, remoteAddr, chosenRoute.SourceHint, netProto); addressEndpoint != nil {
					if r := constructAndValidateRoute(netProto, addressEndpoint, aNIC /* localAddressNIC */, nic /* outgoingNIC */, gateway, localAddr, remoteAddr, s.handleLocal, multicastLoop, chosenRoute.MTU); r != nil {
						return r, nil
					}
				}
			}

			return nil, &tcpip.ErrNetworkUnreachable{}
		}

		if id == 0 {
			// If an interface is not specified, try to find a NIC that holds the local
			// address endpoint to construct a route.
			if r := s.findRouteWithLocalAddrFromAnyInterfaceRLocked(nic, localAddr, remoteAddr, chosenRoute.SourceHint, gateway, netProto, multicastLoop, chosenRoute.MTU); r != nil {
				return r, nil
			}
		}
	}

	if needRoute {
		return nil, &tcpip.ErrNetworkUnreachable{}
	}
	if header.IsV6LoopbackAddress(remoteAddr) {
		return nil, &tcpip.ErrBadLocalAddress{}
	}
	return nil, &tcpip.ErrNetworkUnreachable{}
}

// CheckNetworkProtocol checks if a given network protocol is enabled in the
// stack.
func (s *Stack) CheckNetworkProtocol(protocol tcpip.NetworkProtocolNumber) bool {
	_, ok := s.networkProtocols[protocol]
	return ok
}

// CheckLocalAddress determines if the given local address exists, and if it
// does, returns the id of the NIC it's bound to. Returns 0 if the address
// does not exist.
func (s *Stack) CheckLocalAddress(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) tcpip.NICID {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// If a NIC is specified, use its NIC id.
	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return 0
		}
		// In IPv4, linux only checks the interface. If it matches, then it does
		// not bother with the address.
		// https://github.com/torvalds/linux/blob/15205c2829ca2cbb5ece5ceaafe1171a8470e62b/net/ipv4/igmp.c#L1829-L1837
		if protocol == header.IPv4ProtocolNumber {
			return nic.id
		}
		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}
		return 0
	}

	// Go through all the NICs.
	for _, nic := range s.nics {
		if nic.CheckLocalAddress(protocol, addr) {
			return nic.id
		}
	}

	return 0
}

// SetPromiscuousMode enables or disables promiscuous mode in the given NIC.
func (s *Stack) SetPromiscuousMode(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setPromiscuousMode(enable)

	return nil
}

// SetSpoofing enables or disables address spoofing in the given NIC, allowing
// endpoints to bind to any address in the NIC.
func (s *Stack) SetSpoofing(nicID tcpip.NICID, enable bool) tcpip.Error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	nic.setSpoofing(enable)

	return nil
}

// RegisterTransportEndpoint registers the given endpoint with the stack
// transport dispatcher. Received packets that match the provided id will be
// delivered to the given endpoint; specifying a nic is optional, but
// nic-specific IDs have precedence over global ones.
func (s *Stack) RegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.registerEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CheckRegisterTransportEndpoint checks if an endpoint can be registered with
// the stack transport dispatcher.
func (s *Stack) CheckRegisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, flags ports.Flags, bindToDevice tcpip.NICID) tcpip.Error {
	return s.demux.checkEndpoint(netProtos, protocol, id, flags, bindToDevice)
}

// UnregisterTransportEndpoint removes the endpoint with the given id from the
// stack transport dispatcher.
func (s *Stack) UnregisterTransportEndpoint(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// StartTransportEndpointCleanup removes the endpoint with the given id from
// the stack transport dispatcher. It also transitions it to the cleanup stage.
func (s *Stack) StartTransportEndpointCleanup(netProtos []tcpip.NetworkProtocolNumber, protocol tcpip.TransportProtocolNumber, id TransportEndpointID, ep TransportEndpoint, flags ports.Flags, bindToDevice tcpip.NICID) {
	s.cleanupEndpointsMu.Lock()
	s.cleanupEndpoints[ep] = struct{}{}
	s.cleanupEndpointsMu.Unlock()

	s.demux.unregisterEndpoint(netProtos, protocol, id, ep, flags, bindToDevice)
}

// CompleteTransportEndpointCleanup removes the endpoint from the cleanup
// stage.
func (s *Stack) CompleteTransportEndpointCleanup(ep TransportEndpoint) {
	s.cleanupEndpointsMu.Lock()
	delete(s.cleanupEndpoints, ep)
	s.cleanupEndpointsMu.Unlock()
}

// FindTransportEndpoint finds an endpoint that most closely matches the provided
// id. If no endpoint is found it returns nil.
func (s *Stack) FindTransportEndpoint(netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, id TransportEndpointID, nicID tcpip.NICID) TransportEndpoint {
	return s.demux.findTransportEndpoint(netProto, transProto, id, nicID)
}

// RegisteredEndpoints returns all endpoints which are currently registered.
func (s *Stack) RegisteredEndpoints() []TransportEndpoint {
	s.mu.Lock()
	defer s.mu.Unlock()

	var es []TransportEndpoint
	for _, e := range s.demux.protocol {
		es = append(es, e.transportEndpoints()...)
	}
	return es
}

// CleanupEndpoints returns endpoints currently in the cleanup state.
func (s *Stack) CleanupEndpoints() []TransportEndpoint {
	s.cleanupEndpointsMu.Lock()
	defer s.cleanupEndpointsMu.Unlock()

	es := make([]TransportEndpoint, 0, len(s.cleanupEndpoints))
	for e := range s.cleanupEndpoints {
		es = append(es, e)
	}
	return es
}

// Close closes all currently registered transport endpoints.
//
// Endpoints created or modified during this call may not get closed.
func (s *Stack) Close() {
	for _, e := range s.RegisteredEndpoints() {
		e.Abort()
	}
	for _, p := range s.transportProtocols {
		p.proto.Close()
	}
	for _, p := range s.networkProtocols {
		p.Close()
	}
}

// Wait waits for all transport and link endpoints to halt their worker
// goroutines.
//
// Endpoints created or modified during this call may not get waited on.
//
// Note that link endpoints must be stopped via an implementation specific
// mechanism.
func (s *Stack) Wait() {
	for _, e := range s.RegisteredEndpoints() {
		e.Wait()
	}
	for _, e := range s.CleanupEndpoints() {
		e.Wait()
	}
	for _, p := range s.transportProtocols {
		p.proto.Wait()
	}
	for _, p := range s.networkProtocols {
		p.Wait()
	}

	deferActs := make([]func(), 0)

	s.mu.Lock()
	for id, n := range s.nics {
		// Remove NIC to ensure that qDisc goroutines are correctly
		// terminated on stack teardown.
		act, _ := s.removeNICLocked(id, true /* closeLinkEndpoint */)
		n.Wait()
		if act != nil {
			deferActs = append(deferActs, act)
		}
	}
	s.mu.Unlock()

	for _, act := range deferActs {
		act()
	}
}

// Destroy destroys the stack with all endpoints.
func (s *Stack) Destroy() {
	s.Close()
	s.Wait()
}

// WritePacketToRemote writes a payload on the specified NIC using the provided
// network protocol and remote link address.
func (s *Stack) WritePacketToRemote(nicID tcpip.NICID, remote tcpip.LinkAddress, netProto tcpip.NetworkProtocolNumber, payload buffer.Buffer) tcpip.Error {
	s.mu.Lock()
	nic, ok := s.nics[nicID]
	s.mu.Unlock()
	if !ok {
		return &tcpip.ErrUnknownDevice{}
	}
	pkt := NewPacketBuffer(PacketBufferOptions{
		ReserveHeaderBytes: int(nic.MaxHeaderLength()),
		Payload:            payload,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = netProto
	return nic.WritePacketToRemote(remote, pkt)
}

// WriteRawPacket writes data directly to the specified NIC without adding any
// headers.
func (s *Stack) WriteRawPacket(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber, payload buffer.Buffer) tcpip.Error {
	s.mu.RLock()
	nic, ok := s.nics[nicID]
	s.mu.RUnlock()
	if !ok {
		return &tcpip.ErrUnknownNICID{}
	}

	pkt := NewPacketBuffer(PacketBufferOptions{
		Payload: payload,
	})
	defer pkt.DecRef()
	pkt.NetworkProtocolNumber = proto
	return nic.writeRawPacketWithLinkHeaderInPayload(pkt)
}

// NetworkProtocolInstance returns the protocol instance in the stack for the
// specified network protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) NetworkProtocolInstance(num tcpip.NetworkProtocolNumber) NetworkProtocol {
	if p, ok := s.networkProtocols[num]; ok {
		return p
	}
	return nil
}

// TransportProtocolInstance returns the protocol instance in the stack for the
// specified transport protocol. This method is public for protocol implementers
// and tests to use.
func (s *Stack) TransportProtocolInstance(num tcpip.TransportProtocolNumber) TransportProtocol {
	if pState, ok := s.transportProtocols[num]; ok {
		return pState.proto
	}
	return nil
}

// GetNetworkEndpoint returns the NetworkEndpoint with the specified protocol
// number installed on the specified NIC.
func (s *Stack) GetNetworkEndpoint(nicID tcpip.NICID, proto tcpip.NetworkProtocolNumber) (NetworkEndpoint, tcpip.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nic, ok := s.nics[nicID]
	if !ok {
		return nil, &tcpip.ErrUnknownNICID{}
	}

	return nic.getNetworkEndpoint(proto), nil
}

// SecureRNG returns the stack's cryptographically secure random number
// generator.
func (s *Stack) SecureRNG() io.Reader {
	return s.secureRNG
}

// FindNICNameFromID returns the name of the NIC for the given NICID.
func (s *Stack) FindNICNameFromID(id tcpip.NICID) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nic, ok := s.nics[id]
	if !ok {
		return ""
	}

	return nic.Name()
}

// ParseResult indicates the result of a parsing attempt.
type ParseResult int

const (
	// ParsedOK indicates that a packet was successfully parsed.
	ParsedOK ParseResult = iota

	// UnknownTransportProtocol indicates that the transport protocol is unknown.
	UnknownTransportProtocol

	// TransportLayerParseError indicates that the transport packet was not
	// successfully parsed.
	TransportLayerParseError
)

// ParsePacketBufferTransport parses the provided packet buffer's transport
// header.
func (s *Stack) ParsePacketBufferTransport(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) ParseResult {
	pkt.TransportProtocolNumber = protocol
	// Parse the transport header if present.
	state, ok := s.transportProtocols[protocol]
	if !ok {
		return UnknownTransportProtocol
	}

	if !state.proto.Parse(pkt) {
		return TransportLayerParseError
	}

	return ParsedOK
}

// networkProtocolNumbers returns the network protocol numbers the stack is
// configured with.
func (s *Stack) networkProtocolNumbers() []tcpip.NetworkProtocolNumber {
	protos := make([]tcpip.NetworkProtocolNumber, 0, len(s.networkProtocols))
	for p := range s.networkProtocols {
		protos = append(protos, p)
	}
	return protos
}

func isSubnetBroadcastOnNIC(nic *nic, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	addressEndpoint := nic.getAddressOrCreateTempInner(protocol, addr, false /* createTemp */, NeverPrimaryEndpoint)
	if addressEndpoint == nil {
		return false
	}

	subnet := addressEndpoint.Subnet()
	addressEndpoint.DecRef()
	return subnet.IsBroadcast(addr)
}

// IsSubnetBroadcast returns true if the provided address is a subnet-local
// broadcast address on the specified NIC and protocol.
//
// Returns false if the NIC is unknown or if the protocol is unknown or does
// not support addressing.
//
// If the NIC is not specified, the stack will check all NICs.
func (s *Stack) IsSubnetBroadcast(nicID tcpip.NICID, protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if nicID != 0 {
		nic, ok := s.nics[nicID]
		if !ok {
			return false
		}

		return isSubnetBroadcastOnNIC(nic, protocol, addr)
	}

	for _, nic := range s.nics {
		if isSubnetBroadcastOnNIC(nic, protocol, addr) {
			return true
		}
	}

	return false
}

// SetNICStack moves the network device to the specified network namespace.
func (s *Stack) SetNICStack(id tcpip.NICID, peer *Stack) (tcpip.NICID, tcpip.Error) {
	s.mu.Lock()
	nic, ok := s.nics[id]
	if !ok {
		s.mu.Unlock()
		return 0, &tcpip.ErrUnknownNICID{}
	}
	if s == peer {
		s.mu.Unlock()
		return id, nil
	}

	linkEp := nic.NetworkLinkEndpoint.(LinkEndpoint)
	name := nic.Name()

	deferAct, err := s.removeNICLocked(id, false /* closeLinkEndpoint */)
	s.mu.Unlock()
	if deferAct != nil {
		deferAct()
	}
	if err != nil {
		return 0, err
	}

	id = tcpip.NICID(peer.NextNICID())
	return id, peer.CreateNICWithOptions(id, linkEp, NICOptions{Name: name})
}
