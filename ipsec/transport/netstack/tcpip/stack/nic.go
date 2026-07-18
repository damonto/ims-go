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

package stack

import (
	"fmt"
	"reflect"
	"sort"
	"sync/atomic"

	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
)

var _ NetworkInterface = (*nic)(nil)
var _ NetworkDispatcher = (*nic)(nil)

// nic represents a "network interface card" to which the networking stack is
// attached.
type nic struct {
	NetworkLinkEndpoint

	stack   *Stack
	id      tcpip.NICID
	name    string
	context NICContext

	stats sharedStats

	// enableDisableMu is used to synchronize attempts to enable/disable the NIC.
	// Without this mutex, calls to enable/disable the NIC may interleave and
	// leave the NIC in an inconsistent state.
	enableDisableMu nicRWMutex

	// The network endpoints themselves may be modified by calling the interface's
	// methods, but the map reference and entries must be constant.
	networkEndpoints map[tcpip.NetworkProtocolNumber]NetworkEndpoint

	// enabled indicates whether the NIC is enabled.
	enabled atomic.Bool

	// spoofing indicates whether the NIC is spoofing.
	spoofing atomic.Bool

	// promiscuous indicates whether the NIC is promiscuous.
	promiscuous atomic.Bool

	qDisc QueueingDiscipline

	// Primary is the main controlling interface in a bonded setup.
	Primary *nic

	// experimentIPOptionEnabled indicates whether the NIC supports the
	// experiment IP option.
	experimentIPOptionEnabled bool
}

// makeNICStats initializes the NIC statistics and associates them to the global
// NIC statistics.
func makeNICStats(global tcpip.NICStats) sharedStats {
	var stats sharedStats
	tcpip.InitStatCounters(reflect.ValueOf(&stats.local).Elem())
	stats.init(&stats.local, &global)
	return stats
}

var _ QueueingDiscipline = (*delegatingQueueingDiscipline)(nil)

type delegatingQueueingDiscipline struct {
	LinkWriter
}

func (*delegatingQueueingDiscipline) Close() {}

// WritePacket passes the packet through to the underlying LinkWriter's WritePackets.
func (qDisc *delegatingQueueingDiscipline) WritePacket(pkt *PacketBuffer) tcpip.Error {
	var pkts PacketBufferList
	pkts.PushBack(pkt)
	_, err := qDisc.LinkWriter.WritePackets(pkts)
	return err
}

// newNIC returns a NIC backed by ep.
func newNIC(stack *Stack, id tcpip.NICID, ep LinkEndpoint, opts NICOptions) *nic {
	// TODO(b/141011931): Validate a LinkEndpoint (ep) is valid. For
	// example, make sure that the link address it provides is a valid
	// unicast ethernet address.

	// If no queueing discipline was specified provide a stub implementation that
	// just delegates to the lower link endpoint.
	qDisc := opts.QDisc
	if qDisc == nil {
		qDisc = &delegatingQueueingDiscipline{LinkWriter: ep}
	}

	// TODO(b/143357959): RFC 8200 section 5 requires that IPv6 endpoints
	// observe an MTU of at least 1280 bytes. Ensure that this requirement
	// of IPv6 is supported on this endpoint's LinkEndpoint.
	nic := &nic{
		NetworkLinkEndpoint:       ep,
		stack:                     stack,
		id:                        id,
		name:                      opts.Name,
		context:                   opts.Context,
		stats:                     makeNICStats(stack.Stats().NICs),
		networkEndpoints:          make(map[tcpip.NetworkProtocolNumber]NetworkEndpoint),
		qDisc:                     qDisc,
		experimentIPOptionEnabled: opts.EnableExperimentIPOption,
	}
	for _, netProto := range stack.networkProtocols {
		netNum := netProto.Number()
		netEP := netProto.NewEndpoint(nic, nic)
		nic.networkEndpoints[netNum] = netEP

	}

	nic.NetworkLinkEndpoint.Attach(nic)

	return nic
}

func (n *nic) getNetworkEndpoint(proto tcpip.NetworkProtocolNumber) NetworkEndpoint {
	return n.networkEndpoints[proto]
}

// Enabled implements NetworkInterface.
func (n *nic) Enabled() bool {
	return n.enabled.Load()
}

// setEnabled sets the enabled status for the NIC.
//
// Returns true if the enabled status was updated.
//
// +checklocks:n.enableDisableMu
func (n *nic) setEnabled(v bool) bool {
	return n.enabled.Swap(v) != v
}

// disable disables n.
//
// It undoes the work done by enable.
func (n *nic) disable() {
	n.enableDisableMu.Lock()
	defer n.enableDisableMu.Unlock()
	n.disableLocked()
}

// disableLocked disables n.
//
// It undoes the work done by enable.
//
// +checklocks:n.enableDisableMu
func (n *nic) disableLocked() {
	if !n.Enabled() {
		return
	}

	// TODO(gvisor.dev/issue/1491): Should Routes that are currently bound to n be
	// invalidated? Currently, Routes will continue to work when a NIC is enabled
	// again, and applications may not know that the underlying NIC was ever
	// disabled.

	for _, ep := range n.networkEndpoints {
		ep.Disable()

	}

	if !n.setEnabled(false) {
		panic("should have only done work to disable the NIC if it was enabled")
	}
}

// enable enables n and its network endpoints.
func (n *nic) enable() tcpip.Error {
	n.enableDisableMu.Lock()
	defer n.enableDisableMu.Unlock()

	if !n.setEnabled(true) {
		return nil
	}

	for _, ep := range n.networkEndpoints {
		if err := ep.Enable(); err != nil {
			return err
		}
	}

	return nil
}

// remove detaches NIC from the link endpoint and releases network endpoint
// resources. This guarantees no packets between this NIC and the network
// stack.
//
// It returns an action that has to be executed after releasing the Stack lock
// and any error encountered.
func (n *nic) remove(closeLinkEndpoint bool) (func(), tcpip.Error) {
	n.enableDisableMu.Lock()

	n.disableLocked()

	for _, ep := range n.networkEndpoints {
		ep.Close()
	}

	n.enableDisableMu.Unlock()

	var deferAct func()
	// Prevent packets from going down to the link before shutting the link down.
	n.qDisc.Close()
	n.NetworkLinkEndpoint.Attach(nil)
	if closeLinkEndpoint {
		ep := n.NetworkLinkEndpoint
		ep.SetOnCloseAction(nil)
		// The link endpoint has to be closed without holding a
		// netstack lock, because it can trigger other netstack
		// operations.
		deferAct = ep.Close
	}

	return deferAct, nil
}

// setPromiscuousMode enables or disables promiscuous mode.
func (n *nic) setPromiscuousMode(enable bool) {
	n.promiscuous.Store(enable)
}

// Promiscuous implements NetworkInterface.
func (n *nic) Promiscuous() bool {
	return n.promiscuous.Load()
}

// IsLoopback implements NetworkInterface.
func (n *nic) IsLoopback() bool {
	return n.NetworkLinkEndpoint.Capabilities()&CapabilityLoopback != 0
}

// WritePacket implements NetworkEndpoint.
func (n *nic) WritePacket(r *Route, pkt *PacketBuffer) tcpip.Error {
	pkt.EgressRoute = r.Fields()
	return n.writePacket(pkt)
}

// WritePacketToRemote implements NetworkInterface.
func (n *nic) WritePacketToRemote(remoteLinkAddr tcpip.LinkAddress, pkt *PacketBuffer) tcpip.Error {
	pkt.EgressRoute = RouteInfo{
		routeInfo: routeInfo{
			NetProto:         pkt.NetworkProtocolNumber,
			LocalLinkAddress: n.LinkAddress(),
		},
		RemoteLinkAddress: remoteLinkAddr,
	}
	return n.writePacket(pkt)
}

func (n *nic) writePacket(pkt *PacketBuffer) tcpip.Error {
	n.NetworkLinkEndpoint.AddHeader(pkt)
	return n.writeRawPacket(pkt)
}

func (n *nic) writeRawPacketWithLinkHeaderInPayload(pkt *PacketBuffer) tcpip.Error {
	if !n.NetworkLinkEndpoint.ParseHeader(pkt) {
		return &tcpip.ErrMalformedHeader{}
	}
	return n.writeRawPacket(pkt)
}

func (n *nic) writeRawPacket(pkt *PacketBuffer) tcpip.Error {
	if err := n.qDisc.WritePacket(pkt); err != nil {
		if _, ok := err.(*tcpip.ErrNoBufferSpace); ok {
			n.stats.txPacketsDroppedNoBufferSpace.Increment()
		}
		return err
	}

	n.stats.tx.packets.Increment()
	n.stats.tx.bytes.IncrementBy(uint64(pkt.Size()))
	return nil
}

// setSpoofing enables or disables address spoofing.
func (n *nic) setSpoofing(enable bool) {
	n.spoofing.Store(enable)
}

// Spoofing implements NetworkInterface.
func (n *nic) Spoofing() bool {
	return n.spoofing.Load()
}

// primaryAddress returns an address that can be used to communicate with
// remoteAddr.
func (n *nic) primaryEndpoint(protocol tcpip.NetworkProtocolNumber, remoteAddr, srcHint tcpip.Address) AssignableAddressEndpoint {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireOutgoingPrimaryAddress(remoteAddr, srcHint, n.Spoofing())
}

type getAddressBehaviour int

const (
	// spoofing indicates that the NIC's spoofing flag should be observed when
	// getting a NIC's address endpoint.
	spoofing getAddressBehaviour = iota

	// promiscuous indicates that the NIC's promiscuous flag should be observed
	// when getting a NIC's address endpoint.
	promiscuous
)

func (n *nic) getAddress(protocol tcpip.NetworkProtocolNumber, dst tcpip.Address) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, dst, CanBePrimaryEndpoint, promiscuous)
}

func (n *nic) hasAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	ep := n.getAddressOrCreateTempInner(protocol, addr, false, NeverPrimaryEndpoint)
	if ep != nil {
		ep.DecRef()
		return true
	}

	return false
}

// findEndpoint finds the endpoint, if any, with the given address.
func (n *nic) findEndpoint(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	return n.getAddressOrCreateTemp(protocol, address, peb, spoofing)
}

// getAddressEpOrCreateTemp returns the address endpoint for the given protocol
// and address.
//
// If none exists a temporary one may be created if we are in promiscuous mode
// or spoofing. Promiscuous mode will only be checked if promiscuous is true.
// Similarly, spoofing will only be checked if spoofing is true.
//
// If the address is the IPv4 broadcast address for an endpoint's network, that
// endpoint will be returned.
func (n *nic) getAddressOrCreateTemp(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, peb PrimaryEndpointBehavior, tempRef getAddressBehaviour) AssignableAddressEndpoint {
	var spoofingOrPromiscuous bool
	switch tempRef {
	case spoofing:
		spoofingOrPromiscuous = n.Spoofing()
	case promiscuous:
		spoofingOrPromiscuous = n.Promiscuous()
	}
	return n.getAddressOrCreateTempInner(protocol, address, spoofingOrPromiscuous, peb)
}

// getAddressOrCreateTempInner is like getAddressEpOrCreateTemp except a boolean
// is passed to indicate whether or not we should generate temporary endpoints.
func (n *nic) getAddressOrCreateTempInner(protocol tcpip.NetworkProtocolNumber, address tcpip.Address, createTemp bool, peb PrimaryEndpointBehavior) AssignableAddressEndpoint {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return nil
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return nil
	}

	return addressableEndpoint.AcquireAssignedAddress(address, createTemp, peb, false)
}

// addAddress adds a new address to n, so that it starts accepting packets
// targeted at the given address (and network protocol).
func (n *nic) addAddress(protocolAddress tcpip.ProtocolAddress, properties AddressProperties) tcpip.Error {
	ep := n.getNetworkEndpoint(protocolAddress.Protocol)
	if ep == nil {
		return &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return &tcpip.ErrNotSupported{}
	}

	addressEndpoint, err := addressableEndpoint.AddAndAcquirePermanentAddress(protocolAddress.AddressWithPrefix, properties)
	if err == nil {
		// We have no need for the address endpoint.
		addressEndpoint.DecRef()
	}
	return err
}

// allPermanentAddresses returns all permanent addresses associated with
// this NIC.
func (n *nic) allPermanentAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress
	for p, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		for _, a := range addressableEndpoint.PermanentAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// primaryAddresses returns the primary addresses associated with this NIC.
func (n *nic) primaryAddresses() []tcpip.ProtocolAddress {
	var addrs []tcpip.ProtocolAddress

	protocolNumbers := make([]tcpip.NetworkProtocolNumber, 0, len(n.networkEndpoints))
	for p := range n.networkEndpoints {
		protocolNumbers = append(protocolNumbers, p)
	}
	// Sort the network protocol numbers so that IPv4 address is always
	// added to the list before IPv6 address.
	sort.Slice(protocolNumbers, func(i, j int) bool {
		return protocolNumbers[i] < protocolNumbers[j]
	})

	for _, p := range protocolNumbers {
		addressableEndpoint, ok := n.networkEndpoints[p].(AddressableEndpoint)
		if !ok {
			continue
		}
		for _, a := range addressableEndpoint.PrimaryAddresses() {
			addrs = append(addrs, tcpip.ProtocolAddress{Protocol: p, AddressWithPrefix: a})
		}
	}
	return addrs
}

// PrimaryAddress implements NetworkInterface.
func (n *nic) PrimaryAddress(proto tcpip.NetworkProtocolNumber) (tcpip.AddressWithPrefix, tcpip.Error) {
	ep := n.getNetworkEndpoint(proto)
	if ep == nil {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrUnknownProtocol{}
	}

	addressableEndpoint, ok := ep.(AddressableEndpoint)
	if !ok {
		return tcpip.AddressWithPrefix{}, &tcpip.ErrNotSupported{}
	}

	return addressableEndpoint.MainAddress(), nil
}

// removeAddress removes an address from n.
func (n *nic) removeAddress(addr tcpip.Address) tcpip.Error {
	for _, ep := range n.networkEndpoints {
		addressableEndpoint, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		switch err := addressableEndpoint.RemovePermanentAddress(addr); err.(type) {
		case *tcpip.ErrBadLocalAddress:
			continue
		default:
			return err
		}
	}

	return &tcpip.ErrBadLocalAddress{}
}

func (n *nic) setAddressLifetimes(addr tcpip.Address, lifetimes AddressLifetimes) tcpip.Error {
	for _, ep := range n.networkEndpoints {
		ep, ok := ep.(AddressableEndpoint)
		if !ok {
			continue
		}

		switch err := ep.SetLifetimes(addr, lifetimes); err.(type) {
		case *tcpip.ErrBadLocalAddress:
			continue
		default:
			return err
		}
	}

	return &tcpip.ErrBadLocalAddress{}
}

// DeliverNetworkPacket finds the appropriate network protocol endpoint and
// hands the packet over for further processing. This function is called when
// the NIC receives a packet from the link endpoint.
func (n *nic) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) {
	enabled := n.Enabled()
	// If the NIC is not yet enabled, don't receive any packets.
	if !enabled {
		n.stats.disabledRx.packets.Increment()
		n.stats.disabledRx.bytes.IncrementBy(uint64(pkt.Data().Size()))
		return
	}

	n.stats.rx.packets.Increment()
	n.stats.rx.bytes.IncrementBy(uint64(pkt.Data().Size()))

	networkEndpoint := n.getNetworkEndpoint(protocol)
	if networkEndpoint == nil {
		n.stats.unknownL3ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return
	}

	pkt.RXChecksumValidated = n.NetworkLinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0

	networkEndpoint.HandlePacket(pkt)
}

// DeliverTransportPacket delivers the packets to the appropriate transport
// protocol endpoint.
func (n *nic) DeliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) TransportPacketDisposition {
	res, _ := n.deliverTransportPacket(protocol, pkt)
	return res
}

// DeliverTransportError implements TransportDispatcher.
func (n *nic) DeliverTransportError(local, remote tcpip.Address, netProto tcpip.NetworkProtocolNumber, transProto tcpip.TransportProtocolNumber, transErr TransportError, pkt *PacketBuffer) {
	state, ok := n.stack.transportProtocols[transProto]
	if !ok {
		return
	}
	transHeader, ok := pkt.Data().PullUp(8)
	if !ok {
		return
	}
	srcPort, dstPort, err := state.proto.ParsePorts(transHeader)
	if err != nil {
		return
	}
	id := TransportEndpointID{
		LocalPort:     srcPort,
		LocalAddress:  local,
		RemotePort:    dstPort,
		RemoteAddress: remote,
	}
	n.stack.demux.deliverError(n, netProto, transProto, transErr, pkt, id)
}

// DeliverTransportPacketWithDefaultHandlerResult implements
// TransportDispatcherWithDefaultHandlerResult.DeliverTransportPacketWithDefaultHandlerResult.
func (n *nic) DeliverTransportPacketWithDefaultHandlerResult(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) (TransportPacketDisposition, bool) {
	return n.deliverTransportPacket(protocol, pkt)
}

func (n *nic) deliverTransportPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer) (TransportPacketDisposition, bool) {
	state, ok := n.stack.transportProtocols[protocol]
	if !ok {
		n.stats.unknownL4ProtocolRcvdPacketCounts.Increment(uint64(protocol))
		return TransportPacketProtocolUnreachable, false
	}

	transProto := state.proto

	if len(pkt.TransportHeader().Slice()) == 0 {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	}

	srcPort, dstPort, err := transProto.ParsePorts(pkt.TransportHeader().Slice())
	if err != nil {
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	}

	netProto, ok := n.stack.networkProtocols[pkt.NetworkProtocolNumber]
	if !ok {
		panic(fmt.Sprintf("expected network protocol = %d, have = %#v", pkt.NetworkProtocolNumber, n.stack.networkProtocolNumbers()))
	}

	src, dst := netProto.ParseAddresses(pkt.NetworkHeader().Slice())
	id := TransportEndpointID{
		LocalPort:     dstPort,
		LocalAddress:  dst,
		RemotePort:    srcPort,
		RemoteAddress: src,
	}
	if n.stack.demux.deliverPacket(protocol, pkt, id) {
		return TransportPacketHandled, false
	}

	// Try to deliver to per-stack default handler.
	if state.defaultHandler != nil {
		if state.defaultHandler(id, pkt) {
			return TransportPacketHandled, true
		}
	}

	// We could not find an appropriate destination for this packet so
	// give the protocol specific error handler a chance to handle it.
	// If it doesn't handle it then we should do so.
	switch res := transProto.HandleUnknownDestinationPacket(id, pkt); res {
	case UnknownDestinationPacketMalformed:
		n.stats.malformedL4RcvdPackets.Increment()
		return TransportPacketHandled, false
	case UnknownDestinationPacketUnhandled:
		return TransportPacketDestinationPortUnreachable, false
	case UnknownDestinationPacketHandled:
		return TransportPacketHandled, false
	default:
		panic(fmt.Sprintf("unrecognized result from HandleUnknownDestinationPacket = %d", res))
	}
}

// ID implements NetworkInterface.
func (n *nic) ID() tcpip.NICID {
	return n.id
}

// Name implements NetworkInterface.
func (n *nic) Name() string {
	return n.name
}

// isValidForOutgoing returns true if the endpoint can be used to send out a
// packet. It requires the endpoint to not be marked expired (i.e., its address
// has been removed) unless the NIC is in spoofing mode, or temporary.
func (n *nic) isValidForOutgoing(ep AssignableAddressEndpoint) bool {
	return n.Enabled() && ep.IsAssigned(n.Spoofing())
}

// CheckLocalAddress implements NetworkInterface.
func (n *nic) CheckLocalAddress(protocol tcpip.NetworkProtocolNumber, addr tcpip.Address) bool {
	if n.Spoofing() {
		return true
	}

	if addressEndpoint := n.getAddressOrCreateTempInner(protocol, addr, false /* createTemp */, NeverPrimaryEndpoint); addressEndpoint != nil {
		addressEndpoint.DecRef()
		return true
	}

	return false
}

func (n *nic) setForwarding(protocol tcpip.NetworkProtocolNumber, enable bool) (bool, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingEP.SetForwarding(enable), nil
}

func (n *nic) forwarding(protocol tcpip.NetworkProtocolNumber) (bool, tcpip.Error) {
	ep := n.getNetworkEndpoint(protocol)
	if ep == nil {
		return false, &tcpip.ErrUnknownProtocol{}
	}

	forwardingEP, ok := ep.(ForwardingNetworkEndpoint)
	if !ok {
		return false, &tcpip.ErrNotSupported{}
	}

	return forwardingEP.Forwarding(), nil
}

// GetExperimentIPOptionEnabled returns whether the NIC is responsible for
// passing the experiment IP option.
func (n *nic) GetExperimentIPOptionEnabled() bool {
	return n.experimentIPOptionEnabled
}

// CoordinatorNIC represents NetworkLinkEndpoint that can join multiple network devices.
type CoordinatorNIC interface {
	// AddNIC adds the specified NIC device.
	AddNIC(n *nic) tcpip.Error
	// DelNIC deletes the specified NIC device.
	DelNIC(n *nic) tcpip.Error
}
