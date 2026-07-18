// Copyright 2021 The gVisor Authors.
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

package ipv4

import (
	"encoding/binary"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/checksum"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

const (
	icmpv4DestinationUnreachable = 3
	icmpv4EchoReply              = 0
	icmpv4EchoRequest            = 8
	icmpv4TimeExceeded           = 11
	icmpv4ParameterProblem       = 12

	icmpv4NetUnreachable         = 0
	icmpv4HostUnreachable        = 1
	icmpv4ProtoUnreachable       = 2
	icmpv4PortUnreachable        = 3
	icmpv4FragmentationNeeded    = 4
	icmpv4SourceRouteFailed      = 5
	icmpv4SourceHostIsolated     = 8
	icmpv4DestinationNetUnknown  = 6
	icmpv4DestinationHostUnknown = 7
	icmpv4NetProhibited          = 9
	icmpv4HostProhibited         = 10
	icmpv4NetUnreachableForTOS   = 11
	icmpv4HostUnreachableForTOS  = 12
	icmpv4AdminProhibited        = 13

	icmpv4TTLExceeded               = 0
	icmpv4FragmentReassemblyTimeout = 1
	icmpv4PointerIndicatesError     = 0
	icmpv4MissingRequiredOption     = 1
	icmpv4BadLength                 = 2
)

type icmpTransportError struct {
	origin tcpip.SockErrOrigin
	typ    uint8
	code   uint8
	info   uint32
	kind   stack.TransportErrorKind
}

func (e *icmpTransportError) Origin() tcpip.SockErrOrigin { return e.origin }
func (e *icmpTransportError) Type() uint8                 { return e.typ }
func (e *icmpTransportError) Code() uint8                 { return e.code }
func (e *icmpTransportError) Info() uint32                { return e.info }
func (e *icmpTransportError) Kind() stack.TransportErrorKind {
	return e.kind
}

func (e *endpoint) checkLocalAddress(addr tcpip.Address) bool {
	if e.nic.Spoofing() {
		return true
	}
	return e.AcquireAssignedAddress(addr, false, stack.NeverPrimaryEndpoint, true) != nil
}

func (e *endpoint) handleControl(transErr stack.TransportError, pkt *stack.PacketBuffer) {
	h, ok := pkt.Data().PullUp(header.IPv4MinimumSize)
	if !ok {
		return
	}
	ip := header.IPv4(h)
	src := ip.SourceAddress()
	if !e.checkLocalAddress(src) {
		return
	}
	headerLength := int(ip.HeaderLength())
	if pkt.Data().Size() < headerLength || ip.FragmentOffset() != 0 {
		return
	}
	protocol := ip.TransportProtocol()
	dst := ip.DestinationAddress()
	if _, ok := pkt.Data().Consume(headerLength); !ok {
		return
	}
	e.dispatcher.DeliverTransportError(src, dst, ProtocolNumber, protocol, transErr, pkt)
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer) {
	view := pkt.Data().AsRange().ToView()
	defer view.Release()
	message := view.AsSlice()
	if len(message) < 8 || checksum.Checksum(message, 0) != 0xffff {
		return
	}
	if message[0] == icmpv4EchoRequest && message[1] == 0 {
		e.sendEchoReply(message, header.IPv4(pkt.NetworkHeader().Slice()))
		return
	}
	transErr, ok := icmpTransportErrorFromMessage(message)
	if !ok {
		return
	}
	if _, ok := pkt.Data().Consume(8); !ok {
		return
	}
	e.handleControl(transErr, pkt)
}

func icmpTransportErrorFromMessage(message []byte) (*icmpTransportError, bool) {
	if len(message) < 8 {
		return nil, false
	}
	typ := message[0]
	code := message[1]
	transErr := &icmpTransportError{
		origin: tcpip.SockExtErrorOriginICMP,
		typ:    typ,
		code:   code,
	}
	switch typ {
	case icmpv4DestinationUnreachable:
		switch code {
		case icmpv4NetUnreachable, icmpv4DestinationNetUnknown, icmpv4NetProhibited, icmpv4NetUnreachableForTOS:
			transErr.kind = stack.DestinationNetworkUnreachableTransportError
		case icmpv4HostUnreachable, icmpv4HostProhibited, icmpv4HostUnreachableForTOS, icmpv4AdminProhibited:
			transErr.kind = stack.DestinationHostUnreachableTransportError
		case icmpv4DestinationHostUnknown:
			transErr.kind = stack.DestinationHostDownTransportError
		case icmpv4ProtoUnreachable:
			transErr.kind = stack.DestinationProtoUnreachableTransportError
		case icmpv4PortUnreachable:
			transErr.kind = stack.DestinationPortUnreachableTransportError
		case icmpv4FragmentationNeeded:
			networkMTU, err := calculateNetworkMTU(uint32(binary.BigEndian.Uint16(message[6:8])), header.IPv4MinimumSize)
			if err != nil || networkMTU == 0 {
				return nil, false
			}
			transErr.info = networkMTU
			transErr.kind = stack.PacketTooBigTransportError
		case icmpv4SourceRouteFailed:
			transErr.kind = stack.SourceRouteFailedTransportError
		case icmpv4SourceHostIsolated:
			transErr.kind = stack.SourceHostIsolatedTransportError
		default:
			return nil, false
		}
	case icmpv4TimeExceeded:
		if code != icmpv4TTLExceeded && code != icmpv4FragmentReassemblyTimeout {
			return nil, false
		}
		transErr.kind = stack.TimeExceededTransportError
	case icmpv4ParameterProblem:
		if code != icmpv4PointerIndicatesError && code != icmpv4MissingRequiredOption && code != icmpv4BadLength {
			return nil, false
		}
		transErr.kind = stack.ParameterProblemTransportError
	default:
		return nil, false
	}
	return transErr, true
}

func (e *endpoint) sendEchoReply(request []byte, ip header.IPv4) {
	dst := ip.DestinationAddress()
	if dst == header.IPv4Broadcast || header.IsV4MulticastAddress(dst) {
		return
	}
	route, err := e.protocol.stack.FindRoute(e.nic.ID(), dst, ip.SourceAddress(), ProtocolNumber, false)
	if err != nil {
		return
	}
	defer route.Release()
	reply := append([]byte(nil), request...)
	reply[0] = icmpv4EchoReply
	binary.BigEndian.PutUint16(reply[2:4], 0)
	binary.BigEndian.PutUint16(reply[2:4], ^checksum.Checksum(reply, 0))
	replyPacket := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(reply),
	})
	defer replyPacket.DecRef()
	replyPacket.TransportProtocolNumber = 1
	_ = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: 1,
		TTL:      route.DefaultTTL(),
	}, replyPacket)
}
