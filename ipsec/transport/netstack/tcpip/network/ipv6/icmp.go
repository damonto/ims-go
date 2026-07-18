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

package ipv6

import (
	"encoding/binary"

	"github.com/damonto/ims-go/ipsec/transport/netstack/buffer"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/checksum"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/header"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/stack"
)

const (
	icmpv6DestinationUnreachable = 1
	icmpv6PacketTooBig           = 2
	icmpv6TimeExceeded           = 3
	icmpv6ParameterProblem       = 4
	icmpv6EchoRequest            = 128
	icmpv6EchoReply              = 129

	icmpv6NetworkUnreachable = 0
	icmpv6PortUnreachable    = 4

	icmpv6HopLimitExceeded          = 0
	icmpv6FragmentReassemblyTimeout = 1
	icmpv6ErroneousHeaderField      = 0
	icmpv6UnrecognizedNextHeader    = 1
	icmpv6UnrecognizedIPv6Option    = 2
)

type icmpTransportError struct {
	typ  uint8
	code uint8
	info uint32
	kind stack.TransportErrorKind
}

func (*icmpTransportError) Origin() tcpip.SockErrOrigin { return tcpip.SockExtErrorOriginICMP6 }
func (e *icmpTransportError) Type() uint8               { return e.typ }
func (e *icmpTransportError) Code() uint8               { return e.code }
func (e *icmpTransportError) Info() uint32              { return e.info }
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
	view := pkt.Data().AsRange().ToView()
	defer view.Release()
	quoted := view.AsSlice()
	if len(quoted) < header.IPv6MinimumSize {
		return
	}
	ip := header.IPv6(quoted)
	src := ip.SourceAddress()
	if !e.checkLocalAddress(src) {
		return
	}
	dst := ip.DestinationAddress()
	protocol := quoted[6]
	offset := header.IPv6MinimumSize
	for {
		switch protocol {
		case 0, 43, 60:
			if offset+2 > len(quoted) {
				return
			}
			next := quoted[offset]
			length := (int(quoted[offset+1]) + 1) * 8
			if length < 8 || offset+length > len(quoted) {
				return
			}
			protocol = next
			offset += length
		case 44:
			if offset+8 > len(quoted) {
				return
			}
			if binary.BigEndian.Uint16(quoted[offset+2:offset+4])>>3 != 0 {
				return
			}
			protocol = quoted[offset]
			offset += 8
		case 51:
			if offset+2 > len(quoted) {
				return
			}
			next := quoted[offset]
			length := (int(quoted[offset+1]) + 2) * 4
			if length < 8 || offset+length > len(quoted) {
				return
			}
			protocol = next
			offset += length
		default:
			if _, ok := pkt.Data().Consume(offset); !ok {
				return
			}
			e.dispatcher.DeliverTransportError(src, dst, ProtocolNumber, tcpip.TransportProtocolNumber(protocol), transErr, pkt)
			return
		}
	}
}

func (e *endpoint) handleICMP(pkt *stack.PacketBuffer) {
	view := pkt.Data().AsRange().ToView()
	defer view.Release()
	message := view.AsSlice()
	if len(message) < 8 {
		return
	}
	ip := header.IPv6(pkt.NetworkHeader().Slice())
	initial := header.PseudoHeaderChecksum(58, ip.SourceAddress(), ip.DestinationAddress(), uint16(len(message)))
	if checksum.Checksum(message, initial) != 0xffff {
		return
	}
	switch message[0] {
	case icmpv6EchoRequest:
		if message[1] == 0 {
			e.sendEchoReply(message, ip)
		}
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
	transErr := &icmpTransportError{typ: message[0], code: message[1]}
	switch message[0] {
	case icmpv6PacketTooBig:
		if message[1] != 0 {
			return nil, false
		}
		linkMTU := binary.BigEndian.Uint32(message[4:8])
		if linkMTU < header.IPv6MinimumMTU {
			linkMTU = header.IPv6MinimumMTU
		}
		networkMTU, err := calculateNetworkMTU(linkMTU, header.IPv6MinimumSize)
		if err != nil || networkMTU == 0 {
			return nil, false
		}
		transErr.info = networkMTU
		transErr.kind = stack.PacketTooBigTransportError
	case icmpv6DestinationUnreachable:
		switch message[1] {
		case icmpv6NetworkUnreachable:
			transErr.kind = stack.DestinationNetworkUnreachableTransportError
		case icmpv6PortUnreachable:
			transErr.kind = stack.DestinationPortUnreachableTransportError
		default:
			transErr.kind = stack.DestinationHostUnreachableTransportError
		}
	case icmpv6TimeExceeded:
		if message[1] != icmpv6HopLimitExceeded && message[1] != icmpv6FragmentReassemblyTimeout {
			return nil, false
		}
		transErr.kind = stack.TimeExceededTransportError
	case icmpv6ParameterProblem:
		if message[1] != icmpv6ErroneousHeaderField && message[1] != icmpv6UnrecognizedNextHeader && message[1] != icmpv6UnrecognizedIPv6Option {
			return nil, false
		}
		transErr.kind = stack.ParameterProblemTransportError
	default:
		return nil, false
	}
	return transErr, true
}

func (e *endpoint) sendEchoReply(request []byte, ip header.IPv6) {
	local := ip.DestinationAddress()
	if header.IsV6MulticastAddress(local) {
		local = tcpip.Address{}
	}
	route, err := e.protocol.stack.FindRoute(e.nic.ID(), local, ip.SourceAddress(), ProtocolNumber, false)
	if err != nil {
		return
	}
	defer route.Release()
	reply := append([]byte(nil), request...)
	reply[0] = icmpv6EchoReply
	binary.BigEndian.PutUint16(reply[2:4], 0)
	initial := header.PseudoHeaderChecksum(58, route.LocalAddress(), route.RemoteAddress(), uint16(len(reply)))
	binary.BigEndian.PutUint16(reply[2:4], ^checksum.Checksum(reply, initial))
	replyPacket := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()),
		Payload:            buffer.MakeWithData(reply),
	})
	defer replyPacket.DecRef()
	replyPacket.TransportProtocolNumber = 58
	_ = route.WritePacket(stack.NetworkHeaderParams{
		Protocol: 58,
		TTL:      route.DefaultTTL(),
	}, replyPacket)
}
