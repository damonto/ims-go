package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/swu/ike"
)

type innerWriteState struct {
	connected      bool
	codec          esp.Codec
	outer          *net.UDPAddr
	seq            uint32
	protectedBytes uint64
}

func (s *Session) prepareInnerWrite(pkt packet.InnerPacket, payloadLen int) (innerWriteState, error) {
	if s.isClosed() {
		return innerWriteState{}, errors.New("writing packet: session is closed")
	}
	s.mu.Lock()
	if !s.connected {
		if err := s.disconnectedTunnelErr(); err != nil {
			s.mu.Unlock()
			return innerWriteState{}, fmt.Errorf("writing packet: %w", err)
		}
		outer := cloneUDPAddr(s.outerRemote)
		s.mu.Unlock()
		if outer == nil {
			return innerWriteState{}, errors.New("writing packet: remote address is nil")
		}
		return innerWriteState{outer: outer}, nil
	}
	if s.childSAExpired(time.Now()) {
		s.mu.Unlock()
		s.discardChildSecurityAssociations(errChildSAExpired)
		return innerWriteState{}, fmt.Errorf("writing packet: %w", errChildSAExpired)
	}
	if !innerPacketMatchesOutboundChildSASelectors(pkt, s.tunnel) {
		s.mu.Unlock()
		return innerWriteState{}, errors.New("writing packet: inner packet is outside child sa traffic selectors")
	}
	codec := s.outboundESP
	protectedBytes, err := codec.CryptoPayloadBytes(payloadLen)
	if err != nil {
		s.mu.Unlock()
		return innerWriteState{}, fmt.Errorf("writing packet: %w", err)
	}
	if s.childSAByteExpired(protectedBytes) {
		s.mu.Unlock()
		s.discardChildSecurityAssociations(errChildSAExpired)
		return innerWriteState{}, fmt.Errorf("writing packet: %w", errChildSAExpired)
	}
	outer := cloneUDPAddr(s.outerNAT)
	seq, ok := esp.NextSequence(&s.espSeq)
	s.mu.Unlock()
	if !ok {
		s.failSecurityAssociations(errors.New("esp sequence number overflow"))
		return innerWriteState{}, errors.New("writing packet: esp sequence number overflow")
	}
	return innerWriteState{connected: true, codec: codec, outer: outer, seq: seq, protectedBytes: protectedBytes}, nil
}

func sealInnerPacket(state innerWriteState, innerPacket []byte, nextHeader byte) ([]byte, error) {
	return state.codec.Encode(esp.ESPPacket{SPI: state.codec.SPI, Sequence: state.seq, NextHeader: nextHeader, Payload: innerPacket})
}

func (s *Session) writeInner(ctx context.Context, pkt packet.InnerPacket, innerPacket []byte, nextHeader byte) error {
	state, err := s.prepareInnerWrite(pkt, len(innerPacket))
	if err != nil {
		return err
	}
	if !state.connected {
		s.logger.Debug("writing outer plain packet", "remote_addr", state.outer, "packet_len", len(innerPacket))
		return s.writeOuter(ctx, innerPacket, state.outer)
	}
	sealed, err := sealInnerPacket(state, innerPacket, nextHeader)
	if err != nil {
		return fmt.Errorf("writing packet: %w", err)
	}
	s.logger.Debug("writing outer ESP packet", "remote_addr", state.outer, "packet_len", len(sealed))
	if err := s.writeOuter(ctx, sealed, state.outer); err != nil {
		return err
	}
	now := time.Now()
	if s.addCurrentChildSAOutboundBytes(state.protectedBytes, now) {
		s.discardChildSecurityAssociations(errChildSAExpired)
	}
	s.markProtectedTx(now)
	return nil
}

func (s *Session) WriteInnerPacket(ctx context.Context, pkt packet.InnerPacket) error {
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return fmt.Errorf("writing inner packet: %w", err)
	}
	nextHeader, err := pkt.OuterNextHeader()
	if err != nil {
		return fmt.Errorf("writing inner packet: %w", err)
	}
	return s.writeInner(ctx, pkt, wire, nextHeader)
}

func (s *Session) readLoop() {
	defer s.wg.Done()
	buf := make([]byte, maxUDPPacketSize)
	for {
		packet, addr, ok := s.readLoopPacket(buf)
		if !ok {
			return
		}
		if packet == nil {
			continue
		}
		s.handleOuterPacket(packet, addr)
	}
}

func (s *Session) readLoopPacket(buf []byte) ([]byte, net.Addr, bool) {
	if s.isClosed() {
		return nil, nil, false
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(outerReadPollDelay)); err != nil {
		s.failSecurityAssociations(fmt.Errorf("reading packet: setting read deadline: %w", err))
		return nil, nil, false
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) || s.isClosed() {
			return nil, nil, false
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if s.isClosed() {
				return nil, nil, false
			}
			return nil, nil, true
		}
		s.failSecurityAssociations(fmt.Errorf("reading packet: %w", err))
		return nil, nil, false
	}
	return append([]byte(nil), buf[:n]...), addr, true
}

func (s *Session) handleOuterPacket(packet []byte, addr net.Addr) {
	s.logger.Debug("read outer packet", "packet_len", len(packet))
	if isNATKeepalive(packet) {
		s.logger.Debug("ignoring NAT keepalive")
		return
	}
	if hasNonESPMarker(packet) {
		s.handleNonESPPacket(packet[nonESPMarkerLen:], addr)
		return
	}
	s.handleESPPacket(packet)
}

func (s *Session) handleNonESPPacket(packet []byte, addr net.Addr) {
	handled, err := s.handleIKEPacket(packet, addr)
	if err != nil {
		s.logger.Debug("handling IKE packet failed", "err", err)
	}
	if handled {
		return
	}
	if header, ok := decodeIKEHeader(packet); ok && header.ExchangeType == exchangeTypeInformational && header.Flags&flagResponse != 0 {
		s.logger.Debug("ignoring unmatched informational response", "message_id", header.MessageID, "initiator_spi", header.InitiatorSPI, "responder_spi", header.ResponderSPI)
		return
	}
	s.logger.Debug("ignoring unexpected non-ESP marker packet")
}

type inboundESPContext struct {
	codec esp.Codec
	info  Info
}

func (s *Session) inboundPacketContexts(spi uint32) []inboundESPContext {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneRetiredChildSAs(time.Now())
	contexts := make([]inboundESPContext, 0, 1+len(s.retiredChildSAs))
	if s.inboundESP.SPI == spi {
		contexts = append(contexts, inboundESPContext{codec: s.inboundESP, info: cloneInfo(s.tunnel)})
	}
	for _, child := range s.retiredChildSAs {
		if child.inbound.SPI == spi {
			contexts = append(contexts, inboundESPContext{codec: child.inbound, info: cloneInfo(child.info)})
		}
	}
	return contexts
}

func (s *Session) handleESPPacket(data []byte) {
	if err := s.expireChildSAIfNeeded(); err != nil {
		s.logger.Debug("dropping ESP packet after child SA expiry", "err", fmt.Errorf("reading packet: %w", err))
		return
	}
	spi, ok := espPacketSPI(data)
	if !ok {
		s.logger.Debug("dropping truncated ESP packet", "packet_len", len(data))
		return
	}
	contexts := s.inboundPacketContexts(spi)
	if len(contexts) == 0 {
		s.logger.Debug("dropping ESP packet for unknown SPI", "spi", spi)
		return
	}
	var espPacket esp.ESPPacket
	var info Info
	var protectedBytes uint64
	var err error
	for _, context := range contexts {
		espPacket, err = context.codec.Decode(data)
		if err == nil {
			protectedBytes, err = context.codec.CryptoPacketBytes(len(data))
			if err != nil {
				s.logger.Debug("counting ESP packet bytes failed", "err", err)
				return
			}
			info = context.info
			break
		}
	}
	if err != nil {
		if len(data) <= 16 {
			s.logger.Debug("decoding ESP packet failed", "err", err, "packet_hex", shortPacketHex(data))
		} else {
			s.logger.Debug("decoding ESP packet failed", "err", err)
		}
		return
	}
	accept := s.acceptESPSequence(espPacket.SPI, espPacket.Sequence, protectedBytes)
	if !accept.accepted {
		if accept.expireCurrent {
			s.discardChildSecurityAssociations(errChildSAExpired)
		}
		s.logger.Debug("dropping replayed ESP packet", "esp_sequence", espPacket.Sequence)
		return
	}
	s.promoteOutboundAfterInboundESP(espPacket.SPI)
	s.markProtectedRx(time.Now())
	if espPacket.NextHeader == esp.NextHeaderNoNext {
		s.logger.Debug("dropping ESP dummy packet", "esp_sequence", espPacket.Sequence)
		return
	}
	if espPacket.NextHeader != packet.OuterIPv4 && espPacket.NextHeader != packet.OuterIPv6 {
		s.logger.Debug("dropping ESP packet with unsupported next header", "next_header", espPacket.NextHeader)
		return
	}
	var inner packet.InnerPacket
	err = inner.UnmarshalBinary(espPacket.Payload)
	if err != nil {
		s.logger.Debug("parsing inner IP packet failed", "err", err)
		return
	}
	nextHeader, err := inner.OuterNextHeader()
	if err != nil {
		s.logger.Debug("resolving inner IP next header failed", "err", err)
		return
	}
	if nextHeader != espPacket.NextHeader {
		s.logger.Debug("dropping ESP packet with mismatched inner IP version", "next_header", espPacket.NextHeader, "inner_next_header", nextHeader)
		return
	}
	if !innerPacketMatchesChildSASelectors(inner, info) {
		s.logger.Debug("dropping ESP packet outside child sa traffic selectors", "src_ip", inner.IP.SrcIP, "dst_ip", inner.IP.DstIP, "protocol", inner.IP.Protocol)
		return
	}
	s.handleInnerPacket(inner)
	if accept.expireCurrent {
		s.discardChildSecurityAssociations(errChildSAExpired)
	}
}

func innerPacketMatchesChildSASelectors(pkt packet.InnerPacket, info Info) bool {
	if len(info.InitiatorTrafficSelectors) == 0 || len(info.ResponderTrafficSelectors) == 0 {
		return true
	}
	srcIP, dstIP, proto, srcPort, dstPort, portsKnown := innerPacketSelectorFields(pkt)
	return ipMatchesTrafficSelectors(info.ResponderTrafficSelectors, srcIP, proto, srcPort, portsKnown) &&
		ipMatchesTrafficSelectors(info.InitiatorTrafficSelectors, dstIP, proto, dstPort, portsKnown)
}

func innerPacketMatchesOutboundChildSASelectors(pkt packet.InnerPacket, info Info) bool {
	if len(info.InitiatorTrafficSelectors) == 0 || len(info.ResponderTrafficSelectors) == 0 {
		return true
	}
	srcIP, dstIP, proto, srcPort, dstPort, portsKnown := innerPacketSelectorFields(pkt)
	return ipMatchesTrafficSelectors(info.InitiatorTrafficSelectors, srcIP, proto, srcPort, portsKnown) &&
		ipMatchesTrafficSelectors(info.ResponderTrafficSelectors, dstIP, proto, dstPort, portsKnown)
}

func innerPacketSelectorFields(pkt packet.InnerPacket) (net.IP, net.IP, byte, int, int, bool) {
	srcIP := pkt.IP.SrcIP
	dstIP := pkt.IP.DstIP
	proto := pkt.IP.Protocol
	switch {
	case pkt.UDP != nil:
		proto = packet.ProtocolUDP
		srcPort := 0
		dstPort := 0
		if pkt.UDP.Src != nil {
			srcIP = pkt.UDP.Src.IP
			srcPort = pkt.UDP.Src.Port
		}
		if pkt.UDP.Dst != nil {
			dstIP = pkt.UDP.Dst.IP
			dstPort = pkt.UDP.Dst.Port
		}
		return srcIP, dstIP, proto, srcPort, dstPort, true
	case pkt.TCP != nil:
		proto = packet.ProtocolTCP
		srcPort := 0
		dstPort := 0
		if pkt.TCP.Src != nil {
			srcIP = pkt.TCP.Src.IP
			srcPort = pkt.TCP.Src.Port
		}
		if pkt.TCP.Dst != nil {
			dstIP = pkt.TCP.Dst.IP
			dstPort = pkt.TCP.Dst.Port
		}
		return srcIP, dstIP, proto, srcPort, dstPort, true
	case pkt.ESP != nil:
		proto = packet.ProtocolESP
		return srcIP, dstIP, proto, 0, 0, true
	default:
		if pkt.IP.FragmentOffset == 0 && (proto == packet.ProtocolICMP || proto == packet.ProtocolICMPv6) && len(pkt.IP.Payload) >= 2 {
			typeCode := int(binary.BigEndian.Uint16(pkt.IP.Payload[:2]))
			return srcIP, dstIP, proto, typeCode, typeCode, true
		}
		if pkt.IP.FragmentOffset == 0 && (proto == packet.ProtocolTCP || proto == packet.ProtocolUDP) && len(pkt.IP.Payload) >= 4 {
			return srcIP, dstIP, proto,
				int(binary.BigEndian.Uint16(pkt.IP.Payload[:2])),
				int(binary.BigEndian.Uint16(pkt.IP.Payload[2:4])), true
		}
		hasSelectorValue := proto == packet.ProtocolTCP || proto == packet.ProtocolUDP ||
			proto == packet.ProtocolICMP || proto == packet.ProtocolICMPv6
		return srcIP, dstIP, proto, 0, 0, !hasSelectorValue
	}
}

func ipMatchesTrafficSelectors(selectors []ike.TrafficSelector, ip net.IP, protocol byte, port int, portKnown bool) bool {
	for _, selector := range selectors {
		if trafficSelectorMatchesPacket(selector, ip, protocol, port, portKnown) {
			return true
		}
	}
	return false
}

func trafficSelectorMatchesPacket(selector ike.TrafficSelector, ip net.IP, protocol byte, port int, portKnown bool) bool {
	if selector.ProtocolID != 0 && selector.ProtocolID != protocol {
		return false
	}
	if len(selector.Data) < 4 {
		return false
	}
	startPort := int(binary.BigEndian.Uint16(selector.Data[0:2]))
	endPort := int(binary.BigEndian.Uint16(selector.Data[2:4]))
	usesPorts := protocol == packet.ProtocolTCP || protocol == packet.ProtocolUDP ||
		protocol == packet.ProtocolICMP || protocol == packet.ProtocolICMPv6
	if usesPorts && ((!portKnown && (startPort != 0 || endPort != 65535)) || (portKnown && (port < startPort || port > endPort))) {
		return false
	}
	addressLen := (len(selector.Data) - 4) / 2
	if addressLen != net.IPv4len && addressLen != net.IPv6len {
		return false
	}
	normalized := ip.To4()
	if addressLen == net.IPv6len {
		normalized = ip.To16()
	}
	if len(normalized) != addressLen {
		return false
	}
	start := selector.Data[4 : 4+addressLen]
	end := selector.Data[4+addressLen : 4+addressLen*2]
	return bytes.Compare(normalized, start) >= 0 && bytes.Compare(normalized, end) <= 0
}

func (s *Session) promoteOutboundAfterInboundESP(spi uint32) {
	s.mu.RLock()
	promote := s.pendingChildSA.ready && s.inboundESP.SPI == spi
	s.mu.RUnlock()
	if promote {
		s.promotePendingChildSecurityAssociation()
	}
}

func espPacketSPI(data []byte) (uint32, bool) {
	if len(data) < 4 {
		return 0, false
	}
	return binary.BigEndian.Uint32(data[:4]), true
}

func (s *Session) handleInnerPacket(pkt packet.InnerPacket) {
	if s.dispatchInnerPacket(pkt) {
		return
	}
	switch pkt.IP.Protocol {
	case packet.ProtocolUDP:
		if pkt.UDP != nil {
			s.logger.Debug("dropping inner UDP packet without attachment", "src_addr", pkt.UDP.Src, "dst_addr", pkt.UDP.Dst)
			return
		}
		s.logger.Debug("dropping inner UDP packet without attachment", "src_ip", pkt.IP.SrcIP, "dst_ip", pkt.IP.DstIP)
	case packet.ProtocolTCP:
		if pkt.TCP != nil {
			s.logger.Debug("dropping inner TCP packet without attachment", "src_addr", pkt.TCP.Src, "dst_addr", pkt.TCP.Dst, "tcp_flags", pkt.TCP.Flags)
			return
		}
		s.logger.Debug("dropping inner TCP packet without attachment", "src_ip", pkt.IP.SrcIP, "dst_ip", pkt.IP.DstIP)
	case packet.ProtocolESP:
		s.logger.Debug("dropping inner ESP packet without attachment", "src_ip", pkt.IP.SrcIP, "dst_ip", pkt.IP.DstIP)
	default:
		s.logger.Debug("dropping inner packet without attachment", "inner_proto", pkt.IP.Protocol)
	}
}

func hasNonESPMarker(data []byte) bool {
	return len(data) >= nonESPMarkerLen && bytes.Equal(data[:nonESPMarkerLen], nonESPMarker[:])
}

func isNATKeepalive(data []byte) bool {
	return len(data) == 1 && data[0] == 0xff
}

func shortPacketHex(packet []byte) string {
	const maxBytes = 16
	if len(packet) <= maxBytes {
		return hex.EncodeToString(packet)
	}
	return hex.EncodeToString(packet[:maxBytes]) + "..."
}
