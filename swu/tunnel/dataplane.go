package tunnel

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-client/swu/esp"
	"github.com/damonto/ims-client/swu/packet"
)

type innerWriteState struct {
	connected bool
	codec     esp.Codec
	outer     *net.UDPAddr
	seq       uint32
}

func (s *Session) WritePacket(ctx context.Context, data []byte) error {
	ctx = normalizeContext(ctx)
	if s.isClosed() {
		return errors.New("writing packet: session is closed")
	}
	s.mu.RLock()
	connected := s.connected
	tunnelErr := s.disconnectedTunnelErrLocked()
	innerLocal := cloneUDPAddr(s.innerLocal)
	innerRemote := cloneUDPAddr(s.innerRemote)
	outerRemote := cloneUDPAddr(s.outerRemote)
	s.mu.RUnlock()
	if !connected {
		if tunnelErr != nil {
			return fmt.Errorf("writing packet: %w", tunnelErr)
		}
		if outerRemote == nil {
			return errors.New("writing packet: remote address is nil")
		}
		return s.writeOuter(ctx, data, outerRemote)
	}
	return s.WriteInnerPacket(ctx, packet.InnerPacket{
		UDP: &packet.UDPSegment{
			Src:     innerLocal,
			Dst:     innerRemote,
			Payload: append([]byte(nil), data...),
		},
	})
}

func (s *Session) prepareInnerWrite() (innerWriteState, error) {
	if s.isClosed() {
		return innerWriteState{}, errors.New("writing packet: session is closed")
	}
	s.mu.Lock()
	if !s.connected {
		if err := s.disconnectedTunnelErrLocked(); err != nil {
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
	codec := s.outboundESP
	outer := cloneUDPAddr(s.outerNAT)
	seq, ok := esp.NextSequence(&s.espSeq)
	s.mu.Unlock()
	if !ok {
		s.failSecurityAssociations(errors.New("esp sequence number overflow"))
		return innerWriteState{}, errors.New("writing packet: esp sequence number overflow")
	}
	return innerWriteState{connected: true, codec: codec, outer: outer, seq: seq}, nil
}

func sealInnerPacket(state innerWriteState, innerPacket []byte, nextHeader byte) ([]byte, error) {
	return state.codec.Encode(esp.ESPPacket{SPI: state.codec.SPI, Sequence: state.seq, NextHeader: nextHeader, Payload: innerPacket})
}

func (s *Session) writeInner(ctx context.Context, innerPacket []byte, nextHeader byte) error {
	state, err := s.prepareInnerWrite()
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
	s.markProtectedTx(time.Now())
	return nil
}

func (s *Session) WriteInnerPacket(ctx context.Context, pkt packet.InnerPacket) error {
	ctx = normalizeContext(ctx)
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return fmt.Errorf("writing inner packet: %w", err)
	}
	nextHeader, err := pkt.OuterNextHeader()
	if err != nil {
		return fmt.Errorf("writing inner packet: %w", err)
	}
	return s.writeInner(ctx, wire, nextHeader)
}

func (s *Session) readConnectedPacket(ctx context.Context) ([]byte, net.Addr, error) {
	s.mu.RLock()
	dataPlaneDone := s.dataPlaneDone
	s.mu.RUnlock()
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-s.closeCtx.Done():
			return nil, nil, errors.New("reading packet: session is closed")
		case <-dataPlaneDone:
			return nil, nil, s.currentDisconnectedTunnelErr("reading packet")
		case inbound, ok := <-s.readCh:
			if !ok {
				return nil, nil, errors.New("reading packet: session is closed")
			}
			if err := s.currentDisconnectedTunnelErr("reading packet"); err != nil {
				return nil, nil, err
			}
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (s *Session) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	ctx = normalizeContext(ctx)
	if s.isClosed() {
		return nil, nil, errors.New("reading packet: session is closed")
	}
	if err := s.currentDisconnectedTunnelErr("reading packet"); err != nil {
		return nil, nil, err
	}
	s.mu.RLock()
	connected := s.connected
	s.mu.RUnlock()
	if !connected {
		return s.readOuterPacket(ctx)
	}
	return s.readConnectedPacket(ctx)
}

func (s *Session) readLoop() {
	defer s.wg.Done()
	defer close(s.readCh)
	buf := make([]byte, 64*1024)
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
	if s.closeCtx != nil && s.closeCtx.Err() != nil {
		return nil, nil, false
	}
	if err := s.conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		s.tryDeliverError(fmt.Errorf("reading packet: setting read deadline: %w", err))
		return nil, nil, false
	}
	n, addr, err := s.conn.ReadFrom(buf)
	if err != nil {
		if errors.Is(err, net.ErrClosed) || s.closeCtx.Err() != nil {
			return nil, nil, false
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			if s.closeCtx != nil && s.closeCtx.Err() != nil {
				return nil, nil, false
			}
			return nil, nil, true
		}
		s.tryDeliverError(fmt.Errorf("reading packet: %w", err))
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
		s.handleNonESPPacket(packet[4:], addr)
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
	s.logger.Debug("ignoring unexpected non-ESP marker packet")
}

func (s *Session) inboundPacketContext() (esp.Codec, int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inboundESP, s.cfg.LocalSIPPort
}

func (s *Session) handleESPPacket(data []byte) {
	codec, localUDPPort := s.inboundPacketContext()
	espPacket, err := codec.Decode(data)
	if err != nil {
		if len(data) <= 16 {
			s.logger.Debug("decoding ESP packet failed", "err", err, "packet_hex", shortPacketHex(data))
		} else {
			s.logger.Debug("decoding ESP packet failed", "err", err)
		}
		return
	}
	if !s.acceptInboundESPSequence(espPacket.Sequence) {
		s.logger.Debug("dropping replayed ESP packet", "esp_sequence", espPacket.Sequence)
		return
	}
	s.markProtectedRx(time.Now())
	var inner packet.InnerPacket
	err = inner.UnmarshalBinary(espPacket.Payload)
	if err != nil {
		s.logger.Debug("parsing inner IP packet failed", "err", err)
		return
	}
	s.handleInnerPacket(inner, localUDPPort)
}

func (s *Session) handleInnerPacket(pkt packet.InnerPacket, localUDPPort int) {
	if s.dispatchInnerPacket(pkt) {
		return
	}
	switch pkt.IP.Protocol {
	case packet.ProtocolUDP:
		s.handleInnerUDPPacket(pkt, localUDPPort)
	case packet.ProtocolTCP:
		s.logger.Debug("dropping inner TCP packet without attachment", "src_ip", pkt.IP.SrcIP, "dst_ip", pkt.IP.DstIP)
	case packet.ProtocolESP:
		s.logger.Debug("dropping inner ESP packet without attachment", "src_ip", pkt.IP.SrcIP, "dst_ip", pkt.IP.DstIP)
	default:
		s.logger.Debug("dropping unsupported inner protocol", "inner_proto", pkt.IP.Protocol)
	}
}

func (s *Session) handleInnerUDPPacket(pkt packet.InnerPacket, localUDPPort int) {
	if pkt.UDP == nil || pkt.UDP.Src == nil || pkt.UDP.Dst == nil {
		s.logger.Debug("parsing inner UDP packet failed", "err", errors.New("udp segment is missing"))
		return
	}
	if localUDPPort != 0 && pkt.UDP.Dst.Port != localUDPPort {
		s.logger.Debug("parsing inner UDP packet failed", "err", fmt.Errorf("unexpected destination port %d", pkt.UDP.Dst.Port))
		return
	}
	peer := cloneUDPAddr(pkt.UDP.Src)
	payload := append([]byte(nil), pkt.UDP.Payload...)
	s.logger.Debug("read inner UDP packet", "peer_addr", peer, "payload_len", len(payload))
	select {
	case s.readCh <- inboundPacket{data: payload, addr: peer}:
	case <-s.closeCtx.Done():
	}
}

func (s *Session) tryDeliverError(err error) {
	select {
	case s.readCh <- inboundPacket{err: err}:
	case <-s.closeCtx.Done():
	default:
	}
}

func hasNonESPMarker(data []byte) bool {
	return len(data) >= 4 && data[0] == 0 && data[1] == 0 && data[2] == 0 && data[3] == 0
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
