package swu

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

type SecureUDPConfig = SecureTCPConfig

type SecureUDPTransport struct {
	session *Session
	local   *net.UDPAddr
	remote  *net.UDPAddr

	mu            sync.Mutex
	closed        bool
	espSeq        uint32
	outboundESP   ESPCodec
	inboundESP    ESPCodec
	inboundReplay replayWindow
	readCh        chan inboundPacket
	done          chan struct{}
	closeOnce     sync.Once
}

func (s *Session) ListenSecureUDP(cfg SecureUDPConfig) (*SecureUDPTransport, error) {
	if s.conn == nil {
		return nil, errors.New("listening secure udp transport: session is closed")
	}
	s.mu.RLock()
	innerLocal := cloneUDPAddr(s.innerLocal)
	innerRemote := cloneUDPAddr(s.innerRemote)
	connected := s.connected
	s.mu.RUnlock()
	if !connected || innerLocal == nil || innerRemote == nil {
		return nil, errors.New("listening secure udp transport: session is not connected")
	}
	if cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return nil, errors.New("listening secure udp transport: ports are required")
	}
	if cfg.OutboundSPI == 0 || cfg.InboundSPI == 0 {
		return nil, errors.New("listening secure udp transport: spi is zero")
	}
	if len(cfg.IntegrityKey) == 0 {
		return nil, errors.New("listening secure udp transport: integrity key is empty")
	}
	transport := &SecureUDPTransport{
		session:     s,
		local:       &net.UDPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort, Zone: innerLocal.Zone},
		remote:      &net.UDPAddr{IP: append(net.IP(nil), innerRemote.IP...), Port: cfg.RemotePort, Zone: innerRemote.Zone},
		outboundESP: ESPCodec{SPI: cfg.OutboundSPI, Encryption: EncryptionNull, Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		inboundESP:  ESPCodec{SPI: cfg.InboundSPI, Encryption: EncryptionNull, Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		readCh:      make(chan inboundPacket, 16),
		done:        make(chan struct{}),
	}
	s.udpMu.Lock()
	if s.udpServer != nil {
		s.udpMu.Unlock()
		return nil, errors.New("listening secure udp transport: only one server transport is supported")
	}
	s.udpServer = transport
	s.udpMu.Unlock()
	return transport, nil
}

func (t *SecureUDPTransport) LocalAddr() net.Addr {
	if t.local == nil {
		return nil
	}
	return cloneUDPAddr(t.local)
}

func (t *SecureUDPTransport) RemoteAddr() net.Addr {
	if t.remote == nil {
		return nil
	}
	return cloneUDPAddr(t.remote)
}

func (t *SecureUDPTransport) WritePacket(ctx context.Context, data []byte) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing secure udp packet: transport is closed")
	}
	espSeq, ok := nextESPSequence(&t.espSeq)
	codec := t.outboundESP
	t.mu.Unlock()
	if !ok {
		_ = t.Close()
		return errors.New("writing secure udp packet: esp sequence number overflow")
	}

	udpPacket, err := buildUDPSegment(t.local, t.remote, data)
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	sealed, err := codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: espSeq, NextHeader: 17, Payload: udpPacket})
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	packet, nextHeader, err := buildInnerIPPacket(t.local.IP, t.remote.IP, 50, sealed)
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	return t.session.writeInner(ctx, packet, nextHeader)
}

func (t *SecureUDPTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.done:
			return nil, nil, errors.New("reading secure udp packet: transport is closed")
		case inbound := <-t.readCh:
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (t *SecureUDPTransport) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		alreadyClosed := t.closed
		t.closed = true
		t.mu.Unlock()
		if alreadyClosed {
			return
		}
		t.session.clearUDPTransport(t)
		close(t.done)
	})
	return nil
}

func (t *SecureUDPTransport) deliver(payload []byte, peer net.Addr) {
	select {
	case <-t.done:
		return
	default:
	}
	select {
	case <-t.done:
	case t.readCh <- inboundPacket{data: append([]byte(nil), payload...), addr: peer}:
	default:
	}
}

func (t *SecureUDPTransport) acceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	return t.inboundReplay.Accept(sequence)
}

func (s *Session) clearUDPTransport(transport *SecureUDPTransport) {
	s.udpMu.Lock()
	if s.udpServer == transport {
		s.udpServer = nil
	}
	s.udpMu.Unlock()
}

func buildUDPSegment(src, dst *net.UDPAddr, payload []byte) ([]byte, error) {
	if src == nil || dst == nil {
		return nil, errors.New("building udp segment: endpoint is nil")
	}
	srcIP := append(net.IP(nil), src.IP...)
	dstIP := append(net.IP(nil), dst.IP...)
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], uint16(src.Port))
	binary.BigEndian.PutUint16(udp[2:4], uint16(dst.Port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	if srcIP.To4() != nil && dstIP.To4() != nil {
		binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv4(srcIP.To4(), dstIP.To4(), udp))
		return udp, nil
	}
	if srcIP.To16() == nil || dstIP.To16() == nil {
		return nil, errors.New("building udp segment: mismatched ip family")
	}
	binary.BigEndian.PutUint16(udp[6:8], udpChecksumIPv6(srcIP.To16(), dstIP.To16(), udp))
	return udp, nil
}
