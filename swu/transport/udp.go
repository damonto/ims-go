package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	imssession "github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/swu/esp"
	"github.com/damonto/ims-client/swu/packet"
	"github.com/damonto/ims-client/swu/tunnel"
)

var _ imssession.Transport = (*UDPConn)(nil)

type SecureUDPConfig struct {
	TCPConfig
	OutboundSPI   uint32
	InboundSPI    uint32
	Encryption    string
	EncryptionKey []byte
	Integrity     string
	IntegrityKey  []byte
}

type UDPConn struct {
	session    *tunnel.Session
	attachment tunnel.Attachment
	local      *net.UDPAddr
	remote     *net.UDPAddr

	mu            sync.Mutex
	closed        bool
	terminalErr   error
	espSeq        uint32
	outboundESP   esp.Codec
	inboundESP    esp.Codec
	inboundReplay esp.ReplayWindow
	readCh        chan inboundPacket
	done          chan struct{}
	closeOnce     sync.Once
}

type inboundPacket struct {
	data []byte
	addr net.Addr
	err  error
}

func DialSecureUDP(ctx context.Context, s *tunnel.Session, cfg SecureUDPConfig) (*UDPConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return newSecureUDPConn(s, cfg, "dialing secure udp transport")
}

func ListenSecureUDP(s *tunnel.Session, cfg SecureUDPConfig) (*UDPConn, error) {
	return newSecureUDPConn(s, cfg, "listening secure udp transport")
}

func newSecureUDPConn(s *tunnel.Session, cfg SecureUDPConfig, action string) (*UDPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	if cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return nil, fmt.Errorf("%s: ports are required", action)
	}
	if cfg.OutboundSPI == 0 || cfg.InboundSPI == 0 {
		return nil, fmt.Errorf("%s: spi is zero", action)
	}
	if len(cfg.IntegrityKey) == 0 {
		return nil, fmt.Errorf("%s: integrity key is empty", action)
	}
	encryption := secureEncryption(cfg.Encryption)
	if encryption == esp.EncryptionAESCBC && len(cfg.EncryptionKey) == 0 {
		return nil, fmt.Errorf("%s: encryption key is empty", action)
	}
	conn := &UDPConn{
		session:     s,
		local:       &net.UDPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort, Zone: innerLocal.Zone},
		remote:      &net.UDPAddr{IP: append(net.IP(nil), innerRemote.IP...), Port: cfg.RemotePort, Zone: innerRemote.Zone},
		outboundESP: esp.Codec{SPI: cfg.OutboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		inboundESP:  esp.Codec{SPI: cfg.InboundSPI, Encryption: encryption, EncryptionKey: append([]byte(nil), cfg.EncryptionKey...), Integrity: cfg.Integrity, IntegrityKey: append([]byte(nil), cfg.IntegrityKey...)},
		readCh:      make(chan inboundPacket, 16),
		done:        make(chan struct{}),
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	conn.attachment = attachment
	return conn, nil
}

func (t *UDPConn) LocalAddr() net.Addr {
	return cloneUDPAddr(t.local)
}

func (t *UDPConn) RemoteAddr() net.Addr {
	return cloneUDPAddr(t.remote)
}

func (t *UDPConn) WritePacket(ctx context.Context, data []byte) error {
	return t.writePacket(ctx, data, t.remote)
}

func (t *UDPConn) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	remote, ok := addr.(*net.UDPAddr)
	if !ok || remote == nil {
		return t.WritePacket(ctx, data)
	}
	t.mu.Lock()
	configuredRemote := cloneUDPAddr(t.remote)
	t.mu.Unlock()
	if remote.IP.Equal(configuredRemote.IP) {
		// The protected UDP flow is bound to the peer's IPsec port-c/port-s
		// tuple. SIP Via may advertise 5060/6000, but sending outside the
		// established protected flow makes networks retransmit the request.
		remote.Port = configuredRemote.Port
	}
	return t.writePacket(ctx, data, cloneUDPAddr(remote))
}

func (t *UDPConn) writePacket(ctx context.Context, data []byte, remote *net.UDPAddr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing secure udp packet: transport is closed")
	}
	espSeq, ok := esp.NextSequence(&t.espSeq)
	codec := t.outboundESP
	t.mu.Unlock()
	if !ok {
		_ = t.Close()
		return errors.New("writing secure udp packet: esp sequence number overflow")
	}
	segment := packet.UDPSegment{
		Src:     cloneUDPAddr(t.local),
		Dst:     cloneUDPAddr(remote),
		Payload: append([]byte(nil), data...),
	}
	wire, err := segment.MarshalBinary()
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	sealed, err := codec.Encode(esp.ESPPacket{SPI: codec.SPI, Sequence: espSeq, NextHeader: packet.ProtocolUDP, Payload: wire})
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	return t.session.WriteInnerPacket(ctx, packet.InnerPacket{
		IP: packet.IPPacket{
			SrcIP:    append(net.IP(nil), t.local.IP...),
			DstIP:    append(net.IP(nil), remote.IP...),
			Protocol: packet.ProtocolESP,
			Payload:  sealed,
		},
	})
}

func (t *UDPConn) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.done:
			return nil, nil, t.closedErr("reading secure udp packet: transport is closed")
		case inbound := <-t.readCh:
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (t *UDPConn) Close() error {
	t.closeWithError(nil)
	return nil
}

func (t *UDPConn) HandleInnerPacket(pkt packet.InnerPacket) bool {
	if pkt.IP.Protocol != packet.ProtocolESP {
		return false
	}
	spi := packetSPI(pkt.IP.Payload)
	espPacket, err := t.inboundESP.Decode(pkt.IP.Payload)
	if err != nil || espPacket.SPI != t.inboundESP.SPI {
		return false
	}
	if !t.acceptInboundESP(espPacket.Sequence) {
		t.session.Logger().Debug("dropping replayed secure UDP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
		return false
	}
	if espPacket.NextHeader != packet.ProtocolUDP {
		t.session.Logger().Debug("secure ESP packet", "next_header", espPacket.NextHeader, "spi", spi, "local_addr", t.local, "remote_addr", t.remote)
		return false
	}
	inner, err := packet.DecodePayload(packet.ProtocolUDP, pkt.IP.SrcIP, pkt.IP.DstIP, espPacket.Payload)
	if err != nil || inner.UDP == nil {
		t.session.Logger().Debug("parsing secure UDP packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
		return false
	}
	if !inner.UDP.Src.IP.Equal(t.remote.IP) || inner.UDP.Src.Port != t.remote.Port || inner.UDP.Dst.Port != t.local.Port {
		t.session.Logger().Debug("secure UDP flow mismatch", "spi", spi, "peer_addr", inner.UDP.Src, "expected_remote_addr", t.remote, "expected_local_addr", t.local)
		return false
	}
	t.session.Logger().Debug("received secure UDP packet", "peer_addr", inner.UDP.Src, "local_addr", t.local, "payload_len", len(inner.UDP.Payload))
	t.deliver(inner.UDP.Payload, inner.UDP.Src)
	return true
}

func (t *UDPConn) HandleError(err error) {
	t.closeWithError(fmt.Errorf("reading secure udp packet: %w", err))
}

func (t *UDPConn) closeWithError(err error) {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		if err != nil {
			t.terminalErr = err
		}
		attachment := t.attachment
		t.mu.Unlock()
		if attachment != nil {
			_ = attachment.Close()
		}
		close(t.done)
	})
}

func (t *UDPConn) deliver(payload []byte, peer net.Addr) {
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

func (t *UDPConn) acceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	return t.inboundReplay.Accept(sequence)
}

func (t *UDPConn) closedErr(fallback string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errors.New(fallback)
}
