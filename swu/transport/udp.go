package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	imssession "github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/packet"
	"github.com/damonto/vowifi-go/swu/tunnel"
)

var _ imssession.Transport = (*UDPConn)(nil)

type UDPConfig struct {
	LocalPort  int
	RemotePort int
	RemoteIP   net.IP
}

type SecureUDPConfig struct {
	UDPConfig
	OutboundSPI  uint32
	InboundSPI   uint32
	Encryption   string
	Integrity    string
	Mode         string
	Associations *SecurityAssociations

	EncryptionKey []byte
	IntegrityKey  []byte
	Salt          [4]byte
}

type UDPConn struct {
	session    *tunnel.Session
	attachment tunnel.Attachment
	local      *net.UDPAddr
	remote     *net.UDPAddr

	mu           sync.Mutex
	closed       bool
	terminalErr  error
	outboundESP  esp.Codec
	inboundESP   esp.Codec
	secureMode   string
	associations *SecurityAssociations
	readCh       chan inboundPacket
	done         chan struct{}
	closeOnce    sync.Once
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
	return newSecureUDPConn(s, cfg, transportActionDialSecureUDP)
}

func ListenSecureUDP(s *tunnel.Session, cfg SecureUDPConfig) (*UDPConn, error) {
	return newSecureUDPConn(s, cfg, transportActionListenSecureUDP)
}

func newSecureUDPConn(s *tunnel.Session, cfg SecureUDPConfig, action transportAction) (*UDPConn, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(s)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	if cfg.LocalPort == 0 || cfg.RemotePort == 0 {
		return nil, fmt.Errorf("%s: ports are required", action)
	}
	if err := validateSecureSPIs(cfg.OutboundSPI, cfg.InboundSPI); err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	encryption, err := secureEncryption(cfg.Encryption)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	mode, err := secureMode(cfg.Mode)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	if err := validateSecureESPConfig(encryption, cfg.Integrity, cfg.EncryptionKey, cfg.IntegrityKey); err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	conn := &UDPConn{
		session:      s,
		local:        &net.UDPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort, Zone: innerLocal.Zone},
		remote:       udpRemoteAddr(innerRemote, cfg.RemotePort, cfg.RemoteIP),
		outboundESP:  secureESPCodec(cfg.OutboundSPI, encryption, cfg.EncryptionKey, cfg.Integrity, cfg.IntegrityKey, cfg.Salt),
		inboundESP:   secureESPCodec(cfg.InboundSPI, encryption, cfg.EncryptionKey, cfg.Integrity, cfg.IntegrityKey, cfg.Salt),
		secureMode:   mode,
		associations: secureAssociations(cfg.Associations),
		readCh:       make(chan inboundPacket, 16),
		done:         make(chan struct{}),
	}
	attachment, err := s.Attach(conn)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", action, err)
	}
	conn.attachment = attachment
	if action == transportActionDialSecureUDP {
		conn.startUDPEncTunnelKeepalive()
	}
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
		return t.writePacket(ctx, data, t.remote)
	}
	t.mu.Lock()
	configuredRemote := cloneUDPAddr(t.remote)
	t.mu.Unlock()
	return t.writePacket(ctx, data, protectedUDPWriteRemote(configuredRemote, remote))
}

func (t *UDPConn) writePacket(ctx context.Context, data []byte, remote *net.UDPAddr) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing secure udp packet: transport is closed")
	}
	codec := t.outboundESP
	mode := t.secureMode
	associations := t.associations
	t.mu.Unlock()
	segment := packet.UDPSegment{
		Src:     cloneUDPAddr(t.local),
		Dst:     cloneUDPAddr(remote),
		Payload: append([]byte(nil), data...),
	}
	wire, err := segment.MarshalBinary()
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	nextHeader := packet.ProtocolUDP
	payload := wire
	if mode == SecureModeUDPEncTunnel {
		inner := packet.InnerPacket{UDP: &segment}
		payload, err = inner.MarshalBinary()
		if err != nil {
			return fmt.Errorf("writing secure udp packet: %w", err)
		}
		nextHeader, err = secureTunnelNextHeader(t.local.IP, remote.IP)
		if err != nil {
			return fmt.Errorf("writing secure udp packet: %w", err)
		}
	}
	sealed, err := associations.sealESP(codec, nextHeader, payload)
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	inner, err := secureInnerPacket(t.local.IP, remote.IP, mode, sealed)
	if err != nil {
		return fmt.Errorf("writing secure udp packet: %w", err)
	}
	return t.session.WriteInnerPacket(ctx, inner)
}

func protectedUDPWriteRemote(configuredRemote, requested *net.UDPAddr) *net.UDPAddr {
	if configuredRemote != nil {
		// SIP Via can point at an advertised response target, but this transport
		// represents one ESP-protected SA flow. Keep writes on the negotiated
		// P-CSCF protected peer tuple.
		return cloneUDPAddr(configuredRemote)
	}
	if requested == nil {
		return nil
	}
	return cloneUDPAddr(requested)
}

func (t *UDPConn) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	for {
		if inbound, ok := t.nextPacket(); ok {
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.done:
			if inbound, ok := t.nextPacket(); ok {
				if inbound.err != nil {
					return nil, nil, inbound.err
				}
				return inbound.data, inbound.addr, nil
			}
			return nil, nil, t.closedErr("reading secure udp packet: transport is closed")
		case inbound := <-t.readCh:
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (t *UDPConn) nextPacket() (inboundPacket, bool) {
	select {
	case inbound := <-t.readCh:
		return inbound, true
	default:
		return inboundPacket{}, false
	}
}

func (t *UDPConn) Close() error {
	t.closeWithError(nil)
	return nil
}

func (t *UDPConn) HandleInnerPacket(pkt packet.InnerPacket) bool {
	t.mu.Lock()
	mode := t.secureMode
	t.mu.Unlock()
	espPayload, ok := secureESPPayload(pkt, mode)
	if !ok {
		return false
	}
	spi := packetSPI(espPayload)
	if spi != t.inboundESP.SPI {
		return false
	}
	if sequence, ok := packetESPSequence(espPayload); ok && !t.mayAcceptInboundESP(sequence) {
		t.session.Logger().Debug("dropping replayed secure UDP packet before decode", "spi", spi, "esp_sequence", sequence)
		return false
	}
	espPacket, err := t.inboundESP.Decode(espPayload)
	if err != nil {
		return false
	}
	var inner packet.InnerPacket
	if mode == SecureModeUDPEncTunnel {
		if espPacket.NextHeader != packet.OuterIPv4 && espPacket.NextHeader != packet.OuterIPv6 {
			t.session.Logger().Debug("secure ESP tunnel packet", "next_header", espPacket.NextHeader, "spi", spi, "local_addr", t.local, "remote_addr", t.remote)
			return false
		}
		if err := inner.UnmarshalBinary(espPacket.Payload); err != nil || inner.UDP == nil {
			t.session.Logger().Debug("parsing secure UDP tunnel packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
			return false
		}
	} else if espPacket.NextHeader == packet.ProtocolUDP {
		inner, err = packet.DecodePayload(packet.ProtocolUDP, pkt.IP.SrcIP, pkt.IP.DstIP, espPacket.Payload)
		if err != nil || inner.UDP == nil {
			t.session.Logger().Debug("parsing secure UDP packet failed", "spi", spi, "local_addr", t.local, "remote_addr", t.remote, "err", err)
			return false
		}
	} else {
		t.session.Logger().Debug("secure ESP packet", "next_header", espPacket.NextHeader, "spi", spi, "local_addr", t.local, "remote_addr", t.remote)
		return false
	}
	if !udpFlowMatches(inner.UDP, t.local, t.remote) {
		t.session.Logger().Debug("secure UDP flow mismatch", "spi", spi, "peer_addr", inner.UDP.Src, "expected_remote_addr", t.remote, "expected_local_addr", t.local)
		return false
	}
	if !t.acceptInboundESP(espPacket.Sequence) {
		t.session.Logger().Debug("dropping replayed secure UDP packet", "spi", spi, "esp_sequence", espPacket.Sequence)
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

func (t *UDPConn) startUDPEncTunnelKeepalive() {
	t.mu.Lock()
	mode := t.secureMode
	t.mu.Unlock()
	if mode != SecureModeUDPEncTunnel {
		return
	}
	startUDPEncTunnelKeepalive(t.done, t.writeUDPEncTunnelKeepalive, func(err error) {
		if t.session != nil {
			t.session.Logger().Debug("writing UDP-enc-tun keepalive", "err", err)
		}
	})
}

func (t *UDPConn) writeUDPEncTunnelKeepalive(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing UDP-enc-tun keepalive: transport is closed")
	}
	session := t.session
	local := cloneUDPAddr(t.local)
	remote := cloneUDPAddr(t.remote)
	t.mu.Unlock()
	if local == nil || remote == nil {
		return errors.New("writing UDP-enc-tun keepalive: endpoint is nil")
	}
	return writeUDPEncTunnelKeepalive(ctx, session, local.IP, remote.IP)
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
		if t.session != nil {
			t.session.Logger().Debug("dropping secure UDP packet: read queue is full", "peer_addr", peer, "payload_len", len(payload))
		}
	}
}

func (t *UDPConn) acceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	codec := t.inboundESP
	associations := t.associations
	t.mu.Unlock()
	return associations.acceptInboundESP(codec, sequence)
}

func (t *UDPConn) mayAcceptInboundESP(sequence uint32) bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	codec := t.inboundESP
	associations := t.associations
	t.mu.Unlock()
	return associations.mayAcceptInboundESP(codec, sequence)
}

func (t *UDPConn) closedErr(fallback string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errors.New(fallback)
}
