package ipsec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	ipsecbase "github.com/damonto/ims-go/ipsec"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/ipsec/transport"
)

const (
	udpEncapPort      = 4500
	readPollInterval  = 250 * time.Millisecond
	maxIPPacketLength = 65535
)

type packetConn interface {
	ReadFrom([]byte) (int, net.Addr, error)
	WriteTo([]byte, net.Addr) (int, error)
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	LocalAddr() net.Addr
	Close() error
}

// PacketListener opens the outer ESP transports used by an LTE IPsec session.
// Implementations may bind those sockets to a specific IMS network interface.
type PacketListener interface {
	ListenIPPacket(context.Context, string, *net.IPAddr) (net.PacketConn, error)
	ListenUDPPacket(context.Context, *net.UDPAddr) (net.PacketConn, error)
}

type Session struct {
	localIP  net.IP
	remoteIP net.IP
	logger   *slog.Logger

	openESP func(context.Context, net.IP) (packetConn, error)
	openUDP func(context.Context, net.IP) (packetConn, error)

	mu          sync.RWMutex
	espConn     packetConn
	udpConn     packetConn
	attachments []*attachment
	closed      bool

	closeCh   chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	writeMu   sync.Mutex
}

// SessionConfig configures an LTE IPsec session and its outer packet sockets.
type SessionConfig struct {
	LocalIP        net.IP
	RemoteIP       net.IP
	Logger         *slog.Logger
	PacketListener PacketListener
}

type attachment struct {
	session *Session
	handler ipsecbase.InnerHandler

	mu     sync.RWMutex
	closed bool
	once   sync.Once
}

func NewSession(localIP, remoteIP net.IP, logger *slog.Logger) (*Session, error) {
	return NewSessionWithConfig(SessionConfig{LocalIP: localIP, RemoteIP: remoteIP, Logger: logger})
}

// NewSessionWithConfig creates an LTE IPsec session with an optional packet listener.
func NewSessionWithConfig(cfg SessionConfig) (*Session, error) {
	local, remote, err := normalizeIPPair(cfg.LocalIP, cfg.RemoteIP)
	if err != nil {
		return nil, fmt.Errorf("creating LTE IPsec session: %w", err)
	}
	listener := cfg.PacketListener
	if listener == nil {
		listener = systemPacketListener{}
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Session{
		localIP:  local,
		remoteIP: remote,
		logger:   logger.With("component", "lte-ipsec"),
		openESP: func(ctx context.Context, localIP net.IP) (packetConn, error) {
			return listenESP(ctx, listener, localIP)
		},
		openUDP: func(ctx context.Context, localIP net.IP) (packetConn, error) {
			return listenUDPEncap(ctx, listener, localIP)
		},
		closeCh: make(chan struct{}),
	}, nil
}

func (s *Session) Enable(ctx context.Context, mode string) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("enabling LTE IPsec session: session is closed")
	}
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", transport.SecureModeTransport:
		if s.espConn != nil {
			return nil
		}
		conn, err := s.openESP(ctx, s.localIP)
		if err != nil {
			return fmt.Errorf("enabling LTE IPsec transport mode: %w", err)
		}
		s.espConn = conn
		s.startReadLoop(conn, transport.SecureModeTransport)
		return nil
	case strings.ToLower(transport.SecureModeUDPEncTunnel):
		if s.udpConn != nil {
			return nil
		}
		conn, err := s.openUDP(ctx, s.localIP)
		if err != nil {
			return fmt.Errorf("enabling LTE IPsec UDP encapsulation: %w", err)
		}
		s.udpConn = conn
		s.startReadLoop(conn, transport.SecureModeUDPEncTunnel)
		return nil
	default:
		return fmt.Errorf("enabling LTE IPsec session: unsupported mode %q", mode)
	}
}

func (s *Session) InnerIPsForRemote(remoteIP net.IP) (net.IP, net.IP, error) {
	if len(remoteIP) != 0 && !remoteIP.Equal(s.remoteIP) {
		return nil, nil, fmt.Errorf("resolving LTE IPsec route: remote IP %s does not match P-CSCF %s", remoteIP, s.remoteIP)
	}
	return append(net.IP(nil), s.localIP...), append(net.IP(nil), s.remoteIP...), nil
}

func (s *Session) Logger() *slog.Logger {
	return s.logger
}

func (s *Session) Attach(handler ipsecbase.InnerHandler) (ipsecbase.Attachment, error) {
	if handler == nil {
		return nil, errors.New("attaching LTE IPsec handler: handler is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("attaching LTE IPsec handler: session is closed")
	}
	a := &attachment{session: s, handler: handler}
	s.attachments = append(s.attachments, a)
	return a, nil
}

func (s *Session) WriteInnerPacket(ctx context.Context, pkt packet.InnerPacket) error {
	var conn packetConn
	var data []byte
	var remote net.Addr

	s.mu.RLock()
	switch {
	case pkt.IP.Protocol == packet.ProtocolESP:
		conn = s.espConn
		data = append([]byte(nil), pkt.IP.Payload...)
		remote = &net.IPAddr{IP: append(net.IP(nil), s.remoteIP...)}
	case pkt.UDP != nil && pkt.UDP.Dst != nil && pkt.UDP.Dst.Port == udpEncapPort:
		conn = s.udpConn
		data = append([]byte(nil), pkt.UDP.Payload...)
		remote = &net.UDPAddr{IP: append(net.IP(nil), s.remoteIP...), Port: udpEncapPort}
	}
	closed := s.closed
	s.mu.RUnlock()
	if closed {
		return errors.New("writing LTE IPsec packet: session is closed")
	}
	if conn == nil {
		return errors.New("writing LTE IPsec packet: transport mode is not enabled")
	}
	if len(data) == 0 {
		return errors.New("writing LTE IPsec packet: payload is empty")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("writing LTE IPsec packet: %w", err)
		}
		defer func() {
			_ = conn.SetWriteDeadline(time.Time{})
		}()
	}
	n, err := conn.WriteTo(data, remote)
	if err != nil {
		return fmt.Errorf("writing LTE IPsec packet: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("writing LTE IPsec packet: wrote %d of %d bytes: %w", n, len(data), io.ErrShortWrite)
	}
	return nil
}

func (s *Session) Close() error {
	var closeErr error
	s.closeOnce.Do(func() {
		s.mu.Lock()
		s.closed = true
		attachments := append([]*attachment(nil), s.attachments...)
		s.attachments = nil
		espConn := s.espConn
		udpConn := s.udpConn
		s.espConn = nil
		s.udpConn = nil
		close(s.closeCh)
		s.mu.Unlock()
		for _, a := range attachments {
			a.close()
		}
		if espConn != nil {
			closeErr = errors.Join(closeErr, normalizeCloseError(espConn.Close()))
		}
		if udpConn != nil {
			closeErr = errors.Join(closeErr, normalizeCloseError(udpConn.Close()))
		}
	})
	s.wg.Wait()
	return closeErr
}

func (s *Session) startReadLoop(conn packetConn, mode string) {
	s.wg.Go(func() {
		buf := make([]byte, maxIPPacketLength)
		for {
			if err := conn.SetReadDeadline(time.Now().Add(readPollInterval)); err != nil {
				s.fail(err)
				return
			}
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				if isTimeout(err) {
					select {
					case <-s.closeCh:
						return
					default:
						continue
					}
				}
				if errors.Is(err, net.ErrClosed) {
					return
				}
				s.fail(fmt.Errorf("reading LTE IPsec packet: %w", err))
				return
			}
			pkt, err := s.inboundPacket(mode, peer, buf[:n], conn.LocalAddr())
			if err != nil {
				s.logger.Debug("discarding LTE IPsec packet", "err", err)
				continue
			}
			handled := s.dispatch(pkt)
			s.logger.Debug("received LTE IPsec packet", "mode", mode, "peer", peer, "bytes", n, "handled", handled)
		}
	})
}

func (s *Session) inboundPacket(mode string, peer net.Addr, data []byte, local net.Addr) (packet.InnerPacket, error) {
	switch mode {
	case transport.SecureModeTransport:
		peerIP := addrIP(peer)
		if len(peerIP) == 0 || !peerIP.Equal(s.remoteIP) {
			return packet.InnerPacket{}, fmt.Errorf("unexpected ESP peer %v", peer)
		}
		return packet.InnerPacket{IP: packet.IPPacket{
			Protocol: packet.ProtocolESP,
			SrcIP:    append(net.IP(nil), peerIP...),
			DstIP:    append(net.IP(nil), s.localIP...),
			Payload:  append([]byte(nil), data...),
		}}, nil
	case transport.SecureModeUDPEncTunnel:
		peerUDP, ok := peer.(*net.UDPAddr)
		if !ok || peerUDP == nil || peerUDP.Port != udpEncapPort || !peerUDP.IP.Equal(s.remoteIP) {
			return packet.InnerPacket{}, fmt.Errorf("unexpected UDP-encapsulated ESP peer %v", peer)
		}
		localUDP, ok := local.(*net.UDPAddr)
		if !ok || localUDP == nil {
			localUDP = &net.UDPAddr{IP: append(net.IP(nil), s.localIP...), Port: udpEncapPort}
		}
		return packet.InnerPacket{UDP: &packet.UDPSegment{
			Src:     cloneUDPAddr(peerUDP),
			Dst:     cloneUDPAddr(localUDP),
			Payload: append([]byte(nil), data...),
		}}, nil
	default:
		return packet.InnerPacket{}, fmt.Errorf("unsupported LTE IPsec mode %q", mode)
	}
}

func (s *Session) dispatch(pkt packet.InnerPacket) bool {
	s.mu.RLock()
	attachments := append([]*attachment(nil), s.attachments...)
	s.mu.RUnlock()
	for _, a := range attachments {
		if a == nil || a.isClosed() {
			continue
		}
		if a.handler.HandleInnerPacket(pkt) {
			return true
		}
	}
	return false
}

func (s *Session) fail(err error) {
	s.mu.RLock()
	attachments := append([]*attachment(nil), s.attachments...)
	s.mu.RUnlock()
	for _, a := range attachments {
		if a != nil && !a.isClosed() {
			a.handler.HandleError(err)
		}
	}
}

func (s *Session) removeAttachment(target *attachment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, candidate := range s.attachments {
		if candidate == target {
			s.attachments = append(s.attachments[:i], s.attachments[i+1:]...)
			return
		}
	}
}

func (a *attachment) Close() error {
	a.close()
	return nil
}

func (a *attachment) close() {
	a.once.Do(func() {
		a.mu.Lock()
		a.closed = true
		a.mu.Unlock()
		if a.session != nil {
			a.session.removeAttachment(a)
		}
	})
}

func (a *attachment) isClosed() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.closed
}

type systemPacketListener struct{}

func (systemPacketListener) ListenIPPacket(ctx context.Context, network string, local *net.IPAddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return net.ListenIP(network, local)
}

func (systemPacketListener) ListenUDPPacket(ctx context.Context, local *net.UDPAddr) (net.PacketConn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return net.ListenUDP("udp", local)
}

func listenESP(ctx context.Context, listener PacketListener, localIP net.IP) (packetConn, error) {
	network := "ip6:esp"
	if localIP.To4() != nil {
		network = "ip4:esp"
	}
	conn, err := listener.ListenIPPacket(ctx, network, &net.IPAddr{IP: append(net.IP(nil), localIP...)})
	if err != nil {
		return nil, fmt.Errorf("opening raw ESP socket: %w", err)
	}
	return conn, nil
}

func listenUDPEncap(ctx context.Context, listener PacketListener, localIP net.IP) (packetConn, error) {
	conn, err := listener.ListenUDPPacket(ctx, &net.UDPAddr{IP: append(net.IP(nil), localIP...), Port: udpEncapPort})
	if err != nil {
		return nil, fmt.Errorf("opening UDP-encapsulated ESP socket: %w", err)
	}
	return conn, nil
}

func normalizeIPPair(localIP, remoteIP net.IP) (net.IP, net.IP, error) {
	local := net.ParseIP(strings.TrimSpace(localIP.String()))
	remote := net.ParseIP(strings.TrimSpace(remoteIP.String()))
	if local == nil || remote == nil {
		return nil, nil, errors.New("local and remote IP addresses are required")
	}
	if (local.To4() == nil) != (remote.To4() == nil) {
		return nil, nil, errors.New("local and remote IP families do not match")
	}
	return append(net.IP(nil), local...), append(net.IP(nil), remote...), nil
}

func addrIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP
	case *net.UDPAddr:
		return value.IP
	default:
		return nil
	}
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func normalizeCloseError(err error) error {
	if errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
}
