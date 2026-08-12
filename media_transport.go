package ims

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	imsvoice "github.com/damonto/ims-go/ims/voice"
	ipsectransport "github.com/damonto/ims-go/ipsec/transport"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

var errVoiceMediaTransportClosed = errors.New("reading voice media packet: transport is closed")

type netstackMediaTransport struct {
	rtpConn  *ipsectransport.NetstackUDPConn
	rtcpConn *ipsectransport.NetstackUDPConn
	readStop context.CancelFunc
	logger   *slog.Logger
	local    *net.UDPAddr
	remote   imsvoice.MediaRemote
	readCh   chan mediaPacket
	rtcpCh   chan mediaPacket
	done     chan struct{}
	onPacket func(imsvoice.MediaPacket)

	mu          sync.Mutex
	closed      bool
	terminalErr error
	closeErr    error
	inRTP       int
	inRTCP      int
	outRTP      int
	outRTCP     int
	closeOnce   sync.Once
	readWG      sync.WaitGroup
}

type mediaPacket struct {
	data []byte
	addr net.Addr
}

func newNetstackMediaTransport(ctx context.Context, session *swutunnel.Session, netstack *ipsectransport.Netstack, cfg imsvoice.MediaConfig) (*netstackMediaTransport, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if netstack == nil {
		return nil, errors.New("opening voice media transport: userspace network stack is unavailable")
	}
	if cfg.LocalPort <= 0 || cfg.LocalPort >= 65535 {
		return nil, errors.New("opening voice media transport: local RTP port must be between 1 and 65534")
	}
	info, err := session.ReadyInfo()
	if err != nil {
		return nil, fmt.Errorf("opening voice media transport: %w", err)
	}
	localIP := info.InnerIPForRemote(cfg.RemoteIP)
	if len(localIP) == 0 {
		return nil, errors.New("opening voice media transport: matching local IP is unavailable")
	}
	rtpConn, err := netstack.ListenUDP(ctx, ipsectransport.UDPConfig{LocalPort: cfg.LocalPort, RemoteIP: cfg.RemoteIP})
	if err != nil {
		return nil, fmt.Errorf("opening voice media transport: RTP socket: %w", err)
	}
	rtcpConn, err := netstack.ListenUDP(ctx, ipsectransport.UDPConfig{LocalPort: cfg.LocalPort + 1, RemoteIP: cfg.RemoteIP})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("opening voice media transport: RTCP socket: %w", err), rtpConn.Close())
	}
	readCtx, readStop := context.WithCancel(context.WithoutCancel(ctx))
	transport := &netstackMediaTransport{
		rtpConn:  rtpConn,
		rtcpConn: rtcpConn,
		readStop: readStop,
		logger:   session.Logger(),
		local:    &net.UDPAddr{IP: append(net.IP(nil), localIP...), Port: cfg.LocalPort},
		readCh:   make(chan mediaPacket, 32),
		rtcpCh:   make(chan mediaPacket, 32),
		done:     make(chan struct{}),
		onPacket: cfg.OnPacket,
	}
	if len(cfg.RemoteIP) != 0 && cfg.RemotePort != 0 {
		if err := transport.applyRemoteConfig(cfg); err != nil {
			readStop()
			return nil, errors.Join(err, rtpConn.Close(), rtcpConn.Close())
		}
	}
	transport.readWG.Add(2)
	go func() {
		defer transport.readWG.Done()
		transport.readLoop(readCtx, rtpConn)
	}()
	go func() {
		defer transport.readWG.Done()
		transport.readLoop(readCtx, rtcpConn)
	}()
	return transport, nil
}

func (t *netstackMediaTransport) LocalAddr() net.Addr {
	return imsvoice.CloneUDPAddr(t.local)
}

func (t *netstackMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote.Addr(false)
}

func (t *netstackMediaTransport) ConfigureRemote(ctx context.Context, cfg imsvoice.MediaConfig) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("configuring voice media remote: transport is closed")
	}
	if err := t.applyRemoteConfig(cfg); err != nil {
		return err
	}
	t.onPacket = cfg.OnPacket
	return nil
}

func (t *netstackMediaTransport) applyRemoteConfig(cfg imsvoice.MediaConfig) error {
	remote, err := imsvoice.MediaRemoteFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("configuring voice media remote: %w", err)
	}
	t.remote = remote
	return nil
}

func (t *netstackMediaTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.write(ctx, data, false)
}

func (t *netstackMediaTransport) WriteRTCP(ctx context.Context, data []byte) error {
	return t.write(ctx, data, true)
}

func (t *netstackMediaTransport) write(ctx context.Context, data []byte, rtcp bool) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("writing voice media packet: transport is closed")
	}
	remote := t.remote.Addr(rtcp)
	rtcpMux := t.remote.RTCPMux
	local := imsvoice.MediaLocalUDPAddr(t.local, rtcp, rtcpMux)
	count := t.nextMediaCount(rtcp, false)
	t.mu.Unlock()
	if remote == nil {
		return errors.New("writing voice media packet: remote address is not configured")
	}
	conn := t.rtpConn
	if rtcp && !rtcpMux {
		conn = t.rtcpConn
	}
	t.logMediaPacket("send", rtcp, count, local, remote, len(data))
	if err := conn.WritePacketTo(ctx, data, remote); err != nil {
		return fmt.Errorf("writing voice media packet: %w", err)
	}
	return nil
}

func (t *netstackMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.read(ctx, false)
}

func (t *netstackMediaTransport) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	return t.read(ctx, true)
}

func (t *netstackMediaTransport) read(ctx context.Context, rtcp bool) ([]byte, net.Addr, error) {
	readCh := t.readCh
	if rtcp {
		readCh = t.rtcpCh
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.done:
		return nil, nil, t.closedErr()
	case packet := <-readCh:
		return packet.data, packet.addr, nil
	}
}

func (t *netstackMediaTransport) readLoop(ctx context.Context, conn *ipsectransport.NetstackUDPConn) {
	for {
		data, peer, err := conn.ReadPacket(ctx)
		if err != nil {
			select {
			case <-t.done:
				return
			default:
			}
			t.closeWithError(fmt.Errorf("reading voice media packet: %w", err))
			return
		}
		peerUDP, ok := peer.(*net.UDPAddr)
		if !ok {
			continue
		}
		local, ok := conn.LocalAddr().(*net.UDPAddr)
		if !ok {
			continue
		}
		t.handlePacket(data, peerUDP, local)
	}
}

func (t *netstackMediaTransport) handlePacket(data []byte, peer, local *net.UDPAddr) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return
	}
	remote := t.remote.Addr(false)
	rtcpMux := t.remote.RTCPMux
	rtpLocal := imsvoice.CloneUDPAddr(t.local)
	rtcpLocal := imsvoice.MediaLocalUDPAddr(t.local, true, rtcpMux)
	rtcp := false
	switch {
	case imsvoice.UDPAddrMatches(local, rtpLocal):
		rtcp = rtcpMux && imsvoice.IsRTCPPacket(data)
	case imsvoice.UDPAddrMatches(local, rtcpLocal):
		rtcp = true
	default:
		t.mu.Unlock()
		return
	}
	if remote == nil {
		t.mu.Unlock()
		return
	}
	count := t.nextMediaCount(rtcp, true)
	onPacket := t.onPacket
	t.mu.Unlock()

	t.logMediaPacket("recv", rtcp, count, local, peer, len(data))
	if onPacket != nil {
		onPacket(imsvoice.MediaPacketFromPayload(rtcp, data))
	}
	readCh := t.readCh
	if rtcp {
		readCh = t.rtcpCh
	}
	select {
	case readCh <- mediaPacket{data: append([]byte(nil), data...), addr: imsvoice.CloneUDPAddr(peer)}:
	case <-t.done:
	default:
	}
}

func (t *netstackMediaTransport) nextMediaCount(rtcp, inbound bool) int {
	if inbound {
		if rtcp {
			t.inRTCP++
			return t.inRTCP
		}
		t.inRTP++
		return t.inRTP
	}
	if rtcp {
		t.outRTCP++
		return t.outRTCP
	}
	t.outRTP++
	return t.outRTP
}

func (t *netstackMediaTransport) logMediaPacket(direction string, rtcp bool, count int, local, peer *net.UDPAddr, payloadLen int) {
	if count != 1 && count%100 != 0 {
		return
	}
	kind := "rtp"
	if rtcp {
		kind = "rtcp"
	}
	t.logger.Debug("voice media packet", "direction", direction, "kind", kind, "count", count, "local_addr", local, "peer_addr", peer, "payload_len", payloadLen)
}

func (t *netstackMediaTransport) Close() error {
	t.closeWithError(nil)
	t.readWG.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeErr
}

func (t *netstackMediaTransport) closeWithError(err error) {
	t.closeOnce.Do(func() {
		t.readStop()
		t.mu.Lock()
		t.closed = true
		t.terminalErr = err
		t.mu.Unlock()
		close(t.done)
		t.closeErr = errors.Join(t.closeErr, t.rtpConn.Close(), t.rtcpConn.Close())
	})
}

func (t *netstackMediaTransport) closedErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errVoiceMediaTransportClosed
}
