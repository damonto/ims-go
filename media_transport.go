package ims

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	imsvoice "github.com/damonto/ims-go/ims/voice"
	"github.com/damonto/ims-go/swu/packet"
	swutunnel "github.com/damonto/ims-go/swu/tunnel"
)

const mediaTransportDrainDelay = 2 * time.Second

type tunnelMediaTransport struct {
	session    *swutunnel.Session
	logger     *slog.Logger
	attachment swutunnel.Attachment
	local      *net.UDPAddr
	remote     imsvoice.MediaRemote
	readCh     chan tunnelMediaPacket
	rtcpCh     chan tunnelMediaPacket
	done       chan struct{}
	onPacket   func(imsvoice.MediaPacket)
	closeOnce  sync.Once

	mu          sync.Mutex
	closed      bool
	terminalErr error
	inRTP       int
	inRTCP      int
	outRTP      int
	outRTCP     int
}

type tunnelMediaPacket struct {
	data []byte
	addr net.Addr
	err  error
}

func newTunnelMediaTransport(ctx context.Context, session *swutunnel.Session, cfg imsvoice.MediaConfig) (*tunnelMediaTransport, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	info, err := session.ReadyInfo()
	if err != nil {
		return nil, fmt.Errorf("opening voice media transport: %w", err)
	}
	if cfg.LocalPort == 0 {
		return nil, errors.New("opening voice media transport: local port is required")
	}
	localIP := info.InnerIPForRemote(cfg.RemoteIP)
	if len(localIP) == 0 {
		return nil, errors.New("opening voice media transport: matching local ip is unavailable")
	}
	transport := &tunnelMediaTransport{
		session: session,
		logger:  session.Logger(),
		local: &net.UDPAddr{
			IP:   localIP,
			Port: cfg.LocalPort,
		},
		readCh:   make(chan tunnelMediaPacket, 32),
		rtcpCh:   make(chan tunnelMediaPacket, 32),
		done:     make(chan struct{}),
		onPacket: cfg.OnPacket,
	}
	if len(cfg.RemoteIP) != 0 && cfg.RemotePort != 0 {
		if err := transport.applyRemoteConfig(cfg); err != nil {
			return nil, err
		}
	}
	attachment, err := session.Attach(transport)
	if err != nil {
		return nil, fmt.Errorf("opening voice media transport: %w", err)
	}
	transport.attachment = attachment
	return transport, nil
}

func (t *tunnelMediaTransport) LocalAddr() net.Addr {
	return imsvoice.CloneUDPAddr(t.local)
}

func (t *tunnelMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote.Addr(false)
}

func (t *tunnelMediaTransport) ConfigureRemote(ctx context.Context, cfg imsvoice.MediaConfig) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if len(cfg.RemoteIP) == 0 || cfg.RemotePort == 0 {
		return errors.New("configuring voice media remote: remote address is required")
	}
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return errors.New("configuring voice media remote: transport is closed")
	}
	if err := t.applyRemoteConfig(cfg); err != nil {
		t.mu.Unlock()
		return err
	}
	t.onPacket = cfg.OnPacket
	t.mu.Unlock()
	return nil
}

func (t *tunnelMediaTransport) applyRemoteConfig(cfg imsvoice.MediaConfig) error {
	remote, err := imsvoice.MediaRemoteFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("configuring voice media remote: %w", err)
	}
	t.remote = remote
	return nil
}

func (t *tunnelMediaTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.writeUDP(ctx, data, false)
}

func (t *tunnelMediaTransport) WriteRTCP(ctx context.Context, data []byte) error {
	return t.writeUDP(ctx, data, true)
}

func (t *tunnelMediaTransport) writeUDP(ctx context.Context, data []byte, rtcp bool) error {
	t.mu.Lock()
	closed := t.closed
	local := t.localMediaAddr(rtcp)
	remote := t.remote.Addr(rtcp)
	count := t.nextMediaCount(rtcp, false)
	t.mu.Unlock()
	if closed {
		return errors.New("writing voice media packet: transport is closed")
	}
	if remote == nil {
		return errors.New("writing voice media packet: remote address is not configured")
	}
	t.logMediaPacket("send", rtcp, count, local, remote, len(data))
	return t.session.WriteInnerPacket(ctx, packet.InnerPacket{
		UDP: &packet.UDPSegment{
			Src:     local,
			Dst:     remote,
			Payload: append([]byte(nil), data...),
		},
	})
}

func (t *tunnelMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.readUDP(ctx, false)
}

func (t *tunnelMediaTransport) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	return t.readUDP(ctx, true)
}

func (t *tunnelMediaTransport) readUDP(ctx context.Context, rtcp bool) ([]byte, net.Addr, error) {
	readCh := t.readCh
	if rtcp {
		readCh = t.rtcpCh
	}
	for {
		select {
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		case <-t.done:
			return nil, nil, t.closedErr()
		case inbound := <-readCh:
			if inbound.err != nil {
				return nil, nil, inbound.err
			}
			return inbound.data, inbound.addr, nil
		}
	}
}

func (t *tunnelMediaTransport) Close() error {
	t.closeWithError(nil)
	return nil
}

func (t *tunnelMediaTransport) HandleInnerPacket(pkt packet.InnerPacket) bool {
	if pkt.UDP == nil || pkt.UDP.Src == nil || pkt.UDP.Dst == nil {
		return false
	}
	t.mu.Lock()
	closed := t.closed
	local := imsvoice.CloneUDPAddr(t.local)
	rtcpLocal := t.localMediaAddr(true)
	remote := t.remote.Addr(false)
	rtcpMux := t.remote.RTCPMux
	t.mu.Unlock()
	if local == nil {
		return false
	}
	rtcp := false
	switch {
	case imsvoice.UDPAddrMatches(pkt.UDP.Dst, local):
		rtcp = rtcpMux && imsvoice.IsRTCPPacket(pkt.UDP.Payload)
	case imsvoice.UDPAddrMatches(pkt.UDP.Dst, rtcpLocal):
		rtcp = true
	default:
		return false
	}
	if closed {
		if remote == nil {
			return false
		}
		t.mu.Lock()
		wantRemote := t.remote.Addr(rtcp)
		t.mu.Unlock()
		return imsvoice.UDPAddrMatches(pkt.UDP.Src, wantRemote)
	}
	if remote == nil {
		return true
	}
	t.mu.Lock()
	count := t.nextMediaCount(rtcp, true)
	t.mu.Unlock()
	t.logMediaPacket("recv", rtcp, count, pkt.UDP.Dst, pkt.UDP.Src, len(pkt.UDP.Payload))
	t.notifyPacket(rtcp, pkt.UDP.Payload)
	readCh := t.readCh
	if rtcp {
		readCh = t.rtcpCh
	}
	select {
	case readCh <- tunnelMediaPacket{data: append([]byte(nil), pkt.UDP.Payload...), addr: imsvoice.CloneUDPAddr(pkt.UDP.Src)}:
	case <-t.done:
	default:
	}
	return true
}

func (t *tunnelMediaTransport) nextMediaCount(rtcp bool, inbound bool) int {
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

func (t *tunnelMediaTransport) logMediaPacket(direction string, rtcp bool, count int, local *net.UDPAddr, peer *net.UDPAddr, payloadLen int) {
	if count != 1 && count%100 != 0 {
		return
	}
	kind := "rtp"
	if rtcp {
		kind = "rtcp"
	}
	t.logger.Debug("voice media packet", "direction", direction, "kind", kind, "count", count, "local_addr", local, "peer_addr", peer, "payload_len", payloadLen)
}

func (t *tunnelMediaTransport) notifyPacket(rtcp bool, payload []byte) {
	t.mu.Lock()
	onPacket := t.onPacket
	t.mu.Unlock()
	if onPacket != nil {
		onPacket(imsvoice.MediaPacketFromPayload(rtcp, payload))
	}
}

func (t *tunnelMediaTransport) HandleError(err error) {
	t.closeWithError(fmt.Errorf("reading voice media packet: %w", err))
}

func (t *tunnelMediaTransport) closeWithError(err error) {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.terminalErr = err
		attachment := t.attachment
		t.mu.Unlock()
		if attachment != nil && err != nil {
			_ = attachment.Close()
		}
		if attachment != nil && err == nil {
			time.AfterFunc(mediaTransportDrainDelay, func() {
				_ = attachment.Close()
			})
		}
		close(t.done)
	})
}

func (t *tunnelMediaTransport) closedErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errors.New("reading voice media packet: transport is closed")
}

func (t *tunnelMediaTransport) localMediaAddr(rtcp bool) *net.UDPAddr {
	return imsvoice.MediaLocalUDPAddr(t.local, rtcp, t.remote.RTCPMux)
}
