package ims

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	imsvoice "github.com/damonto/ims-go/ims/voice"
)

const (
	volteMediaQueueSize      = 16
	volteMediaReadPoll       = 250 * time.Millisecond
	maxVolteMediaPacketBytes = 64 * 1024
)

var _ imsvoice.MediaTransport = (*volteMediaTransport)(nil)
var _ imsvoice.RTCPMediaTransport = (*volteMediaTransport)(nil)

type volteMediaTransport struct {
	rtp   *net.UDPConn
	rtcp  *net.UDPConn
	local *net.UDPAddr

	rtpCh  chan volteMediaPacket
	rtcpCh chan volteMediaPacket
	done   chan struct{}

	mu          sync.Mutex
	writeMu     sync.Mutex
	closeOnce   sync.Once
	closed      bool
	remote      imsvoice.MediaRemote
	onPacket    func(imsvoice.MediaPacket)
	terminalErr error
}

type volteMediaPacket struct {
	data []byte
	addr net.Addr
	err  error
}

func openVoLTEMediaTransport(ctx context.Context, interfaceName string, localIP net.IP, cfg imsvoice.MediaConfig) (imsvoice.MediaTransport, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	if len(localIP) == 0 {
		return nil, errors.New("opening voice media transport: local address is required")
	}
	if cfg.LocalPort == 0 {
		return nil, errors.New("opening voice media transport: local port is required")
	}
	if cfg.LocalPort == 65535 {
		return nil, errors.New("opening voice media transport: local rtcp port would exceed 65535")
	}
	local := &net.UDPAddr{IP: append(net.IP(nil), localIP...), Port: cfg.LocalPort}
	rtp, err := listenVoLTEUDP(ctx, interfaceName, local)
	if err != nil {
		return nil, fmt.Errorf("opening voice media transport: %w", err)
	}
	rtcp, err := listenVoLTEUDP(ctx, interfaceName, imsvoice.RTCPAddr(local))
	if err != nil {
		_ = rtp.Close()
		return nil, fmt.Errorf("opening voice media rtcp transport: %w", err)
	}
	transport := &volteMediaTransport{
		rtp:      rtp,
		rtcp:     rtcp,
		local:    imsvoice.CloneUDPAddr(rtp.LocalAddr().(*net.UDPAddr)),
		rtpCh:    make(chan volteMediaPacket, volteMediaQueueSize),
		rtcpCh:   make(chan volteMediaPacket, volteMediaQueueSize),
		done:     make(chan struct{}),
		onPacket: cfg.OnPacket,
	}
	if len(cfg.RemoteIP) != 0 && cfg.RemotePort != 0 {
		if err := transport.applyRemoteConfig(cfg); err != nil {
			_ = transport.Close()
			return nil, err
		}
	}
	go transport.readLoop(rtp, false)
	go transport.readLoop(rtcp, true)
	return transport, nil
}

func (t *volteMediaTransport) LocalAddr() net.Addr {
	return imsvoice.CloneUDPAddr(t.local)
}

func (t *volteMediaTransport) RemoteAddr() net.Addr {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remote.Addr(false)
}

func (t *volteMediaTransport) ConfigureRemote(ctx context.Context, cfg imsvoice.MediaConfig) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if len(cfg.RemoteIP) == 0 || cfg.RemotePort == 0 {
		return errors.New("configuring voice media remote: remote address is required")
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

func (t *volteMediaTransport) applyRemoteConfig(cfg imsvoice.MediaConfig) error {
	remote, err := imsvoice.MediaRemoteFromConfig(cfg)
	if err != nil {
		return fmt.Errorf("configuring voice media remote: %w", err)
	}
	t.remote = remote
	return nil
}

func (t *volteMediaTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.writeUDP(ctx, data, false)
}

func (t *volteMediaTransport) WriteRTCP(ctx context.Context, data []byte) error {
	return t.writeUDP(ctx, data, true)
}

func (t *volteMediaTransport) writeUDP(ctx context.Context, data []byte, rtcp bool) error {
	t.mu.Lock()
	closed := t.closed
	remote := t.remote.Addr(rtcp)
	rtcpMux := t.remote.RTCPMux
	t.mu.Unlock()
	if closed {
		return errors.New("writing voice media packet: transport is closed")
	}
	if remote == nil {
		return errors.New("writing voice media packet: remote address is not configured")
	}
	conn := t.rtp
	if rtcp && !rtcpMux {
		conn = t.rtcp
	}
	deadline, hasDeadline := volteMediaContextDeadline(ctx)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if hasDeadline {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("writing voice media packet: %w", err)
		}
		defer conn.SetWriteDeadline(time.Time{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := conn.WriteToUDP(data, remote); err != nil {
		return fmt.Errorf("writing voice media packet: %w", err)
	}
	return nil
}

func (t *volteMediaTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	return t.readUDP(ctx, false)
}

func (t *volteMediaTransport) ReadRTCP(ctx context.Context) ([]byte, net.Addr, error) {
	return t.readUDP(ctx, true)
}

func (t *volteMediaTransport) readUDP(ctx context.Context, rtcp bool) ([]byte, net.Addr, error) {
	ch := t.rtpCh
	if rtcp {
		ch = t.rtcpCh
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-t.done:
		return nil, nil, t.closedErr()
	case packet := <-ch:
		return packet.data, packet.addr, packet.err
	}
}

func (t *volteMediaTransport) readLoop(conn *net.UDPConn, rtcpSocket bool) {
	buf := make([]byte, maxVolteMediaPacketBytes)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(volteMediaReadPoll)); err != nil {
			t.queuePacket(rtcpSocket, volteMediaPacket{err: fmt.Errorf("reading voice media packet: %w", err)})
			return
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if isVolteMediaTimeout(err) {
				select {
				case <-t.done:
					return
				default:
					continue
				}
			}
			select {
			case <-t.done:
				return
			default:
				t.queuePacket(rtcpSocket, volteMediaPacket{err: fmt.Errorf("reading voice media packet: %w", err)})
				return
			}
		}
		data := append([]byte(nil), buf[:n]...)
		rtcp := rtcpSocket
		if !rtcpSocket {
			t.mu.Lock()
			mux := t.remote.RTCPMux
			t.mu.Unlock()
			if mux {
				rtcp = imsvoice.IsRTCPPacket(data)
			}
		}
		t.notifyPacket(rtcp, data)
		t.queuePacket(rtcp, volteMediaPacket{data: data, addr: imsvoice.CloneUDPAddr(addr)})
	}
}

func (t *volteMediaTransport) queuePacket(rtcp bool, packet volteMediaPacket) {
	ch := t.rtpCh
	if rtcp {
		ch = t.rtcpCh
	}
	select {
	case ch <- packet:
	default:
	}
}

func (t *volteMediaTransport) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		t.mu.Unlock()
		close(t.done)
		_ = t.rtp.Close()
		if t.rtcp != nil && t.rtcp != t.rtp {
			_ = t.rtcp.Close()
		}
	})
	return nil
}

func (t *volteMediaTransport) notifyPacket(rtcp bool, payload []byte) {
	t.mu.Lock()
	onPacket := t.onPacket
	t.mu.Unlock()
	if onPacket != nil {
		onPacket(imsvoice.MediaPacketFromPayload(rtcp, payload))
	}
}

func (t *volteMediaTransport) closedErr() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.terminalErr != nil {
		return t.terminalErr
	}
	return errVoiceMediaTransportClosed
}

func volteMediaContextDeadline(ctx context.Context) (time.Time, bool) {
	deadline, ok := ctx.Deadline()
	return deadline, ok
}

func isVolteMediaTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
