package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

var _ Transport = (*udpTransport)(nil)

type udpTransport struct {
	conn   *net.UDPConn
	local  *net.UDPAddr
	remote *net.UDPAddr

	writeMu sync.Mutex
}

// OpenUDPTransport opens a UDP SIP transport bound to the supplied local IP.
func OpenUDPTransport(ctx context.Context, localIP, remoteIP net.IP, remotePort int) (Transport, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	local := &net.UDPAddr{IP: append(net.IP(nil), localIP...)}
	remote := &net.UDPAddr{IP: append(net.IP(nil), remoteIP...), Port: remotePort}
	conn, err := net.ListenUDP("udp", local)
	if err != nil {
		return nil, fmt.Errorf("opening udp transport: %w", err)
	}
	return &udpTransport{
		conn:   conn,
		local:  cloneUDPAddr(conn.LocalAddr().(*net.UDPAddr)),
		remote: remote,
	}, nil
}

func (t *udpTransport) LocalAddr() net.Addr {
	return cloneUDPAddr(t.local)
}

func (t *udpTransport) RemoteAddr() net.Addr {
	return cloneUDPAddr(t.remote)
}

func (t *udpTransport) WritePacket(ctx context.Context, data []byte) error {
	return t.WritePacketTo(ctx, data, nil)
}

func (t *udpTransport) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	remote := t.remote
	if udp, ok := addr.(*net.UDPAddr); ok && udp != nil {
		remote = udp
	}
	if remote == nil {
		return errors.New("writing udp packet: remote address is not configured")
	}
	deadline, hasDeadline := contextDeadline(ctx)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if hasDeadline {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("writing udp packet: %w", err)
		}
		defer t.conn.SetWriteDeadline(time.Time{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := t.conn.WriteToUDP(data, remote); err != nil {
		return fmt.Errorf("writing udp packet: %w", err)
	}
	return nil
}

func (t *udpTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	buf := make([]byte, maxSIPMessageBytes)
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := t.conn.SetReadDeadline(networkReadDeadline(ctx)); err != nil {
			return nil, nil, fmt.Errorf("reading udp packet: %w", err)
		}
		n, addr, err := t.conn.ReadFromUDP(buf)
		if err == nil {
			return append([]byte(nil), buf[:n]...), cloneUDPAddr(addr), nil
		}
		if isNetworkTimeout(err) {
			continue
		}
		return nil, nil, fmt.Errorf("reading udp packet: %w", err)
	}
}

func (t *udpTransport) Close() error {
	return t.conn.Close()
}
