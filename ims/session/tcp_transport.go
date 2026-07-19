package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var _ Transport = (*tcpTransport)(nil)

type tcpTransport struct {
	conn   *net.TCPConn
	local  *net.TCPAddr
	remote *net.TCPAddr

	readMu  sync.Mutex
	writeMu sync.Mutex
	stream  []byte
	queued  [][]byte
}

// OpenTCPTransport opens a TCP SIP transport bound to the supplied local IP.
func OpenTCPTransport(ctx context.Context, localIP, remoteIP net.IP, remotePort int) (Transport, error) {
	local := &net.TCPAddr{IP: append(net.IP(nil), localIP...)}
	remote := &net.TCPAddr{IP: append(net.IP(nil), remoteIP...), Port: remotePort}
	dialer := net.Dialer{LocalAddr: local}
	conn, err := dialer.DialContext(ctx, "tcp", remote.String())
	if err != nil {
		return nil, fmt.Errorf("opening tcp transport: %w", err)
	}
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("opening tcp transport: connection is not TCP")
	}
	transport, err := NewTCPTransport(tcp)
	if err != nil {
		_ = tcp.Close()
		return nil, fmt.Errorf("opening tcp transport: %w", err)
	}
	return transport, nil
}

// NewTCPTransport takes ownership of an established TCP connection.
func NewTCPTransport(conn *net.TCPConn) (Transport, error) {
	if conn == nil {
		return nil, errors.New("TCP connection is required")
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("TCP connection has an invalid local address")
	}
	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, errors.New("TCP connection has an invalid remote address")
	}
	return &tcpTransport{
		conn:   conn,
		local:  cloneTCPAddr(local),
		remote: cloneTCPAddr(remote),
	}, nil
}

func (t *tcpTransport) LocalAddr() net.Addr {
	return cloneTCPAddr(t.local)
}

func (t *tcpTransport) RemoteAddr() net.Addr {
	return cloneTCPAddr(t.remote)
}

func (t *tcpTransport) WritePacket(ctx context.Context, data []byte) error {
	deadline, hasDeadline := contextDeadline(ctx)
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if hasDeadline {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("writing tcp packet: %w", err)
		}
		defer t.conn.SetWriteDeadline(time.Time{})
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	for written := 0; written < len(data); {
		n, err := t.conn.Write(data[written:])
		if err != nil {
			return fmt.Errorf("writing tcp packet: %w", err)
		}
		if n == 0 {
			return errors.New("writing tcp packet: zero bytes written")
		}
		written += n
	}
	return nil
}

func (t *tcpTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()

	buf := make([]byte, sipReadBufferLength)
	for {
		if packet, ok := t.dequeuePacket(); ok {
			return packet, cloneTCPAddr(t.remote), nil
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		if err := t.conn.SetReadDeadline(networkReadDeadline(ctx)); err != nil {
			return nil, nil, fmt.Errorf("reading tcp packet: %w", err)
		}
		n, err := t.conn.Read(buf)
		if n > 0 {
			t.stream = append(t.stream, buf[:n]...)
			for {
				keepalive, rest, ok := nextCRLFKeepAlive(t.stream)
				if !ok {
					break
				}
				t.queued = append(t.queued, keepalive)
				t.stream = rest
			}
			messages, rest, parseErr := StageSIPMessages(t.stream)
			if parseErr != nil {
				return nil, nil, fmt.Errorf("reading tcp packet: %w", parseErr)
			}
			t.stream = append([]byte(nil), rest...)
			t.queued = append(t.queued, messages...)
			continue
		}
		if err == nil {
			continue
		}
		if isNetworkTimeout(err) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return nil, nil, err
		}
		return nil, nil, fmt.Errorf("reading tcp packet: %w", err)
	}
}

func nextCRLFKeepAlive(stream []byte) ([]byte, []byte, bool) {
	if len(stream) >= 4 && string(stream[:4]) == "\r\n\r\n" {
		return append([]byte(nil), stream[:4]...), stream[4:], true
	}
	if len(stream) >= 2 && string(stream[:2]) == "\r\n" {
		return append([]byte(nil), stream[:2]...), stream[2:], true
	}
	return nil, stream, false
}

func (t *tcpTransport) Close() error {
	return t.conn.Close()
}

func (t *tcpTransport) dequeuePacket() ([]byte, bool) {
	if len(t.queued) == 0 {
		return nil, false
	}
	packet := t.queued[0]
	copy(t.queued, t.queued[1:])
	t.queued[len(t.queued)-1] = nil
	t.queued = t.queued[:len(t.queued)-1]
	return packet, true
}
