package transport

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/gonet"
)

const (
	netstackTCPMSS          = 1024
	netstackTCPCloseTimeout = 500 * time.Millisecond
	netstackEphemeralBase   = 40000
	netstackEphemeralRange  = 20000
)

var (
	_ imssession.Transport = (*NetstackTCPConn)(nil)
	_ imssession.Transport = (*NetstackUDPConn)(nil)
)

type recoverableTCPConnectionError struct{ err error }

func (e *recoverableTCPConnectionError) Error() string         { return e.err.Error() }
func (e *recoverableTCPConnectionError) Unwrap() error         { return e.err }
func (e *recoverableTCPConnectionError) TransportUsable() bool { return true }

type TCPConfig struct {
	LocalPort  int
	RemotePort int
	RemoteIP   net.IP
}

type SecureTCPConfig struct {
	TCPConfig
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

type NetstackTCPConn struct {
	netstack *Netstack
	local    *net.TCPAddr
	remote   *net.TCPAddr
	passive  bool
	policy   *netstackSecurityPolicy

	mu     sync.Mutex
	conn   net.Conn
	server *netstackTCPListener
	closed bool

	readMu    sync.Mutex
	writeMu   sync.Mutex
	streamMu  sync.Mutex
	stream    []byte
	queued    [][]byte
	done      chan struct{}
	accept    chan net.Conn
	errCh     chan error
	closeOnce sync.Once
}

type netstackTCPListener struct {
	netstack   *Netstack
	key        netstackTCPListenerKey
	listener   net.Listener
	transports map[*NetstackTCPConn]struct{}
	done       chan struct{}
	closeOnce  sync.Once
}

type NetstackUDPConn struct {
	netstack *Netstack
	conn     net.PacketConn
	local    *net.UDPAddr
	remote   *net.UDPAddr
	policy   *netstackSecurityPolicy
	done     chan struct{}

	writeMu   sync.Mutex
	closeOnce sync.Once
}

func (n *Netstack) DialTCP(ctx context.Context, cfg TCPConfig) (*NetstackTCPConn, error) {
	return n.dialTCP(ctx, cfg, nil)
}

func (n *Netstack) DialSecureTCP(ctx context.Context, cfg SecureTCPConfig) (*NetstackTCPConn, error) {
	return n.dialTCP(ctx, cfg.TCPConfig, &cfg)
}

func (n *Netstack) ListenSecureTCP(ctx context.Context, cfg SecureTCPConfig) (*NetstackTCPConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	local, remote, network, err := n.tcpEndpoints(cfg.TCPConfig)
	if err != nil {
		return nil, fmt.Errorf("listening IMS netstack TCP: %w", err)
	}
	policy, err := n.registerTCPPolicy(local, remote, cfg)
	if err != nil {
		return nil, fmt.Errorf("listening IMS netstack TCP: %w", err)
	}
	conn := &NetstackTCPConn{
		netstack: n,
		local:    local,
		remote:   remote,
		passive:  true,
		policy:   policy,
		done:     make(chan struct{}),
		accept:   make(chan net.Conn, 1),
		errCh:    make(chan error, 1),
	}
	if err := n.registerTCPListener(conn, network); err != nil {
		n.removeSecurity(policy)
		return nil, fmt.Errorf("listening IMS netstack TCP: %w", err)
	}
	return conn, nil
}

func (n *Netstack) registerTCPListener(conn *NetstackTCPConn, network tcpip.NetworkProtocolNumber) error {
	key := netstackTCPListenerKey{localIP: conn.local.IP.String(), port: conn.local.Port}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return n.closedErr()
	}
	listener := n.tcpListeners[key]
	start := false
	if listener == nil {
		opened, err := gonet.ListenTCPWithMaxSeg(n.stack, netstackFullAddress(conn.local.IP, conn.local.Port), network, netstackTCPMSS)
		if err != nil {
			n.mu.Unlock()
			return err
		}
		listener = &netstackTCPListener{
			netstack: n, key: key, listener: opened,
			transports: make(map[*NetstackTCPConn]struct{}), done: make(chan struct{}),
		}
		n.tcpListeners[key] = listener
		start = true
	}
	listener.transports[conn] = struct{}{}
	conn.server = listener
	n.mu.Unlock()
	if start {
		go listener.acceptLoop()
	}
	return nil
}

func (l *netstackTCPListener) acceptLoop() {
	for {
		conn, err := l.listener.Accept()
		if err != nil {
			select {
			case <-l.done:
				return
			default:
			}
			l.netstack.mu.Lock()
			transports := make([]*NetstackTCPConn, 0, len(l.transports))
			for transport := range l.transports {
				transports = append(transports, transport)
			}
			l.netstack.mu.Unlock()
			for _, transport := range transports {
				select {
				case transport.errCh <- fmt.Errorf("accepting IMS netstack TCP connection: %w", err):
				default:
				}
			}
			return
		}

		l.netstack.mu.Lock()
		var target *NetstackTCPConn
		for transport := range l.transports {
			if sameTCPAddr(conn.RemoteAddr(), transport.remote) {
				target = transport
				break
			}
		}
		l.netstack.mu.Unlock()
		if target == nil {
			_ = conn.Close()
			continue
		}
		select {
		case target.accept <- conn:
		case <-target.done:
			_ = conn.Close()
		case <-l.done:
			_ = conn.Close()
			return
		}
	}
}

func (n *Netstack) releaseTCPListener(listener *netstackTCPListener, conn *NetstackTCPConn) {
	if listener == nil {
		return
	}
	n.mu.Lock()
	delete(listener.transports, conn)
	stop := len(listener.transports) == 0 && n.tcpListeners[listener.key] == listener
	if stop {
		delete(n.tcpListeners, listener.key)
	}
	n.mu.Unlock()
	if stop {
		listener.stop()
	}
}

func (n *Netstack) retireTCPPolicy(conn net.Conn, policy *netstackSecurityPolicy, key netstackFlowKey) {
	tcpConn, ok := conn.(*gonet.TCPConn)
	n.mu.Lock()
	closed := n.closed
	if ok && !closed {
		n.wg.Add(1)
	}
	n.mu.Unlock()
	if !ok || closed {
		n.removeSecurity(policy)
		n.clearFlow(key)
		return
	}
	go func() {
		defer n.wg.Done()
		_ = tcpConn.WaitClosed(n.ctx)
		n.removeSecurity(policy)
		n.clearFlow(key)
	}()
}

func (l *netstackTCPListener) stop() {
	l.closeOnce.Do(func() {
		close(l.done)
		_ = l.listener.Close()
	})
}

func (n *Netstack) dialTCP(ctx context.Context, cfg TCPConfig, secure *SecureTCPConfig) (*NetstackTCPConn, error) {
	local, remote, network, err := n.tcpEndpoints(cfg)
	if err != nil {
		return nil, fmt.Errorf("dialing IMS netstack TCP: %w", err)
	}
	var policy *netstackSecurityPolicy
	if secure != nil {
		policy, err = n.registerTCPPolicy(local, remote, *secure)
		if err != nil {
			return nil, fmt.Errorf("dialing IMS netstack TCP: %w", err)
		}
	}
	key := netstackFlowKeyForAddresses(packet.ProtocolTCP, local.IP, remote.IP, local.Port, remote.Port)
	var conn net.Conn
	err = n.withWriteContext(key, ctx, func() error {
		opened, dialErr := gonet.DialTCPWithBindAndMaxSeg(ctx, n.stack, netstackFullAddress(local.IP, local.Port), netstackFullAddress(remote.IP, remote.Port), network, netstackTCPMSS)
		conn = opened
		return dialErr
	})
	if err != nil {
		n.removeSecurity(policy)
		return nil, fmt.Errorf("dialing IMS netstack TCP: %w", n.transportError(key, err))
	}
	local = cloneTCPAddr(conn.LocalAddr().(*net.TCPAddr))
	return &NetstackTCPConn{
		netstack: n,
		local:    local,
		remote:   remote,
		policy:   policy,
		conn:     conn,
		done:     make(chan struct{}),
		accept:   make(chan net.Conn, 1),
		errCh:    make(chan error, 1),
	}, nil
}

func (n *Netstack) tcpEndpoints(cfg TCPConfig) (*net.TCPAddr, *net.TCPAddr, tcpip.NetworkProtocolNumber, error) {
	innerLocal, innerRemote, err := connectedUDPAddrs(n.session, cfg.RemoteIP)
	if err != nil {
		return nil, nil, 0, err
	}
	remotePort := cfg.RemotePort
	if remotePort == 0 {
		remotePort = standardSIPPort
	}
	localPort := cfg.LocalPort
	if localPort == 0 {
		random, err := randomUint32()
		if err != nil {
			return nil, nil, 0, err
		}
		localPort = netstackEphemeralBase + int(random%netstackEphemeralRange)
	}
	network, err := n.ensureAddress(innerLocal.IP)
	if err != nil {
		return nil, nil, 0, err
	}
	if _, remoteNetwork, _, err := netstackIP(innerRemote.IP); err != nil {
		return nil, nil, 0, err
	} else if remoteNetwork != network {
		return nil, nil, 0, errors.New("local and remote TCP address families differ")
	}
	return &net.TCPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: localPort},
		tcpRemoteAddr(innerRemote, remotePort, cfg.RemoteIP), network, nil
}

func (n *Netstack) registerTCPPolicy(local, remote *net.TCPAddr, cfg SecureTCPConfig) (*netstackSecurityPolicy, error) {
	return n.registerSecurity(netstackSecurityConfig{
		protocol: packet.ProtocolTCP, localIP: local.IP, remoteIP: remote.IP,
		localPort: local.Port, remotePort: remote.Port, mode: cfg.Mode,
		outboundSPI: cfg.OutboundSPI, inboundSPI: cfg.InboundSPI,
		encryption: cfg.Encryption, integrity: cfg.Integrity, associations: cfg.Associations,
		encryptionKey: cfg.EncryptionKey, integrityKey: cfg.IntegrityKey, salt: cfg.Salt,
	})
}

func (n *Netstack) DialUDP(ctx context.Context, cfg UDPConfig) (*NetstackUDPConn, error) {
	return n.openUDP(ctx, cfg, nil, true)
}

func (n *Netstack) ListenUDP(ctx context.Context, cfg UDPConfig) (*NetstackUDPConn, error) {
	return n.openUDP(ctx, cfg, nil, false)
}

func (n *Netstack) DialSecureUDP(ctx context.Context, cfg SecureUDPConfig) (*NetstackUDPConn, error) {
	return n.openUDP(ctx, cfg.UDPConfig, &cfg, true)
}

func (n *Netstack) ListenSecureUDP(ctx context.Context, cfg SecureUDPConfig) (*NetstackUDPConn, error) {
	return n.openUDP(ctx, cfg.UDPConfig, &cfg, true)
}

func (n *Netstack) openUDP(ctx context.Context, cfg UDPConfig, secure *SecureUDPConfig, connected bool) (*NetstackUDPConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	innerLocal, innerRemote, err := connectedUDPAddrs(n.session, cfg.RemoteIP)
	if err != nil {
		return nil, fmt.Errorf("opening IMS netstack UDP: %w", err)
	}
	network, err := n.ensureAddress(innerLocal.IP)
	if err != nil {
		return nil, fmt.Errorf("opening IMS netstack UDP: %w", err)
	}
	local := &net.UDPAddr{IP: append(net.IP(nil), innerLocal.IP...), Port: cfg.LocalPort}
	remote := udpRemoteAddr(innerRemote, cfg.RemotePort, cfg.RemoteIP)
	var policy *netstackSecurityPolicy
	if secure != nil {
		policy, err = n.registerSecurity(netstackSecurityConfig{
			protocol: packet.ProtocolUDP, localIP: local.IP, remoteIP: remote.IP,
			localPort: local.Port, remotePort: remote.Port, mode: secure.Mode,
			outboundSPI: secure.OutboundSPI, inboundSPI: secure.InboundSPI,
			encryption: secure.Encryption, integrity: secure.Integrity, associations: secure.Associations,
			encryptionKey: secure.EncryptionKey, integrityKey: secure.IntegrityKey, salt: secure.Salt,
		})
		if err != nil {
			return nil, fmt.Errorf("opening IMS netstack UDP: %w", err)
		}
	}
	var remoteAddress *tcpip.FullAddress
	if connected {
		remoteAddress = fullAddress(remote)
	}
	conn, err := gonet.DialUDP(n.stack, fullAddress(local), remoteAddress, network)
	if err != nil {
		n.removeSecurity(policy)
		return nil, fmt.Errorf("opening IMS netstack UDP: %w", err)
	}
	local = cloneUDPAddr(conn.LocalAddr().(*net.UDPAddr))
	if !connected {
		remote = nil
	}
	return &NetstackUDPConn{netstack: n, conn: conn, local: local, remote: remote, policy: policy, done: make(chan struct{})}, nil
}

func fullAddress(addr *net.UDPAddr) *tcpip.FullAddress {
	if addr == nil {
		return nil
	}
	full := netstackFullAddress(addr.IP, addr.Port)
	return &full
}

func (t *NetstackTCPConn) LocalAddr() net.Addr  { return cloneTCPAddr(t.local) }
func (t *NetstackTCPConn) RemoteAddr() net.Addr { return cloneTCPAddr(t.remote) }

// OutboundCapable reports whether this transport owns an initiated connection.
func (t *NetstackTCPConn) OutboundCapable() bool { return !t.passive }

// SecureTransport reports whether the connection is protected by an IPsec policy.
func (t *NetstackTCPConn) SecureTransport() bool { return t.policy != nil }

// SecurityAssociationID identifies the security context protecting the connection.
func (t *NetstackTCPConn) SecurityAssociationID() string {
	if t.policy == nil {
		return ""
	}
	return t.policy.associationID
}

func (t *NetstackTCPConn) flowKey() netstackFlowKey {
	return netstackFlowKeyForAddresses(packet.ProtocolTCP, t.local.IP, t.remote.IP, t.local.Port, t.remote.Port)
}

func (t *NetstackTCPConn) WritePacket(ctx context.Context, data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	conn, err := t.awaitConn(ctx)
	if err != nil {
		return err
	}
	if err := setConnDeadline(conn, ctx, true); err != nil {
		return fmt.Errorf("writing IMS netstack TCP packet: %w", err)
	}
	defer conn.SetWriteDeadline(time.Time{})
	err = t.netstack.withWriteContext(t.flowKey(), ctx, func() error {
		for written := 0; written < len(data); {
			n, writeErr := conn.Write(data[written:])
			if writeErr != nil {
				return writeErr
			}
			if n == 0 {
				return errors.New("zero bytes written")
			}
			written += n
		}
		return nil
	})
	if err != nil {
		return t.connectionError("writing IMS netstack TCP packet", conn, err)
	}
	return nil
}

func (t *NetstackTCPConn) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	t.readMu.Lock()
	defer t.readMu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("reading IMS netstack TCP packet: %w", err)
		}
		t.streamMu.Lock()
		if msg, ok := t.dequeue(); ok {
			t.streamMu.Unlock()
			return msg, t.RemoteAddr(), nil
		}
		t.streamMu.Unlock()
		conn, err := t.awaitConn(ctx)
		if err != nil {
			return nil, nil, err
		}
		buf := make([]byte, 64*1024)
		n, err := readTCPConn(ctx, conn, buf)
		if n > 0 {
			t.streamMu.Lock()
			t.stream = append(t.stream, buf[:n]...)
			for {
				keepalive, rest, ok := netstackCRLFKeepAlive(t.stream)
				if !ok {
					break
				}
				t.queued = append(t.queued, keepalive)
				t.stream = rest
			}
			messages, rest, parseErr := imssession.StageSIPMessages(t.stream)
			if parseErr != nil {
				t.streamMu.Unlock()
				return nil, nil, fmt.Errorf("reading IMS netstack TCP packet: %w", parseErr)
			}
			t.stream = append([]byte(nil), rest...)
			t.queued = append(t.queued, messages...)
			t.streamMu.Unlock()
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, nil, fmt.Errorf("reading IMS netstack TCP packet: %w", ctxErr)
			}
			continue
		}
		if err == nil {
			continue
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, nil, fmt.Errorf("reading IMS netstack TCP packet: %w", ctxErr)
		}
		return nil, nil, t.connectionError("reading IMS netstack TCP packet", conn, netstackReadError(err))
	}
}

func readTCPConn(ctx context.Context, conn net.Conn, buf []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if err := setConnDeadline(conn, ctx, false); err != nil {
		return 0, err
	}
	interrupted := make(chan struct{})
	stopInterrupt := context.AfterFunc(ctx, func() {
		_ = conn.SetReadDeadline(time.Now())
		close(interrupted)
	})
	n, err := conn.Read(buf)
	if !stopInterrupt() {
		<-interrupted
	}
	if clearErr := conn.SetReadDeadline(time.Time{}); err == nil {
		err = clearErr
	}
	if ctxErr := ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func (t *NetstackTCPConn) awaitConn(ctx context.Context) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("using IMS netstack TCP connection: transport is closed")
	}
	if t.conn != nil {
		conn := t.conn
		t.mu.Unlock()
		return conn, nil
	}
	t.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.done:
		return nil, errors.New("using IMS netstack TCP connection: transport is closed")
	case err := <-t.errCh:
		return nil, t.netstack.transportError(t.flowKey(), err)
	case conn := <-t.accept:
		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			_ = conn.Close()
			return nil, errors.New("using IMS netstack TCP connection: transport is closed")
		}
		t.conn = conn
		t.mu.Unlock()
		return conn, nil
	}
}

func (t *NetstackTCPConn) connectionError(action string, conn net.Conn, err error) error {
	err = t.netstack.transportError(t.flowKey(), err)
	if t.netstack.terminalErr() != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	if !t.passive {
		return fmt.Errorf("%s: %w", action, err)
	}
	t.mu.Lock()
	if t.conn == conn {
		t.conn = nil
		t.streamMu.Lock()
		t.stream = nil
		t.queued = nil
		t.streamMu.Unlock()
	}
	t.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), netstackTCPCloseTimeout)
	_ = t.netstack.withWriteContext(t.flowKey(), ctx, conn.Close)
	cancel()
	return &recoverableTCPConnectionError{err: fmt.Errorf("%s: %w", action, err)}
}

func (t *NetstackTCPConn) dequeue() ([]byte, bool) {
	if len(t.queued) == 0 {
		return nil, false
	}
	msg := t.queued[0]
	t.queued[0] = nil
	t.queued = t.queued[1:]
	return msg, true
}

func netstackCRLFKeepAlive(stream []byte) ([]byte, []byte, bool) {
	if len(stream) >= 4 && string(stream[:4]) == "\r\n\r\n" {
		return append([]byte(nil), stream[:4]...), stream[4:], true
	}
	if len(stream) >= 2 && string(stream[:2]) == "\r\n" {
		return append([]byte(nil), stream[:2]...), stream[2:], true
	}
	return nil, stream, false
}

func (t *NetstackTCPConn) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		t.closed = true
		conn := t.conn
		server := t.server
		t.conn = nil
		t.mu.Unlock()
		close(t.done)
		if conn != nil {
			ctx, cancel := context.WithTimeout(context.Background(), netstackTCPCloseTimeout)
			_ = t.netstack.withWriteContext(t.flowKey(), ctx, conn.Close)
			cancel()
		}
		t.netstack.releaseTCPListener(server, t)
		if conn != nil {
			t.netstack.retireTCPPolicy(conn, t.policy, t.flowKey())
		} else {
			t.netstack.removeSecurity(t.policy)
			t.netstack.clearFlow(t.flowKey())
		}
	})
	return nil
}

func (t *NetstackUDPConn) LocalAddr() net.Addr  { return cloneUDPAddr(t.local) }
func (t *NetstackUDPConn) RemoteAddr() net.Addr { return cloneUDPAddr(t.remote) }

// SecureTransport reports whether the connection is protected by an IPsec policy.
func (t *NetstackUDPConn) SecureTransport() bool { return t.policy != nil }

// SecurityAssociationID identifies the security context protecting the connection.
func (t *NetstackUDPConn) SecurityAssociationID() string {
	if t.policy == nil {
		return ""
	}
	return t.policy.associationID
}

func (t *NetstackUDPConn) flowKey(remote *net.UDPAddr) netstackFlowKey {
	return netstackFlowKeyForAddresses(packet.ProtocolUDP, t.local.IP, remote.IP, t.local.Port, remote.Port)
}

func (t *NetstackUDPConn) WritePacket(ctx context.Context, data []byte) error {
	return t.WritePacketTo(ctx, data, nil)
}

func (t *NetstackUDPConn) WritePacketTo(ctx context.Context, data []byte, addr net.Addr) error {
	remote := net.Addr(t.remote)
	if t.policy == nil && addr != nil {
		remote = addr
	}
	if remote == nil {
		return errors.New("writing IMS netstack UDP packet: remote address is required")
	}
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	if err := setPacketDeadline(t.conn, ctx, true); err != nil {
		return fmt.Errorf("writing IMS netstack UDP packet: %w", err)
	}
	defer t.conn.SetWriteDeadline(time.Time{})
	remoteUDP, ok := remote.(*net.UDPAddr)
	if !ok || remoteUDP == nil {
		return errors.New("writing IMS netstack UDP packet: remote address is invalid")
	}
	key := t.flowKey(remoteUDP)
	err := t.netstack.withWriteContext(key, ctx, func() error {
		_, writeErr := t.conn.WriteTo(data, remote)
		return writeErr
	})
	if err != nil {
		return fmt.Errorf("writing IMS netstack UDP packet: %w", t.netstack.transportError(key, err))
	}
	return nil
}

func (t *NetstackUDPConn) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	if err := setPacketDeadline(t.conn, ctx, false); err != nil {
		return nil, nil, t.readError(ctx, err)
	}
	defer t.conn.SetReadDeadline(time.Time{})
	buf := make([]byte, 65535)
	n, addr, err := t.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, t.readError(ctx, err)
	}
	return append([]byte(nil), buf[:n]...), addr, nil
}

func (t *NetstackUDPConn) readError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		err = ctxErr
	} else if terminalErr := t.netstack.terminalErr(); terminalErr != nil {
		err = terminalErr
	} else if errors.Is(err, io.EOF) {
		err = net.ErrClosed
	}
	return fmt.Errorf("reading IMS netstack UDP packet: %w", err)
}

func (t *NetstackUDPConn) Close() error {
	t.closeOnce.Do(func() {
		_ = t.conn.Close()
		t.netstack.removeSecurity(t.policy)
		if t.remote != nil {
			t.netstack.clearFlow(t.flowKey(t.remote))
		}
		close(t.done)
	})
	return nil
}

func setConnDeadline(conn net.Conn, ctx context.Context, write bool) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	if write {
		return conn.SetWriteDeadline(deadline)
	}
	return conn.SetReadDeadline(deadline)
}

func setPacketDeadline(conn net.PacketConn, ctx context.Context, write bool) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Time{}
	}
	if write {
		return conn.SetWriteDeadline(deadline)
	}
	return conn.SetReadDeadline(deadline)
}

func netstackReadError(err error) error {
	if errors.Is(err, io.EOF) {
		return errors.New("peer closed connection")
	}
	return err
}

func sameTCPAddr(addr net.Addr, want *net.TCPAddr) bool {
	got, ok := addr.(*net.TCPAddr)
	return ok && want != nil && got.Port == want.Port && got.IP.Equal(want.IP)
}
