package transport

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	imssession "github.com/damonto/ims-go/ims/session"
	ipsecbase "github.com/damonto/ims-go/ipsec"
	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/ipsec/transport/netstack/tcpip/gonet"
)

type interruptedReadConn struct {
	startedOnce sync.Once
	stopOnce    sync.Once
	started     chan struct{}
	interrupted chan struct{}
}

type blockingWriteConn struct {
	started     chan struct{}
	interrupted chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
}

func newBlockingWriteConn() *blockingWriteConn {
	return &blockingWriteConn{
		started:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
}

func (c *blockingWriteConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *blockingWriteConn) Write([]byte) (int, error) {
	c.startOnce.Do(func() { close(c.started) })
	<-c.interrupted
	return 0, net.ErrClosed
}

func (c *blockingWriteConn) Close() error {
	c.stopOnce.Do(func() { close(c.interrupted) })
	return nil
}

func (*blockingWriteConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (*blockingWriteConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
}

func (*blockingWriteConn) SetDeadline(time.Time) error { return nil }

func (c *blockingWriteConn) SetReadDeadline(time.Time) error { return nil }

func (c *blockingWriteConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.stopOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}

func newInterruptedReadConn() *interruptedReadConn {
	return &interruptedReadConn{
		started:     make(chan struct{}),
		interrupted: make(chan struct{}),
	}
}

func (c *interruptedReadConn) Read(p []byte) (int, error) {
	c.startedOnce.Do(func() { close(c.started) })
	<-c.interrupted
	return copy(p, "\r\n"), nil
}

func (*interruptedReadConn) Write(p []byte) (int, error) { return len(p), nil }

func (c *interruptedReadConn) Close() error {
	c.stopOnce.Do(func() { close(c.interrupted) })
	return nil
}

func (*interruptedReadConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}
}

func (*interruptedReadConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060}
}

func (c *interruptedReadConn) SetDeadline(deadline time.Time) error {
	return c.SetReadDeadline(deadline)
}

func (c *interruptedReadConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		c.stopOnce.Do(func() { close(c.interrupted) })
	}
	return nil
}

func (*interruptedReadConn) SetWriteDeadline(time.Time) error { return nil }

func closeTestResource(t *testing.T, closer io.Closer) {
	t.Helper()
	if err := closer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Errorf("Close() error = %v", err)
	}
}

func closeAfterTest(t *testing.T, closer io.Closer) {
	t.Helper()
	t.Cleanup(func() {
		closeTestResource(t, closer)
	})
}

func TestNetstackLoopback(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *Netstack, *Netstack)
	}{
		{name: "plain TCP", run: testNetstackPlainTCP},
		{name: "protected TCP", run: testNetstackProtectedTCP},
		{name: "plain UDP", run: testNetstackPlainUDP},
		{name: "protected UDP", run: testNetstackProtectedUDP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, serverSession := newLoopbackPacketSessions()
			client := newTestNetstack(t, clientSession)
			server := newTestNetstack(t, serverSession)
			tt.run(t, client, server)
		})
	}
}

func TestNetstackUDPEncTunnelSeparatesInnerAndOuterAddresses(t *testing.T) {
	tests := []struct {
		name           string
		outerLocalIP   net.IP
		innerLocalIP   net.IP
		remoteIP       net.IP
		wantNextHeader byte
		encryption     string
		encryptionKey  []byte
		integrity      string
		integrityKey   []byte
	}{
		{
			name:         "IPv4 NAT",
			outerLocalIP: net.ParseIP("10.0.0.10"), innerLocalIP: net.ParseIP("198.51.100.10"),
			remoteIP: net.ParseIP("192.0.2.20"), wantNextHeader: packet.OuterIPv4,
			encryption: esp.EncryptionAESCBC, encryptionKey: []byte("0123456789abcdef"),
			integrity: esp.IntegrityHMACMD596, integrityKey: []byte("fedcba9876543210"),
		},
		{
			name:         "IPv6 address translation",
			outerLocalIP: net.ParseIP("fd00::10"), innerLocalIP: net.ParseIP("2001:db8:1::10"),
			remoteIP: net.ParseIP("2001:db8:2::20"), wantNextHeader: packet.OuterIPv6,
			encryption: esp.EncryptionNull,
			integrity:  esp.IntegrityHMACSHA196, integrityKey: []byte("0123456789abcdefghij"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, _ := newLoopbackPacketSessions()
			clientSession.localIP = tt.outerLocalIP
			clientSession.remoteIP = tt.remoteIP
			stopWrite := errors.New("stop after recording outer packet")
			clientSession.setWriteHook(func(context.Context, packet.InnerPacket) error { return stopWrite })
			n := newTestNetstack(t, clientSession)
			policy, err := n.registerSecurity(netstackSecurityConfig{
				protocol: packet.ProtocolUDP,
				localIP:  tt.innerLocalIP, remoteIP: tt.remoteIP,
				outerLocalIP: tt.outerLocalIP, outerRemoteIP: tt.remoteIP,
				localPort: 40000, remotePort: 6000, mode: SecureModeUDPEncTunnel,
				outboundSPI: 0x1001, inboundSPI: 0x2001,
				encryption: tt.encryption, encryptionKey: tt.encryptionKey,
				integrity: tt.integrity, integrityKey: tt.integrityKey,
			})
			if err != nil {
				t.Fatalf("registerSecurity() error = %v", err)
			}
			inner := packet.InnerPacket{UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: tt.innerLocalIP, Port: 40000},
				Dst:     &net.UDPAddr{IP: tt.remoteIP, Port: 6000},
				Payload: []byte("REGISTER sip:ims.example SIP/2.0\r\n\r\n"),
			}}
			wire, err := inner.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if err := n.writePacket(t.Context(), inner, wire); !errors.Is(err, stopWrite) {
				t.Fatalf("writePacket() error = %v, want %v", err, stopWrite)
			}
			writes := clientSession.snapshotWrites()
			if len(writes) != 1 || writes[0].UDP == nil {
				t.Fatalf("outer writes = %+v, want one UDP packet", writes)
			}
			outer := writes[0].UDP
			if !outer.Src.IP.Equal(tt.outerLocalIP) || !outer.Dst.IP.Equal(tt.remoteIP) {
				t.Fatalf("outer addresses = %s -> %s, want %s -> %s", outer.Src.IP, outer.Dst.IP, tt.outerLocalIP, tt.remoteIP)
			}
			decoded, err := policy.outboundESP.Decode(outer.Payload)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if decoded.NextHeader != tt.wantNextHeader {
				t.Fatalf("ESP next header = %d, want %d", decoded.NextHeader, tt.wantNextHeader)
			}
			var protectedInner packet.InnerPacket
			if err := protectedInner.UnmarshalBinary(decoded.Payload); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if !protectedInner.IP.SrcIP.Equal(tt.innerLocalIP) || !protectedInner.IP.DstIP.Equal(tt.remoteIP) {
				t.Fatalf("inner addresses = %s -> %s, want %s -> %s", protectedInner.IP.SrcIP, protectedInner.IP.DstIP, tt.innerLocalIP, tt.remoteIP)
			}
		})
	}
}

func TestNetstackRejectsPlaintextForProtectedUDPFlow(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "transport mode", mode: SecureModeTransport},
		{name: "UDP encapsulated tunnel", mode: SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, serverSession := newLoopbackPacketSessions()
			server := newTestNetstack(t, serverSession)
			_, serverConfig := testSecureUDPConfigs()
			serverConfig.Mode = tt.mode
			conn, err := server.ListenSecureUDP(t.Context(), serverConfig)
			if err != nil {
				t.Fatalf("ListenSecureUDP() error = %v", err)
			}
			closeAfterTest(t, conn)

			if !server.HandleInnerPacket(packet.InnerPacket{UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
				Dst:     &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6000},
				Payload: []byte("plaintext must not enter the protected socket"),
			}}) {
				t.Fatal("HandleInnerPacket() = false, want protected flow consumed")
			}

			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			_, _, err = conn.ReadPacket(ctx)
			netErr, ok := errors.AsType[net.Error](err)
			if !ok || !netErr.Timeout() {
				t.Fatalf("ReadPacket() error = %v, want timeout", err)
			}
		})
	}
}

func TestNetstackRejectsPlaintextOnProtectedPortFromUnexpectedTuple(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		packet packet.InnerPacket
	}{
		{
			name: "TCP from unnegotiated source port",
			mode: SecureModeTransport,
			packet: packet.InnerPacket{TCP: &packet.TCPSegment{
				Src: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001},
				Dst: &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6000},
				Seq: 1, Flags: 0x02, Window: 65535, MSS: 1024,
			}},
		},
		{
			name: "UDP on TCP protected port",
			mode: SecureModeUDPEncTunnel,
			packet: packet.InnerPacket{UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001},
				Dst:     &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6000},
				Payload: []byte("plaintext"),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, serverSession := newLoopbackPacketSessions()
			server := newTestNetstack(t, serverSession)
			_, cfg := testSecureTCPConfigs()
			cfg.Mode = tt.mode
			conn, err := server.ListenSecureTCP(t.Context(), cfg)
			if err != nil {
				t.Fatalf("ListenSecureTCP() error = %v", err)
			}
			closeAfterTest(t, conn)

			if !server.HandleInnerPacket(tt.packet) {
				t.Fatal("HandleInnerPacket() = false, want protected port packet consumed")
			}
			time.Sleep(20 * time.Millisecond)
			if got := len(serverSession.snapshotWrites()); got != 0 {
				t.Fatalf("plaintext response packet count = %d, want 0", got)
			}
		})
	}
}

func TestNetstackRejectsPlaintextOutboundFromProtectedPort(t *testing.T) {
	tests := []struct {
		name   string
		packet packet.InnerPacket
	}{
		{
			name: "TCP policy miss",
			packet: packet.InnerPacket{TCP: &packet.TCPSegment{
				Src: &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6000},
				Dst: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001},
				Seq: 1, Ack: 1, Flags: 0x10, Window: 65535,
			}},
		},
		{
			name: "UDP policy miss",
			packet: packet.InnerPacket{UDP: &packet.UDPSegment{
				Src:     &net.UDPAddr{IP: net.ParseIP("2001:db8::2"), Port: 6000},
				Dst:     &net.UDPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40001},
				Payload: []byte("plaintext"),
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, serverSession := newLoopbackPacketSessions()
			server := newTestNetstack(t, serverSession)
			_, cfg := testSecureTCPConfigs()
			conn, err := server.ListenSecureTCP(t.Context(), cfg)
			if err != nil {
				t.Fatalf("ListenSecureTCP() error = %v", err)
			}
			closeAfterTest(t, conn)
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if err := server.writePacket(t.Context(), tt.packet, wire); err == nil {
				t.Fatal("writePacket() error = nil, want protected port plaintext rejection")
			}
			if got := len(serverSession.snapshotWrites()); got != 0 {
				t.Fatalf("plaintext packet count = %d, want 0", got)
			}
		})
	}
}

func TestNetstackIgnoresUDPEncapsulatedESPKeepalive(t *testing.T) {
	_, serverSession := newLoopbackPacketSessions()
	server := newTestNetstack(t, serverSession)
	_, cfg := testSecureUDPConfigs()
	cfg.Mode = SecureModeUDPEncTunnel
	conn, err := server.ListenSecureUDP(t.Context(), cfg)
	if err != nil {
		t.Fatalf("ListenSecureUDP() error = %v", err)
	}
	closeAfterTest(t, conn)

	keepalive, err := udpEncTunnelKeepalivePacket(serverSession.remoteIP, serverSession.localIP)
	if err != nil {
		t.Fatalf("udpEncTunnelKeepalivePacket() error = %v", err)
	}
	if !server.HandleInnerPacket(keepalive) {
		t.Fatal("HandleInnerPacket() = false, want keepalive consumed")
	}
	time.Sleep(20 * time.Millisecond)
	if got := len(serverSession.snapshotWrites()); got != 0 {
		t.Fatalf("keepalive response packet count = %d, want 0", got)
	}
}

func TestNetstackSharesUDPEncapsulatedESPKeepaliveByPeer(t *testing.T) {
	_, serverSession := newLoopbackPacketSessions()
	server := newTestNetstack(t, serverSession)
	_, tcpCfg := testSecureTCPConfigs()
	_, udpCfg := testSecureUDPConfigs()
	tcpCfg.Mode = SecureModeUDPEncTunnel
	udpCfg.Mode = SecureModeUDPEncTunnel
	tcpConn, err := server.ListenSecureTCP(t.Context(), tcpCfg)
	if err != nil {
		t.Fatalf("ListenSecureTCP() error = %v", err)
	}
	udpConn, err := server.ListenSecureUDP(t.Context(), udpCfg)
	if err != nil {
		t.Fatalf("ListenSecureUDP() error = %v", err)
	}

	server.mu.Lock()
	if got := len(server.udpKeepalives); got != 1 {
		server.mu.Unlock()
		t.Fatalf("UDP-enc-tun keepalive count = %d, want 1", got)
	}
	var keepalive *netstackUDPEncKeepalive
	for _, candidate := range server.udpKeepalives {
		keepalive = candidate
	}
	refs := keepalive.refs
	server.mu.Unlock()
	if refs != 2 {
		t.Fatalf("UDP-enc-tun keepalive refs = %d, want 2", refs)
	}

	closeTestResource(t, tcpConn)
	server.mu.Lock()
	refs = keepalive.refs
	server.mu.Unlock()
	if refs != 1 {
		t.Fatalf("UDP-enc-tun keepalive refs after TCP close = %d, want 1", refs)
	}
	closeTestResource(t, udpConn)
	server.mu.Lock()
	remaining := len(server.udpKeepalives)
	server.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("UDP-enc-tun keepalive count after close = %d, want 0", remaining)
	}
}

func TestNetstackUDPEncapsulatedTransportsSupportSIPKeepalive(t *testing.T) {
	tests := []struct {
		name string
		open func(*Netstack) (imssession.Transport, error)
	}{
		{
			name: "TCP",
			open: func(n *Netstack) (imssession.Transport, error) {
				_, cfg := testSecureTCPConfigs()
				cfg.Mode = SecureModeUDPEncTunnel
				return n.ListenSecureTCP(t.Context(), cfg)
			},
		},
		{
			name: "UDP",
			open: func(n *Netstack) (imssession.Transport, error) {
				_, cfg := testSecureUDPConfigs()
				cfg.Mode = SecureModeUDPEncTunnel
				return n.ListenSecureUDP(t.Context(), cfg)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, packetSession := newLoopbackPacketSessions()
			n := newTestNetstack(t, packetSession)
			transport, err := tt.open(n)
			if err != nil {
				t.Fatalf("opening transport: %v", err)
			}
			sess, err := imssession.Open(imssession.Config{}, transport)
			if err != nil {
				t.Fatalf("session.Open() error = %v", err)
			}
			defer func() {
				if err := sess.Close(); err != nil {
					t.Errorf("Stack.Close() error = %v", err)
				}
			}()
			if !sess.SupportsKeepAlive() {
				t.Fatal("SupportsKeepAlive() = false, want RFC 6223 keepalive enabled")
			}
		})
	}
}

func TestNetstackSharedESPAssociationDispatchesByTransport(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "transport mode", mode: SecureModeTransport},
		{name: "UDP encapsulated tunnel", mode: SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, session := newLoopbackPacketSessions()
			n := newTestNetstack(t, session)
			associations := NewSecurityAssociations()
			const inboundSPI = 0x1001
			base := netstackSecurityConfig{
				localIP: session.localIP, remoteIP: session.remoteIP,
				outboundSPI: 0x2001, inboundSPI: inboundSPI,
				encryption: esp.EncryptionNull, integrity: esp.IntegrityHMACSHA196,
				integrityKey: []byte("0123456789abcdefghij"), associations: associations,
				mode: tt.mode,
			}
			tcpConfig := base
			tcpConfig.protocol = packet.ProtocolTCP
			tcpConfig.localPort, tcpConfig.remotePort = 6000, 40000
			if _, err := n.registerSecurity(tcpConfig); err != nil {
				t.Fatalf("registerSecurity(TCP) error = %v", err)
			}
			udpConfig := base
			udpConfig.protocol = packet.ProtocolUDP
			udpConfig.localPort, udpConfig.remotePort = 6001, 40001
			if _, err := n.registerSecurity(udpConfig); err != nil {
				t.Fatalf("registerSecurity(UDP) error = %v", err)
			}

			want := []byte("shared SPI must dispatch to TCP")
			segment := packet.TCPSegment{
				Src: &net.TCPAddr{IP: session.remoteIP, Port: tcpConfig.remotePort},
				Dst: &net.TCPAddr{IP: session.localIP, Port: tcpConfig.localPort},
				Seq: 1, Ack: 1, Flags: packet.TCPFlagACK, Window: 65535, Payload: want,
			}
			payload, err := segment.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			nextHeader := byte(packet.ProtocolTCP)
			if tt.mode == SecureModeUDPEncTunnel {
				payload, err = (packet.InnerPacket{TCP: &segment}).MarshalBinary()
				if err != nil {
					t.Fatalf("InnerPacket.MarshalBinary() error = %v", err)
				}
				nextHeader, err = secureTunnelNextHeader(session.remoteIP, session.localIP)
				if err != nil {
					t.Fatalf("secureTunnelNextHeader() error = %v", err)
				}
			}
			codec := secureESPCodec(inboundSPI, base.encryption, nil, base.integrity, base.integrityKey, [4]byte{})
			sealed, err := codec.Encode(esp.Packet{SPI: inboundSPI, Sequence: 1, NextHeader: nextHeader, Payload: payload})
			if err != nil {
				t.Fatalf("ESP Encode() error = %v", err)
			}
			outer, err := secureInnerPacket(session.remoteIP, session.localIP, tt.mode, sealed)
			if err != nil {
				t.Fatalf("secureInnerPacket() error = %v", err)
			}

			got, recognized, valid := n.unprotect(outer)
			if !recognized || !valid {
				t.Fatalf("unprotect() = recognized %t, valid %t; want true, true", recognized, valid)
			}
			if got.TCP == nil {
				t.Fatal("unprotect() TCP = nil")
			}
			if !bytes.Equal(got.TCP.Payload, want) {
				t.Fatalf("unprotect() TCP payload = %q, want %q", got.TCP.Payload, want)
			}
		})
	}
}

func TestSecurityAssociationFingerprintGroupsOneNegotiation(t *testing.T) {
	base := netstackSecurityConfig{
		protocol:      packet.ProtocolUDP,
		localPort:     45000,
		remotePort:    4060,
		outboundSPI:   0x1001,
		inboundSPI:    0x2001,
		encryption:    esp.EncryptionAESCBC,
		integrity:     esp.IntegrityHMACSHA196,
		encryptionKey: []byte("0123456789abcdef"),
		integrityKey:  []byte("0123456789abcdefghij"),
		mode:          SecureModeTransport,
	}
	want := securityAssociationFingerprint(base, esp.EncryptionAESCBC, SecureModeTransport)
	tests := []struct {
		name      string
		mutate    func(*netstackSecurityConfig)
		wantEqual bool
	}{
		{
			name: "TCP fallback in same negotiation",
			mutate: func(cfg *netstackSecurityConfig) {
				cfg.protocol = packet.ProtocolTCP
				cfg.localPort = 45001
			},
			wantEqual: true,
		},
		{
			name: "new outbound SPI",
			mutate: func(cfg *netstackSecurityConfig) {
				cfg.outboundSPI++
			},
		},
		{
			name: "new integrity key",
			mutate: func(cfg *netstackSecurityConfig) {
				cfg.integrityKey = []byte("abcdefghij0123456789")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			tt.mutate(&cfg)
			got := securityAssociationFingerprint(cfg, esp.EncryptionAESCBC, SecureModeTransport)
			if (got == want) != tt.wantEqual {
				t.Fatalf("fingerprint equality = %t, want %t", got == want, tt.wantEqual)
			}
		})
	}
}

func TestNetstackProtectedIPv6UDPLargerThanMinimumMTU(t *testing.T) {
	tests := []struct {
		name string
		mode string
	}{
		{name: "transport mode", mode: SecureModeTransport},
		{name: "UDP encapsulated tunnel", mode: SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, serverSession := newLoopbackPacketSessions()
			client := newTestNetstack(t, clientSession)
			server := newTestNetstack(t, serverSession)
			clientConfig, serverConfig := testSecureUDPConfigs()
			clientConfig.Mode = tt.mode
			serverConfig.Mode = tt.mode

			clientConn, err := client.DialSecureUDP(t.Context(), clientConfig)
			if err != nil {
				t.Fatalf("DialSecureUDP() error = %v", err)
			}
			closeAfterTest(t, clientConn)
			serverConn, err := server.ListenSecureUDP(t.Context(), serverConfig)
			if err != nil {
				t.Fatalf("ListenSecureUDP() error = %v", err)
			}
			closeAfterTest(t, serverConn)

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			want := bytes.Repeat([]byte("R"), 2048)
			if err := clientConn.WritePacket(ctx, want); err != nil {
				t.Fatalf("WritePacket() error = %v", err)
			}
			got, _, err := serverConn.ReadPacket(ctx)
			if err != nil {
				t.Fatalf("ReadPacket() error = %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("packet length = %d, want %d", len(got), len(want))
			}
		})
	}
}

func TestNetstackSecureServerPortReuse(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *Netstack, *Netstack)
	}{
		{name: "TCP", run: testNetstackSecureTCPServerPortReuse},
		{name: "UDP", run: testNetstackSecureUDPServerPortReuse},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, serverSession := newLoopbackPacketSessions()
			client := newTestNetstack(t, clientSession)
			server := newTestNetstack(t, serverSession)
			tt.run(t, client, server)
		})
	}
}

func TestNetstackTCPUsesTunnelSafeMSS(t *testing.T) {
	clientSession, serverSession := newLoopbackPacketSessions()
	client := newTestNetstack(t, clientSession)
	server := newTestNetstack(t, serverSession)
	network, err := server.ensureAddress(serverSession.localIP)
	if err != nil {
		t.Fatalf("ensureAddress() error = %v", err)
	}
	listener, err := gonet.ListenTCP(server.stack, netstackFullAddress(serverSession.localIP, 5060), network)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	closeAfterTest(t, listener)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, TCPConfig{LocalPort: 40000, RemotePort: 5060})
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	closeAfterTest(t, conn)
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	closeAfterTest(t, accepted)

	synFound := false
	for _, pkt := range clientSession.snapshotWrites() {
		if pkt.TCP != nil && pkt.TCP.Flags&packet.TCPFlagSYN != 0 {
			if pkt.TCP.MSS != netstackTCPMSS {
				t.Fatalf("SYN MSS = %d, want %d", pkt.TCP.MSS, netstackTCPMSS)
			}
			synFound = true
			break
		}
	}
	if !synFound {
		t.Fatal("outbound SYN not captured")
	}
	clientSession.clearWrites()
	data := bytes.Repeat([]byte("x"), 3*netstackTCPMSS)
	if err := conn.WritePacket(ctx, data); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	dataSegments := 0
	for _, pkt := range clientSession.snapshotWrites() {
		if pkt.TCP == nil || len(pkt.TCP.Payload) == 0 {
			continue
		}
		dataSegments++
		if got := len(pkt.TCP.Payload); got > netstackTCPMSS {
			t.Fatalf("TCP payload length = %d, want <= %d", got, netstackTCPMSS)
		}
	}
	if dataSegments < 2 {
		t.Fatalf("TCP data segment count = %d, want at least 2", dataSegments)
	}
}

func TestNetstackWriteUsesCallerContextWithoutClosingStack(t *testing.T) {
	clientSession, serverSession := newLoopbackPacketSessions()
	client := newTestNetstack(t, clientSession)
	server := newTestNetstack(t, serverSession)
	clientConn, err := client.DialUDP(t.Context(), UDPConfig{LocalPort: 40000, RemotePort: 5060})
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	closeAfterTest(t, clientConn)
	serverConn, err := server.DialUDP(t.Context(), UDPConfig{LocalPort: 5060, RemotePort: 40000})
	if err != nil {
		t.Fatalf("DialUDP() error = %v", err)
	}
	closeAfterTest(t, serverConn)

	clientSession.setWriteHook(func(ctx context.Context, _ packet.InnerPacket) error {
		<-ctx.Done()
		return ctx.Err()
	})
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	err = clientConn.WritePacket(ctx, []byte("blocked"))
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WritePacket() error = %v, want context deadline exceeded", err)
	}
	if client.Err() != nil {
		t.Fatalf("Netstack.Err() = %v, want nil after flow write failure", client.Err())
	}

	clientSession.setWriteHook(nil)
	ctx, cancel = context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := clientConn.WritePacket(ctx, []byte("after failure")); err != nil {
		t.Fatalf("WritePacket() after failure error = %v", err)
	}
	got, _, err := serverConn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(got) != "after failure" {
		t.Fatalf("packet = %q, want %q", got, "after failure")
	}
}

func TestNetstackWriteContextRemovalHandlesOutOfOrderCompletion(t *testing.T) {
	tests := []struct {
		name string
		key  netstackFlowKey
	}{
		{
			name: "same UDP flow",
			key:  netstackFlowKeyForAddresses(packet.ProtocolUDP, net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2"), 40000, 5060),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := &Netstack{
				writeContexts: make(map[netstackFlowKey][]netstackWriteContext),
				writeErrors:   make(map[netstackFlowKey]error),
			}
			firstStarted := make(chan struct{})
			secondStarted := make(chan struct{})
			releaseFirst := make(chan struct{})
			releaseSecond := make(chan struct{})
			firstDone := make(chan error, 1)
			secondDone := make(chan error, 1)

			go func() {
				firstDone <- n.withWriteContext(t.Context(), tt.key, func() error {
					close(firstStarted)
					<-releaseFirst
					return nil
				})
			}()
			<-firstStarted
			go func() {
				secondDone <- n.withWriteContext(t.Context(), tt.key, func() error {
					close(secondStarted)
					<-releaseSecond
					return nil
				})
			}()
			<-secondStarted

			close(releaseFirst)
			if err := <-firstDone; err != nil {
				t.Fatalf("first withWriteContext() error = %v", err)
			}
			n.mu.Lock()
			remaining := append([]netstackWriteContext(nil), n.writeContexts[tt.key]...)
			n.mu.Unlock()
			if len(remaining) != 1 || remaining[0].id != 2 {
				t.Fatalf("remaining write contexts = %+v, want only second context", remaining)
			}

			close(releaseSecond)
			if err := <-secondDone; err != nil {
				t.Fatalf("second withWriteContext() error = %v", err)
			}
			n.mu.Lock()
			remaining = append(remaining[:0], n.writeContexts[tt.key]...)
			n.mu.Unlock()
			if len(remaining) != 0 {
				t.Fatalf("remaining write contexts = %+v, want none", remaining)
			}
		})
	}
}

func TestNetstackWriteContextLifecycle(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "link uses original context",
			run: func(t *testing.T) {
				n := &Netstack{
					writeContexts: make(map[netstackFlowKey][]netstackWriteContext),
					writeErrors:   make(map[netstackFlowKey]error),
				}
				key := netstackFlowKeyForAddresses(packet.ProtocolTCP, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 2), 40000, 5060)
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				started := make(chan struct{})
				finished := make(chan struct{})
				go func() {
					_ = n.withWriteContext(ctx, key, func() error {
						close(started)
						<-ctx.Done()
						return ctx.Err()
					})
					close(finished)
				}()
				<-started
				got, stop := n.writeContext(key)
				defer stop()
				if got != ctx {
					t.Fatalf("writeContext() returned %p, want original context %p", got, ctx)
				}
				cancel()
				select {
				case <-got.Done():
				case <-time.After(time.Second):
					t.Fatal("original context did not observe cancellation")
				}
				select {
				case <-finished:
				case <-time.After(time.Second):
					t.Fatal("withWriteContext() did not finish after cancellation")
				}
			},
		},
		{
			name: "TCP close interrupts blocked write",
			run: func(t *testing.T) {
				raw := newBlockingWriteConn()
				n := &Netstack{
					writeContexts: make(map[netstackFlowKey][]netstackWriteContext),
					writeErrors:   make(map[netstackFlowKey]error),
				}
				conn := &NetstackTCPConn{
					writeGate: make(chan struct{}, 1),
					netstack:  n,
					local:     raw.LocalAddr().(*net.TCPAddr),
					remote:    raw.RemoteAddr().(*net.TCPAddr),
					conn:      raw,
					done:      make(chan struct{}),
				}

				writeDone := make(chan error, 1)
				go func() { writeDone <- conn.WritePacket(t.Context(), []byte("blocked")) }()
				<-raw.started
				closeDone := make(chan error, 1)
				go func() { closeDone <- conn.Close() }()

				select {
				case err := <-writeDone:
					if err == nil {
						t.Fatal("WritePacket() error = nil, want close cancellation")
					}
				case <-time.After(time.Second):
					t.Fatal("WritePacket() did not stop after Close()")
				}
				select {
				case err := <-closeDone:
					if err != nil {
						t.Fatalf("Close() error = %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("Close() did not finish")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestNetstackLifetimeEndsOnClose(t *testing.T) {
	tests := []struct {
		name string
		stop func(*Netstack) error
	}{
		{
			name: "explicit close",
			stop: func(n *Netstack) error {
				return n.Close()
			},
		},
		{
			name: "packet session failure",
			stop: func(n *Netstack) error {
				n.HandleError(errors.New("packet session stopped"))
				return nil
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session, _ := newLoopbackPacketSessions()
			n, err := NewNetstack(session)
			if err != nil {
				t.Fatalf("NewNetstack() error = %v", err)
			}
			closeAfterTest(t, n)
			select {
			case <-n.done:
				t.Fatal("Netstack lifetime ended before termination")
			default:
			}
			if err := tt.stop(n); err != nil {
				t.Fatalf("stopping Netstack error = %v", err)
			}
			select {
			case <-n.done:
			case <-time.After(time.Second):
				t.Fatal("Netstack lifetime did not end after termination")
			}
		})
	}
}

func TestNetstackSecureTCPCloseProtectsFIN(t *testing.T) {
	clientSession, serverSession := newLoopbackPacketSessions()
	client := newTestNetstack(t, clientSession)
	server := newTestNetstack(t, serverSession)
	clientConfig, serverConfig := testSecureTCPConfigs()
	serverConn, err := server.ListenSecureTCP(t.Context(), serverConfig)
	if err != nil {
		t.Fatalf("ListenSecureTCP() error = %v", err)
	}
	closeAfterTest(t, serverConn)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	clientConn, err := client.DialSecureTCP(ctx, clientConfig)
	if err != nil {
		t.Fatalf("DialSecureTCP() error = %v", err)
	}
	clientSession.clearWrites()
	if err := clientConn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	codec := secureESPCodec(clientConfig.OutboundSPI, clientConfig.Encryption, clientConfig.EncryptionKey, clientConfig.Integrity, clientConfig.IntegrityKey, clientConfig.OutboundSalt)
	for _, pkt := range clientSession.snapshotWrites() {
		if pkt.TCP != nil {
			t.Fatalf("Close() emitted plaintext TCP flags %#x", pkt.TCP.Flags)
		}
		if pkt.IP.Protocol != packet.ProtocolESP {
			continue
		}
		decoded, err := codec.Decode(pkt.IP.Payload)
		if err != nil || decoded.NextHeader != packet.ProtocolTCP {
			continue
		}
		inner, err := packet.DecodePayload(packet.ProtocolTCP, pkt.IP.SrcIP, pkt.IP.DstIP, decoded.Payload)
		if err == nil && inner.TCP != nil && inner.TCP.Flags&packet.TCPFlagFIN != 0 {
			return
		}
	}
	t.Fatal("Close() did not emit an ESP-protected TCP FIN")
}

func TestNetstackTCPReadReportsPacketSessionCause(t *testing.T) {
	clientSession, serverSession := newLoopbackPacketSessions()
	client := newTestNetstack(t, clientSession)
	server := newTestNetstack(t, serverSession)
	network, err := server.ensureAddress(serverSession.localIP)
	if err != nil {
		t.Fatalf("ensureAddress() error = %v", err)
	}
	listener, err := gonet.ListenTCP(server.stack, netstackFullAddress(serverSession.localIP, 5060), network)
	if err != nil {
		t.Fatalf("ListenTCP() error = %v", err)
	}
	closeAfterTest(t, listener)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, err := client.DialTCP(ctx, TCPConfig{LocalPort: 40000, RemotePort: 5060})
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	closeAfterTest(t, conn)
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	closeAfterTest(t, accepted)

	want := errors.New("packet session stopped")
	clientSession.fail(want)
	_, _, err = conn.ReadPacket(t.Context())
	if !errors.Is(err, want) {
		t.Fatalf("ReadPacket() error = %v, want %v", err, want)
	}
}

func TestNetstackTCPReadCancellationReleasesConnection(t *testing.T) {
	tests := []struct {
		name        string
		readContext func() (context.Context, context.CancelFunc)
		wantErr     error
	}{
		{
			name: "explicit cancellation without deadline",
			readContext: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(t.Context())
			},
			wantErr: context.Canceled,
		},
		{
			name: "parent context cancellation without deadline",
			readContext: func() (context.Context, context.CancelFunc) {
				parent, cancelParent := context.WithCancel(t.Context())
				ctx, cancelChild := context.WithCancel(parent)
				return ctx, func() {
					cancelParent()
					cancelChild()
				}
			},
			wantErr: context.Canceled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, serverSession := newLoopbackPacketSessions()
			client := newTestNetstack(t, clientSession)
			server := newTestNetstack(t, serverSession)
			network, err := server.ensureAddress(serverSession.localIP)
			if err != nil {
				t.Fatalf("ensureAddress() error = %v", err)
			}
			listener, err := gonet.ListenTCP(server.stack, netstackFullAddress(serverSession.localIP, 5060), network)
			if err != nil {
				t.Fatalf("ListenTCP() error = %v", err)
			}
			closeAfterTest(t, listener)

			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			conn, err := client.DialTCP(ctx, TCPConfig{LocalPort: 40000, RemotePort: 5060})
			if err != nil {
				t.Fatalf("DialTCP() error = %v", err)
			}
			closeAfterTest(t, conn)
			accepted, err := listener.Accept()
			if err != nil {
				t.Fatalf("Accept() error = %v", err)
			}
			closeAfterTest(t, accepted)

			readCtx, stopRead := tt.readContext()
			readErr := make(chan error, 1)
			go func() {
				_, _, err := conn.ReadPacket(readCtx)
				readErr <- err
			}()
			for conn.readMu.TryLock() {
				conn.readMu.Unlock()
				select {
				case err := <-readErr:
					stopRead()
					t.Fatalf("ReadPacket() returned before cancellation: %v", err)
				case <-time.After(time.Millisecond):
				}
			}
			stopRead()
			select {
			case err := <-readErr:
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("ReadPacket() error = %v, want %v", err, tt.wantErr)
				}
			case <-time.After(time.Second):
				t.Fatal("ReadPacket() did not stop after context cancellation")
			}

			if _, err := accepted.Write([]byte("\r\n")); err != nil {
				t.Fatalf("Write() error = %v", err)
			}
			nextCtx, stopNext := context.WithTimeout(t.Context(), time.Second)
			defer stopNext()
			packet, _, err := conn.ReadPacket(nextCtx)
			if err != nil {
				t.Fatalf("ReadPacket() after cancellation error = %v", err)
			}
			if string(packet) != "\r\n" {
				t.Fatalf("ReadPacket() after cancellation = %q, want CRLF keepalive", packet)
			}
		})
	}
}

func TestNetstackTCPReadCancellationPreservesReceivedData(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{name: "CRLF received while cancellation interrupts read", data: "\r\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := newInterruptedReadConn()
			conn := &NetstackTCPConn{
				writeGate: make(chan struct{}, 1),
				local:     raw.LocalAddr().(*net.TCPAddr),
				remote:    raw.RemoteAddr().(*net.TCPAddr),
				conn:      raw,
				done:      make(chan struct{}),
			}
			ctx, cancel := context.WithCancel(t.Context())
			readErr := make(chan error, 1)
			go func() {
				_, _, err := conn.ReadPacket(ctx)
				readErr <- err
			}()
			<-raw.started
			cancel()
			if err := <-readErr; !errors.Is(err, context.Canceled) {
				t.Fatalf("ReadPacket() error = %v, want context.Canceled", err)
			}

			packet, _, err := conn.ReadPacket(t.Context())
			if err != nil {
				t.Fatalf("ReadPacket() after cancellation error = %v", err)
			}
			if string(packet) != tt.data {
				t.Fatalf("ReadPacket() after cancellation = %q, want %q", packet, tt.data)
			}
		})
	}
}

func TestNetstackUDPReadReportsCloseCause(t *testing.T) {
	packetSessionErr := errors.New("packet session stopped")
	tests := []struct {
		name string
		stop func(*testing.T, *loopbackPacketSession, *Netstack, *NetstackUDPConn)
		want error
	}{
		{
			name: "connection closed",
			stop: func(t *testing.T, _ *loopbackPacketSession, _ *Netstack, conn *NetstackUDPConn) {
				closeTestResource(t, conn)
			},
			want: net.ErrClosed,
		},
		{
			name: "netstack closed",
			stop: func(t *testing.T, _ *loopbackPacketSession, netstack *Netstack, _ *NetstackUDPConn) {
				closeTestResource(t, netstack)
			},
			want: errNetstackClosed,
		},
		{
			name: "packet session failed",
			stop: func(_ *testing.T, session *loopbackPacketSession, _ *Netstack, _ *NetstackUDPConn) {
				session.fail(packetSessionErr)
			},
			want: packetSessionErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientSession, _ := newLoopbackPacketSessions()
			client := newTestNetstack(t, clientSession)
			conn, err := client.DialUDP(t.Context(), UDPConfig{LocalPort: 40000, RemotePort: 5060})
			if err != nil {
				t.Fatalf("DialUDP() error = %v", err)
			}
			closeAfterTest(t, conn)

			tt.stop(t, clientSession, client, conn)
			_, _, err = conn.ReadPacket(t.Context())
			if !errors.Is(err, tt.want) {
				t.Fatalf("ReadPacket() error = %v, want %v", err, tt.want)
			}
			if errors.Is(err, io.EOF) {
				t.Fatalf("ReadPacket() error = %v, UDP must not report EOF", err)
			}
		})
	}
}

func testNetstackPlainTCP(t *testing.T, client, server *Netstack) {
	t.Helper()
	network, err := server.ensureAddress(net.ParseIP("2001:db8::2"))
	if err != nil {
		t.Fatalf("ensureAddress() error = %v", err)
	}
	listener, err := gonet.ListenTCP(server.stack, netstackFullAddress(net.ParseIP("2001:db8::2"), 5060), network)
	if err != nil {
		t.Fatalf("gonet.ListenTCP() error = %v", err)
	}
	closeAfterTest(t, listener)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	clientConn, err := client.DialTCP(ctx, TCPConfig{LocalPort: 40000, RemotePort: 5060})
	if err != nil {
		t.Fatalf("DialTCP() error = %v", err)
	}
	closeAfterTest(t, clientConn)
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	closeAfterTest(t, serverConn)

	wantRequest := []byte("OPTIONS sip:ims.example SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	if err := clientConn.WritePacket(ctx, wantRequest); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	gotRequest := make([]byte, len(wantRequest))
	if _, err := io.ReadFull(serverConn, gotRequest); err != nil {
		t.Fatalf("ReadFull() error = %v", err)
	}
	if string(gotRequest) != string(wantRequest) {
		t.Fatalf("request = %q, want %q", gotRequest, wantRequest)
	}

	wantResponse := []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n")
	if _, err := serverConn.Write(wantResponse); err != nil {
		t.Fatalf("server Write() error = %v", err)
	}
	gotResponse, _, err := clientConn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(gotResponse) != string(wantResponse) {
		t.Fatalf("response = %q, want %q", gotResponse, wantResponse)
	}
}

func testNetstackProtectedTCP(t *testing.T, client, server *Netstack) {
	t.Helper()
	clientConfig, serverConfig := testSecureTCPConfigs()
	serverConn, err := server.ListenSecureTCP(t.Context(), serverConfig)
	if err != nil {
		t.Fatalf("ListenSecureTCP() error = %v", err)
	}
	closeAfterTest(t, serverConn)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	clientConn, err := client.DialSecureTCP(ctx, clientConfig)
	if err != nil {
		t.Fatalf("DialSecureTCP() error = %v", err)
	}
	closeAfterTest(t, clientConn)

	want := []byte("MESSAGE tel:+12245550100 SIP/2.0\r\nContent-Length: 0\r\n\r\n")
	if err := clientConn.WritePacket(ctx, want); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	got, _, err := serverConn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("packet = %q, want %q", got, want)
	}
}

func testNetstackPlainUDP(t *testing.T, client, server *Netstack) {
	t.Helper()
	clientConn, err := client.DialUDP(t.Context(), UDPConfig{LocalPort: 40000, RemotePort: 5060})
	if err != nil {
		t.Fatalf("client DialUDP() error = %v", err)
	}
	closeAfterTest(t, clientConn)
	serverConn, err := server.DialUDP(t.Context(), UDPConfig{LocalPort: 5060, RemotePort: 40000})
	if err != nil {
		t.Fatalf("server DialUDP() error = %v", err)
	}
	closeAfterTest(t, serverConn)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	want := []byte("plain UDP")
	if err := clientConn.WritePacket(ctx, want); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	got, _, err := serverConn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("packet = %q, want %q", got, want)
	}
}

func testNetstackProtectedUDP(t *testing.T, client, server *Netstack) {
	t.Helper()
	clientConfig, serverConfig := testSecureUDPConfigs()
	clientConn, err := client.DialSecureUDP(t.Context(), clientConfig)
	if err != nil {
		t.Fatalf("client DialSecureUDP() error = %v", err)
	}
	closeAfterTest(t, clientConn)
	serverConn, err := server.ListenSecureUDP(t.Context(), serverConfig)
	if err != nil {
		t.Fatalf("server ListenSecureUDP() error = %v", err)
	}
	closeAfterTest(t, serverConn)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	want := []byte("protected UDP")
	if err := clientConn.WritePacket(ctx, want); err != nil {
		t.Fatalf("WritePacket() error = %v", err)
	}
	got, _, err := serverConn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("packet = %q, want %q", got, want)
	}
}

func testNetstackSecureTCPServerPortReuse(t *testing.T, client, server *Netstack) {
	t.Helper()
	clientConfig1, serverConfig1 := testSecureTCPConfigs()
	clientConfig2, serverConfig2 := testSecureTCPConfigs()
	clientConfig2.LocalPort = 40001
	clientConfig2.OutboundSPI = 0x1003
	clientConfig2.InboundSPI = 0x2003
	clientConfig2.Associations = NewSecurityAssociations()
	serverConfig2.RemotePort = clientConfig2.LocalPort
	serverConfig2.OutboundSPI = clientConfig2.InboundSPI
	serverConfig2.InboundSPI = clientConfig2.OutboundSPI
	serverConfig2.Associations = NewSecurityAssociations()

	serverConn1, err := server.ListenSecureTCP(t.Context(), serverConfig1)
	if err != nil {
		t.Fatalf("first ListenSecureTCP() error = %v", err)
	}
	closeAfterTest(t, serverConn1)
	serverConn2, err := server.ListenSecureTCP(t.Context(), serverConfig2)
	if err != nil {
		t.Fatalf("second ListenSecureTCP() error = %v", err)
	}
	closeAfterTest(t, serverConn2)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	clientConn1, err := client.DialSecureTCP(ctx, clientConfig1)
	if err != nil {
		t.Fatalf("first DialSecureTCP() error = %v", err)
	}
	closeAfterTest(t, clientConn1)
	clientConn2, err := client.DialSecureTCP(ctx, clientConfig2)
	if err != nil {
		t.Fatalf("second DialSecureTCP() error = %v", err)
	}
	closeAfterTest(t, clientConn2)

	tests := []struct {
		name   string
		client *NetstackTCPConn
		server *NetstackTCPConn
		want   string
	}{
		{name: "old SA", client: clientConn1, server: serverConn1, want: "OPTIONS sip:old.example SIP/2.0\r\nContent-Length: 0\r\n\r\n"},
		{name: "new SA", client: clientConn2, server: serverConn2, want: "OPTIONS sip:new.example SIP/2.0\r\nContent-Length: 0\r\n\r\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			writeCtx, writeCancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer writeCancel()
			if err := tt.client.WritePacket(writeCtx, []byte(tt.want)); err != nil {
				t.Fatalf("WritePacket() error = %v", err)
			}
			got, _, err := tt.server.ReadPacket(writeCtx)
			if err != nil {
				t.Fatalf("ReadPacket() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("packet = %q, want %q", got, tt.want)
			}
		})
	}
	closeTestResource(t, clientConn1)
	closeTestResource(t, serverConn1)
	want := "OPTIONS sip:remaining.example SIP/2.0\r\nContent-Length: 0\r\n\r\n"
	if err := clientConn2.WritePacket(ctx, []byte(want)); err != nil {
		t.Fatalf("new SA WritePacket() after old SA close error = %v", err)
	}
	got, _, err := serverConn2.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("new SA ReadPacket() after old SA close error = %v", err)
	}
	if string(got) != want {
		t.Fatalf("new SA packet after old SA close = %q, want %q", got, want)
	}
}

func testNetstackSecureUDPServerPortReuse(t *testing.T, client, server *Netstack) {
	t.Helper()
	clientConfig1, serverConfig1 := testSecureUDPConfigs()
	clientConfig2, serverConfig2 := testSecureUDPConfigs()
	clientConfig2.LocalPort = 40001
	clientConfig2.OutboundSPI = 0x1004
	clientConfig2.InboundSPI = 0x2004
	clientConfig2.Associations = NewSecurityAssociations()
	serverConfig2.RemotePort = clientConfig2.LocalPort
	serverConfig2.OutboundSPI = clientConfig2.InboundSPI
	serverConfig2.InboundSPI = clientConfig2.OutboundSPI
	serverConfig2.Associations = NewSecurityAssociations()

	serverConn1, err := server.ListenSecureUDP(t.Context(), serverConfig1)
	if err != nil {
		t.Fatalf("first ListenSecureUDP() error = %v", err)
	}
	closeAfterTest(t, serverConn1)
	serverConn2, err := server.ListenSecureUDP(t.Context(), serverConfig2)
	if err != nil {
		t.Fatalf("second ListenSecureUDP() error = %v", err)
	}
	closeAfterTest(t, serverConn2)
	clientConn1, err := client.DialSecureUDP(t.Context(), clientConfig1)
	if err != nil {
		t.Fatalf("first DialSecureUDP() error = %v", err)
	}
	closeAfterTest(t, clientConn1)
	clientConn2, err := client.DialSecureUDP(t.Context(), clientConfig2)
	if err != nil {
		t.Fatalf("second DialSecureUDP() error = %v", err)
	}
	closeAfterTest(t, clientConn2)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	tests := []struct {
		name   string
		client *NetstackUDPConn
		server *NetstackUDPConn
		want   string
	}{
		{name: "old SA", client: clientConn1, server: serverConn1, want: "old security association"},
		{name: "new SA", client: clientConn2, server: serverConn2, want: "new security association"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.client.WritePacket(ctx, []byte(tt.want)); err != nil {
				t.Fatalf("WritePacket() error = %v", err)
			}
			got, _, err := tt.server.ReadPacket(ctx)
			if err != nil {
				t.Fatalf("ReadPacket() error = %v", err)
			}
			if string(got) != tt.want {
				t.Fatalf("packet = %q, want %q", got, tt.want)
			}
		})
	}
	closeTestResource(t, clientConn1)
	closeTestResource(t, serverConn1)
	want := "remaining security association"
	if err := clientConn2.WritePacket(ctx, []byte(want)); err != nil {
		t.Fatalf("new SA WritePacket() after old SA close error = %v", err)
	}
	got, _, err := serverConn2.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("new SA ReadPacket() after old SA close error = %v", err)
	}
	if string(got) != want {
		t.Fatalf("new SA packet after old SA close = %q, want %q", got, want)
	}
}

func testSecureTCPConfigs() (SecureTCPConfig, SecureTCPConfig) {
	client := SecureTCPConfig{
		TCPConfig:   TCPConfig{LocalPort: 40000, RemotePort: 6000},
		OutboundSPI: 0x1001, InboundSPI: 0x2001,
		Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196,
		IntegrityKey: []byte("0123456789abcdefghij"), Associations: NewSecurityAssociations(),
	}
	server := SecureTCPConfig{
		TCPConfig:   TCPConfig{LocalPort: 6000, RemotePort: 40000},
		OutboundSPI: client.InboundSPI, InboundSPI: client.OutboundSPI,
		Encryption: client.Encryption, Integrity: client.Integrity,
		IntegrityKey: append([]byte(nil), client.IntegrityKey...), Associations: NewSecurityAssociations(),
	}
	return client, server
}

func testSecureUDPConfigs() (SecureUDPConfig, SecureUDPConfig) {
	client := SecureUDPConfig{
		UDPConfig:   UDPConfig{LocalPort: 40000, RemotePort: 6000},
		OutboundSPI: 0x1002, InboundSPI: 0x2002,
		Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196,
		IntegrityKey: []byte("0123456789abcdefghij"), Associations: NewSecurityAssociations(),
	}
	server := SecureUDPConfig{
		UDPConfig:   UDPConfig{LocalPort: 6000, RemotePort: 40000},
		OutboundSPI: client.InboundSPI, InboundSPI: client.OutboundSPI,
		Encryption: client.Encryption, Integrity: client.Integrity,
		IntegrityKey: append([]byte(nil), client.IntegrityKey...), Associations: NewSecurityAssociations(),
	}
	return client, server
}

func newTestNetstack(t *testing.T, session ipsecbase.PacketSession) *Netstack {
	t.Helper()
	n, err := NewNetstack(session)
	if err != nil {
		t.Fatalf("NewNetstack() error = %v", err)
	}
	closeAfterTest(t, n)
	return n
}

func newLoopbackPacketSessions() (*loopbackPacketSession, *loopbackPacketSession) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := &loopbackPacketSession{
		localIP: net.ParseIP("2001:db8::1"), remoteIP: net.ParseIP("2001:db8::2"),
		logger: logger, processors: make(map[*loopbackAttachment]ipsecbase.InnerPacketProcessor),
	}
	server := &loopbackPacketSession{
		localIP: net.ParseIP("2001:db8::2"), remoteIP: net.ParseIP("2001:db8::1"),
		logger: logger, processors: make(map[*loopbackAttachment]ipsecbase.InnerPacketProcessor),
	}
	client.peer = server
	server.peer = client
	return client, server
}

type loopbackPacketSession struct {
	mu         sync.RWMutex
	localIP    net.IP
	remoteIP   net.IP
	peer       *loopbackPacketSession
	logger     *slog.Logger
	processors map[*loopbackAttachment]ipsecbase.InnerPacketProcessor
	writes     []packet.InnerPacket
	writeHook  func(context.Context, packet.InnerPacket) error
	closed     bool
}

func (s *loopbackPacketSession) InnerIPsForRemote(remoteIP net.IP) (net.IP, net.IP, error) {
	if len(remoteIP) != 0 && !remoteIP.Equal(s.remoteIP) {
		return nil, nil, errors.New("remote IP does not match loopback peer")
	}
	return append(net.IP(nil), s.localIP...), append(net.IP(nil), s.remoteIP...), nil
}

func (s *loopbackPacketSession) Attach(processor ipsecbase.InnerPacketProcessor) (ipsecbase.Attachment, error) {
	if processor == nil {
		return nil, errors.New("attaching loopback processor: processor is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("attaching loopback processor: session is closed")
	}
	attachment := &loopbackAttachment{session: s}
	s.processors[attachment] = processor
	return attachment, nil
}

func (s *loopbackPacketSession) WriteInnerPacket(ctx context.Context, pkt packet.InnerPacket) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	wire, err := pkt.MarshalBinary()
	if err != nil {
		return err
	}
	var cloned packet.InnerPacket
	if err := cloned.UnmarshalBinary(wire); err != nil {
		return err
	}
	s.mu.Lock()
	s.writes = append(s.writes, cloned)
	hook := s.writeHook
	s.mu.Unlock()
	if hook != nil {
		if err := hook(ctx, cloned); err != nil {
			return err
		}
	}
	return s.peer.dispatch(cloned)
}

func (s *loopbackPacketSession) snapshotWrites() []packet.InnerPacket {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]packet.InnerPacket(nil), s.writes...)
}

func (s *loopbackPacketSession) clearWrites() {
	s.mu.Lock()
	s.writes = nil
	s.mu.Unlock()
}

func (s *loopbackPacketSession) setWriteHook(hook func(context.Context, packet.InnerPacket) error) {
	s.mu.Lock()
	s.writeHook = hook
	s.mu.Unlock()
}

func (s *loopbackPacketSession) dispatch(pkt packet.InnerPacket) error {
	s.mu.RLock()
	if s.closed {
		s.mu.RUnlock()
		return net.ErrClosed
	}
	processors := make([]ipsecbase.InnerPacketProcessor, 0, len(s.processors))
	for _, processor := range s.processors {
		processors = append(processors, processor)
	}
	s.mu.RUnlock()
	for _, processor := range processors {
		if processor.HandleInnerPacket(pkt) {
			return nil
		}
	}
	return errors.New("loopback packet was not handled")
}

func (s *loopbackPacketSession) fail(err error) {
	s.mu.RLock()
	processors := make([]ipsecbase.InnerPacketProcessor, 0, len(s.processors))
	for _, processor := range s.processors {
		processors = append(processors, processor)
	}
	s.mu.RUnlock()
	for _, processor := range processors {
		processor.HandleError(err)
	}
}

func (s *loopbackPacketSession) Logger() *slog.Logger { return s.logger }

func (s *loopbackPacketSession) Close() error {
	s.mu.Lock()
	s.closed = true
	s.processors = nil
	s.mu.Unlock()
	return nil
}

type loopbackAttachment struct {
	session *loopbackPacketSession
	once    sync.Once
}

func (a *loopbackAttachment) Close() error {
	a.once.Do(func() {
		a.session.mu.Lock()
		delete(a.session.processors, a)
		a.session.mu.Unlock()
	})
	return nil
}
