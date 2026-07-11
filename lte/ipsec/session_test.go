package ipsec

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/ipsec/transport"
)

type testPacketConn struct {
	mu        sync.Mutex
	local     net.Addr
	writes    [][]byte
	writeAddr []net.Addr
	closed    bool
}

func (c *testPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, net.ErrClosed
}

func (c *testPacketConn) WriteTo(data []byte, addr net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), data...))
	c.writeAddr = append(c.writeAddr, addr)
	return len(data), nil
}

func (c *testPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *testPacketConn) SetWriteDeadline(time.Time) error { return nil }
func (c *testPacketConn) LocalAddr() net.Addr              { return c.local }

func (c *testPacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

type testInnerHandler struct {
	handle  bool
	packets []packet.InnerPacket
	errors  []error
}

func (h *testInnerHandler) HandleInnerPacket(pkt packet.InnerPacket) bool {
	h.packets = append(h.packets, pkt)
	return h.handle
}

func (h *testInnerHandler) HandleError(err error) {
	h.errors = append(h.errors, err)
}

func TestNewSessionValidatesIPPair(t *testing.T) {
	tests := []struct {
		name      string
		localIP   net.IP
		remoteIP  net.IP
		wantLocal net.IP
		wantErr   string
	}{
		{name: "IPv4", localIP: net.IPv4(192, 0, 2, 10), remoteIP: net.IPv4(192, 0, 2, 20), wantLocal: net.ParseIP("192.0.2.10")},
		{name: "IPv6", localIP: net.ParseIP("2001:db8::10"), remoteIP: net.ParseIP("2001:db8::20"), wantLocal: net.ParseIP("2001:db8::10")},
		{name: "missing local", remoteIP: net.IPv4(192, 0, 2, 20), wantErr: "required"},
		{name: "missing remote", localIP: net.IPv4(192, 0, 2, 10), wantErr: "required"},
		{name: "mixed families", localIP: net.IPv4(192, 0, 2, 10), remoteIP: net.ParseIP("2001:db8::20"), wantErr: "families do not match"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSession(tt.localIP, tt.remoteIP, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("NewSession() error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}
			if !s.localIP.Equal(tt.wantLocal) {
				t.Fatalf("local IP = %v, want %v", s.localIP, tt.wantLocal)
			}
		})
	}
}

func TestSessionEnableOpensModeOnce(t *testing.T) {
	tests := []struct {
		name string
		mode string
		want string
	}{
		{name: "empty defaults to transport", mode: "", want: transport.SecureModeTransport},
		{name: "transport", mode: "trans", want: transport.SecureModeTransport},
		{name: "UDP encapsulated tunnel", mode: "UDP-enc-tun", want: transport.SecureModeUDPEncTunnel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSession(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 20), nil)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}
			calls := 0
			s.openESP = func(net.IP) (packetConn, error) {
				calls++
				return &testPacketConn{local: &net.IPAddr{IP: s.localIP}}, nil
			}
			s.openUDP = func(net.IP) (packetConn, error) {
				calls++
				return &testPacketConn{local: &net.UDPAddr{IP: s.localIP, Port: udpEncapPort}}, nil
			}

			if err := s.Enable(context.Background(), tt.mode); err != nil {
				t.Fatalf("Enable() error = %v", err)
			}
			if err := s.Enable(context.Background(), tt.mode); err != nil {
				t.Fatalf("second Enable() error = %v", err)
			}
			if calls != 1 {
				t.Fatalf("socket opens = %d, want 1", calls)
			}
			if tt.want == transport.SecureModeTransport && s.espConn == nil {
				t.Fatal("ESP socket = nil, want enabled")
			}
			if tt.want == transport.SecureModeUDPEncTunnel && s.udpConn == nil {
				t.Fatal("UDP encapsulation socket = nil, want enabled")
			}
			if err := s.Close(); err != nil {
				t.Fatalf("Close() error = %v", err)
			}
		})
	}
}

func TestSessionWriteInnerPacketMapsOuterTransport(t *testing.T) {
	localIP := net.IPv4(192, 0, 2, 10)
	remoteIP := net.IPv4(192, 0, 2, 20)
	tests := []struct {
		name        string
		packet      packet.InnerPacket
		wantNetwork string
		wantAddr    string
	}{
		{
			name:        "raw ESP",
			packet:      packet.InnerPacket{IP: packet.IPPacket{Protocol: packet.ProtocolESP, Payload: []byte{1, 2, 3}}},
			wantNetwork: "ip",
			wantAddr:    "192.0.2.20",
		},
		{
			name:        "UDP 4500",
			packet:      packet.InnerPacket{UDP: &packet.UDPSegment{Dst: &net.UDPAddr{IP: remoteIP, Port: udpEncapPort}, Payload: []byte{4, 5, 6}}},
			wantNetwork: "udp",
			wantAddr:    "192.0.2.20:4500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewSession(localIP, remoteIP, nil)
			if err != nil {
				t.Fatalf("NewSession() error = %v", err)
			}
			espConn := &testPacketConn{}
			udpConn := &testPacketConn{}
			s.espConn = espConn
			s.udpConn = udpConn

			if err := s.WriteInnerPacket(context.Background(), tt.packet); err != nil {
				t.Fatalf("WriteInnerPacket() error = %v", err)
			}
			conn := espConn
			if tt.wantNetwork == "udp" {
				conn = udpConn
			}
			if len(conn.writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(conn.writes))
			}
			if !bytes.Equal(conn.writes[0], tt.packet.IP.Payload) && (tt.packet.UDP == nil || !bytes.Equal(conn.writes[0], tt.packet.UDP.Payload)) {
				t.Fatalf("payload = % X, want packet payload", conn.writes[0])
			}
			if got := conn.writeAddr[0]; got.Network() != tt.wantNetwork || got.String() != tt.wantAddr {
				t.Fatalf("remote = %s %s, want %s %s", got.Network(), got, tt.wantNetwork, tt.wantAddr)
			}
		})
	}
}

func TestSessionInboundPacketFiltersPeer(t *testing.T) {
	s, err := NewSession(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 20), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	tests := []struct {
		name    string
		mode    string
		peer    net.Addr
		local   net.Addr
		wantErr bool
	}{
		{name: "ESP expected peer", mode: transport.SecureModeTransport, peer: &net.IPAddr{IP: net.IPv4(192, 0, 2, 20)}},
		{name: "ESP unexpected peer", mode: transport.SecureModeTransport, peer: &net.IPAddr{IP: net.IPv4(198, 51, 100, 20)}, wantErr: true},
		{name: "UDP expected peer", mode: transport.SecureModeUDPEncTunnel, peer: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: udpEncapPort}, local: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: udpEncapPort}},
		{name: "UDP wrong port", mode: transport.SecureModeUDPEncTunnel, peer: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 20), Port: 5060}, wantErr: true},
		{name: "UDP unexpected peer", mode: transport.SecureModeUDPEncTunnel, peer: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 20), Port: udpEncapPort}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.inboundPacket(tt.mode, tt.peer, []byte{1, 2, 3}, tt.local)
			if tt.wantErr && err == nil {
				t.Fatal("inboundPacket() error = nil, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("inboundPacket() error = %v", err)
			}
		})
	}
}

func TestSessionAttachmentDispatchAndClose(t *testing.T) {
	s, err := NewSession(net.IPv4(192, 0, 2, 10), net.IPv4(192, 0, 2, 20), nil)
	if err != nil {
		t.Fatalf("NewSession() error = %v", err)
	}
	tests := []struct {
		name        string
		closeFirst  bool
		wantFirst   int
		wantSecond  int
		wantHandled bool
	}{
		{name: "first handler accepts", wantFirst: 1, wantHandled: true},
		{name: "closed first handler is skipped", closeFirst: true, wantSecond: 1, wantHandled: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first := &testInnerHandler{handle: true}
			second := &testInnerHandler{handle: true}
			firstAttachment, err := s.Attach(first)
			if err != nil {
				t.Fatalf("Attach(first) error = %v", err)
			}
			secondAttachment, err := s.Attach(second)
			if err != nil {
				t.Fatalf("Attach(second) error = %v", err)
			}
			if tt.closeFirst {
				if err := firstAttachment.Close(); err != nil {
					t.Fatalf("Close(first) error = %v", err)
				}
			}

			got := s.dispatch(packet.InnerPacket{IP: packet.IPPacket{Protocol: packet.ProtocolESP}})
			if got != tt.wantHandled {
				t.Fatalf("dispatch() = %v, want %v", got, tt.wantHandled)
			}
			if len(first.packets) != tt.wantFirst || len(second.packets) != tt.wantSecond {
				t.Fatalf("handler calls = %d/%d, want %d/%d", len(first.packets), len(second.packets), tt.wantFirst, tt.wantSecond)
			}
			_ = firstAttachment.Close()
			_ = secondAttachment.Close()
		})
	}

	if err := s.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := s.Attach(&testInnerHandler{}); err == nil {
		t.Fatal("Attach() after Close error = nil, want non-nil")
	}
	if err := s.WriteInnerPacket(context.Background(), packet.InnerPacket{}); err == nil {
		t.Fatal("WriteInnerPacket() after Close error = nil, want non-nil")
	}
}
