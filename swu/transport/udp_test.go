package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestUDPConnReadPacketUnblocksOnHandleError(t *testing.T) {
	conn := &UDPConn{
		readCh:       make(chan inboundPacket, 1),
		done:         make(chan struct{}),
		associations: NewSecurityAssociations(),
	}
	cause := errors.New("session failed")
	conn.HandleError(cause)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, _, err := conn.ReadPacket(ctx)
	if err == nil {
		t.Fatal("ReadPacket() error = nil, want terminal error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("ReadPacket() error = %v, want wrapped %v", err, cause)
	}
}

func TestUDPConnReadPacketDrainsQueuedPacketBeforeTerminalError(t *testing.T) {
	conn := &UDPConn{
		readCh:       make(chan inboundPacket, 1),
		done:         make(chan struct{}),
		associations: NewSecurityAssociations(),
	}
	conn.readCh <- inboundPacket{
		data: []byte("SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n"),
		addr: &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 5060},
	}
	cause := errors.New("session failed")
	conn.HandleError(cause)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	got, addr, err := conn.ReadPacket(ctx)
	if err != nil {
		t.Fatalf("ReadPacket() error = %v, want queued packet", err)
	}
	if string(got) != "SIP/2.0 200 OK\r\nContent-Length: 0\r\n\r\n" {
		t.Fatalf("ReadPacket() data = %q, want queued SIP response", got)
	}
	if addr.String() != "192.0.2.10:5060" {
		t.Fatalf("ReadPacket() addr = %v, want 192.0.2.10:5060", addr)
	}

	_, _, err = conn.ReadPacket(ctx)
	if err == nil {
		t.Fatal("ReadPacket() second error = nil, want terminal error")
	}
	if !errors.Is(err, cause) {
		t.Fatalf("ReadPacket() second error = %v, want wrapped %v", err, cause)
	}
}

func TestProtectedUDPWriteRemoteStaysOnProtectedPeerFlow(t *testing.T) {
	tests := []struct {
		name       string
		configured *net.UDPAddr
		requested  *net.UDPAddr
		want       *net.UDPAddr
	}{
		{
			name:       "same IP uses protected peer port",
			configured: &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
			requested:  &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 6000},
			want:       &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
		},
		{
			name:       "different IP stays on protected peer flow",
			configured: &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
			requested:  &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000},
			want:       &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
		},
		{
			name:       "nil request falls back to configured remote",
			configured: &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
			want:       &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
		},
		{
			name:      "no configured remote uses requested target",
			requested: &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000},
			want:      &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var before int
			if tt.requested != nil {
				before = tt.requested.Port
			}
			got := protectedUDPWriteRemote(tt.configured, tt.requested)
			if !got.IP.Equal(tt.want.IP) || got.Port != tt.want.Port {
				t.Fatalf("protectedUDPWriteRemote() = %v, want %v", got, tt.want)
			}
			if tt.requested != nil && tt.requested.Port != before {
				t.Fatalf("requested port mutated to %d, want %d", tt.requested.Port, before)
			}
		})
	}
}
