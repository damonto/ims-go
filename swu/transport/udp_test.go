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
		readCh: make(chan inboundPacket, 1),
		done:   make(chan struct{}),
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

func TestProtectedUDPWriteRemoteUsesConfiguredPeerPort(t *testing.T) {
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
			name:       "different IP keeps requested port",
			configured: &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
			requested:  &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000},
			want:       &net.UDPAddr{IP: net.IPv4(198, 51, 100, 10), Port: 6000},
		},
		{
			name:       "nil request falls back to configured remote",
			configured: &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
			want:       &net.UDPAddr{IP: net.IPv4(172, 25, 63, 232), Port: 32773},
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
