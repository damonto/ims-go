package swu

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestSecureUDPTransportClose(t *testing.T) {
	tests := []struct {
		name  string
		check func(t *testing.T, transport *SecureUDPTransport)
	}{
		{
			name: "unblocks read",
			check: func(t *testing.T, transport *SecureUDPTransport) {
				t.Helper()
				result := make(chan error, 1)
				go func() {
					_, _, err := transport.ReadPacket(context.Background())
					result <- err
				}()
				if err := transport.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				select {
				case err := <-result:
					if err == nil {
						t.Fatal("ReadPacket() error = nil, want non-nil")
					}
				case <-time.After(time.Second):
					t.Fatal("ReadPacket() did not unblock after Close")
				}
			},
		},
		{
			name: "drops deliveries after close",
			check: func(t *testing.T, transport *SecureUDPTransport) {
				t.Helper()
				if err := transport.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				transport.deliver([]byte("payload"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5060})
				select {
				case <-transport.readCh:
					t.Fatal("deliver() queued data after Close")
				default:
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport := &SecureUDPTransport{
				session: &Session{logger: testLogger()},
				readCh:  make(chan inboundPacket, 1),
				done:    make(chan struct{}),
			}
			tt.check(t, transport)
		})
	}
}
