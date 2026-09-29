package transport

import (
	"context"
	"errors"
	"net"
	"testing"
	"testing/synctest"
	"time"
)

func TestTCPWriteQueueCancellation(t *testing.T) {
	tests := []struct {
		name     string
		deadline bool
	}{
		{name: "cancellation"},
		{name: "deadline", deadline: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				// A passive transport holds its write slot while waiting for a peer.
				conn := &NetstackTCPConn{writeGate: make(chan struct{}, 1), done: make(chan struct{}), accept: make(chan net.Conn)}
				firstCtx, cancelFirst := context.WithCancel(t.Context())
				firstExited := make(chan struct{})
				go func() {
					defer close(firstExited)
					if err := conn.WritePacket(firstCtx, []byte("first")); !errors.Is(err, context.Canceled) {
						t.Errorf("first write = %v, want cancellation", err)
					}
				}()
				t.Cleanup(func() { cancelFirst(); <-firstExited })
				synctest.Wait()
				if len(conn.writeGate) != 1 {
					t.Fatal("first writer did not acquire slot")
				}

				ctx, cancel := context.WithCancel(t.Context())
				want := error(context.Canceled)
				if tt.deadline {
					cancel()
					ctx, cancel = context.WithTimeout(t.Context(), 10*time.Millisecond)
					want = context.DeadlineExceeded
				}
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- conn.WritePacket(ctx, []byte("second")) }()
				synctest.Wait()
				if !tt.deadline {
					cancel()
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatalf("queued write = %v, want %v", err, want)
				}
				select {
				case <-firstExited:
					t.Fatal("canceling queued writer interrupted first writer")
				default:
				}
			})
		})
	}
}
