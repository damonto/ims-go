package session

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

func TestDispatcherWritesHaveDeadline(t *testing.T) {
	tests := []struct {
		name        string
		keepalive   bool
		callerLimit time.Duration
	}{
		{name: "SIP reply"},
		{name: "CRLF reply", keepalive: true},
		{name: "caller deadline", callerLimit: time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				transport := newBlockingWriteTransport()
				// A SIP transaction timer must not redefine the transport write budget.
				sess, err := Open(Config{TransactionTimers: TransactionTimers{TF: 20 * time.Millisecond}}, transport)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := sess.Close(); err != nil {
						t.Error(err)
					}
				})
				ctx := t.Context()
				want := sipWriteTimeout
				if tt.callerLimit != 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, tt.callerLimit)
					defer cancel()
					want = tt.callerLimit
				}
				started := time.Now()
				if tt.keepalive {
					err = sess.handleKeepAlivePacket(ctx, inboundMessage{transport: transport, packet: []byte("\r\n\r\n")})
				} else {
					err = sess.WriteStatus(ctx, Request{Transport: transport, Message: newRequest("OPTIONS", "reply-timeout", "1 OPTIONS")}, 200, "OK")
				}
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("reply error = %v, want timeout", err)
				}
				if elapsed := time.Since(started); elapsed != want {
					t.Fatalf("write duration = %v, want %v", elapsed, want)
				}
			})
		})
	}
}
