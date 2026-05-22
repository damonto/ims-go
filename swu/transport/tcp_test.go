package transport

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestNextSIPMessage(t *testing.T) {
	tests := []struct {
		name    string
		stream  string
		wantMsg string
		wantOK  bool
		wantErr bool
	}{
		{name: "complete", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello", wantMsg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello", wantOK: true},
		{name: "incomplete body", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhel", wantOK: false},
		{name: "missing length", stream: "MESSAGE sip:test SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n", wantErr: true},
		{name: "invalid length", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: nope\r\n\r\n", wantErr: true},
		{name: "negative length", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: -1\r\n\r\n", wantErr: true},
		{name: "compact length", stream: "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello", wantMsg: "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello", wantOK: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg, _, ok, err := nextSIPMessage([]byte(tt.stream))
			if tt.wantErr {
				if err == nil {
					t.Fatal("nextSIPMessage() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("nextSIPMessage() error = %v", err)
			}
			if ok != tt.wantOK {
				t.Fatalf("ok = %t, want %t", ok, tt.wantOK)
			}
			if tt.wantOK && string(msg) != tt.wantMsg {
				t.Fatalf("msg = %q, want %q", string(msg), tt.wantMsg)
			}
		})
	}
}

func TestTCPConnWritePacketUnblocksOnHandleError(t *testing.T) {
	conn := &TCPConn{
		errCh:   make(chan error, 1),
		msgCh:   make(chan []byte, 1),
		readyCh: make(chan struct{}),
		ackCh:   make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	result := make(chan error, 1)
	go func() {
		result <- conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	}()

	select {
	case err := <-result:
		t.Fatalf("WritePacket() returned early with %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	cause := errors.New("session failed")
	conn.HandleError(cause)

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("WritePacket() error = nil, want terminal error")
		}
		if !errors.Is(err, cause) {
			t.Fatalf("WritePacket() error = %v, want wrapped %v", err, cause)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket() did not unblock after HandleError()")
	}
}

func TestTCPConnReadPacketReturnsTerminalErrorAfterHandleError(t *testing.T) {
	conn := &TCPConn{
		errCh:   make(chan error, 1),
		msgCh:   make(chan []byte, 1),
		readyCh: make(chan struct{}),
		ackCh:   make(chan struct{}, 1),
		done:    make(chan struct{}),
	}
	cause := errors.New("session failed")
	conn.HandleError(cause)

	for range 2 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_, _, err := conn.ReadPacket(ctx)
		cancel()
		if err == nil {
			t.Fatal("ReadPacket() error = nil, want terminal error")
		}
		if !errors.Is(err, cause) {
			t.Fatalf("ReadPacket() error = %v, want wrapped %v", err, cause)
		}
	}
}
