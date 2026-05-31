package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"log/slog"

	"github.com/damonto/vowifi-go/swu/packet"
	"github.com/damonto/vowifi-go/swu/tunnel"
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

func TestTCPConnWritePacketClosesOnAckTimeout(t *testing.T) {
	oldTimeout := tcpDataACKTimeout
	tcpDataACKTimeout = 10 * time.Millisecond
	t.Cleanup(func() {
		tcpDataACKTimeout = oldTimeout
	})

	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() {
		_ = packetConn.Close()
	})
	session, err := tunnel.Dial(context.Background(), tunnel.Config{
		RemoteAddr: "127.0.0.1:9",
		PacketConn: packetConn,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
	})
	conn := &TCPConn{
		session:     session,
		local:       &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
		remote:      &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
		established: true,
		sendSeq:     1001,
		recvSeq:     2001,
		ackedSeq:    1000,
		errCh:       make(chan error, 1),
		msgCh:       make(chan []byte, 1),
		readyCh:     make(chan struct{}),
		ackCh:       make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
	err = conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	if err == nil {
		t.Fatal("WritePacket() error = nil, want ack timeout")
	}
	if !strings.Contains(err.Error(), "waiting for ack") {
		t.Fatalf("WritePacket() error = %v, want ack timeout", err)
	}

	if !conn.closed {
		t.Fatal("closed = false, want true")
	}
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("done was not closed after ack timeout")
	}

	_, _, readErr := conn.ReadPacket(context.Background())
	if readErr == nil {
		t.Fatal("ReadPacket() error = nil, want terminal error")
	}
	if !strings.Contains(readErr.Error(), "waiting for ack") {
		t.Fatalf("ReadPacket() error = %v, want ack timeout", readErr)
	}
}

func TestTCPConnACKWindow(t *testing.T) {
	tests := []struct {
		name      string
		sendSeq   uint32
		ackedSeq  uint32
		ack       uint32
		wantAcked uint32
	}{
		{name: "valid ack advances", sendSeq: 1100, ackedSeq: 1000, ack: 1050, wantAcked: 1050},
		{name: "duplicate ack ignored", sendSeq: 1100, ackedSeq: 1050, ack: 1050, wantAcked: 1050},
		{name: "future ack ignored", sendSeq: 1100, ackedSeq: 1000, ack: 1200, wantAcked: 1000},
		{name: "wrapped valid ack advances", sendSeq: 5, ackedSeq: ^uint32(0) - 4, ack: 3, wantAcked: 3},
		{name: "wrapped future ack ignored", sendSeq: 5, ackedSeq: ^uint32(0) - 4, ack: 32, wantAcked: ^uint32(0) - 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &TCPConn{
				sendSeq:  tt.sendSeq,
				ackedSeq: tt.ackedSeq,
				ackCh:    make(chan struct{}, 1),
			}
			conn.mu.Lock()
			conn.noteAckLocked(tt.ack)
			got := conn.ackedSeq
			conn.mu.Unlock()
			if got != tt.wantAcked {
				t.Fatalf("ackedSeq = %d, want %d", got, tt.wantAcked)
			}
		})
	}
}

func TestTCPConnClosesOnTerminalInboundSegment(t *testing.T) {
	tests := []struct {
		name    string
		segment packet.TCPSegment
		wantErr string
	}{
		{
			name: "peer fin",
			segment: packet.TCPSegment{
				Src:   &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
				Dst:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
				Seq:   2001,
				Ack:   1001,
				Flags: packet.TCPFlagFIN | packet.TCPFlagACK,
			},
			wantErr: "peer closed connection",
		},
		{
			name: "peer reset",
			segment: packet.TCPSegment{
				Src:   &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
				Dst:   &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
				Seq:   2001,
				Ack:   1001,
				Flags: packet.TCPFlagRST | packet.TCPFlagACK,
			},
			wantErr: "peer reset connection",
		},
		{
			name: "invalid sip framing",
			segment: packet.TCPSegment{
				Src:     &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
				Dst:     &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
				Seq:     2001,
				Ack:     1001,
				Flags:   packet.TCPFlagPSH | packet.TCPFlagACK,
				Payload: []byte("MESSAGE sip:test SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n"),
			},
			wantErr: "missing Content-Length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.handleSegment(tt.segment)
			waitTCPDone(t, conn)

			for range 2 {
				_, _, err := conn.ReadPacket(context.Background())
				if err == nil {
					t.Fatal("ReadPacket() error = nil, want terminal error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadPacket() error = %v, want %q", err, tt.wantErr)
				}
			}
			if err := conn.WritePacket(context.Background(), []byte("MESSAGE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n")); err == nil {
				t.Fatal("WritePacket() error = nil, want terminal error")
			}
		})
	}
}

func newEstablishedTCPConnForTest(t *testing.T) *TCPConn {
	t.Helper()
	packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	t.Cleanup(func() {
		_ = packetConn.Close()
	})
	session, err := tunnel.Dial(context.Background(), tunnel.Config{
		RemoteAddr: "127.0.0.1:9",
		PacketConn: packetConn,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("Dial() error = %v", err)
	}
	t.Cleanup(func() {
		_ = session.Close()
	})
	return &TCPConn{
		session:     session,
		local:       &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
		remote:      &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
		established: true,
		sendSeq:     1001,
		recvSeq:     2001,
		ackedSeq:    1000,
		errCh:       make(chan error, 1),
		msgCh:       make(chan []byte, 1),
		readyCh:     make(chan struct{}),
		ackCh:       make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
}

func waitTCPDone(t *testing.T, conn *TCPConn) {
	t.Helper()
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("done was not closed")
	}
}
