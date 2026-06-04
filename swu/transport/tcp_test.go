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
		{name: "leading crlf ignored", stream: "\r\n\r\nMESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello", wantMsg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello", wantOK: true},
		{name: "incomplete body", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhel", wantOK: false},
		{name: "missing length", stream: "MESSAGE sip:test SIP/2.0\r\nVia: SIP/2.0/TCP 127.0.0.1:5060\r\n\r\n", wantErr: true},
		{name: "invalid length", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: nope\r\n\r\n", wantErr: true},
		{name: "negative length", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: -1\r\n\r\n", wantErr: true},
		{name: "compact length", stream: "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello", wantMsg: "MESSAGE sip:test SIP/2.0\r\nl: 5\r\n\r\nhello", wantOK: true},
		{name: "header too large", stream: "MESSAGE sip:test SIP/2.0\r\n" + strings.Repeat("X-Test: x\r\n", tcpMaxSIPHeaderBytes/10+1), wantErr: true},
		{name: "message too large", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 1048577\r\n\r\n", wantErr: true},
		{name: "message length overflows total", stream: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 9223372036854775807\r\n\r\n", wantErr: true},
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

func TestTCPConnReserveSendSeqAcceptsFastACK(t *testing.T) {
	conn := &TCPConn{
		sendSeq:      1001,
		ackedSeq:     1000,
		ackCh:        make(chan struct{}, 1),
		associations: NewSecurityAssociations(),
	}

	seq, wantAck, err := conn.reserveSendSeq(48)
	if err != nil {
		t.Fatalf("reserveSendSeq() error = %v", err)
	}
	if seq != 1001 {
		t.Fatalf("seq = %d, want 1001", seq)
	}
	if wantAck != 1049 {
		t.Fatalf("wantAck = %d, want 1049", wantAck)
	}

	conn.mu.Lock()
	conn.noteAck(wantAck)
	got := conn.ackedSeq
	conn.mu.Unlock()
	if got != wantAck {
		t.Fatalf("ackedSeq = %d, want %d", got, wantAck)
	}
}

func TestTCPConnAckContext(t *testing.T) {
	tests := []struct {
		name   string
		cancel func(done chan struct{}, stop context.CancelFunc)
	}{
		{
			name: "transport done",
			cancel: func(done chan struct{}, stop context.CancelFunc) {
				close(done)
			},
		},
		{
			name: "caller stop",
			cancel: func(done chan struct{}, stop context.CancelFunc) {
				stop()
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			done := make(chan struct{})
			conn := &TCPConn{done: done}
			ctx, stop := conn.ackContext(time.Hour)

			tt.cancel(done, stop)

			select {
			case <-ctx.Done():
				if !errors.Is(ctx.Err(), context.Canceled) {
					t.Fatalf("ackContext() error = %v, want context canceled", ctx.Err())
				}
			case <-time.After(time.Second):
				t.Fatal("ackContext() did not stop")
			}
		})
	}
}

func TestNormalizedTCPDataACKTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		input   []time.Duration
		want    []time.Duration
		wantErr bool
	}{
		{name: "default", want: tcpDataACKTimeouts},
		{name: "custom", input: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}, want: []time.Duration{10 * time.Millisecond, 20 * time.Millisecond}},
		{name: "zero", input: []time.Duration{0}, wantErr: true},
		{name: "negative", input: []time.Duration{-time.Millisecond}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizedTCPDataACKTimeouts("testing tcp transport", tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("normalizedTCPDataACKTimeouts() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizedTCPDataACKTimeouts() error = %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("len(timeouts) = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("timeout[%d] = %s, want %s", i, got[i], tt.want[i])
				}
			}
			if len(got) > 0 {
				got[0] = time.Nanosecond
				again, err := normalizedTCPDataACKTimeouts("testing tcp transport", tt.input)
				if err != nil {
					t.Fatalf("normalizedTCPDataACKTimeouts() second error = %v", err)
				}
				if again[0] != tt.want[0] {
					t.Fatalf("timeout copy mutated default: got %s, want %s", again[0], tt.want[0])
				}
			}
		})
	}
}

func TestTCPConnWritePacketUnblocksOnHandleError(t *testing.T) {
	conn := &TCPConn{
		errCh:        make(chan error, 1),
		msgCh:        make(chan []byte, 1),
		readyCh:      make(chan struct{}),
		ackCh:        make(chan struct{}, 1),
		done:         make(chan struct{}),
		associations: NewSecurityAssociations(),
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
		errCh:        make(chan error, 1),
		msgCh:        make(chan []byte, 1),
		readyCh:      make(chan struct{}),
		ackCh:        make(chan struct{}, 1),
		done:         make(chan struct{}),
		associations: NewSecurityAssociations(),
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
		session:         session,
		local:           &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
		remote:          &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
		established:     true,
		sendSeq:         1001,
		recvSeq:         2001,
		ackedSeq:        1000,
		errCh:           make(chan error, 1),
		msgCh:           make(chan []byte, 1),
		readyCh:         make(chan struct{}),
		ackCh:           make(chan struct{}, 1),
		done:            make(chan struct{}),
		associations:    NewSecurityAssociations(),
		dataACKTimeouts: []time.Duration{10 * time.Millisecond},
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

func TestTCPConnWritePacketClosesOnSendError(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	_ = conn.session.Close()

	err := conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	if err == nil {
		t.Fatal("WritePacket() error = nil, want send error")
	}
	if !strings.Contains(err.Error(), "session is closed") {
		t.Fatalf("WritePacket() error = %v, want session closed", err)
	}
	if !conn.closed {
		t.Fatal("closed = false, want true")
	}
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("done was not closed after send error")
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
				sendSeq:      tt.sendSeq,
				ackedSeq:     tt.ackedSeq,
				ackCh:        make(chan struct{}, 1),
				associations: NewSecurityAssociations(),
			}
			conn.mu.Lock()
			conn.noteAck(tt.ack)
			got := conn.ackedSeq
			conn.mu.Unlock()
			if got != tt.wantAcked {
				t.Fatalf("ackedSeq = %d, want %d", got, tt.wantAcked)
			}
		})
	}
}

func TestTCPConnIgnoresAckNumberWithoutACKFlag(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.sendSeq = 5
	conn.ackedSeq = ^uint32(0) - 4

	conn.mu.Lock()
	_, err := conn.processSegment(packet.TCPSegment{Seq: 2001, Ack: 3})
	got := conn.ackedSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	if got != ^uint32(0)-4 {
		t.Fatalf("ackedSeq = %d, want %d", got, ^uint32(0)-4)
	}
}

func TestTCPConnActiveHandshakeRequiresValidSYNACK(t *testing.T) {
	tests := []struct {
		name            string
		ack             uint32
		wantEstablished bool
		wantAcked       uint32
		wantResponse    tcpSegmentResponse
	}{
		{
			name:      "invalid stale ack is ignored",
			ack:       1000,
			wantAcked: 1000,
		},
		{
			name:      "invalid future ack is ignored",
			ack:       1002,
			wantAcked: 1000,
		},
		{
			name:            "valid ack establishes",
			ack:             1001,
			wantEstablished: true,
			wantAcked:       1001,
			wantResponse:    tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.established = false
			conn.passive = false
			conn.sendSeq = 1001
			conn.ackedSeq = 1000
			conn.recvSeq = 0

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:   2000,
				Ack:   tt.ack,
				Flags: packet.TCPFlagSYN | packet.TCPFlagACK,
			})
			established := conn.established
			acked := conn.ackedSeq
			recvSeq := conn.recvSeq
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			if established != tt.wantEstablished {
				t.Fatalf("established = %t, want %t", established, tt.wantEstablished)
			}
			if acked != tt.wantAcked {
				t.Fatalf("ackedSeq = %d, want %d", acked, tt.wantAcked)
			}
			if response != tt.wantResponse {
				t.Fatalf("response = %+v, want %+v", response, tt.wantResponse)
			}
			if !tt.wantEstablished && recvSeq != 0 {
				t.Fatalf("recvSeq = %d, want unchanged 0", recvSeq)
			}
		})
	}
}

func TestTCPConnPassiveHandshakeProcessesACKPayload(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.established = false
	conn.passive = true
	conn.sendSeq = 1001
	conn.ackedSeq = 1000
	conn.recvSeq = 2001
	payload := "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:     2001,
		Ack:     1001,
		Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
		Payload: []byte(payload),
	})
	established := conn.established
	acked := conn.ackedSeq
	recvSeq := conn.recvSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	if !established {
		t.Fatal("established = false, want true")
	}
	if acked != 1001 {
		t.Fatalf("ackedSeq = %d, want 1001", acked)
	}
	wantAck := uint32(2001 + len(payload))
	if recvSeq != wantAck {
		t.Fatalf("recvSeq = %d, want %d", recvSeq, wantAck)
	}
	if response != (tcpSegmentResponse{seq: 1001, ack: wantAck, flags: packet.TCPFlagACK}) {
		t.Fatalf("response = %+v, want ACK %d", response, wantAck)
	}
	select {
	case got := <-conn.msgCh:
		if string(got) != payload {
			t.Fatalf("message = %q, want %q", string(got), payload)
		}
	default:
		t.Fatal("message queue was empty")
	}
}

func TestTCPConnDialReady(t *testing.T) {
	tests := []struct {
		name        string
		established bool
		closed      bool
		wantReady   bool
		wantErr     bool
	}{
		{name: "not signaled"},
		{name: "established", established: true, wantReady: true},
		{name: "closed before established", closed: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.established = tt.established
			conn.closed = tt.closed
			if tt.established || tt.closed {
				conn.signalReady()
			}

			ready, err := conn.dialReady("dialing tcp transport")
			if ready != tt.wantReady {
				t.Fatalf("dialReady() ready = %t, want %t", ready, tt.wantReady)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("dialReady() error = %v, wantErr %t", err, tt.wantErr)
			}
		})
	}
}

func TestTCPConnIgnoresOutOfOrderFIN(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:   2002,
		Ack:   1001,
		Flags: packet.TCPFlagFIN | packet.TCPFlagACK,
	})
	closed := conn.closed
	recvSeq := conn.recvSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	if closed {
		t.Fatal("closed = true, want false")
	}
	if recvSeq != 2001 {
		t.Fatalf("recvSeq = %d, want 2001", recvSeq)
	}
	want := tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK}
	if response != want {
		t.Fatalf("response = %+v, want %+v", response, want)
	}
}

func TestTCPConnConsumesFINSequence(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantMessage bool
	}{
		{
			name:        "fin with complete sip message",
			payload:     "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello",
			wantMessage: true,
		},
		{
			name: "fin without payload",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:     2001,
				Ack:     1001,
				Flags:   packet.TCPFlagPSH | packet.TCPFlagACK | packet.TCPFlagFIN,
				Payload: []byte(tt.payload),
			})
			recvSeq := conn.recvSeq
			conn.mu.Unlock()

			wantAck := uint32(2001 + len(tt.payload) + 1)
			if response != (tcpSegmentResponse{seq: 1001, ack: wantAck, flags: packet.TCPFlagACK}) {
				t.Fatalf("response = %+v, want seq 1001 ack %d ACK", response, wantAck)
			}
			if recvSeq != wantAck {
				t.Fatalf("recvSeq = %d, want %d", recvSeq, wantAck)
			}
			if err == nil || !strings.Contains(err.Error(), "peer closed connection") {
				t.Fatalf("processSegment() error = %v, want peer closed connection", err)
			}
			if tt.wantMessage {
				select {
				case got := <-conn.msgCh:
					if string(got) != tt.payload {
						t.Fatalf("message = %q, want %q", string(got), tt.payload)
					}
				default:
					t.Fatal("message queue was empty")
				}
				return
			}
			select {
			case got := <-conn.msgCh:
				t.Fatalf("message = %q, want none", string(got))
			default:
			}
		})
	}
}

func TestTCPConnReadPacketDrainsMessageBeforeTerminalError(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	payload := "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"

	conn.mu.Lock()
	_, err := conn.processSegment(packet.TCPSegment{
		Seq:     2001,
		Ack:     1001,
		Flags:   packet.TCPFlagPSH | packet.TCPFlagACK | packet.TCPFlagFIN,
		Payload: []byte(payload),
	})
	conn.mu.Unlock()
	if err == nil {
		t.Fatal("processSegment() error = nil, want peer close")
	}
	conn.closeWithError(err)

	got, _, err := conn.ReadPacket(context.Background())
	if err != nil {
		t.Fatalf("ReadPacket() first error = %v, want queued message", err)
	}
	if string(got) != payload {
		t.Fatalf("ReadPacket() first message = %q, want %q", string(got), payload)
	}

	_, _, err = conn.ReadPacket(context.Background())
	if err == nil || !strings.Contains(err.Error(), "peer closed connection") {
		t.Fatalf("ReadPacket() second error = %v, want peer closed connection", err)
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
		session:      session,
		local:        &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 40000},
		remote:       &net.TCPAddr{IP: net.ParseIP("2001:db8::2"), Port: 5060},
		established:  true,
		sendSeq:      1001,
		recvSeq:      2001,
		ackedSeq:     1000,
		errCh:        make(chan error, 1),
		msgCh:        make(chan []byte, 1),
		readyCh:      make(chan struct{}),
		ackCh:        make(chan struct{}, 1),
		done:         make(chan struct{}),
		associations: NewSecurityAssociations(),
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
