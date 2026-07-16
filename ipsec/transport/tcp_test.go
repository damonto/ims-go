package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"

	"github.com/damonto/ims-go/ipsec/packet"
	"github.com/damonto/ims-go/swu/tunnel"
)

func TestTCPConnReserveSendSegmentAcceptsFastACK(t *testing.T) {
	conn := &TCPConn{
		sendSeq:      1001,
		ackedSeq:     1000,
		ackCh:        make(chan struct{}, 1),
		associations: NewSecurityAssociations(),
	}

	pending, err := conn.reserveSendSegment(packet.TCPFlagACK, make([]byte, 48))
	if err != nil {
		t.Fatalf("reserveSendSegment() error = %v", err)
	}
	if pending.seq != 1001 {
		t.Fatalf("seq = %d, want 1001", pending.seq)
	}
	wantAck := uint32(1049)
	if pending.nextSeq != wantAck {
		t.Fatalf("nextSeq = %d, want %d", pending.nextSeq, wantAck)
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

func TestTCPConnAdvertisesTunnelSafeMSS(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		want  uint16
	}{
		{name: "syn", flags: packet.TCPFlagSYN, want: uint16(tcpDefaultSegmentSize)},
		{name: "syn ack", flags: packet.TCPFlagSYN | packet.TCPFlagACK, want: uint16(tcpDefaultSegmentSize)},
		{name: "ack", flags: packet.TCPFlagACK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, packetConn := newEstablishedTCPConnWithCapture(t)
			if err := conn.sendSegmentWithSeq(context.Background(), 1000, 2000, tt.flags, nil); err != nil {
				t.Fatalf("sendSegmentWithSeq() error = %v", err)
			}
			writes := packetConn.snapshotWrites()
			if len(writes) != 1 {
				t.Fatalf("writes = %d, want 1", len(writes))
			}
			if got := decodeTCPWrite(t, writes[0]).MSS; got != tt.want {
				t.Fatalf("MSS = %d, want %d", got, tt.want)
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
		{name: "custom", input: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second}, want: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second}},
		{name: "zero", input: []time.Duration{0}, wantErr: true},
		{name: "negative", input: []time.Duration{-time.Millisecond}, wantErr: true},
		{name: "sub second", input: []time.Duration{500 * time.Millisecond, time.Second}, wantErr: true},
		{name: "too aggressive backoff", input: []time.Duration{time.Second, time.Second, 4 * time.Second}, wantErr: true},
		{name: "short budget", input: []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizedTCPDataACKTimeouts(tt.input)
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
				again, err := normalizedTCPDataACKTimeouts(tt.input)
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

func TestDefaultTCPRetransmissionBudgets(t *testing.T) {
	tests := []struct {
		name         string
		values       []time.Duration
		wantMin      time.Duration
		wantFirstMin time.Duration
	}{
		{name: "syn", values: tcpSYNTimeouts, wantMin: tcpSYNMinTimeout, wantFirstMin: time.Second},
		{name: "data", values: tcpDataACKTimeouts, wantMin: tcpDataMinTimeout, wantFirstMin: time.Second},
		{name: "data after syn timeout", values: tcpDataACKTimeoutsAfterSYNTimeout, wantMin: tcpDataMinTimeout, wantFirstMin: 3 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if len(tt.values) == 0 {
				t.Fatal("timeout budget is empty")
			}
			if tt.values[0] < tt.wantFirstMin {
				t.Fatalf("first timeout = %s, want at least %s", tt.values[0], tt.wantFirstMin)
			}
			var got time.Duration
			for _, value := range tt.values {
				got += value
			}
			if got < tt.wantMin {
				t.Fatalf("timeout budget = %s, want at least %s", got, tt.wantMin)
			}
		})
	}
}

func TestTCPConnApplySYNTimeoutDataRTO(t *testing.T) {
	tests := []struct {
		name                  string
		customDataACKTimeouts bool
		synTimedOut           bool
		initial               []time.Duration
		want                  []time.Duration
	}{
		{
			name:        "default after syn timeout",
			synTimedOut: true,
			initial:     tcpDataACKTimeouts,
			want:        tcpDataACKTimeoutsAfterSYNTimeout,
		},
		{
			name:    "default without syn timeout",
			initial: tcpDataACKTimeouts,
			want:    tcpDataACKTimeouts,
		},
		{
			name:                  "custom after syn timeout",
			customDataACKTimeouts: true,
			synTimedOut:           true,
			initial:               []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second},
			want:                  []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second, 64 * time.Second},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &TCPConn{dataACKTimeouts: append([]time.Duration(nil), tt.initial...)}
			conn.applySYNTimeoutDataRTO(tt.customDataACKTimeouts, tt.synTimedOut)
			got := conn.tcpDataACKTimeouts()
			if len(got) != len(tt.want) {
				t.Fatalf("len(timeouts) = %d, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("timeout[%d] = %s, want %s", i, got[i], tt.want[i])
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
	conn := newEstablishedTCPConnForTest(t)
	conn.dataACKTimeouts = []time.Duration{10 * time.Millisecond}
	err := conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
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

func TestTCPConnWritePacketRetransmitsPendingSegment(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	conn.dataACKTimeouts = []time.Duration{10 * time.Millisecond, 10 * time.Millisecond}

	err := conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	if err == nil {
		t.Fatal("WritePacket() error = nil, want ack timeout")
	}
	writes := packetConn.snapshotWrites()
	if len(writes) != 2 {
		t.Fatalf("writes = %d, want 2 retransmissions", len(writes))
	}
	first := decodeTCPWrite(t, writes[0])
	second := decodeTCPWrite(t, writes[1])
	if first.Seq != second.Seq {
		t.Fatalf("retransmit seq = %d, want original seq %d", second.Seq, first.Seq)
	}
	if string(first.Payload) != string(second.Payload) {
		t.Fatalf("retransmit payload = %q, want %q", string(second.Payload), string(first.Payload))
	}
}

func TestTCPConnWritePacketClosesOnContextCancelAfterSend(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.dataACKTimeouts = []time.Duration{time.Hour}

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		result <- conn.WritePacket(ctx, []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	}()

	select {
	case err := <-result:
		t.Fatalf("WritePacket() returned before cancel with %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	cancel()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("WritePacket() error = nil, want context cancellation")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("WritePacket() error = %v, want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket() did not return after context cancel")
	}
	if !conn.closed {
		t.Fatal("closed = false, want true")
	}
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("done was not closed after context cancel")
	}
}

func TestTCPConnCloseUnblocksPendingWrite(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	conn.dataACKTimeouts = []time.Duration{time.Hour}

	result := make(chan error, 1)
	go func() {
		result <- conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	}()
	waitTCPWriteCount(t, packetConn, 1)

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- conn.Close()
	}()

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not return while WritePacket() was waiting for ACK")
	}

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "transport is closed") {
			t.Fatalf("WritePacket() error = %v, want transport closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket() did not unblock after Close()")
	}

	writes := packetConn.snapshotWrites()
	if len(writes) < 2 {
		t.Fatalf("writes = %d, want data and FIN writes", len(writes))
	}
	finSeen := false
	for _, write := range writes {
		segment := decodeTCPWrite(t, write)
		if segment.Flags&(packet.TCPFlagFIN|packet.TCPFlagACK) == packet.TCPFlagFIN|packet.TCPFlagACK {
			finSeen = true
		}
	}
	if !finSeen {
		t.Fatal("FIN write was not sent by Close()")
	}
}

func TestTCPConnCloseSendsFINAfterReservedData(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	conn.dataACKTimeouts = []time.Duration{time.Hour}
	firstWriteStarted, releaseFirstWrite := packetConn.blockFirstWrite()
	defer releaseFirstWrite()

	writeResult := make(chan error, 1)
	go func() {
		writeResult <- conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	}()

	select {
	case <-firstWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("first TCP write did not start")
	}

	closeResult := make(chan error, 1)
	go func() {
		closeResult <- conn.Close()
	}()

	select {
	case err := <-closeResult:
		t.Fatalf("Close() returned before reserved data was sent: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if writes := packetConn.snapshotWrites(); len(writes) != 0 {
		t.Fatalf("writes = %d while first data write is blocked, want 0", len(writes))
	}

	releaseFirstWrite()

	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() did not return after reserved data was sent")
	}

	select {
	case err := <-writeResult:
		if err == nil || !strings.Contains(err.Error(), "transport is closed") {
			t.Fatalf("WritePacket() error = %v, want transport closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket() did not unblock after Close()")
	}

	writes := packetConn.snapshotWrites()
	if len(writes) < 2 {
		t.Fatalf("writes = %d, want data then FIN", len(writes))
	}
	data := decodeTCPWrite(t, writes[0])
	if data.Flags&packet.TCPFlagFIN != 0 {
		t.Fatalf("first write flags = %#x, want data before FIN", data.Flags)
	}
	if string(data.Payload) == "" {
		t.Fatal("first write payload is empty, want data segment")
	}
	fin := decodeTCPWrite(t, writes[1])
	if fin.Flags&(packet.TCPFlagFIN|packet.TCPFlagACK) != packet.TCPFlagFIN|packet.TCPFlagACK {
		t.Fatalf("second write flags = %#x, want FIN|ACK", fin.Flags)
	}
	if !tcpSeqAfter(fin.Seq, data.Seq) {
		t.Fatalf("FIN seq = %d, want after data seq %d", fin.Seq, data.Seq)
	}
}

func TestTCPConnCloseWithFINTimeoutCoversSendLock(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	conn.dataACKTimeouts = []time.Duration{time.Hour}
	firstWriteStarted, releaseFirstWrite := packetConn.blockFirstWrite()
	defer releaseFirstWrite()

	writeResult := make(chan error, 1)
	go func() {
		writeResult <- conn.WritePacket(context.Background(), []byte("INVITE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n"))
	}()

	select {
	case <-firstWriteStarted:
	case <-time.After(time.Second):
		t.Fatal("first TCP write did not start")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := conn.closeWithFIN(ctx)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("closeWithFIN() error = %v, want context deadline exceeded", err)
	}
	if writes := packetConn.snapshotWrites(); len(writes) != 0 {
		t.Fatalf("writes = %d while first data write is blocked, want 0", len(writes))
	}

	releaseFirstWrite()
	select {
	case err := <-writeResult:
		if err == nil || !strings.Contains(err.Error(), "transport is closed") {
			t.Fatalf("WritePacket() error = %v, want transport closed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("WritePacket() did not unblock after Close()")
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

func TestTCPSegmentAcceptable(t *testing.T) {
	tests := []struct {
		name   string
		seq    uint32
		length uint32
		recv   uint32
		window uint32
		want   bool
	}{
		{name: "zero window exact ack", seq: 100, recv: 100, want: true},
		{name: "zero window data rejected", seq: 100, length: 1, recv: 100},
		{name: "left edge ack", seq: 100, recv: 100, window: 10, want: true},
		{name: "right edge ack follows gvisor linux behavior", seq: 110, recv: 100, window: 10, want: true},
		{name: "ack beyond right edge rejected", seq: 111, recv: 100, window: 10},
		{name: "old overlap accepted", seq: 95, length: 10, recv: 100, window: 10, want: true},
		{name: "right edge payload follows gvisor linux behavior", seq: 110, length: 1, recv: 100, window: 10, want: true},
		{name: "payload beyond right edge rejected", seq: 111, length: 1, recv: 100, window: 10},
		{name: "wrapped right edge ack accepted", seq: 4, recv: ^uint32(0) - 5, window: 10, want: true},
		{name: "wrapped ack beyond right edge rejected", seq: 5, recv: ^uint32(0) - 5, window: 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tcpSegmentAcceptable(tt.seq, tt.length, tt.recv, tt.window); got != tt.want {
				t.Fatalf("tcpSegmentAcceptable(%d, %d, %d, %d) = %t, want %t", tt.seq, tt.length, tt.recv, tt.window, got, tt.want)
			}
		})
	}
}

func TestTCPConnPendingSegmentClearedOnACK(t *testing.T) {
	conn := &TCPConn{
		sendSeq:      1001,
		ackedSeq:     1000,
		ackCh:        make(chan struct{}, 1),
		associations: NewSecurityAssociations(),
	}

	pending, err := conn.reserveSendSegment(packet.TCPFlagACK|packet.TCPFlagPSH, []byte("abc"))
	if err != nil {
		t.Fatalf("reserveSendSegment() error = %v", err)
	}
	if pending.seq != 1001 || pending.nextSeq != 1004 {
		t.Fatalf("pending = %+v, want seq 1001 nextSeq 1004", pending)
	}
	conn.mu.Lock()
	conn.noteAck(1004)
	got := conn.pending
	conn.mu.Unlock()
	if got != nil {
		t.Fatalf("pending = %+v, want nil after ACK", got)
	}
}

func TestTCPConnRetransmitsPendingSegmentWithOriginalACK(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	conn.recvSeq = 3001
	pending := tcpPendingSegment{
		seq:     1001,
		nextSeq: 1004,
		ack:     2001,
		flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
		payload: []byte("abc"),
	}

	if err := conn.sendPendingSegment(context.Background(), pending); err != nil {
		t.Fatalf("sendPendingSegment() error = %v", err)
	}

	writes := packetConn.snapshotWrites()
	if len(writes) != 1 {
		t.Fatalf("writes = %d, want 1", len(writes))
	}
	segment := decodeTCPWrite(t, writes[0])
	if segment.Ack != pending.ack {
		t.Fatalf("ack = %d, want original ack %d", segment.Ack, pending.ack)
	}
	if segment.Seq != pending.seq || string(segment.Payload) != string(pending.payload) {
		t.Fatalf("segment seq/payload = %d/%q, want %d/%q", segment.Seq, string(segment.Payload), pending.seq, string(pending.payload))
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

func TestTCPConnResetValidation(t *testing.T) {
	tests := []struct {
		name         string
		segment      packet.TCPSegment
		synSent      bool
		wantErr      string
		wantResponse tcpSegmentResponse
	}{
		{
			name: "valid ack reset closes",
			segment: packet.TCPSegment{
				Seq:   2001,
				Ack:   1001,
				Flags: packet.TCPFlagRST | packet.TCPFlagACK,
			},
			wantErr: "peer reset connection",
		},
		{
			name: "valid sequence reset closes",
			segment: packet.TCPSegment{
				Seq:   2001,
				Flags: packet.TCPFlagRST,
			},
			wantErr: "peer reset connection",
		},
		{
			name: "in-window nonexact reset gets challenge ack",
			segment: packet.TCPSegment{
				Seq:   2002,
				Ack:   1001,
				Flags: packet.TCPFlagRST | packet.TCPFlagACK,
			},
			wantResponse: tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK},
		},
		{
			name: "outside-window reset is dropped",
			segment: packet.TCPSegment{
				Seq:   2000,
				Flags: packet.TCPFlagRST,
			},
		},
		{
			name: "syn sent reset uses ack",
			segment: packet.TCPSegment{
				Seq:   9999,
				Ack:   1001,
				Flags: packet.TCPFlagRST | packet.TCPFlagACK,
			},
			synSent: true,
			wantErr: "peer reset connection",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			if tt.synSent {
				conn.established = false
				conn.passive = false
				conn.recvSeq = 0
			}

			conn.mu.Lock()
			response, err := conn.processSegment(tt.segment)
			conn.mu.Unlock()

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("processSegment() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			if response != tt.wantResponse {
				t.Fatalf("response = %+v, want %+v", response, tt.wantResponse)
			}
		})
	}
}

func TestTCPConnPassiveResetReturnsToListen(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.established = false
	conn.passive = true
	conn.initialSeq = 1000
	conn.sendSeq = 1001
	conn.ackedSeq = 1000
	conn.recvSeq = 2001
	conn.peerMSS = 512
	conn.stream = []byte("partial")
	conn.pending = &tcpPendingSegment{seq: 1000, nextSeq: 1001, flags: packet.TCPFlagSYN | packet.TCPFlagACK}

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:   2001,
		Flags: packet.TCPFlagRST,
	})
	closed := conn.closed
	established := conn.established
	recvSeq := conn.recvSeq
	peerMSS := conn.peerMSS
	streamLen := len(conn.stream)
	pending := conn.pending
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment(RST) error = %v", err)
	}
	if response != (tcpSegmentResponse{}) {
		t.Fatalf("RST response = %+v, want none", response)
	}
	if closed {
		t.Fatal("closed = true, want passive listener to remain open")
	}
	if established {
		t.Fatal("established = true, want listen state")
	}
	if recvSeq != 0 {
		t.Fatalf("recvSeq = %d, want 0 after returning to listen", recvSeq)
	}
	if peerMSS != 0 {
		t.Fatalf("peerMSS = %d, want 0 after returning to listen", peerMSS)
	}
	if streamLen != 0 {
		t.Fatalf("stream length = %d, want 0 after returning to listen", streamLen)
	}
	if pending != nil {
		t.Fatalf("pending = %+v, want nil after returning to listen", pending)
	}

	oldInitialSeq := conn.initialSeq
	oldRandomISS := tcpRandomISS
	tcpRandomISS = func() (uint32, error) {
		return 7000, nil
	}
	defer func() {
		tcpRandomISS = oldRandomISS
	}()

	conn.mu.Lock()
	response, err = conn.processSegment(packet.TCPSegment{
		Seq:   3000,
		Flags: packet.TCPFlagSYN,
		MSS:   768,
	})
	recvSeq = conn.recvSeq
	peerMSS = conn.peerMSS
	initialSeq := conn.initialSeq
	sendSeq := conn.sendSeq
	ackedSeq := conn.ackedSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment(SYN) error = %v", err)
	}
	want := tcpSegmentResponse{seq: 7000, ack: 3001, flags: packet.TCPFlagSYN | packet.TCPFlagACK, retransmit: true}
	if response != want {
		t.Fatalf("SYN response = %+v, want %+v", response, want)
	}
	if response.seq == oldInitialSeq {
		t.Fatalf("SYN response seq reused old ISS %d", oldInitialSeq)
	}
	if initialSeq != response.seq || sendSeq != response.seq+1 || ackedSeq != response.seq {
		t.Fatalf("send state = initial %d send %d acked %d, want %d/%d/%d", initialSeq, sendSeq, ackedSeq, response.seq, response.seq+1, response.seq)
	}
	if recvSeq != 3001 {
		t.Fatalf("recvSeq = %d, want 3001", recvSeq)
	}
	if peerMSS != 768 {
		t.Fatalf("peerMSS = %d, want 768", peerMSS)
	}
}

func TestTCPConnEstablishedChallengesUnexpectedSYN(t *testing.T) {
	tests := []struct {
		name    string
		passive bool
	}{
		{name: "active connection"},
		{name: "passive connection", passive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.passive = tt.passive
			conn.stream = []byte("partial")
			conn.pendingRcvdSegments = []tcpReceivedSegment{{seq: 3000, payload: []byte("pending")}}
			conn.pendingRcvdBytes = len("pending")

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:   3000,
				Flags: packet.TCPFlagSYN,
				MSS:   768,
			})
			established := conn.established
			recvSeq := conn.recvSeq
			streamLen := len(conn.stream)
			pendingLen := len(conn.pendingRcvdSegments)
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			want := tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK}
			if response != want {
				t.Fatalf("response = %+v, want %+v", response, want)
			}
			if !established || recvSeq != 2001 || streamLen != len("partial") || pendingLen != 1 {
				t.Fatalf("connection state = established %t recvSeq %d stream %d pending %d, want true/2001/%d/1", established, recvSeq, streamLen, pendingLen, len("partial"))
			}
		})
	}
}

func TestTCPConnPassiveSYNACKRetransmitsUntilACK(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "ack stops retransmission"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			oldRandomISS := tcpRandomISS
			tcpRandomISS = func() (uint32, error) {
				return 7000, nil
			}
			defer func() {
				tcpRandomISS = oldRandomISS
			}()

			oldSYNTimeouts := tcpSYNTimeouts
			tcpSYNTimeouts = []time.Duration{10 * time.Millisecond, 200 * time.Millisecond}
			defer func() {
				tcpSYNTimeouts = oldSYNTimeouts
			}()

			conn, packetConn := newEstablishedTCPConnWithCapture(t)
			conn.established = false
			conn.passive = true
			conn.initialSeq = 0
			conn.sendSeq = 0
			conn.ackedSeq = 0
			conn.recvSeq = 0

			conn.handleSegment(packet.TCPSegment{
				Seq:   3000,
				Flags: packet.TCPFlagSYN,
			})

			waitTCPWriteCount(t, packetConn, 2)
			writes := packetConn.snapshotWrites()
			first := decodeTCPWrite(t, writes[0])
			second := decodeTCPWrite(t, writes[1])
			for i, segment := range []packet.TCPSegment{first, second} {
				if segment.Flags&(packet.TCPFlagSYN|packet.TCPFlagACK) != packet.TCPFlagSYN|packet.TCPFlagACK {
					t.Fatalf("write[%d] flags = %#x, want SYN|ACK", i, segment.Flags)
				}
				if segment.Seq != 7000 || segment.Ack != 3001 {
					t.Fatalf("write[%d] seq/ack = %d/%d, want 7000/3001", i, segment.Seq, segment.Ack)
				}
			}

			conn.handleSegment(packet.TCPSegment{
				Seq:   3001,
				Ack:   7001,
				Flags: packet.TCPFlagACK,
			})
			waitTCPState(t, conn, func(conn *TCPConn) bool {
				return conn.established && conn.pending == nil
			})
		})
	}
}

func TestTCPConnPassiveDuplicateSYNPreservesHalfOpenState(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.established = false
	conn.passive = true
	conn.initialSeq = 7000
	conn.sendSeq = 7001
	conn.ackedSeq = 7000
	conn.recvSeq = 3001
	conn.peerMSS = 768
	conn.pending = &tcpPendingSegment{seq: 7000, nextSeq: 7001, ack: 3001, flags: packet.TCPFlagSYN | packet.TCPFlagACK}

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:   3000,
		Flags: packet.TCPFlagSYN,
		MSS:   1200,
	})
	recvSeq := conn.recvSeq
	peerMSS := conn.peerMSS
	pending := conn.pending
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	want := tcpSegmentResponse{seq: 7000, ack: 3001, flags: packet.TCPFlagSYN | packet.TCPFlagACK}
	if response != want {
		t.Fatalf("response = %+v, want %+v", response, want)
	}
	if recvSeq != 3001 {
		t.Fatalf("recvSeq = %d, want 3001", recvSeq)
	}
	if peerMSS != 768 {
		t.Fatalf("peerMSS = %d, want preserved 768", peerMSS)
	}
	if pending == nil || pending.seq != 7000 || pending.nextSeq != 7001 || pending.ack != 3001 {
		t.Fatalf("pending = %+v, want original SYN-ACK pending", pending)
	}
}

func TestTCPConnPassiveResetInWindowNonExactGetsChallengeACK(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.established = false
	conn.passive = true
	conn.sendSeq = 1001
	conn.ackedSeq = 1000
	conn.recvSeq = 2001

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:   2002,
		Flags: packet.TCPFlagRST,
	})
	closed := conn.closed
	established := conn.established
	recvSeq := conn.recvSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	want := tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK}
	if response != want {
		t.Fatalf("response = %+v, want %+v", response, want)
	}
	if closed {
		t.Fatal("closed = true, want listener open")
	}
	if established {
		t.Fatal("established = true, want half-open state preserved")
	}
	if recvSeq != 2001 {
		t.Fatalf("recvSeq = %d, want 2001", recvSeq)
	}
}

func TestTCPConnPassiveHandshakeRejectsUnacceptableACK(t *testing.T) {
	tests := []struct {
		name string
		ack  uint32
	}{
		{name: "stale ack", ack: 1000},
		{name: "future ack", ack: 1002},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.established = false
			conn.passive = true
			conn.sendSeq = 1001
			conn.ackedSeq = 1000
			conn.recvSeq = 2001

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:   2001,
				Ack:   tt.ack,
				Flags: packet.TCPFlagACK,
			})
			established := conn.established
			recvSeq := conn.recvSeq
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			want := tcpSegmentResponse{seq: tt.ack, flags: packet.TCPFlagRST}
			if response != want {
				t.Fatalf("response = %+v, want %+v", response, want)
			}
			if established {
				t.Fatal("established = true, want false")
			}
			if recvSeq != 2001 {
				t.Fatalf("recvSeq = %d, want 2001", recvSeq)
			}
		})
	}
}

func TestTCPConnOutOfOrderPayloadWaitsForGap(t *testing.T) {
	tests := []struct {
		name string
		msg  string
		cut  int
	}{
		{name: "split sip message", msg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello", cut: 24},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.sendSeq = 1100
			conn.ackedSeq = 1000
			conn.pending = &tcpPendingSegment{seq: 1001, nextSeq: 1050, flags: packet.TCPFlagACK | packet.TCPFlagPSH, payload: []byte("pending")}
			first := []byte(tt.msg[:tt.cut])
			second := []byte(tt.msg[tt.cut:])

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:     2001 + uint32(len(first)),
				Ack:     1050,
				Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
				Payload: second,
			})
			acked := conn.ackedSeq
			pending := conn.pending
			recvSeq := conn.recvSeq
			pendingSegments := len(conn.pendingRcvdSegments)
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment(out-of-order) error = %v", err)
			}
			want := tcpSegmentResponse{seq: 1100, ack: 2001, flags: packet.TCPFlagACK}
			if response != want {
				t.Fatalf("out-of-order response = %+v, want %+v", response, want)
			}
			if acked != 1050 {
				t.Fatalf("ackedSeq = %d, want 1050", acked)
			}
			if recvSeq != 2001 {
				t.Fatalf("recvSeq = %d, want 2001", recvSeq)
			}
			if pending != nil {
				t.Fatalf("pending = %+v, want nil after ACK", pending)
			}
			if pendingSegments != 1 {
				t.Fatalf("pendingSegments = %d, want 1", pendingSegments)
			}
			select {
			case got := <-conn.msgCh:
				t.Fatalf("message = %q, want none before gap is filled", string(got))
			default:
			}

			conn.mu.Lock()
			response, err = conn.processSegment(packet.TCPSegment{
				Seq:     2001,
				Ack:     1050,
				Flags:   packet.TCPFlagACK,
				Payload: first,
			})
			recvSeq = conn.recvSeq
			pendingSegments = len(conn.pendingRcvdSegments)
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment(gap) error = %v", err)
			}
			want = tcpSegmentResponse{seq: 1100, ack: 2001 + uint32(len(tt.msg)), flags: packet.TCPFlagACK}
			if response != want {
				t.Fatalf("gap response = %+v, want %+v", response, want)
			}
			if recvSeq != 2001+uint32(len(tt.msg)) {
				t.Fatalf("recvSeq = %d, want %d", recvSeq, 2001+len(tt.msg))
			}
			if pendingSegments != 0 {
				t.Fatalf("pendingSegments = %d, want 0", pendingSegments)
			}
			select {
			case got := <-conn.msgCh:
				if string(got) != tt.msg {
					t.Fatalf("message = %q, want %q", string(got), tt.msg)
				}
			default:
				t.Fatal("message was not delivered")
			}
		})
	}
}

func TestTCPConnPendingSegmentKeepsMostCompleteDuplicate(t *testing.T) {
	tests := []struct {
		name        string
		first       tcpReceivedSegment
		second      tcpReceivedSegment
		wantPayload string
		wantFlags   byte
		wantBytes   int
	}{
		{
			name: "shorter duplicate does not replace buffered data",
			first: tcpReceivedSegment{
				seq:     2020,
				flags:   packet.TCPFlagFIN,
				payload: []byte("Content-Length: 5\r\n\r\nhello"),
			},
			second: tcpReceivedSegment{
				seq:     2020,
				payload: []byte("Content-Length: 5"),
			},
			wantPayload: "Content-Length: 5\r\n\r\nhello",
			wantFlags:   packet.TCPFlagFIN,
			wantBytes:   len("Content-Length: 5\r\n\r\nhello") + 1,
		},
		{
			name: "longer duplicate replaces partial data",
			first: tcpReceivedSegment{
				seq:     2020,
				payload: []byte("Content-Length: 5"),
			},
			second: tcpReceivedSegment{
				seq:     2020,
				flags:   packet.TCPFlagFIN,
				payload: []byte("Content-Length: 5\r\n\r\nhello"),
			},
			wantPayload: "Content-Length: 5\r\n\r\nhello",
			wantFlags:   packet.TCPFlagFIN,
			wantBytes:   len("Content-Length: 5\r\n\r\nhello") + 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &TCPConn{}

			conn.queuePendingSegment(tt.first.seq, tt.first.flags, tt.first.payload)
			conn.queuePendingSegment(tt.second.seq, tt.second.flags, tt.second.payload)

			if len(conn.pendingRcvdSegments) != 1 {
				t.Fatalf("pending segments = %d, want 1", len(conn.pendingRcvdSegments))
			}
			got := conn.pendingRcvdSegments[0]
			if got.seq != tt.first.seq {
				t.Fatalf("pending seq = %d, want %d", got.seq, tt.first.seq)
			}
			if string(got.payload) != tt.wantPayload {
				t.Fatalf("pending payload = %q, want %q", got.payload, tt.wantPayload)
			}
			if got.flags != tt.wantFlags {
				t.Fatalf("pending flags = %#x, want %#x", got.flags, tt.wantFlags)
			}
			if conn.pendingRcvdBytes != tt.wantBytes {
				t.Fatalf("pending bytes = %d, want %d", conn.pendingRcvdBytes, tt.wantBytes)
			}
		})
	}
}

func TestTCPConnOverlappingPayloadConsumesOnlyNewBytes(t *testing.T) {
	msg := "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"
	tests := []struct {
		name      string
		seq       uint32
		payload   []byte
		wantAck   uint32
		wantMsg   string
		wantRecv  uint32
		wantAcked uint32
	}{
		{
			name:      "old prefix trimmed",
			seq:       1996,
			payload:   append([]byte("stale"), []byte(msg)...),
			wantAck:   2001 + uint32(len(msg)),
			wantMsg:   msg,
			wantRecv:  2001 + uint32(len(msg)),
			wantAcked: 1001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:     tt.seq,
				Ack:     tt.wantAcked,
				Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
				Payload: tt.payload,
			})
			recvSeq := conn.recvSeq
			acked := conn.ackedSeq
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			wantResponse := tcpSegmentResponse{seq: 1001, ack: tt.wantAck, flags: packet.TCPFlagACK}
			if response != wantResponse {
				t.Fatalf("response = %+v, want %+v", response, wantResponse)
			}
			if recvSeq != tt.wantRecv {
				t.Fatalf("recvSeq = %d, want %d", recvSeq, tt.wantRecv)
			}
			if acked != tt.wantAcked {
				t.Fatalf("ackedSeq = %d, want %d", acked, tt.wantAcked)
			}
			select {
			case got := <-conn.msgCh:
				if string(got) != tt.wantMsg {
					t.Fatalf("message = %q, want %q", string(got), tt.wantMsg)
				}
			default:
				t.Fatal("message was not delivered")
			}
		})
	}
}

func TestTCPConnFullMessageQueueDoesNotAdvanceReceive(t *testing.T) {
	tests := []struct {
		name string
		msg  string
	}{
		{name: "complete sip message", msg: "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.msgCh <- []byte("queued")

			conn.mu.Lock()
			response, err := conn.processSegment(packet.TCPSegment{
				Seq:     2001,
				Ack:     1001,
				Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
				Payload: []byte(tt.msg),
			})
			recvSeq := conn.recvSeq
			streamLen := len(conn.stream)
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			want := tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK}
			if response != want {
				t.Fatalf("response = %+v, want %+v", response, want)
			}
			if recvSeq != 2001 {
				t.Fatalf("recvSeq = %d, want 2001", recvSeq)
			}
			if streamLen != 0 {
				t.Fatalf("stream len = %d, want 0", streamLen)
			}

			queued := <-conn.msgCh
			if string(queued) != "queued" {
				t.Fatalf("queued message = %q, want original queued marker", string(queued))
			}

			conn.mu.Lock()
			response, err = conn.processSegment(packet.TCPSegment{
				Seq:     2001,
				Ack:     1001,
				Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
				Payload: []byte(tt.msg),
			})
			recvSeq = conn.recvSeq
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment(retry) error = %v", err)
			}
			want = tcpSegmentResponse{seq: 1001, ack: 2001 + uint32(len(tt.msg)), flags: packet.TCPFlagACK}
			if response != want {
				t.Fatalf("retry response = %+v, want %+v", response, want)
			}
			if recvSeq != 2001+uint32(len(tt.msg)) {
				t.Fatalf("recvSeq = %d, want %d", recvSeq, 2001+len(tt.msg))
			}
			select {
			case got := <-conn.msgCh:
				if string(got) != tt.msg {
					t.Fatalf("message = %q, want %q", string(got), tt.msg)
				}
			default:
				t.Fatal("message was not delivered")
			}
		})
	}
}

func TestTCPConnEstablishedStateDropsUnacceptableSegments(t *testing.T) {
	payload := "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"
	tests := []struct {
		name         string
		segment      packet.TCPSegment
		wantResponse tcpSegmentResponse
		wantRecvSeq  uint32
	}{
		{
			name: "syn gets challenge ack",
			segment: packet.TCPSegment{
				Seq:   2001,
				Ack:   1001,
				Flags: packet.TCPFlagSYN | packet.TCPFlagACK,
			},
			wantResponse: tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK},
			wantRecvSeq:  2001,
		},
		{
			name: "payload without ack bit is dropped",
			segment: packet.TCPSegment{
				Seq:     2001,
				Payload: []byte(payload),
			},
			wantRecvSeq: 2001,
		},
		{
			name: "future ack is acknowledged and dropped",
			segment: packet.TCPSegment{
				Seq:     2001,
				Ack:     2000,
				Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
				Payload: []byte(payload),
			},
			wantResponse: tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK},
			wantRecvSeq:  2001,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)

			conn.mu.Lock()
			response, err := conn.processSegment(tt.segment)
			recvSeq := conn.recvSeq
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			if response != tt.wantResponse {
				t.Fatalf("response = %+v, want %+v", response, tt.wantResponse)
			}
			if recvSeq != tt.wantRecvSeq {
				t.Fatalf("recvSeq = %d, want %d", recvSeq, tt.wantRecvSeq)
			}
			select {
			case got := <-conn.msgCh:
				t.Fatalf("message = %q, want none", string(got))
			default:
			}
		})
	}
}

func TestTCPConnHandshakeTracksPeerMSS(t *testing.T) {
	tests := []struct {
		name    string
		passive bool
		segment packet.TCPSegment
	}{
		{
			name: "active syn ack",
			segment: packet.TCPSegment{
				Seq:   2000,
				Ack:   1001,
				Flags: packet.TCPFlagSYN | packet.TCPFlagACK,
				MSS:   512,
			},
		},
		{
			name:    "passive syn",
			passive: true,
			segment: packet.TCPSegment{
				Seq:   2000,
				Flags: packet.TCPFlagSYN,
				MSS:   768,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.established = false
			conn.passive = tt.passive
			conn.sendSeq = 1001
			conn.ackedSeq = 1000
			conn.recvSeq = 0

			conn.mu.Lock()
			_, err := conn.processSegment(tt.segment)
			peerMSS := conn.peerMSS
			conn.mu.Unlock()

			if err != nil {
				t.Fatalf("processSegment() error = %v", err)
			}
			if peerMSS != tt.segment.MSS {
				t.Fatalf("peerMSS = %d, want %d", peerMSS, tt.segment.MSS)
			}
			if got := conn.maxPayloadSize(); got != int(tt.segment.MSS) {
				t.Fatalf("maxPayloadSize() = %d, want %d", got, tt.segment.MSS)
			}
		})
	}
}

func TestTCPConnMaxPayloadSize(t *testing.T) {
	tests := []struct {
		name    string
		remote  net.IP
		peerMSS uint16
		want    int
	}{
		{name: "ipv4 default", remote: net.IPv4(192, 0, 2, 2), want: tcpDefaultIPv4SendMSS},
		{name: "ipv6 default capped by tunnel", remote: net.ParseIP("2001:db8::2"), want: tcpDefaultSegmentSize},
		{name: "peer advertises smaller mss", remote: net.IPv4(192, 0, 2, 2), peerMSS: 512, want: 512},
		{name: "peer advertises larger mss", remote: net.IPv4(192, 0, 2, 2), peerMSS: 1400, want: tcpDefaultSegmentSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.remote.IP = tt.remote
			conn.peerMSS = tt.peerMSS

			if got := conn.maxPayloadSize(); got != tt.want {
				t.Fatalf("maxPayloadSize() = %d, want %d", got, tt.want)
			}
		})
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

func TestTCPConnPassiveHandshakeRequiresExpectedSeq(t *testing.T) {
	conn := newEstablishedTCPConnForTest(t)
	conn.established = false
	conn.passive = true
	conn.sendSeq = 1001
	conn.ackedSeq = 1000
	conn.recvSeq = 2001
	payload := "MESSAGE sip:test SIP/2.0\r\nContent-Length: 5\r\n\r\nhello"

	conn.mu.Lock()
	response, err := conn.processSegment(packet.TCPSegment{
		Seq:     2002,
		Ack:     1001,
		Flags:   packet.TCPFlagACK | packet.TCPFlagPSH,
		Payload: []byte(payload),
	})
	established := conn.established
	recvSeq := conn.recvSeq
	conn.mu.Unlock()

	if err != nil {
		t.Fatalf("processSegment() error = %v", err)
	}
	if established {
		t.Fatal("established = true, want false")
	}
	if recvSeq != 2001 {
		t.Fatalf("recvSeq = %d, want 2001", recvSeq)
	}
	want := tcpSegmentResponse{seq: 1001, ack: 2001, flags: packet.TCPFlagACK}
	if response != want {
		t.Fatalf("response = %+v, want %+v", response, want)
	}
	select {
	case got := <-conn.msgCh:
		t.Fatalf("message = %q, want none", string(got))
	default:
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

			ready, err := conn.dialReady(transportActionDialTCP)
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

func TestTCPConnConsumesPendingFINAfterGap(t *testing.T) {
	tests := []struct {
		name    string
		passive bool
	}{
		{name: "active connection"},
		{name: "passive connection", passive: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newEstablishedTCPConnForTest(t)
			conn.passive = tt.passive

			conn.mu.Lock()
			_, err := conn.processSegment(packet.TCPSegment{
				Seq:   2002,
				Ack:   1001,
				Flags: packet.TCPFlagFIN | packet.TCPFlagACK,
			})
			if err == nil {
				_, err = conn.processSegment(packet.TCPSegment{
					Seq:     2001,
					Ack:     1001,
					Flags:   packet.TCPFlagACK,
					Payload: []byte("x"),
				})
			}
			recvSeq := conn.recvSeq
			peerClosed := conn.peerClosed
			pending := len(conn.pendingRcvdSegments)
			conn.mu.Unlock()

			if !errors.Is(err, errTCPPeerClosed) {
				t.Fatalf("processSegment() error = %v, want peer close", err)
			}
			if recvSeq != 2003 || !peerClosed || pending != 0 {
				t.Fatalf("receive state = seq %d peerClosed %t pending %d, want 2003/true/0", recvSeq, peerClosed, pending)
			}
		})
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
	t.Cleanup(func() { _ = conn.Close() })
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

func TestTCPConnHandlesTerminalInboundSegment(t *testing.T) {
	tests := []struct {
		name      string
		passive   bool
		peerClose bool
		segment   packet.TCPSegment
		wantErr   string
	}{
		{
			name:      "peer fin",
			peerClose: true,
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
			name:      "passive peer fin",
			passive:   true,
			peerClose: true,
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
			name:    "passive peer reset",
			passive: true,
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
			conn.passive = tt.passive
			conn.handleSegment(tt.segment)
			if tt.peerClose {
				conn.mu.Lock()
				closed := conn.closed
				peerClosed := conn.peerClosed
				conn.mu.Unlock()
				if closed || !peerClosed {
					t.Fatalf("close-wait state = closed %t peerClosed %t, want false/true", closed, peerClosed)
				}
			} else {
				waitTCPDone(t, conn)
			}

			for range 2 {
				_, _, err := conn.ReadPacket(context.Background())
				if err == nil {
					t.Fatal("ReadPacket() error = nil, want terminal error")
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("ReadPacket() error = %v, want %q", err, tt.wantErr)
				}
			}
			if tt.peerClose {
				if err := conn.Close(); err != nil {
					t.Fatalf("Close() error = %v", err)
				}
				waitTCPDone(t, conn)
				return
			}
			if err := conn.WritePacket(context.Background(), []byte("MESSAGE sip:test SIP/2.0\r\nContent-Length: 0\r\n\r\n")); err == nil {
				t.Fatal("WritePacket() error = nil, want terminal error")
			}
		})
	}
}

func TestTCPConnCloseWithFINSendsFIN(t *testing.T) {
	tests := []struct {
		name       string
		peerClosed bool
	}{
		{name: "local close"},
		{name: "close wait", peerClosed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, packetConn := newEstablishedTCPConnWithCapture(t)
			conn.peerClosed = tt.peerClosed
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
			defer cancel()

			if err := conn.closeWithFIN(ctx); err != nil {
				t.Fatalf("closeWithFIN() error = %v", err)
			}
			writes := packetConn.snapshotWrites()
			if len(writes) != 1 {
				t.Fatalf("writes = %d, want FIN write", len(writes))
			}
			segment := decodeTCPWrite(t, writes[0])
			if segment.Flags&(packet.TCPFlagFIN|packet.TCPFlagACK) != packet.TCPFlagFIN|packet.TCPFlagACK {
				t.Fatalf("flags = %#x, want FIN|ACK", segment.Flags)
			}
			if segment.Seq != 1001 || segment.Ack != 2001 {
				t.Fatalf("segment seq/ack = %d/%d, want 1001/2001", segment.Seq, segment.Ack)
			}
		})
	}
}

func TestTCPConnCloseWithFINFailureDoesNotSetTerminalError(t *testing.T) {
	conn, packetConn := newEstablishedTCPConnWithCapture(t)
	_ = packetConn.Close()

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	_, _, err := conn.ReadPacket(context.Background())
	if err == nil {
		t.Fatal("ReadPacket() error = nil, want closed transport")
	}
	if strings.Contains(err.Error(), "closing tcp packet") || strings.Contains(err.Error(), "closed network connection") {
		t.Fatalf("ReadPacket() error = %v, want plain transport closed error", err)
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

func newEstablishedTCPConnWithCapture(t *testing.T) (*TCPConn, *tcpCapturePacketConn) {
	t.Helper()
	packetConn := &tcpCapturePacketConn{local: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000}}
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
	}, packetConn
}

func decodeTCPWrite(t *testing.T, wire []byte) packet.TCPSegment {
	t.Helper()
	var inner packet.InnerPacket
	if err := inner.UnmarshalBinary(wire); err != nil {
		t.Fatalf("InnerPacket.UnmarshalBinary() error = %v", err)
	}
	if inner.TCP == nil {
		t.Fatalf("inner TCP = nil for packet protocol %d", inner.IP.Protocol)
	}
	return *inner.TCP
}

type tcpCapturePacketConn struct {
	mu                sync.Mutex
	local             net.Addr
	writes            [][]byte
	closed            bool
	blockFirst        chan struct{}
	firstWriteStarted chan struct{}
	firstWriteBlocked bool
}

func (c *tcpCapturePacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, nil, net.ErrClosed
	}
	return 0, nil, tcpCaptureTimeoutError{}
}

func (c *tcpCapturePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	var release <-chan struct{}
	var started chan struct{}
	if c.blockFirst != nil && !c.firstWriteBlocked && len(c.writes) == 0 {
		c.firstWriteBlocked = true
		release = c.blockFirst
		started = c.firstWriteStarted
	}
	c.mu.Unlock()

	if started != nil {
		close(started)
		<-release
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes = append(c.writes, append([]byte(nil), p...))
	return len(p), nil
}

func (c *tcpCapturePacketConn) Close() error {
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
	return nil
}

func (c *tcpCapturePacketConn) LocalAddr() net.Addr { return c.local }

func (c *tcpCapturePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *tcpCapturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *tcpCapturePacketConn) SetWriteDeadline(time.Time) error { return nil }

func (c *tcpCapturePacketConn) blockFirstWrite() (<-chan struct{}, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blockFirst = make(chan struct{})
	c.firstWriteStarted = make(chan struct{})
	var once sync.Once
	return c.firstWriteStarted, func() {
		once.Do(func() {
			close(c.blockFirst)
		})
	}
}

func (c *tcpCapturePacketConn) snapshotWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	writes := make([][]byte, 0, len(c.writes))
	for _, write := range c.writes {
		writes = append(writes, append([]byte(nil), write...))
	}
	return writes
}

func waitTCPWriteCount(t *testing.T, packetConn *tcpCapturePacketConn, want int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(packetConn.snapshotWrites()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("writes < %d before timeout", want)
}

func waitTCPState(t *testing.T, conn *TCPConn, ok func(*TCPConn) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		conn.mu.Lock()
		matched := ok(conn)
		conn.mu.Unlock()
		if matched {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("tcp state condition was not met before timeout")
}

type tcpCaptureTimeoutError struct{}

func (tcpCaptureTimeoutError) Error() string   { return "timeout" }
func (tcpCaptureTimeoutError) Timeout() bool   { return true }
func (tcpCaptureTimeoutError) Temporary() bool { return true }

func waitTCPDone(t *testing.T, conn *TCPConn) {
	t.Helper()
	select {
	case <-conn.done:
	case <-time.After(time.Second):
		t.Fatal("done was not closed")
	}
}
