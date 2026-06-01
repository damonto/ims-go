package voice

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDTMFEventCode(t *testing.T) {
	tests := []struct {
		name  string
		digit byte
		want  byte
		ok    bool
	}{
		{name: "zero", digit: '0', want: 0, ok: true},
		{name: "nine", digit: '9', want: 9, ok: true},
		{name: "star", digit: '*', want: 10, ok: true},
		{name: "pound", digit: '#', want: 11, ok: true},
		{name: "a", digit: 'A', want: 12, ok: true},
		{name: "lower d", digit: 'd', want: 15, ok: true},
		{name: "invalid", digit: 'x'},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := dtmfEventCode(tt.digit)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("dtmfEventCode(%q) = %d/%t, want %d/%t", tt.digit, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestBuildDTMFPayload(t *testing.T) {
	tests := []struct {
		name     string
		end      bool
		wantFlag byte
	}{
		{name: "continuation"},
		{name: "end", end: true, wantFlag: 0x80},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDTMFPayload(10, 7, 0x1234, tt.end)
			want := []byte{10, tt.wantFlag | 7, 0x12, 0x34}
			if !bytes.Equal(got, want) {
				t.Fatalf("buildDTMFPayload() = %x, want %x", got, want)
			}
		})
	}
}

func TestSendDTMFWritesTelephoneEventRTP(t *testing.T) {
	writes := make(chan []byte, 8)
	call := &Call{
		state:     CallStateActive,
		transport: &voiceRTPOnlyMediaTransport{writeCh: writes},
		media: NegotiatedMedia{
			Codec:           CodecAMR,
			PayloadType:     102,
			ClockRate:       8000,
			PTime:           20 * time.Millisecond,
			Direction:       mediaDirectionSendRecv,
			HasDTMF:         true,
			DTMFPayloadType: 101,
			DTMFClockRate:   8000,
		},
		rtpSend: rtpSendState{
			initialized:   true,
			ssrc:          0x01020304,
			nextSequence:  1000,
			nextTimestamp: 2000,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := call.SendDTMF(ctx, DTMFRequest{Digits: "*", Duration: 65 * time.Millisecond, Volume: 7}); err != nil {
		t.Fatalf("SendDTMF() error = %v", err)
	}

	var packets []RTPPacket
	for len(writes) > 0 {
		wire := <-writes
		packet, err := ParseRTPPacket(wire)
		if err != nil {
			t.Fatalf("ParseRTPPacket() error = %v", err)
		}
		packets = append(packets, packet)
	}
	if len(packets) != 6 {
		t.Fatalf("packet count = %d, want 6", len(packets))
	}
	for i, packet := range packets {
		if packet.PayloadType != 101 || packet.SequenceNumber != uint16(1000+i) || packet.Timestamp != 2000 || packet.SSRC != 0x01020304 {
			t.Fatalf("packet[%d] = %+v, want DTMF payload 101 seq %d timestamp 2000 ssrc 0x01020304", i, packet, 1000+i)
		}
		if i == 0 && !packet.Marker {
			t.Fatal("first packet marker = false, want true")
		}
		if i != 0 && packet.Marker {
			t.Fatalf("packet[%d] marker = true, want false", i)
		}
		if len(packet.Payload) != dtmfPayloadSize || packet.Payload[0] != 10 {
			t.Fatalf("packet[%d] payload = %x, want event 10", i, packet.Payload)
		}
	}
	for i, packet := range packets[len(packets)-dtmfEndRepeats:] {
		if packet.Payload[1]&0x80 == 0 {
			t.Fatalf("end packet[%d] payload = %x, want end bit", i, packet.Payload)
		}
		if got := binary.BigEndian.Uint16(packet.Payload[2:]); got != 640 {
			t.Fatalf("end packet[%d] duration = %d, want 640", i, got)
		}
	}
	if got := call.rtpSend.nextSequence; got != 1006 {
		t.Fatalf("nextSequence = %d, want 1006", got)
	}
	if got := call.rtpSend.nextTimestamp; got != 3280 {
		t.Fatalf("nextTimestamp = %d, want 3280", got)
	}
}

func TestWriteRTPRebasesSpeechAfterDTMF(t *testing.T) {
	writes := make(chan []byte, 16)
	call := &Call{
		state:     CallStateActive,
		transport: &voiceRTPOnlyMediaTransport{writeCh: writes},
		media: NegotiatedMedia{
			Codec:           CodecAMR,
			PayloadType:     102,
			ClockRate:       8000,
			PTime:           20 * time.Millisecond,
			Direction:       mediaDirectionSendRecv,
			HasDTMF:         true,
			DTMFPayloadType: 101,
			DTMFClockRate:   8000,
		},
		rtpSend: rtpSendState{
			initialized:   true,
			ssrc:          0x01020304,
			nextSequence:  1000,
			nextTimestamp: 2000,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := call.SendDTMF(ctx, DTMFRequest{Digits: "1", Duration: 65 * time.Millisecond}); err != nil {
		t.Fatalf("SendDTMF() error = %v", err)
	}
	for len(writes) > 0 {
		<-writes
	}

	speech, err := BuildRTPPacket(RTPPacket{
		PayloadType:    102,
		SequenceNumber: 77,
		Timestamp:      9000,
		SSRC:           0xaabbccdd,
		Marker:         true,
		Payload:        []byte{0xaa, 0xbb},
	})
	if err != nil {
		t.Fatalf("BuildRTPPacket() error = %v", err)
	}
	if err := call.WriteRTP(context.Background(), speech); err != nil {
		t.Fatalf("WriteRTP() error = %v", err)
	}
	gotWire := <-writes
	got, err := ParseRTPPacket(gotWire)
	if err != nil {
		t.Fatalf("ParseRTPPacket() error = %v", err)
	}
	if got.PayloadType != 102 || got.SequenceNumber != 1006 || got.Timestamp != 3280 || got.SSRC != 0x01020304 {
		t.Fatalf("speech RTP = %+v, want payload 102 seq 1006 timestamp 3280 ssrc 0x01020304", got)
	}
	if !got.Marker || !bytes.Equal(got.Payload, []byte{0xaa, 0xbb}) {
		t.Fatalf("speech RTP marker/payload = %t/%x, want true/aabb", got.Marker, got.Payload)
	}
	if call.rtpSend.nextSequence != 1007 || call.rtpSend.nextTimestamp != 3440 {
		t.Fatalf("rtpSend = %+v, want next sequence 1007 timestamp 3440", call.rtpSend)
	}
}

func TestSendDTMFRequiresNegotiatedTelephoneEvent(t *testing.T) {
	call := &Call{
		state:     CallStateActive,
		transport: &voiceRTPOnlyMediaTransport{},
		media:     NegotiatedMedia{Direction: mediaDirectionSendRecv},
	}
	if err := call.SendDTMF(context.Background(), DTMFRequest{Digits: "1"}); err == nil {
		t.Fatal("SendDTMF() error = nil, want missing telephone-event error")
	}
}

func TestSendDTMFRejectsUnnegotiatedEvent(t *testing.T) {
	tests := []struct {
		name  string
		media NegotiatedMedia
		digit string
	}{
		{
			name: "event mask",
			media: NegotiatedMedia{
				ClockRate:       8000,
				Direction:       mediaDirectionSendRecv,
				HasDTMF:         true,
				DTMFPayloadType: 101,
				DTMFClockRate:   8000,
				DTMFEventMask:   1 << 1,
			},
			digit: "*",
		},
		{
			name: "clock mismatch",
			media: NegotiatedMedia{
				ClockRate:       16000,
				Direction:       mediaDirectionSendRecv,
				HasDTMF:         true,
				DTMFPayloadType: 101,
				DTMFClockRate:   8000,
			},
			digit: "1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{
				state:     CallStateActive,
				transport: &voiceRTPOnlyMediaTransport{},
				media:     tt.media,
			}
			if err := call.SendDTMF(context.Background(), DTMFRequest{Digits: tt.digit}); err == nil {
				t.Fatal("SendDTMF() error = nil, want non-nil")
			}
		})
	}
}

func TestSendDTMFSavesRTPStateOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	transport := &dtmfCancelTransport{cancel: cancel}
	call := &Call{
		state:     CallStateActive,
		transport: transport,
		media: NegotiatedMedia{
			Codec:           CodecAMR,
			PayloadType:     102,
			ClockRate:       8000,
			PTime:           20 * time.Millisecond,
			Direction:       mediaDirectionSendRecv,
			HasDTMF:         true,
			DTMFPayloadType: 101,
			DTMFClockRate:   8000,
		},
		rtpSend: rtpSendState{
			initialized:   true,
			ssrc:          0x01020304,
			nextSequence:  10,
			nextTimestamp: 2000,
		},
	}

	err := call.SendDTMF(ctx, DTMFRequest{Digits: "1", Duration: 65 * time.Millisecond})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("SendDTMF() error = %v, want context.Canceled", err)
	}
	if transport.writes != 1 {
		t.Fatalf("writes = %d, want 1", transport.writes)
	}
	if got := call.rtpSend.nextSequence; got != 11 {
		t.Fatalf("nextSequence = %d, want 11", got)
	}
	if got := call.rtpSend.nextTimestamp; got != 3280 {
		t.Fatalf("nextTimestamp = %d, want 3280", got)
	}
}

func TestNormalizeDTMFInterval(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		frame    time.Duration
		want     time.Duration
	}{
		{name: "rounds minimum to frame multiple", duration: 65 * time.Millisecond, frame: 20 * time.Millisecond, want: 80 * time.Millisecond},
		{name: "keeps exact frame multiple", duration: 100 * time.Millisecond, frame: 20 * time.Millisecond, want: 100 * time.Millisecond},
		{name: "uses default frame", duration: 65 * time.Millisecond, want: 80 * time.Millisecond},
		{name: "raises short interval", duration: 20 * time.Millisecond, frame: 20 * time.Millisecond, want: 80 * time.Millisecond},
		{name: "rounds larger interval", duration: 95 * time.Millisecond, frame: 30 * time.Millisecond, want: 120 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeDTMFInterval(tt.duration, tt.frame); got != tt.want {
				t.Fatalf("normalizeDTMFInterval() = %v, want %v", got, tt.want)
			}
		})
	}
}

type dtmfCancelTransport struct {
	cancel func()
	writes int
}

func (t *dtmfCancelTransport) LocalAddr() net.Addr  { return nil }
func (t *dtmfCancelTransport) RemoteAddr() net.Addr { return nil }

func (t *dtmfCancelTransport) WritePacket(ctx context.Context, data []byte) error {
	t.writes++
	t.cancel()
	return nil
}

func (t *dtmfCancelTransport) ReadPacket(ctx context.Context) ([]byte, net.Addr, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

func (t *dtmfCancelTransport) Close() error { return nil }
