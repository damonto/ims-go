package voice

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"testing"
	"time"
)

var (
	_ encoding.BinaryAppender    = RTPPacket{}
	_ encoding.BinaryMarshaler   = RTPPacket{}
	_ encoding.BinaryUnmarshaler = (*RTPPacket)(nil)
	_ encoding.BinaryAppender    = AMRToCEntry{}
	_ encoding.BinaryMarshaler   = AMRToCEntry{}
	_ encoding.BinaryUnmarshaler = (*AMRToCEntry)(nil)
	_ encoding.BinaryAppender    = EVSPayload{}
	_ encoding.BinaryMarshaler   = EVSPayload{}
	_ encoding.BinaryUnmarshaler = (*EVSPayload)(nil)
)

func TestRTPPacketRoundTrip(t *testing.T) {
	packet := RTPPacket{
		PayloadType:    104,
		SequenceNumber: 0x1234,
		Timestamp:      0x01020304,
		SSRC:           0xa0b0c0d0,
		Marker:         true,
		Payload:        []byte{0xde, 0xad, 0xbe, 0xef},
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("RTPPacket.MarshalBinary() error = %v", err)
	}
	var got RTPPacket
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("RTPPacket.UnmarshalBinary() error = %v", err)
	}
	if got.PayloadType != packet.PayloadType ||
		got.SequenceNumber != packet.SequenceNumber ||
		got.Timestamp != packet.Timestamp ||
		got.SSRC != packet.SSRC ||
		got.Marker != packet.Marker ||
		!bytes.Equal(got.Payload, packet.Payload) {
		t.Fatalf("RTPPacket.UnmarshalBinary() = %+v, want %+v", got, packet)
	}
}

func TestRTPPacketBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet RTPPacket
	}{
		{
			name: "marker with payload",
			packet: RTPPacket{
				PayloadType:    104,
				SequenceNumber: 0x1234,
				Timestamp:      0x01020304,
				SSRC:           0xa0b0c0d0,
				Marker:         true,
				Payload:        []byte{0xde, 0xad, 0xbe, 0xef},
			},
		},
		{
			name: "empty payload",
			packet: RTPPacket{
				PayloadType:    96,
				SequenceNumber: 7,
				Timestamp:      0x10203040,
				SSRC:           0x11223344,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("RTPPacket.MarshalBinary() error = %v", err)
			}
			var got RTPPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("RTPPacket.UnmarshalBinary() error = %v", err)
			}
			if got.PayloadType != tt.packet.PayloadType ||
				got.SequenceNumber != tt.packet.SequenceNumber ||
				got.Timestamp != tt.packet.Timestamp ||
				got.SSRC != tt.packet.SSRC ||
				got.Marker != tt.packet.Marker ||
				!bytes.Equal(got.Payload, tt.packet.Payload) {
				t.Fatalf("RTPPacket.UnmarshalBinary() = %+v, want %+v", got, tt.packet)
			}
		})
	}
}

func TestRTPPacketAppendBinary(t *testing.T) {
	packet := RTPPacket{
		PayloadType:    104,
		SequenceNumber: 0x1234,
		Timestamp:      0x01020304,
		SSRC:           0xa0b0c0d0,
		Marker:         true,
		Payload:        []byte{0xde, 0xad},
	}
	got, err := packet.AppendBinary([]byte{0xaa, 0xbb})
	if err != nil {
		t.Fatalf("RTPPacket.AppendBinary() error = %v", err)
	}
	wire, err := packet.MarshalBinary()
	if err != nil {
		t.Fatalf("RTPPacket.MarshalBinary() error = %v", err)
	}
	want := append([]byte{0xaa, 0xbb}, wire...)
	if !bytes.Equal(got, want) {
		t.Fatalf("RTPPacket.AppendBinary() = %x, want %x", got, want)
	}
}

func TestRTPPacketUnmarshalBinaryRejectsInvalidPacket(t *testing.T) {
	badVersion := make([]byte, rtpHeaderSize)
	badVersion[0] = 1 << rtpVersionShift
	tests := []struct {
		name string
		wire []byte
	}{
		{name: "short", wire: nil},
		{name: "bad version", wire: badVersion},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var packet RTPPacket
			if err := packet.UnmarshalBinary(tt.wire); err == nil {
				t.Fatal("RTPPacket.UnmarshalBinary() error = nil, want error")
			}
		})
	}
}

func TestRTPPacketUnmarshalBinaryHeaderOptions(t *testing.T) {
	tests := []struct {
		name        string
		wire        []byte
		wantPayload []byte
		wantErr     bool
	}{
		{
			name: "skips csrc extension and padding",
			wire: []byte{
				byte(rtpVersion<<rtpVersionShift | rtpPaddingFlag | rtpExtensionFlag | 2),
				byte(rtpMarkerFlag | 104),
				0x12, 0x34,
				0x01, 0x02, 0x03, 0x04,
				0xa0, 0xb0, 0xc0, 0xd0,
				0x10, 0x10, 0x10, 0x10,
				0x20, 0x20, 0x20, 0x20,
				0xbe, 0xde, 0x00, 0x01,
				0x99, 0x88, 0x77, 0x66,
				0xde, 0xad, 0xbe, 0xef,
				0x00, 0x00, 0x03,
			},
			wantPayload: []byte{0xde, 0xad, 0xbe, 0xef},
		},
		{
			name: "rejects invalid padding",
			wire: []byte{
				byte(rtpVersion<<rtpVersionShift | rtpPaddingFlag),
				104,
				0x12, 0x34,
				0x01, 0x02, 0x03, 0x04,
				0xa0, 0xb0, 0xc0, 0xd0,
				0xde, 0xad, 0xbe, 0xef,
				0x00,
			},
			wantErr: true,
		},
		{
			name: "rejects truncated extension payload",
			wire: []byte{
				byte(rtpVersion<<rtpVersionShift | rtpExtensionFlag),
				104,
				0x12, 0x34,
				0x01, 0x02, 0x03, 0x04,
				0xa0, 0xb0, 0xc0, 0xd0,
				0xbe, 0xde, 0x00, 0x01,
				0x99, 0x88, 0x77,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got RTPPacket
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("RTPPacket.UnmarshalBinary() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("RTPPacket.UnmarshalBinary() error = %v", err)
			}
			if got.PayloadType != 104 ||
				got.SequenceNumber != 0x1234 ||
				got.Timestamp != 0x01020304 ||
				got.SSRC != 0xa0b0c0d0 ||
				!got.Marker ||
				!bytes.Equal(got.Payload, tt.wantPayload) {
				t.Fatalf("RTPPacket.UnmarshalBinary() = %+v, want payload %x", got, tt.wantPayload)
			}
		})
	}
}

func TestAMRToCEntryBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		toc  AMRToCEntry
		want []byte
	}{
		{
			name: "follow good speech",
			toc:  AMRToCEntry{Follow: true, FrameType: 9, Quality: true},
			want: []byte{amrToCFollowFlag | byte(9<<amrToCFrameTypeShift) | amrToCQualityFlag},
		},
		{
			name: "no data",
			toc:  AMRToCEntry{FrameType: 15},
			want: []byte{byte(15 << amrToCFrameTypeShift)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.toc.MarshalBinary()
			if err != nil {
				t.Fatalf("AMRToCEntry.MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("AMRToCEntry.MarshalBinary() = %x, want %x", got, tt.want)
			}
			var decoded AMRToCEntry
			if err := decoded.UnmarshalBinary(got); err != nil {
				t.Fatalf("AMRToCEntry.UnmarshalBinary() error = %v", err)
			}
			if decoded != tt.toc {
				t.Fatalf("AMRToCEntry.UnmarshalBinary() = %+v, want %+v", decoded, tt.toc)
			}
		})
	}
}

func TestAMRToCEntryRejectsInvalidBinary(t *testing.T) {
	tests := []struct {
		name string
		run  func() error
	}{
		{
			name: "marshal frame type",
			run: func() error {
				_, err := (AMRToCEntry{FrameType: 16}).MarshalBinary()
				return err
			},
		},
		{
			name: "unmarshal length",
			run: func() error {
				var toc AMRToCEntry
				return toc.UnmarshalBinary(nil)
			},
		},
		{
			name: "reserved bits",
			run: func() error {
				var toc AMRToCEntry
				return toc.UnmarshalBinary([]byte{0x01})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.run(); err == nil {
				t.Fatal("error = nil, want error")
			}
		})
	}
}

func TestBuildRTCPReceiverReport(t *testing.T) {
	tests := []struct {
		name  string
		ssrc  uint32
		cname string
	}{
		{name: "receiver report with cname", ssrc: 0x01020304, cname: "call-id"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := buildRTCPReceiverReport(tt.ssrc, tt.cname)
			if len(wire) < 20 {
				t.Fatalf("RTCP length = %d, want compound packet", len(wire))
			}
			if got := wire[0] >> 6; got != rtpVersion {
				t.Fatalf("RR version = %d, want %d", got, rtpVersion)
			}
			if got := wire[1]; got != rtcpRRPacketType {
				t.Fatalf("RR packet type = %d, want %d", got, rtcpRRPacketType)
			}
			if got := binary.BigEndian.Uint32(wire[4:8]); got != tt.ssrc {
				t.Fatalf("RR SSRC = %#x, want %#x", got, tt.ssrc)
			}
			if got := wire[9]; got != rtcpSDESPacketType {
				t.Fatalf("SDES packet type = %d, want %d", got, rtcpSDESPacketType)
			}
			if !bytes.Contains(wire, []byte(tt.cname)) {
				t.Fatalf("RTCP packet missing CNAME %q: %x", tt.cname, wire)
			}
		})
	}
}

func TestBuildRTCPReceiverReportWithBlock(t *testing.T) {
	block := make([]byte, 24)
	got := buildRTCPReceiverReportWithBlock(7, "call", block)
	if got[0] != (rtpVersion<<rtpVersionShift)|1 {
		t.Fatalf("report count byte = %#x, want %#x", got[0], (rtpVersion<<rtpVersionShift)|1)
	}
	if got[1] != rtcpRRPacketType {
		t.Fatalf("packet type = %d, want %d", got[1], rtcpRRPacketType)
	}
	if binary.BigEndian.Uint16(got[2:4]) != 7 {
		t.Fatalf("report length = %d, want 7", binary.BigEndian.Uint16(got[2:4]))
	}
}

func TestBuildRTCPSenderReportWithBlock(t *testing.T) {
	tests := []struct {
		name  string
		block []byte
		want  byte
	}{
		{name: "without reception report", want: 0},
		{name: "with reception report", block: make([]byte, 24), want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRTCPSenderReport(7, "call", time.Unix(1, 0), 8, 9, 10, tt.block)
			if count := got[0] & 0x1f; count != tt.want {
				t.Fatalf("report count = %d, want %d", count, tt.want)
			}
			if words := binary.BigEndian.Uint16(got[2:4]); words != uint16(6+6*int(tt.want)) {
				t.Fatalf("report length = %d, want %d", words, 6+6*int(tt.want))
			}
		})
	}
}

func TestRTCPSenderTimestamp(t *testing.T) {
	now := time.Unix(100, 0)
	tests := []struct {
		name  string
		state rtcpSendState
		want  uint32
	}{
		{
			name: "advances from the last RTP send instant",
			state: rtcpSendState{
				lastRTPTimestamp: 1000,
				lastRTPSentAt:    now.Add(-1500 * time.Millisecond),
				lastRTPClockRate: 8000,
			},
			want: 13000,
		},
		{
			name:  "missing send instant keeps last timestamp",
			state: rtcpSendState{lastRTPTimestamp: 1000},
			want:  1000,
		},
		{
			name: "future send instant keeps last timestamp",
			state: rtcpSendState{
				lastRTPTimestamp: 1000,
				lastRTPSentAt:    now.Add(time.Second),
				lastRTPClockRate: 8000,
			},
			want: 1000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := rtcpSenderTimestamp(tt.state, now); got != tt.want {
				t.Fatalf("rtcpSenderTimestamp() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestWriteRTCPSenderReportUsesRTPSSRC(t *testing.T) {
	tests := []struct {
		name string
		ssrc uint32
	}{
		{name: "sender report identifies RTP source", ssrc: 0x11223344},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rtcpCh := make(chan []byte, 1)
			call := &Call{
				endpoint: &Endpoint{},
				id:       "call-id",
				media:    NegotiatedMedia{AudioFormat: AudioFormat{ClockRate: 8000}},
				transport: &voiceMediaTransport{
					rtcpCh: rtcpCh,
				},
				rtcpSSRC: 0xaabbccdd,
				rtpSend: rtpSendState{
					initialized: true,
					ssrc:        tt.ssrc,
				},
				rtcpSend: rtcpSendState{
					packetCount:      1,
					octetCount:       20,
					lastRTPTimestamp: 160,
					lastRTPSentAt:    time.Now(),
					lastRTPClockRate: 8000,
				},
			}

			call.writeRTCPReport(make(chan struct{}))
			packet := <-rtcpCh
			if packet[1] != rtcpSRPacketType {
				t.Fatalf("RTCP packet type = %d, want sender report %d", packet[1], rtcpSRPacketType)
			}
			if got := binary.BigEndian.Uint32(packet[4:8]); got != tt.ssrc {
				t.Fatalf("RTCP sender SSRC = %#x, want RTP SSRC %#x", got, tt.ssrc)
			}
		})
	}
}

func TestRTCPReceiverReportFractionUsesReportingInterval(t *testing.T) {
	tests := []struct {
		name string
	}{
		{name: "loss recovered in next reporting interval"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			call := &Call{rtcpRecv: rtcpReceiveState{
				initialized:  true,
				ssrc:         7,
				baseSequence: 1,
				maxSequence:  10,
				received:     8,
			}}
			first := call.rtcpReceiverReportBlockLocked()
			if got := first[4]; got != 51 {
				t.Fatalf("first fraction lost = %d, want 51", got)
			}
			call.rtcpRecv.maxSequence = 20
			call.rtcpRecv.received = 18
			second := call.rtcpReceiverReportBlockLocked()
			if got := second[4]; got != 0 {
				t.Fatalf("second fraction lost = %d, want 0", got)
			}
			if got := uint32(second[5])<<16 | uint32(second[6])<<8 | uint32(second[7]); got != 2 {
				t.Fatalf("cumulative loss = %d, want 2", got)
			}
		})
	}
}

func TestAMRWBPayloadRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		media NegotiatedMedia
	}{
		{
			name:  "octet aligned",
			media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, OctetAlign: true}},
		},
		{
			name:  "bandwidth efficient",
			media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB}},
		},
	}

	frames := []AMRFrame{
		{FrameType: 9, Quality: true, Data: []byte{0x11, 0x22, 0x33, 0x44, 0x55}},
		{FrameType: 15, Quality: false, Data: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := AMRPayloadCodec{Media: tt.media}
			wire, err := codec.Marshal(AMRPayload{CMR: AMRNoModeRequest, Frames: frames})
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
			}
			got, err := codec.Unmarshal(wire)
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Unmarshal() error = %v", err)
			}
			if got.CMR != AMRNoModeRequest {
				t.Fatalf("CMR = %d, want %d", got.CMR, AMRNoModeRequest)
			}
			if len(got.Frames) != len(frames) {
				t.Fatalf("frames = %d, want %d", len(got.Frames), len(frames))
			}
			for i := range frames {
				if got.Frames[i].FrameType != frames[i].FrameType ||
					got.Frames[i].Quality != frames[i].Quality ||
					!bytes.Equal(got.Frames[i].Data, frames[i].Data) {
					t.Fatalf("frame %d = %+v, want %+v", i, got.Frames[i], frames[i])
				}
			}
		})
	}
}

func TestAMRPayloadUsesNegotiatedFormat(t *testing.T) {
	tests := []struct {
		name       string
		media      NegotiatedMedia
		wantLength int
	}{
		{
			name:       "bandwidth efficient",
			media:      NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, PayloadType: 104}},
			wantLength: 7,
		},
		{
			name:       "octet aligned",
			media:      NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, PayloadType: 104, OctetAlign: true}},
			wantLength: 8,
		},
	}

	frames := []AMRFrame{
		{FrameType: 9, Quality: true, Data: []byte{0x11, 0x22, 0x33, 0x44, 0x55}},
		{FrameType: 15, Quality: false, Data: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := AMRPayloadCodec{Media: tt.media}
			wire, err := codec.Marshal(AMRPayload{CMR: -1, Frames: frames})
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
			}
			if len(wire) != tt.wantLength {
				t.Fatalf("payload length = %d, want %d", len(wire), tt.wantLength)
			}
			got, err := codec.Unmarshal(wire)
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Unmarshal() error = %v", err)
			}
			if len(got.Frames) != len(frames) {
				t.Fatalf("frames = %d, want %d", len(got.Frames), len(frames))
			}
		})
	}
}

func TestAMRPayloadCodecRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		media   NegotiatedMedia
		payload AMRPayload
	}{
		{
			name:  "amr bandwidth efficient",
			media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMR, PayloadType: 102}},
			payload: AMRPayload{
				CMR: AMRNoModeRequest,
				Frames: []AMRFrame{
					{FrameType: 0, Quality: true, Data: bytes.Repeat([]byte{0x10}, 12)},
					{FrameType: 15, Quality: false},
				},
			},
		},
		{
			name:  "amr-wb octet aligned",
			media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, PayloadType: 104, OctetAlign: true}},
			payload: AMRPayload{
				CMR: AMRNoModeRequest,
				Frames: []AMRFrame{
					{FrameType: 9, Quality: true, Data: []byte{0x22, 0x33, 0x44, 0x55, 0x66}},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := AMRPayloadCodec{Media: tt.media}
			wire, err := codec.Marshal(tt.payload)
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
			}
			got, err := codec.Unmarshal(wire)
			if err != nil {
				t.Fatalf("AMRPayloadCodec.Unmarshal() error = %v", err)
			}
			if got.CMR != tt.payload.CMR {
				t.Fatalf("CMR = %d, want %d", got.CMR, tt.payload.CMR)
			}
			if len(got.Frames) != len(tt.payload.Frames) {
				t.Fatalf("frames = %d, want %d", len(got.Frames), len(tt.payload.Frames))
			}
			for i, want := range tt.payload.Frames {
				gotFrame := got.Frames[i]
				if gotFrame.FrameType != want.FrameType ||
					gotFrame.Quality != want.Quality ||
					!bytes.Equal(gotFrame.Data, want.Data) {
					t.Fatalf("frame %d = %+v, want %+v", i, gotFrame, want)
				}
			}
		})
	}
}

func TestAMRPayloadCodecAppend(t *testing.T) {
	codec := AMRPayloadCodec{Media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, OctetAlign: true}}}
	payload := AMRPayload{
		CMR: AMRNoModeRequest,
		Frames: []AMRFrame{
			{FrameType: 9, Quality: true, Data: []byte{0x22, 0x33, 0x44, 0x55, 0x66}},
		},
	}
	got, err := codec.Append([]byte{0xaa, 0xbb}, payload)
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Append() error = %v", err)
	}
	wire, err := codec.Marshal(payload)
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
	}
	want := append([]byte{0xaa, 0xbb}, wire...)
	if !bytes.Equal(got, want) {
		t.Fatalf("AMRPayloadCodec.Append() = %x, want %x", got, want)
	}
}

func TestAMRBandwidthEfficientPayloadPreservesSpeechBits(t *testing.T) {
	frame := AMRFrame{
		FrameType: 0,
		Quality:   true,
		Data:      []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xf0},
	}
	codec := AMRPayloadCodec{Media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB}}}
	wire, err := codec.Marshal(AMRPayload{CMR: -1, Frames: []AMRFrame{frame}})
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Marshal() error = %v", err)
	}
	got, err := codec.Unmarshal(wire)
	if err != nil {
		t.Fatalf("AMRPayloadCodec.Unmarshal() error = %v", err)
	}
	if len(got.Frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(got.Frames))
	}
	if !bytes.Equal(got.Frames[0].Data, frame.Data) {
		t.Fatalf("frame data = %x, want %x", got.Frames[0].Data, frame.Data)
	}
}

func TestAMRPayloadRejectsWrongFrameSize(t *testing.T) {
	codec := AMRPayloadCodec{Media: NegotiatedMedia{AudioFormat: AudioFormat{Codec: CodecAMRWB, OctetAlign: true}}}
	_, err := codec.Marshal(AMRPayload{
		CMR:    -1,
		Frames: []AMRFrame{{FrameType: 9, Quality: true, Data: []byte{0x01}}},
	})
	if err == nil {
		t.Fatal("AMRPayloadCodec.Marshal() error = nil, want frame size error")
	}
}

func TestEVSPayloadRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		codec EVSPayloadCodec
		input EVSPayload
	}{
		{
			name:  "compact native 13.2 kbit",
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 4, Quality: true, Data: bytes.Repeat([]byte{0x5a}, 33)}}},
		},
		{
			name:  "compact native sid",
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 12, Quality: true, Data: bytes.Repeat([]byte{0xa5}, 6)}}},
		},
		{
			name: "compact AMR-WB IO",
			input: EVSPayload{
				CMR:    &EVSCMR{Mode: 5},
				Frames: []EVSFrame{{FrameType: 2, Quality: true, AMRWBIO: true, Data: append(bytes.Repeat([]byte{0x5a}, 31), 0x58)}},
			},
		},
		{
			name:  "header-full AMR-WB IO sid",
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 9, Quality: true, AMRWBIO: true, Data: []byte{1, 2, 3, 4, 5}}}},
		},
		{
			name: "header-full aggregation and CMR",
			input: EVSPayload{
				CMR: &EVSCMR{Type: 1, Mode: 4},
				Frames: []EVSFrame{
					{FrameType: 4, Quality: true, Data: bytes.Repeat([]byte{0x5a}, 33)},
					{FrameType: 0, Quality: false, AMRWBIO: true, Data: bytes.Repeat([]byte{0xa5}, 17)},
				},
			},
		},
		{
			name:  "header-full-only native sid collision",
			codec: EVSPayloadCodec{HeaderFullOnly: true},
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 12, Quality: true, Data: bytes.Repeat([]byte{0xa5}, 6)}}},
		},
		{
			name:  "speech lost",
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 14, Quality: false}}},
		},
		{
			name:  "no data",
			input: EVSPayload{Frames: []EVSFrame{{FrameType: 15, Quality: true}}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.codec.Marshal(tt.input)
			if err != nil {
				t.Fatalf("EVSPayloadCodec.Marshal() error = %v", err)
			}
			got, err := tt.codec.Unmarshal(wire)
			if err != nil {
				t.Fatalf("EVSPayloadCodec.Unmarshal() error = %v", err)
			}
			if len(got.Frames) != len(tt.input.Frames) {
				t.Fatalf("frames = %d, want %d", len(got.Frames), len(tt.input.Frames))
			}
			for i := range got.Frames {
				if got.Frames[i].FrameType != tt.input.Frames[i].FrameType ||
					got.Frames[i].Quality != tt.input.Frames[i].Quality ||
					got.Frames[i].AMRWBIO != tt.input.Frames[i].AMRWBIO ||
					!bytes.Equal(got.Frames[i].Data, tt.input.Frames[i].Data) {
					t.Fatalf("frame[%d] = %+v, want %+v", i, got.Frames[i], tt.input.Frames[i])
				}
			}
			if tt.input.CMR != nil {
				if got.CMR == nil || got.CMR.Type != tt.input.CMR.Type || got.CMR.Mode != tt.input.CMR.Mode {
					t.Fatalf("CMR = %+v, want %+v", got.CMR, tt.input.CMR)
				}
			}
		})
	}
}

func TestEVSPayloadRejectsInvalidShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "cmr only", payload: []byte{0x80}},
		{name: "truncated aggregation", payload: []byte{0x40}},
		{name: "reserved native quality", payload: []byte{0x10}},
		{name: "reserved native type", payload: []byte{0x0d}},
		{name: "non-zero padding", payload: []byte{0x0f, 0x01}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload EVSPayload
			if err := payload.UnmarshalBinary(tt.payload); err == nil {
				t.Fatal("EVSPayload.UnmarshalBinary() error = nil, want error")
			}
		})
	}

	if _, err := (EVSPayload{}).MarshalBinary(); err == nil {
		t.Fatal("EVSPayload.MarshalBinary() error = nil, want frame count error")
	}
	if _, err := (EVSPayload{Frames: []EVSFrame{{FrameType: 4, Quality: true, Data: make([]byte, 32)}}}).MarshalBinary(); err == nil {
		t.Fatal("EVSPayload.MarshalBinary() error = nil, want frame size error")
	}
	if _, err := (EVSPayload{Frames: []EVSFrame{{FrameType: 4, Quality: false, Data: make([]byte, 33)}}}).MarshalBinary(); err == nil {
		t.Fatal("EVSPayload.MarshalBinary() error = nil, want quality error")
	}
	if _, err := (EVSPayload{Frames: []EVSFrame{{FrameType: 14, Quality: true}}}).MarshalBinary(); err == nil {
		t.Fatal("EVSPayload.MarshalBinary() error = nil, want speech-lost quality error")
	}
}
