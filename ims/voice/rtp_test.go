package voice

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"testing"
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

func TestAMRWBPayloadRoundTrip(t *testing.T) {
	tests := []struct {
		name  string
		media NegotiatedMedia
	}{
		{
			name:  "octet aligned",
			media: NegotiatedMedia{Codec: CodecAMRWB, OctetAlign: true},
		},
		{
			name:  "bandwidth efficient",
			media: NegotiatedMedia{Codec: CodecAMRWB},
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
			media:      NegotiatedMedia{Codec: CodecAMRWB, PayloadType: 104},
			wantLength: 7,
		},
		{
			name:       "octet aligned",
			media:      NegotiatedMedia{Codec: CodecAMRWB, PayloadType: 104, OctetAlign: true},
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
			media: NegotiatedMedia{Codec: CodecAMR, PayloadType: 102},
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
			media: NegotiatedMedia{Codec: CodecAMRWB, PayloadType: 104, OctetAlign: true},
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
	codec := AMRPayloadCodec{Media: NegotiatedMedia{Codec: CodecAMRWB, OctetAlign: true}}
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
	codec := AMRPayloadCodec{Media: NegotiatedMedia{Codec: CodecAMRWB}}
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
	codec := AMRPayloadCodec{Media: NegotiatedMedia{Codec: CodecAMRWB, OctetAlign: true}}
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
		frame EVSFrame
	}{
		{
			name:  "13.2 kbit",
			frame: EVSFrame{FrameType: 4, Quality: true, Data: bytes.Repeat([]byte{0x5a}, 33)},
		},
		{
			name:  "sid",
			frame: EVSFrame{FrameType: 12, Quality: true, Data: bytes.Repeat([]byte{0xa5}, 6)},
		},
		{
			name:  "speech lost",
			frame: EVSFrame{FrameType: 14, Quality: false, Data: nil},
		},
		{
			name:  "no data",
			frame: EVSFrame{FrameType: 15, Quality: true, Data: nil},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := (EVSPayload{Frames: []EVSFrame{tt.frame}}).MarshalBinary()
			if err != nil {
				t.Fatalf("EVSPayload.MarshalBinary() error = %v", err)
			}
			var got EVSPayload
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("EVSPayload.UnmarshalBinary() error = %v", err)
			}
			if len(got.Frames) != 1 {
				t.Fatalf("frames = %d, want 1", len(got.Frames))
			}
			if got.Frames[0].FrameType != tt.frame.FrameType ||
				got.Frames[0].Quality != tt.frame.Quality ||
				!bytes.Equal(got.Frames[0].Data, tt.frame.Data) {
				t.Fatalf("frame = %+v, want %+v", got.Frames[0], tt.frame)
			}
		})
	}
}

func TestEVSPayloadRejectsUnsupportedShapes(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "empty", payload: nil},
		{name: "header h bit", payload: []byte{0x80}},
		{name: "header f bit", payload: []byte{0x40}},
		{name: "amr-wb io", payload: []byte{0x20}},
		{name: "reserved quality bit", payload: []byte{0x10}},
		{name: "truncated speech", payload: append([]byte{0x04}, bytes.Repeat([]byte{0x00}, 32)...)},
		{name: "unsupported native type", payload: []byte{0x05}},
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
	if _, err := (EVSPayload{Frames: []EVSFrame{
		{FrameType: 15, Quality: true},
		{FrameType: 15, Quality: true},
	}}).MarshalBinary(); err == nil {
		t.Fatal("EVSPayload.MarshalBinary() error = nil, want multi-frame error")
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
