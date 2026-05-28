package voice

import (
	"bytes"
	"encoding/binary"
	"testing"
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
	wire, err := BuildRTPPacket(packet)
	if err != nil {
		t.Fatalf("BuildRTPPacket() error = %v", err)
	}
	got, err := ParseRTPPacket(wire)
	if err != nil {
		t.Fatalf("ParseRTPPacket() error = %v", err)
	}
	if got.PayloadType != packet.PayloadType ||
		got.SequenceNumber != packet.SequenceNumber ||
		got.Timestamp != packet.Timestamp ||
		got.SSRC != packet.SSRC ||
		got.Marker != packet.Marker ||
		!bytes.Equal(got.Payload, packet.Payload) {
		t.Fatalf("ParseRTPPacket() = %+v, want %+v", got, packet)
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
		build func([]AMRFrame, int) ([]byte, error)
		parse func([]byte) (AMRPayload, error)
	}{
		{
			name: "octet aligned",
			build: func(frames []AMRFrame, cmr int) ([]byte, error) {
				return BuildAMROctetAlignedPayload(CodecAMRWB, frames, cmr)
			},
			parse: func(payload []byte) (AMRPayload, error) {
				return ParseAMROctetAlignedPayload(CodecAMRWB, payload)
			},
		},
		{
			name: "bandwidth efficient",
			build: func(frames []AMRFrame, cmr int) ([]byte, error) {
				return BuildAMRBandwidthEfficientPayload(CodecAMRWB, frames, cmr)
			},
			parse: func(payload []byte) (AMRPayload, error) {
				return ParseAMRBandwidthEfficientPayload(CodecAMRWB, payload)
			},
		},
	}

	frames := []AMRFrame{
		{FrameType: 9, Quality: true, Data: []byte{0x11, 0x22, 0x33, 0x44, 0x55}},
		{FrameType: 15, Quality: false, Data: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.build(frames, AMRNoModeRequest)
			if err != nil {
				t.Fatalf("build error = %v", err)
			}
			got, err := tt.parse(wire)
			if err != nil {
				t.Fatalf("parse error = %v", err)
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
			wire, err := BuildAMRPayload(tt.media, frames, -1)
			if err != nil {
				t.Fatalf("BuildAMRPayload() error = %v", err)
			}
			if len(wire) != tt.wantLength {
				t.Fatalf("payload length = %d, want %d", len(wire), tt.wantLength)
			}
			got, err := ParseAMRPayload(tt.media, wire)
			if err != nil {
				t.Fatalf("ParseAMRPayload() error = %v", err)
			}
			if len(got.Frames) != len(frames) {
				t.Fatalf("frames = %d, want %d", len(got.Frames), len(frames))
			}
		})
	}
}

func TestAMRBandwidthEfficientPayloadPreservesSpeechBits(t *testing.T) {
	frame := AMRFrame{
		FrameType: 0,
		Quality:   true,
		Data:      []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xf0},
	}
	wire, err := BuildAMRBandwidthEfficientPayload(CodecAMRWB, []AMRFrame{frame}, -1)
	if err != nil {
		t.Fatalf("BuildAMRBandwidthEfficientPayload() error = %v", err)
	}
	got, err := ParseAMRBandwidthEfficientPayload(CodecAMRWB, wire)
	if err != nil {
		t.Fatalf("ParseAMRBandwidthEfficientPayload() error = %v", err)
	}
	if len(got.Frames) != 1 {
		t.Fatalf("frames = %d, want 1", len(got.Frames))
	}
	if !bytes.Equal(got.Frames[0].Data, frame.Data) {
		t.Fatalf("frame data = %x, want %x", got.Frames[0].Data, frame.Data)
	}
}

func TestAMRPayloadRejectsWrongFrameSize(t *testing.T) {
	_, err := BuildAMROctetAlignedPayload(CodecAMRWB, []AMRFrame{
		{FrameType: 9, Quality: true, Data: []byte{0x01}},
	}, -1)
	if err == nil {
		t.Fatal("BuildAMROctetAlignedPayload() error = nil, want frame size error")
	}
}
