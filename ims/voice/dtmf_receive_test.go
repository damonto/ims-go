package voice

import (
	"slices"
	"testing"
	"time"
)

func TestReceiveDTMF(t *testing.T) {
	tests := []struct {
		name       string
		payloads   [][]byte
		timestamps []uint32
		markers    []bool
		pt         int
		mask       uint16
		ssrcs      []uint32
		noFormat   bool
		closed     bool
		want       string
	}{
		{name: "updates and repeated ends", payloads: [][]byte{{5, 10, 0, 160}, {5, 10, 1, 64}, {5, 138, 2, 128}, {5, 138, 2, 128}, {5, 10, 0, 160}}, want: "5"},
		{name: "only end survives", payloads: [][]byte{{10, 138, 2, 128}}, want: "*"},
		{name: "missing end", payloads: [][]byte{{11, 10, 0, 160}}, want: "#"},
		{name: "reserved bit ignored", payloads: [][]byte{{12, 74, 0, 160}}, want: "A"},
		{name: "same key twice and delayed duplicate", payloads: [][]byte{{5, 138, 2, 128}, {5, 138, 2, 128}, {5, 138, 2, 128}}, timestamps: []uint32{100, 1000, 100}, want: "55"},
		{name: "long event continuation", payloads: [][]byte{{5, 10, 255, 255}, {5, 138, 0, 160}}, timestamps: []uint32{100, 65635}, want: "5"},
		{name: "packed keys", payloads: [][]byte{{1, 138, 0, 160, 2, 138, 0, 160}}, want: "12"},
		{name: "packed continuation", payloads: [][]byte{{5, 10, 255, 255, 5, 138, 0, 160}}, want: "5"},
		{name: "packed duplicate as separate report", payloads: [][]byte{{1, 138, 0, 160, 2, 138, 0, 160}, {2, 138, 0, 160}}, timestamps: []uint32{100, 260}, want: "12"},
		{name: "packed unknown event preserves timestamp", payloads: [][]byte{{16, 138, 0, 160, 2, 138, 0, 160}, {2, 138, 0, 160}}, timestamps: []uint32{100, 260}, want: "2"},
		{name: "partial trailing report rejects whole packet", payloads: [][]byte{{1, 138, 0, 160, 2}}},
		{name: "zero trailing duration rejects whole packet", payloads: [][]byte{{1, 138, 0, 160, 2, 138, 0, 0}}},
		{name: "long boundary arrives late", payloads: [][]byte{{5, 10, 0, 160}, {5, 138, 0, 160}, {5, 10, 255, 255}}, timestamps: []uint32{100, 65635, 100}, want: "55"},
		{name: "long segments in reverse order", payloads: [][]byte{{5, 138, 0, 160}, {5, 10, 255, 255}}, timestamps: []uint32{65635, 100}, want: "5"},
		{name: "missing boundary does not merge distinct keys", payloads: [][]byte{{5, 10, 0, 160}, {5, 138, 0, 160}}, timestamps: []uint32{100, 65635}, want: "55"},
		{name: "marker distinguishes new key", payloads: [][]byte{{5, 10, 0, 160}, {5, 138, 0, 160}}, timestamps: []uint32{100, 65635}, markers: []bool{true, true}, want: "55"},
		{name: "end distinguishes new key", payloads: [][]byte{{5, 138, 0, 160}, {5, 138, 0, 160}}, timestamps: []uint32{100, 65635}, want: "55"},
		{name: "long timestamp wraps", payloads: [][]byte{{5, 10, 255, 255}, {5, 138, 0, 160}}, timestamps: []uint32{0xfffffff0, 65519}, want: "5"},
		{name: "zero duration", payloads: [][]byte{{5, 10, 0, 0}}},
		{name: "unknown event", payloads: [][]byte{{16, 10, 0, 160}}},
		{name: "truncated", payloads: [][]byte{{5, 10, 0}}},
		{name: "speech payload", payloads: [][]byte{{5, 10, 0, 160}}, pt: 96},
		{name: "not negotiated", payloads: [][]byte{{5, 10, 0, 160}}, noFormat: true},
		{name: "event outside negotiated mask", payloads: [][]byte{{5, 10, 0, 160}}, mask: 1 << 1},
		{name: "different sources", payloads: [][]byte{{5, 10, 0, 160}, {5, 10, 0, 160}}, ssrcs: []uint32{1, 2}, want: "55"},
		{name: "closed", payloads: [][]byte{{5, 10, 0, 160}}, closed: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got string
			call := &Call{id: "test", closed: tt.closed, media: NegotiatedMedia{DTMF: &AudioFormat{PayloadType: 101, ClockRate: 8000}}, endpoint: &Endpoint{}}
			call.media.DTMF.DTMFEventMask = tt.mask
			if tt.noFormat {
				call.media.DTMF = nil
			}
			call.endpoint.cfg.OnDTMF = func(event DTMFEvent) {
				if event.Call != call || event.CallID != call.ID() || event.At.IsZero() {
					t.Errorf("invalid event: %+v", event)
				}
				got += event.Digit
			}
			for i, payload := range tt.payloads {
				timestamp := uint32(100)
				if tt.timestamps != nil {
					timestamp = tt.timestamps[i]
				}
				pt := 101
				if tt.pt != 0 {
					pt = tt.pt
				}
				ssrc := uint32(1)
				if tt.ssrcs != nil {
					ssrc = tt.ssrcs[i]
				}
				packet := RTPPacket{PayloadType: pt, SequenceNumber: uint16(i), Timestamp: timestamp, SSRC: ssrc, Payload: payload}
				if tt.markers != nil {
					packet.Marker = tt.markers[i]
				}
				wire, err := packet.MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				call.recordMediaPacket(MediaPacketFromPayload(false, wire))
			}
			if got != tt.want {
				t.Errorf("digits = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDTMFHistory(t *testing.T) {
	tests := []struct {
		name string
		base uint32
	}{
		{name: "ordinary timestamps", base: 100},
		{name: "timestamp rollover", base: 0xfffffff0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state dtmfReceiveState
			for i := range 100 {
				if !state.record(1, dtmfSegment{timestamp: tt.base + uint32(i*1000), event: 5, duration: 160, end: true}) {
					t.Fatalf("key %d not detected", i)
				}
			}
			for i := range 100 {
				if state.record(1, dtmfSegment{timestamp: tt.base + uint32(i*1000), event: 5, duration: 160, end: true}) {
					t.Fatalf("old key %d repeated", i)
				}
			}
			// A previously unseen key inside the reorder window is still delivered.
			if !state.record(1, dtmfSegment{timestamp: tt.base + 98500, event: 6, duration: 160, end: true}) {
				t.Fatal("reordered key lost")
			}
			if !state.record(2, dtmfSegment{timestamp: tt.base, event: 5, duration: 160, end: true}) {
				t.Fatal("source histories are not independent")
			}
		})
	}
}

func TestDTMFSourceLimit(t *testing.T) {
	for _, name := range []string{"retain floors at source limit"} {
		t.Run(name, func(t *testing.T) {
			var state dtmfReceiveState
			segment := dtmfSegment{timestamp: 100, event: 5, duration: 160, end: true}
			for i := range maxDTMFSources {
				if !state.record(uint32(i), segment) {
					t.Fatalf("source %d not detected", i)
				}
			}
			if state.record(maxDTMFSources, segment) {
				t.Fatal("source limit not enforced")
			}
			if state.record(0, segment) {
				t.Fatal("old source was forgotten")
			}
		})
	}
}

func TestDTMFPayloadOwnership(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{name: "single report", payload: []byte{1, 138, 0, 160}},
		{name: "packed reports", payload: []byte{1, 138, 0, 160, 2, 138, 0, 160}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := RTPPacket{PayloadType: 101, Marker: true, Payload: tt.payload}
			wire, err := packet.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			metadata := MediaPacketFromPayload(false, wire)
			clear(wire)
			if !metadata.RTPMarker || !slices.Equal(metadata.RTPPayload, tt.payload) {
				t.Fatalf("metadata did not retain independent RTP content: %+v", metadata)
			}
		})
	}
}

func TestDTMFSourceLifecycle(t *testing.T) {
	tests := []struct {
		name    string
		elapsed time.Duration
		wantNew bool
	}{
		{name: "active sources retain history", elapsed: time.Second},
		{name: "idle sources retire", elapsed: dtmfSourceIdleTimeout, wantNew: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state dtmfReceiveState
			now := time.Now()
			for i := range maxDTMFSources {
				state.source(uint32(i), now)
			}
			if got := state.source(maxDTMFSources, now.Add(tt.elapsed)); (got != nil) != tt.wantNew {
				t.Fatalf("new source accepted = %v, want %v", got != nil, tt.wantNew)
			}
		})
	}
}

func TestDTMFSpeechRetainsHistory(t *testing.T) {
	for _, name := range []string{"speech refreshes source"} {
		t.Run(name, func(t *testing.T) {
			call := &Call{}
			now := time.Now()
			source := call.dtmfRecv.source(1, now.Add(-time.Minute))
			call.recordMediaPacket(MediaPacket{RTPSSRC: 1, RTPPayloadBytes: 160})
			if source.lastSeen.Before(now) {
				t.Fatal("speech did not refresh history")
			}
		})
	}
}
