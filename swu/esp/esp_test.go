package esp

import "testing"

func TestESPPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet ESPPacket
	}{
		{
			name: "basic",
			packet: ESPPacket{
				SPI:        0x11223344,
				Sequence:   7,
				NextHeader: 17,
				Payload:    []byte{0xAA, 0xBB, 0xCC},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got ESPPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.SPI != tt.packet.SPI || got.Sequence != tt.packet.Sequence || got.NextHeader != tt.packet.NextHeader || string(got.Payload) != string(tt.packet.Payload) {
				t.Fatalf("ESPPacket = %+v, want %+v", got, tt.packet)
			}
		})
	}
}

func TestESPPacketMarshalBinaryAddsSequentialPadding(t *testing.T) {
	wire, err := (ESPPacket{
		SPI:        0x11223344,
		Sequence:   7,
		NextHeader: 17,
		Payload:    []byte{0xAA, 0xBB, 0xCC},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	if got, want := wire[len(wire)-2], byte(3); got != want {
		t.Fatalf("PadLen = %d, want %d", got, want)
	}
	if got := wire[11:14]; string(got) != string([]byte{0x01, 0x02, 0x03}) {
		t.Fatalf("padding = % X, want 01 02 03", got)
	}
}

func TestReplayWindowAccept(t *testing.T) {
	tests := []struct {
		name      string
		sequences []uint32
		want      []bool
	}{
		{name: "reject zero and duplicate", sequences: []uint32{0, 1, 1, 2}, want: []bool{false, true, false, true}},
		{name: "accept out of order", sequences: []uint32{10, 12, 11}, want: []bool{true, true, true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var window ReplayWindow
			for i, sequence := range tt.sequences {
				if got := window.Accept(sequence); got != tt.want[i] {
					t.Fatalf("Accept(%d) = %t, want %t", sequence, got, tt.want[i])
				}
			}
		})
	}
}
