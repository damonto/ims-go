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

func TestValidSPI(t *testing.T) {
	tests := []struct {
		name string
		spi  uint32
		want bool
	}{
		{name: "zero", spi: 0},
		{name: "reserved one", spi: 1},
		{name: "reserved max", spi: ReservedSPIMax},
		{name: "first valid", spi: ReservedSPIMax + 1, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ValidSPI(tt.spi); got != tt.want {
				t.Fatalf("ValidSPI(%d) = %t, want %t", tt.spi, got, tt.want)
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

func TestCodecEncodeNullAddsAlignmentPadding(t *testing.T) {
	tests := []struct {
		name       string
		payload    []byte
		wantPadLen byte
		wantLen    int
	}{
		{
			name:       "payload needs padding for four byte trailer alignment",
			payload:    []byte{0xAA, 0xBB, 0xCC},
			wantPadLen: 3,
			wantLen:    espHeaderLen + 8,
		},
		{
			name:       "payload already aligned with trailer",
			payload:    []byte{0xAA, 0xBB},
			wantPadLen: 0,
			wantLen:    espHeaderLen + 4,
		},
	}

	codec := Codec{
		Encryption:   EncryptionNull,
		Integrity:    IntegrityHMACSHA196,
		IntegrityKey: []byte("0123456789abcdef0123"),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := codec.Encode(ESPPacket{SPI: 0x11223344, Sequence: 7, NextHeader: 17, Payload: tt.payload})
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if len(wire) != tt.wantLen+12 {
				t.Fatalf("Encode() length = %d, want %d", len(wire), tt.wantLen+12)
			}
			trailer := len(wire) - 12 - espTrailerLen
			if got := wire[trailer]; got != tt.wantPadLen {
				t.Fatalf("PadLen = %d, want %d", got, tt.wantPadLen)
			}
			for i := byte(1); i <= tt.wantPadLen; i++ {
				if got := wire[espHeaderLen+len(tt.payload)+int(i)-1]; got != i {
					t.Fatalf("padding byte %d = %d, want %d", i, got, i)
				}
			}

			got, err := codec.Decode(wire)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if string(got.Payload) != string(tt.payload) || got.NextHeader != 17 {
				t.Fatalf("Decode() = %+v, want payload % X next header 17", got, tt.payload)
			}
		})
	}
}

func TestCodecRejectsNullEncryptionWithoutIntegrity(t *testing.T) {
	codec := Codec{Encryption: EncryptionNull, Integrity: IntegrityNone}
	if _, err := codec.Encode(ESPPacket{SPI: 0x11223344, Sequence: 7, NextHeader: 17, Payload: []byte{0xAA}}); err == nil {
		t.Fatal("Encode() error = nil, want error")
	}
	if _, err := codec.Decode([]byte{0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x3b}); err == nil {
		t.Fatal("Decode() error = nil, want error")
	}
}

func TestCodecAEADRoundTripAndTamper(t *testing.T) {
	tests := []struct {
		name  string
		codec Codec
	}{
		{
			name: "aes gcm",
			codec: Codec{
				Encryption:    EncryptionAESGCM,
				EncryptionKey: []byte("0123456789abcdef"),
				Integrity:     IntegrityNull,
				Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "aes gmac",
			codec: Codec{
				Encryption:   EncryptionNull,
				Integrity:    IntegrityAESGMAC,
				IntegrityKey: []byte("0123456789abcdef"),
				Salt:         [4]byte{0x05, 0x06, 0x07, 0x08},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := ESPPacket{
				SPI:        0x11223344,
				Sequence:   7,
				NextHeader: 17,
				Payload:    []byte{0xAA, 0xBB, 0xCC},
			}
			wire, err := tt.codec.Encode(packet)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if len(wire) < espHeaderLen+espExplicitIVLen+espGCMICVLen {
				t.Fatalf("Encode() length = %d, want at least ESP header + IV + ICV", len(wire))
			}
			got, err := tt.codec.Decode(wire)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if got.SPI != packet.SPI || got.Sequence != packet.Sequence || got.NextHeader != packet.NextHeader || string(got.Payload) != string(packet.Payload) {
				t.Fatalf("Decode() = %+v, want %+v", got, packet)
			}

			tampered := append([]byte(nil), wire...)
			tampered[espHeaderLen+espExplicitIVLen] ^= 0x01
			if _, err := tt.codec.Decode(tampered); err == nil {
				t.Fatal("Decode() tampered error = nil, want integrity error")
			}
		})
	}
}

func TestCodecDefaultExplicitIVUsesSPIAndSequence(t *testing.T) {
	tests := []struct {
		name  string
		codec Codec
	}{
		{
			name: "aes gcm",
			codec: Codec{
				Encryption:    EncryptionAESGCM,
				EncryptionKey: []byte("0123456789abcdef"),
				Integrity:     IntegrityNull,
				Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "aes gmac",
			codec: Codec{
				Encryption:   EncryptionNull,
				Integrity:    IntegrityAESGMAC,
				IntegrityKey: []byte("0123456789abcdef"),
				Salt:         [4]byte{0x05, 0x06, 0x07, 0x08},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := ESPPacket{
				SPI:        0x11223344,
				Sequence:   7,
				NextHeader: 17,
				Payload:    []byte{0xAA},
			}
			wire, err := tt.codec.Encode(packet)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			iv := wire[espHeaderLen : espHeaderLen+espExplicitIVLen]
			want := []byte{0x11, 0x22, 0x33, 0x44, 0x00, 0x00, 0x00, 0x07}
			if string(iv) != string(want) {
				t.Fatalf("explicit IV = % X, want % X", iv, want)
			}

			packet.SPI = 0x55667788
			other, err := tt.codec.Encode(packet)
			if err != nil {
				t.Fatalf("Encode() other SPI error = %v", err)
			}
			otherIV := other[espHeaderLen : espHeaderLen+espExplicitIVLen]
			if string(otherIV) == string(iv) {
				t.Fatalf("explicit IV reused across SPIs: % X", iv)
			}
		})
	}
}

func TestCodecCryptoPayloadBytesIncludesESPAlignmentPadding(t *testing.T) {
	tests := []struct {
		name       string
		encryption string
		payloadLen int
		want       uint64
	}{
		{name: "null encryption aligns trailer", encryption: EncryptionNull, payloadLen: 3, want: 8},
		{name: "aes cbc aligns to block size", encryption: EncryptionAESCBC, payloadLen: 3, want: 16},
		{name: "aes gcm aligns trailer", encryption: EncryptionAESGCM, payloadLen: 3, want: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := (Codec{Encryption: tt.encryption}).CryptoPayloadBytes(tt.payloadLen)
			if err != nil {
				t.Fatalf("CryptoPayloadBytes() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("CryptoPayloadBytes() = %d, want %d", got, tt.want)
			}
		})
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

func TestReplayWindowWouldAcceptDoesNotMutate(t *testing.T) {
	var window ReplayWindow
	if !window.WouldAccept(1) {
		t.Fatal("WouldAccept(1) = false, want true")
	}
	if !window.WouldAccept(1) {
		t.Fatal("WouldAccept(1) second = false, want true before Accept")
	}
	if !window.Accept(1) {
		t.Fatal("Accept(1) = false, want true")
	}
	if window.WouldAccept(1) {
		t.Fatal("WouldAccept(1) after Accept = true, want false")
	}
}
