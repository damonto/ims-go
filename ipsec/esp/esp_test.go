package esp

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"testing"
)

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
		SPI:          0x11223344,
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

func TestCodecHMACIntegrityRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		integrity string
		key       []byte
	}{
		{name: "HMAC MD5 96", integrity: IntegrityHMACMD596, key: []byte("0123456789abcdef")},
		{name: "HMAC SHA1 96", integrity: IntegrityHMACSHA196, key: []byte("0123456789abcdef0123")},
		{name: "AES XCBC 96", integrity: IntegrityAESXCBC96, key: []byte("0123456789abcdef")},
		{name: "HMAC SHA256 128", integrity: IntegrityHMACSHA256128, key: bytes.Repeat([]byte{0x11}, 32)},
		{name: "HMAC SHA384 192", integrity: IntegrityHMACSHA384192, key: bytes.Repeat([]byte{0x11}, 48)},
		{name: "HMAC SHA512 256", integrity: IntegrityHMACSHA512256, key: bytes.Repeat([]byte{0x11}, 64)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := Codec{
				SPI:          0x11223344,
				Encryption:   EncryptionNull,
				Integrity:    tt.integrity,
				IntegrityKey: tt.key,
			}
			pkt := ESPPacket{SPI: codec.SPI, Sequence: 7, NextHeader: 17, Payload: []byte("REGISTER")}
			wire, err := codec.Encode(pkt)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			decoded, err := codec.Decode(wire)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if string(decoded.Payload) != string(pkt.Payload) {
				t.Fatalf("Decode() payload = %q, want %q", decoded.Payload, pkt.Payload)
			}
			wire[len(wire)-1] ^= 0xff
			if _, err := codec.Decode(wire); err == nil {
				t.Fatal("Decode() error = nil after ICV corruption")
			}
		})
	}
}

func TestCodecAESCTRRoundTripAndTamper(t *testing.T) {
	tests := []struct {
		name string
		key  []byte
		salt [4]byte
	}{
		{
			name: "AES-CTR 128",
			key:  []byte("0123456789abcdef"),
			salt: [4]byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "AES-CTR 256",
			key:  []byte("0123456789abcdef0123456789abcdef"),
			salt: [4]byte{0x05, 0x06, 0x07, 0x08},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := Codec{
				SPI:           0x11223344,
				Encryption:    EncryptionAESCTR,
				EncryptionKey: tt.key,
				Integrity:     IntegrityHMACSHA196,
				IntegrityKey:  []byte("0123456789abcdef0123"),
				Salt:          tt.salt,
			}
			packet := ESPPacket{
				SPI:        codec.SPI,
				Sequence:   7,
				NextHeader: 17,
				Payload:    []byte("REGISTER"),
			}
			wire, err := codec.Encode(packet)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}
			if len(wire) < espHeaderLen+espExplicitIVLen+12 {
				t.Fatalf("Encode() length = %d, want ESP header + IV + ICV", len(wire))
			}
			decoded, err := codec.Decode(wire)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if decoded.NextHeader != packet.NextHeader || !bytes.Equal(decoded.Payload, packet.Payload) {
				t.Fatalf("Decode() = %+v, want %+v", decoded, packet)
			}

			tampered := append([]byte(nil), wire...)
			tampered[espHeaderLen+espExplicitIVLen] ^= 0x01
			if _, err := codec.Decode(tampered); err == nil {
				t.Fatal("Decode(tampered) error = nil, want integrity error")
			}
		})
	}
}

func TestCodecRejectsAESCTRWithoutIntegrity(t *testing.T) {
	tests := []struct {
		name   string
		encode bool
	}{
		{name: "encode", encode: true},
		{name: "decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := Codec{
				SPI:           0x11223344,
				Encryption:    EncryptionAESCTR,
				EncryptionKey: []byte("0123456789abcdef"),
				Integrity:     IntegrityNone,
				Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
			}
			if tt.encode {
				_, err := codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: 7, NextHeader: 17, Payload: []byte("REGISTER")})
				if err == nil {
					t.Fatal("Encode() error = nil, want AES-CTR integrity error")
				}
				return
			}
			if _, err := codec.Decode(make([]byte, espMinPacketLen)); err == nil {
				t.Fatal("Decode() error = nil, want AES-CTR integrity error")
			}
		})
	}
}

func TestCodecRejectsNullEncryptionWithoutIntegrity(t *testing.T) {
	codec := Codec{SPI: 0x11223344, Encryption: EncryptionNull, Integrity: IntegrityNone}
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
				SPI:           0x11223344,
				Encryption:    EncryptionAESGCM,
				EncryptionKey: []byte("0123456789abcdef"),
				Integrity:     IntegrityNull,
				Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "aes gmac",
			codec: Codec{
				SPI:          0x11223344,
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

func TestCodecAESGMACUsesRFC4543AAD(t *testing.T) {
	key := []byte("0123456789abcdef")
	salt := [4]byte{0x05, 0x06, 0x07, 0x08}
	pkt := ESPPacket{
		SPI:        0x11223344,
		Sequence:   7,
		NextHeader: 17,
		Payload:    []byte{0xAA, 0xBB, 0xCC},
	}
	codec := Codec{
		SPI:          pkt.SPI,
		Encryption:   EncryptionNull,
		Integrity:    IntegrityAESGMAC,
		IntegrityKey: key,
		Salt:         salt,
	}

	wire, err := codec.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	plaintext := append([]byte(nil), pkt.Payload...)
	padLen := paddingLength(len(plaintext)+espTrailerLen, espDefaultAlign)
	for i := 1; i <= padLen; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, byte(padLen), pkt.NextHeader)

	header := make([]byte, espHeaderLen)
	binary.BigEndian.PutUint32(header[:espSPILen], pkt.SPI)
	binary.BigEndian.PutUint32(header[espSPILen:espHeaderLen], pkt.Sequence)
	iv := wire[espHeaderLen : espHeaderLen+espExplicitIVLen]
	aad := append(append([]byte(nil), header...), plaintext...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	aead, err := cipher.NewGCMWithTagSize(block, espGCMICVLen)
	if err != nil {
		t.Fatalf("NewGCMWithTagSize() error = %v", err)
	}
	nonceValue := append(append([]byte(nil), salt[:]...), iv...)
	wantTag := aead.Seal(nil, nonceValue, nil, aad)
	gotTag := wire[len(wire)-espGCMICVLen:]
	if !bytes.Equal(gotTag, wantTag) {
		t.Fatalf("AES-GMAC tag = % X, want RFC 4543 AAD tag % X", gotTag, wantTag)
	}

	wrongTag := aead.Seal(nil, nonceValue, nil, wire[:len(wire)-espGCMICVLen])
	wrongWire := append([]byte(nil), wire...)
	copy(wrongWire[len(wrongWire)-espGCMICVLen:], wrongTag)
	if _, err := codec.Decode(wrongWire); err == nil {
		t.Fatal("Decode() accepted tag computed with explicit IV in AAD")
	}
}

func TestESPSealRequiresNextHeader(t *testing.T) {
	esp, err := NewESP(Config{
		SPI:           0x11223344,
		EncryptionKey: []byte("0123456789abcdef"),
		IntegrityKey:  []byte("0123456789abcdef0123"),
	})
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	if _, err := esp.Seal([]byte("payload")); err == nil {
		t.Fatal("Seal() error = nil, want next header error")
	}
	if _, err := esp.SealWithNextHeader([]byte("payload"), NextHeaderNoNext); err == nil {
		t.Fatal("SealWithNextHeader() dummy error = nil")
	}
	wire, err := esp.SealWithNextHeader([]byte("payload"), 17)
	if err != nil {
		t.Fatalf("SealWithNextHeader() error = %v", err)
	}
	got, err := esp.Open(wire)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if string(got) != "payload" {
		t.Fatalf("Open() = %q, want payload", got)
	}
}

func TestNewESPValidatesTS33203Config(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		ok   bool
	}{
		{
			name: "valid separate encryption and integrity keys",
			cfg: Config{
				SPI:           0x11223344,
				EncryptionKey: []byte("0123456789abcdef"),
				IntegrityKey:  []byte("0123456789abcdef0123"),
			},
			ok: true,
		},
		{
			name: "reserved spi",
			cfg: Config{
				SPI:           ReservedSPIMax,
				EncryptionKey: []byte("0123456789abcdef"),
				IntegrityKey:  []byte("0123456789abcdef0123"),
			},
		},
		{
			name: "short encryption key",
			cfg: Config{
				SPI:           0x11223344,
				EncryptionKey: []byte("short"),
				IntegrityKey:  []byte("0123456789abcdef0123"),
			},
		},
		{
			name: "short integrity key",
			cfg: Config{
				SPI:           0x11223344,
				EncryptionKey: []byte("0123456789abcdef"),
				IntegrityKey:  []byte("short"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewESP(tt.cfg)
			if (err == nil) != tt.ok {
				t.Fatalf("NewESP() error = %v, ok %t", err, tt.ok)
			}
		})
	}
}

func TestESPSealUsesDistinctCBCIVs(t *testing.T) {
	esp, err := NewESP(Config{
		SPI:           0x11223344,
		EncryptionKey: []byte("0123456789abcdef"),
		IntegrityKey:  []byte("0123456789abcdef0123"),
	})
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	first, err := esp.SealWithNextHeader([]byte("payload"), 17)
	if err != nil {
		t.Fatalf("SealWithNextHeader() first error = %v", err)
	}
	second, err := esp.SealWithNextHeader([]byte("payload"), 17)
	if err != nil {
		t.Fatalf("SealWithNextHeader() second error = %v", err)
	}
	firstIV := first[espHeaderLen : espHeaderLen+aes.BlockSize]
	secondIV := second[espHeaderLen : espHeaderLen+aes.BlockSize]
	if bytes.Equal(firstIV, secondIV) {
		t.Fatalf("AES-CBC IV repeated: % X", firstIV)
	}
}

func TestCodecRejectsMismatchedSPI(t *testing.T) {
	const (
		packetSPIValue = uint32(0x11223344)
		otherSPI       = uint32(0x55667788)
	)
	base := Codec{
		SPI:          packetSPIValue,
		Encryption:   EncryptionNull,
		Integrity:    IntegrityHMACSHA196,
		IntegrityKey: []byte("0123456789abcdef0123"),
	}
	pkt := ESPPacket{SPI: packetSPIValue, Sequence: 1, NextHeader: 17, Payload: []byte("payload")}
	wire, err := base.Encode(pkt)
	if err != nil {
		t.Fatalf("Encode() fixture error = %v", err)
	}

	tests := []struct {
		name   string
		encode bool
	}{
		{name: "encode", encode: true},
		{name: "decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codec := base
			codec.SPI = otherSPI
			if tt.encode {
				if _, err := codec.Encode(pkt); err == nil {
					t.Fatal("Encode() error = nil, want SPI mismatch")
				}
				return
			}
			if _, err := codec.Decode(wire); err == nil {
				t.Fatal("Decode() error = nil, want SPI mismatch")
			}
		})
	}
}

func TestCodecRejectsInvalidKeyLengths(t *testing.T) {
	tests := []struct {
		name  string
		codec Codec
	}{
		{
			name: "aes cbc",
			codec: Codec{
				SPI:           0x11223344,
				Encryption:    EncryptionAESCBC,
				EncryptionKey: []byte("short"),
				Integrity:     IntegrityHMACSHA196,
				IntegrityKey:  []byte("0123456789abcdef0123"),
			},
		},
		{
			name: "aes gcm",
			codec: Codec{
				SPI:           0x11223344,
				Encryption:    EncryptionAESGCM,
				EncryptionKey: []byte("short"),
				Integrity:     IntegrityNull,
			},
		},
		{
			name: "aes gmac",
			codec: Codec{
				SPI:          0x11223344,
				Encryption:   EncryptionNull,
				Integrity:    IntegrityAESGMAC,
				IntegrityKey: []byte("short"),
			},
		},
		{
			name: "short SHA256 integrity key",
			codec: Codec{
				SPI:          0x11223344,
				Encryption:   EncryptionNull,
				Integrity:    IntegrityHMACSHA256128,
				IntegrityKey: []byte("short"),
			},
		},
		{
			name: "short SHA384 integrity key",
			codec: Codec{
				SPI:          0x11223344,
				Encryption:   EncryptionNull,
				Integrity:    IntegrityHMACSHA384192,
				IntegrityKey: bytes.Repeat([]byte{0x11}, 32),
			},
		},
		{
			name: "empty hmac key",
			codec: Codec{
				SPI:        0x11223344,
				Encryption: EncryptionNull,
				Integrity:  IntegrityHMACSHA196,
			},
		},
	}

	pkt := ESPPacket{SPI: 0x11223344, Sequence: 1, NextHeader: 17}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.codec.Encode(pkt); err == nil {
				t.Fatal("Encode() error = nil, want key length error")
			}
		})
	}
}

func TestCodecRejectsInvalidESPHeader(t *testing.T) {
	tests := []struct {
		name     string
		spi      uint32
		sequence uint32
	}{
		{name: "zero spi", spi: 0, sequence: 1},
		{name: "reserved spi", spi: ReservedSPIMax, sequence: 1},
		{name: "zero sequence", spi: 0x11223344, sequence: 0},
	}
	codec := Codec{
		SPI:          0x11223344,
		Encryption:   EncryptionNull,
		Integrity:    IntegrityHMACSHA196,
		IntegrityKey: []byte("0123456789abcdef"),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Encode(ESPPacket{SPI: tt.spi, Sequence: tt.sequence, NextHeader: 17}); err == nil {
				t.Fatal("Encode() error = nil, want invalid ESP header error")
			}
		})
	}
}

func TestCodecNormalizesIntegrityNames(t *testing.T) {
	codec := Codec{
		SPI:          0x11223344,
		Encryption:   EncryptionNull,
		Integrity:    " AES-GMAC ",
		IntegrityKey: []byte("0123456789abcdef"),
		Salt:         [4]byte{0x05, 0x06, 0x07, 0x08},
	}
	wire, err := codec.Encode(ESPPacket{SPI: codec.SPI, Sequence: 1, NextHeader: 17, Payload: []byte("payload")})
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	if _, err := codec.Decode(wire); err != nil {
		t.Fatalf("Decode() error = %v", err)
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
				SPI:           0x11223344,
				Encryption:    EncryptionAESGCM,
				EncryptionKey: []byte("0123456789abcdef"),
				Integrity:     IntegrityNull,
				Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
			},
		},
		{
			name: "aes gmac",
			codec: Codec{
				SPI:          0x11223344,
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
			otherCodec := tt.codec
			otherCodec.SPI = packet.SPI
			other, err := otherCodec.Encode(packet)
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
