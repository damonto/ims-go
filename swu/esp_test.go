package swu

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"
)

func TestESPSealOpen(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
	}{
		{"short", []byte("hello")},
		{"long", bytes.Repeat([]byte("a"), 256)},
	}
	cfg := ESPConfig{SPI: 7, Key: bytes.Repeat([]byte{0x11}, 16), Salt: [4]byte{0xAA, 0xBB, 0xCC, 0xDD}}
	esp, err := NewESP(cfg)
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealed, err := esp.Seal(tt.payload)
			if err != nil {
				t.Fatalf("Seal() error = %v", err)
			}
			opened, err := esp.Open(sealed)
			if err != nil {
				t.Fatalf("Open() error = %v", err)
			}
			if !bytes.Equal(opened, tt.payload) {
				t.Fatalf("Open() = %X, want %X", opened, tt.payload)
			}
		})
	}
}

func TestESPWrongSPI(t *testing.T) {
	esp, err := NewESP(ESPConfig{SPI: 1, Key: bytes.Repeat([]byte{0x22}, 16)})
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	packet, err := esp.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	packet[3] = 0x02
	if _, err := esp.Open(packet); err == nil {
		t.Fatal("Open() error = nil, want error")
	}
}

func TestESPRejectReplay(t *testing.T) {
	esp, err := NewESP(ESPConfig{SPI: 9, Key: bytes.Repeat([]byte{0x33}, 16)})
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	packet, err := esp.Seal([]byte("payload"))
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if _, err := esp.Open(packet); err != nil {
		t.Fatalf("Open() first error = %v", err)
	}
	if _, err := esp.Open(packet); err == nil {
		t.Fatal("Open() replay error = nil, want non-nil")
	}
}

func TestESPSequenceOverflow(t *testing.T) {
	esp, err := NewESP(ESPConfig{SPI: 11, Key: bytes.Repeat([]byte{0x44}, 16)})
	if err != nil {
		t.Fatalf("NewESP() error = %v", err)
	}
	esp.seq = math.MaxUint32
	if _, err := esp.Seal([]byte("payload")); err == nil {
		t.Fatal("Seal() overflow error = nil, want non-nil")
	}
}

func TestESPDecodeRejectsInvalidPadding(t *testing.T) {
	codec := ESPCodec{SPI: 7, Encryption: EncryptionNull, Integrity: IntegrityNone}
	packet := make([]byte, 0, 16)
	header := make([]byte, 8)
	binary.BigEndian.PutUint32(header[:4], codec.SPI)
	binary.BigEndian.PutUint32(header[4:8], 1)
	packet = append(packet, header...)
	packet = append(packet, []byte("ok")...)
	packet = append(packet, 0x00, 0x00, 0x02, 0x11)
	if _, err := codec.Decode(packet); err == nil {
		t.Fatal("Decode() error = nil, want non-nil")
	}
}
