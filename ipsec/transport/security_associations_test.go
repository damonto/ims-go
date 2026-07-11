package transport

import (
	"testing"

	"github.com/damonto/ims-go/ipsec/esp"
	"github.com/damonto/ims-go/ipsec/packet"
)

func TestSecurityAssociationsSharesOutboundSequenceBySA(t *testing.T) {
	associations := NewSecurityAssociations()
	codec := esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: []byte("0123456789abcdef")}

	first, err := associations.sealESP(codec, packet.ProtocolUDP, []byte("first"))
	if err != nil {
		t.Fatalf("sealESP() first error = %v", err)
	}
	second, err := associations.sealESP(codec, packet.ProtocolTCP, []byte("second"))
	if err != nil {
		t.Fatalf("sealESP() second error = %v", err)
	}

	firstPacket, err := codec.Decode(first)
	if err != nil {
		t.Fatalf("Decode() first error = %v", err)
	}
	secondPacket, err := codec.Decode(second)
	if err != nil {
		t.Fatalf("Decode() second error = %v", err)
	}
	if firstPacket.Sequence != 1 {
		t.Fatalf("first sequence = %d, want 1", firstPacket.Sequence)
	}
	if secondPacket.Sequence != 2 {
		t.Fatalf("second sequence = %d, want 2", secondPacket.Sequence)
	}
}

func TestSecurityAssociationsKeepsOutboundSequencePerSalt(t *testing.T) {
	associations := NewSecurityAssociations()
	base := esp.Codec{
		SPI:           0x10203040,
		Encryption:    esp.EncryptionAESGCM,
		EncryptionKey: []byte("0123456789abcdef"),
		Integrity:     esp.IntegrityNull,
	}
	codecA := base
	codecA.Salt = [4]byte{0x01, 0x02, 0x03, 0x04}
	codecB := base
	codecB.Salt = [4]byte{0x05, 0x06, 0x07, 0x08}

	tests := []struct {
		name  string
		codec esp.Codec
	}{
		{name: "first salt", codec: codecA},
		{name: "second salt", codec: codecB},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := associations.sealESP(tt.codec, packet.ProtocolUDP, []byte("payload"))
			if err != nil {
				t.Fatalf("sealESP() error = %v", err)
			}
			espPacket, err := tt.codec.Decode(wire)
			if err != nil {
				t.Fatalf("Decode() error = %v", err)
			}
			if espPacket.Sequence != 1 {
				t.Fatalf("sequence = %d, want 1", espPacket.Sequence)
			}
		})
	}
}

func TestSecurityAssociationsInboundReplaySharedBySA(t *testing.T) {
	associations := NewSecurityAssociations()
	codec := esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: []byte("0123456789abcdef")}

	tests := []struct {
		name     string
		sequence uint32
		want     bool
	}{
		{name: "first packet accepted", sequence: 1, want: true},
		{name: "duplicate rejected", sequence: 1, want: false},
		{name: "next packet accepted", sequence: 2, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := associations.acceptInboundESP(codec, tt.sequence); got != tt.want {
				t.Fatalf("acceptInboundESP() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSecurityAssociationsAEADInboundReplayProtected(t *testing.T) {
	associations := NewSecurityAssociations()
	codec := esp.Codec{
		SPI:           0x10203040,
		Encryption:    esp.EncryptionAESGCM,
		EncryptionKey: []byte("0123456789abcdef"),
		Integrity:     esp.IntegrityNull,
		Salt:          [4]byte{0x01, 0x02, 0x03, 0x04},
	}

	tests := []struct {
		name     string
		sequence uint32
		want     bool
	}{
		{name: "first packet accepted", sequence: 1, want: true},
		{name: "duplicate rejected", sequence: 1, want: false},
		{name: "next packet accepted", sequence: 2, want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := associations.acceptInboundESP(codec, tt.sequence); got != tt.want {
				t.Fatalf("acceptInboundESP() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestSecurityAssociationsInboundReplayPrecheckDoesNotAdvanceWindow(t *testing.T) {
	associations := NewSecurityAssociations()
	codec := esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: []byte("0123456789abcdef")}

	if !associations.mayAcceptInboundESP(codec, 1) {
		t.Fatal("mayAcceptInboundESP() first = false, want true")
	}
	if !associations.mayAcceptInboundESP(codec, 1) {
		t.Fatal("mayAcceptInboundESP() second = false, want true before commit")
	}
	if !associations.acceptInboundESP(codec, 1) {
		t.Fatal("acceptInboundESP() first = false, want true")
	}
	if associations.mayAcceptInboundESP(codec, 1) {
		t.Fatal("mayAcceptInboundESP() duplicate = true, want false after commit")
	}
	if associations.acceptInboundESP(codec, 1) {
		t.Fatal("acceptInboundESP() duplicate = true, want false")
	}
}

func TestSecurityAssociationsZeroValue(t *testing.T) {
	var associations SecurityAssociations
	codec := esp.Codec{SPI: 0x10203040, Encryption: esp.EncryptionNull, Integrity: esp.IntegrityHMACSHA196, IntegrityKey: []byte("0123456789abcdef")}

	wire, err := associations.sealESP(codec, packet.ProtocolUDP, []byte("payload"))
	if err != nil {
		t.Fatalf("sealESP() error = %v", err)
	}
	espPacket, err := codec.Decode(wire)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if espPacket.Sequence != 1 {
		t.Fatalf("sequence = %d, want 1", espPacket.Sequence)
	}
	if !associations.acceptInboundESP(codec, 1) {
		t.Fatal("first inbound packet was rejected")
	}
	if associations.acceptInboundESP(codec, 1) {
		t.Fatal("duplicate inbound packet was accepted")
	}
}
