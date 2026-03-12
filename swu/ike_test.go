package swu

import "testing"

func TestIKEHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header IKEHeader
	}{
		{"basic", IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, NextPayload: 33, Version: 0x20, ExchangeType: 34, Flags: 0x08, MessageID: 7, Length: ikeHeaderSize}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.header.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got IKEHeader
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got != tt.header {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.header)
			}

		})
	}
}

func TestIKEPacketBinaryCodec(t *testing.T) {
	tests := []struct {
		name   string
		packet IKEPacket
	}{
		{
			name: "nonce",
			packet: IKEPacket{
				Header:   IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: 9},
				Payloads: []Payload{&NoncePayload{Data: []byte{0x01, 0x02, 0x03}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var got IKEPacket
			if err := got.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Header.MessageID != tt.packet.Header.MessageID || got.Header.ExchangeType != tt.packet.Header.ExchangeType {
				t.Fatalf("header = %+v, want %+v", got.Header, tt.packet.Header)
			}
			if len(got.Payloads) != len(tt.packet.Payloads) {
				t.Fatalf("payload count = %d, want %d", len(got.Payloads), len(tt.packet.Payloads))
			}

			var parsed IKEPacket
			if err := parsed.UnmarshalBinary(data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if parsed.Header.Length != got.Header.Length {
				t.Fatalf("UnmarshalBinary() length = %d, want %d", parsed.Header.Length, got.Header.Length)
			}
		})
	}
}
