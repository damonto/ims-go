package ike

import "testing"

func TestIKEHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		header IKEHeader
	}{
		{
			name: "basic",
			header: IKEHeader{
				InitiatorSPI: 1,
				ResponderSPI: 2,
				NextPayload:  33,
				Version:      Version20,
				ExchangeType: ExchangeTypeIKEAuth,
				Flags:        FlagInitiator,
				MessageID:    7,
				Length:       28,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.header.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got IKEHeader
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got != tt.header {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.header)
			}
		})
	}
}

func TestIKEPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		packet IKEPacket
	}{
		{
			name: "nonce payload",
			packet: IKEPacket{
				Header: IKEHeader{
					InitiatorSPI: 10,
					ResponderSPI: 20,
					Version:      Version20,
					ExchangeType: ExchangeTypeIKESAInit,
					Flags:        FlagResponse,
					MessageID:    0,
				},
				Payloads: []Payload{&NoncePayload{Data: []byte{0x01, 0x02, 0x03, 0x04}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got IKEPacket
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Header.InitiatorSPI != tt.packet.Header.InitiatorSPI || got.Header.ExchangeType != tt.packet.Header.ExchangeType {
				t.Fatalf("Header = %+v, want %+v", got.Header, tt.packet.Header)
			}
			nonce, ok := got.Payloads[0].(*NoncePayload)
			if !ok {
				t.Fatalf("Payload[0] type = %T, want *NoncePayload", got.Payloads[0])
			}
			if string(nonce.Data) != string([]byte{0x01, 0x02, 0x03, 0x04}) {
				t.Fatalf("NoncePayload.Data = %x", nonce.Data)
			}
		})
	}
}
