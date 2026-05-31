package ike

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

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
				Version:      ikeVersion20,
				ExchangeType: exchangeTypeIKEAuth,
				Flags:        flagInitiator,
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
					Version:      ikeVersion20,
					ExchangeType: exchangeTypeIKESAInit,
					Flags:        flagResponse,
					MessageID:    0,
				},
				Payloads: []Payload{&NoncePayload{Data: bytes.Repeat([]byte{0x01}, nonceDataMinLen)}},
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
			if !bytes.Equal(nonce.Data, bytes.Repeat([]byte{0x01}, nonceDataMinLen)) {
				t.Fatalf("NoncePayload.Data = %x", nonce.Data)
			}
		})
	}
}

func TestIKEPacketRejectsMalformedHeader(t *testing.T) {
	validWire, err := (IKEPacket{
		Header: IKEHeader{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKESAInit,
			Flags:        flagResponse,
			MessageID:    0,
		},
		Payloads: []Payload{&NoncePayload{Data: bytes.Repeat([]byte{0x01}, nonceDataMinLen)}},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	tests := []struct {
		name    string
		mutate  func([]byte) []byte
		wantErr string
	}{
		{
			name: "major version too small",
			mutate: func(wire []byte) []byte {
				wire[17] = 0x10
				return wire
			},
			wantErr: "invalid major version",
		},
		{
			name: "major version too large",
			mutate: func(wire []byte) []byte {
				wire[17] = 0x30
				return wire
			},
			wantErr: "invalid major version",
		},
		{
			name: "invalid exchange type",
			mutate: func(wire []byte) []byte {
				wire[18] = 33
				return wire
			},
			wantErr: "invalid exchange type",
		},
		{
			name: "trailing bytes",
			mutate: func(wire []byte) []byte {
				return append(wire, 0x00)
			},
			wantErr: "invalid packet length",
		},
		{
			name: "header only",
			mutate: func([]byte) []byte {
				header, err := (IKEHeader{
					InitiatorSPI: 1,
					ResponderSPI: 2,
					Version:      ikeVersion20,
					ExchangeType: exchangeTypeInformational,
					Flags:        flagResponse,
					Length:       ikeHeaderSize,
				}).MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				return header
			},
			wantErr: "invalid packet length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire := append([]byte(nil), validWire...)
			wire = tt.mutate(wire)
			var got IKEPacket
			err := got.UnmarshalBinary(wire)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestNoncePayloadValidatesDataLength(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "minimum", data: bytes.Repeat([]byte{0x01}, nonceDataMinLen)},
		{name: "maximum", data: bytes.Repeat([]byte{0x01}, nonceDataMaxLen)},
		{name: "too short", data: bytes.Repeat([]byte{0x01}, nonceDataMinLen-1), wantErr: true},
		{name: "too long", data: bytes.Repeat([]byte{0x01}, nonceDataMaxLen+1), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := NoncePayload{Data: tt.data}
			_, marshalErr := payload.MarshalBinary()
			var decoded NoncePayload
			unmarshalErr := decoded.UnmarshalBinary(tt.data)
			if tt.wantErr {
				if marshalErr == nil || unmarshalErr == nil {
					t.Fatalf("nonce errors = (%v, %v), want both invalid length", marshalErr, unmarshalErr)
				}
				return
			}
			if marshalErr != nil || unmarshalErr != nil {
				t.Fatalf("nonce errors = (%v, %v), want nil", marshalErr, unmarshalErr)
			}
		})
	}
}

func TestDeletePayloadValidatesProtocolSPIShape(t *testing.T) {
	tests := []struct {
		name    string
		payload DeletePayload
		wantErr string
	}{
		{
			name:    "ike delete has no spis",
			payload: DeletePayload{ProtocolID: deleteProtocolIDIKE},
		},
		{
			name: "esp delete has four byte spi",
			payload: DeletePayload{
				ProtocolID: deleteProtocolIDESP,
				SPIs:       [][]byte{uint32Bytes(0x01020304)},
			},
		},
		{
			name: "ike delete rejects spis",
			payload: DeletePayload{
				ProtocolID: deleteProtocolIDIKE,
				SPIs:       [][]byte{uint32Bytes(0x01020304)},
			},
			wantErr: "protocol IKE requires zero spi size and count",
		},
		{
			name:    "esp delete rejects missing spi",
			payload: DeletePayload{ProtocolID: deleteProtocolIDESP},
			wantErr: "requires 4-byte spi and at least one spi",
		},
		{
			name: "esp delete rejects short spi",
			payload: DeletePayload{
				ProtocolID: deleteProtocolIDESP,
				SPIs:       [][]byte{{0x01, 0x02}},
			},
			wantErr: "requires 4-byte spi and at least one spi",
		},
		{
			name:    "unsupported protocol id",
			payload: DeletePayload{ProtocolID: 99},
			wantErr: "protocol id 99 is unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.payload.MarshalBinary()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got DeletePayload
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.ProtocolID != tt.payload.ProtocolID || len(got.SPIs) != len(tt.payload.SPIs) {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.payload)
			}
		})
	}
}

func TestDeletePayloadRejectsMalformedWire(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr string
	}{
		{
			name:    "ike delete with spi is invalid",
			wire:    deletePayloadWire(deleteProtocolIDIKE, [][]byte{uint32Bytes(0x01020304)}),
			wantErr: "protocol IKE requires zero spi size and count",
		},
		{
			name:    "esp delete without spi is invalid",
			wire:    []byte{deleteProtocolIDESP, 0, 0, 0},
			wantErr: "requires 4-byte spi and at least one spi",
		},
		{
			name:    "unsupported protocol id is invalid",
			wire:    []byte{99, 0, 0, 0},
			wantErr: "protocol id 99 is unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DeletePayload
			err := got.UnmarshalBinary(tt.wire)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestKeyExchangePayloadValidatesMODPDataLength(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr string
	}{
		{
			name: "valid 1024-bit modp key exchange",
			wire: keyExchangePayloadWire(dhGroup1024MODP, bytesOfLen(keyExchange1024MODPDataLength)),
		},
		{
			name:    "short 1024-bit modp key exchange",
			wire:    keyExchangePayloadWire(dhGroup1024MODP, bytesOfLen(keyExchange1024MODPDataLength-1)),
			wantErr: "invalid data length 127 for dh group 2",
		},
		{
			name:    "short 2048-bit modp key exchange",
			wire:    keyExchangePayloadWire(dhGroup2048MODP, bytesOfLen(keyExchange2048MODPDataLength-1)),
			wantErr: "invalid data length 255 for dh group 14",
		},
		{
			name: "unknown dh group length is left to negotiation",
			wire: keyExchangePayloadWire(65000, []byte{0x01}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got KeyExchangePayload
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.DHGroup != binary.BigEndian.Uint16(tt.wire[0:2]) {
				t.Fatalf("DHGroup = %d, want %d", got.DHGroup, binary.BigEndian.Uint16(tt.wire[0:2]))
			}
		})
	}
}

func TestKeyExchangePayloadMarshalValidatesMODPDataLength(t *testing.T) {
	tests := []struct {
		name    string
		payload KeyExchangePayload
		wantErr string
	}{
		{
			name: "valid 2048-bit modp key exchange",
			payload: KeyExchangePayload{
				DHGroup: dhGroup2048MODP,
				Data:    bytesOfLen(keyExchange2048MODPDataLength),
			},
		},
		{
			name: "short 2048-bit modp key exchange",
			payload: KeyExchangePayload{
				DHGroup: dhGroup2048MODP,
				Data:    bytesOfLen(keyExchange2048MODPDataLength - 1),
			},
			wantErr: "invalid data length 255 for dh group 14",
		},
		{
			name: "unknown dh group length is left to negotiation",
			payload: KeyExchangePayload{
				DHGroup: 65000,
				Data:    []byte{0x01},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.payload.MarshalBinary()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestTrafficSelectorValidatesWireShape(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr string
	}{
		{
			name: "valid ipv4",
			wire: trafficSelectorWire(
				trafficSelectorIPv4Range,
				ipProtocolUDP,
				0,
				65535,
				net.IPv4(0, 0, 0, 0).To4(),
				net.IPv4(255, 255, 255, 255).To4(),
			),
		},
		{
			name: "valid ipv6",
			wire: trafficSelectorWire(
				trafficSelectorIPv6Range,
				ipProtocolAny,
				0,
				65535,
				net.IPv6zero.To16(),
				net.ParseIP("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff").To16(),
			),
		},
		{
			name: "unknown type",
			wire: trafficSelectorWire(
				99,
				ipProtocolUDP,
				0,
				65535,
				net.IPv4(0, 0, 0, 0).To4(),
				net.IPv4(255, 255, 255, 255).To4(),
			),
			wantErr: "invalid type",
		},
		{
			name: "invalid protocol",
			wire: trafficSelectorWire(
				trafficSelectorIPv4Range,
				99,
				0,
				65535,
				net.IPv4(0, 0, 0, 0).To4(),
				net.IPv4(255, 255, 255, 255).To4(),
			),
			wantErr: "invalid ip protocol id",
		},
		{
			name: "wrong ipv4 length",
			wire: []byte{
				trafficSelectorIPv4Range, ipProtocolUDP, 0x00, 0x14,
				0x00, 0x00, 0xff, 0xff,
				0, 0, 0, 0,
				255, 255, 255, 255,
				0, 0, 0, 0,
			},
			wantErr: "invalid ipv4 length",
		},
		{
			name: "reversed ports",
			wire: trafficSelectorWire(
				trafficSelectorIPv4Range,
				ipProtocolTCP,
				5061,
				5060,
				net.IPv4(0, 0, 0, 0).To4(),
				net.IPv4(255, 255, 255, 255).To4(),
			),
			wantErr: "invalid port range",
		},
		{
			name: "reversed address",
			wire: trafficSelectorWire(
				trafficSelectorIPv4Range,
				ipProtocolUDP,
				0,
				65535,
				net.IPv4(192, 0, 2, 2).To4(),
				net.IPv4(192, 0, 2, 1).To4(),
			),
			wantErr: "invalid address range",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got TrafficSelector
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if _, err := got.MarshalBinary(); err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestTrafficSelectorPayloadRequiresSelectors(t *testing.T) {
	tests := []struct {
		name    string
		payload TrafficSelectorPayload
		wire    []byte
		wantErr string
	}{
		{
			name:    "marshal empty",
			payload: TrafficSelectorPayload{Tag: payloadTypeTSi},
			wantErr: "expected at least one selector",
		},
		{
			name:    "unmarshal empty",
			wire:    []byte{0, 0, 0, 0},
			wantErr: "expected at least one selector",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wire != nil {
				var got TrafficSelectorPayload
				err := got.UnmarshalBinary(tt.wire)
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			_, err := tt.payload.MarshalBinary()
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestTrafficSelectorContains(t *testing.T) {
	selector := func(protocol byte, startPort, endPort uint16, start, end net.IP) TrafficSelector {
		return TrafficSelector{
			Type:       trafficSelectorIPv4Range,
			ProtocolID: protocol,
			Data:       trafficSelectorWire(trafficSelectorIPv4Range, protocol, startPort, endPort, start.To4(), end.To4())[trafficSelectorHeaderLen:],
		}
	}
	tests := []struct {
		name string
		base TrafficSelector
		sub  TrafficSelector
		want bool
	}{
		{
			name: "same selector",
			base: selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			sub:  selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			want: true,
		},
		{
			name: "narrower ports and addresses",
			base: selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			sub:  selector(ipProtocolUDP, 5060, 5061, net.IPv4(10, 0, 0, 3), net.IPv4(10, 0, 0, 4)),
			want: true,
		},
		{
			name: "protocol must match android behavior",
			base: selector(ipProtocolAny, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			sub:  selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
		},
		{
			name: "port outside range",
			base: selector(ipProtocolUDP, 5060, 5061, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			sub:  selector(ipProtocolUDP, 5060, 5062, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
		},
		{
			name: "address outside range",
			base: selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 10)),
			sub:  selector(ipProtocolUDP, 0, 65535, net.IPv4(10, 0, 0, 1), net.IPv4(10, 0, 0, 11)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.base.Contains(tt.sub); got != tt.want {
				t.Fatalf("Contains() = %t, want %t", got, tt.want)
			}
		})
	}
}

func TestTransformRejectsMalformedAttributes(t *testing.T) {
	tests := []struct {
		name    string
		body    []byte
		wantErr string
	}{
		{
			name: "duplicate key length",
			body: append(
				[]byte{1, 0, 0, 12},
				append(transformTVAttribute(transformAttrKeyLength, 128), transformTVAttribute(transformAttrKeyLength, 256)...)...,
			),
			wantErr: "duplicate attribute",
		},
		{
			name: "key length as tlv",
			body: append(
				[]byte{1, 0, 0, 12},
				transformTLVAttribute(transformAttrKeyLength, []byte{0x00, 0x80})...,
			),
			wantErr: "must use TV format",
		},
		{
			name: "single key length",
			body: append([]byte{1, 0, 0, 12}, transformTVAttribute(transformAttrKeyLength, 128)...),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got Transform
			err := got.UnmarshalBinary(tt.body)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if _, err := got.MarshalBinary(); err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestSecurityAssociationRejectsMalformedProposals(t *testing.T) {
	const transformTypeENCR = 1
	validTransform := transformSubstructure(t, payloadTypeNone, []byte{transformTypeENCR, 0, 0, 12})
	tests := []struct {
		name    string
		body    []byte
		wantErr string
	}{
		{
			name:    "empty sa",
			body:    nil,
			wantErr: "proposal count is zero",
		},
		{
			name:    "zero transforms",
			body:    proposalSubstructure(t, payloadTypeNone, []byte{1, protocolIDIKE, proposalSPISizeNone, 0}),
			wantErr: "transform count is zero",
		},
		{
			name: "invalid spi size",
			body: proposalSubstructure(t, payloadTypeNone, append(
				[]byte{1, protocolIDIKE, 2, 1, 0x01, 0x02},
				validTransform...,
			)),
			wantErr: "invalid spi size",
		},
		{
			name: "invalid proposal tag",
			body: proposalSubstructure(t, 5, append(
				[]byte{1, protocolIDIKE, proposalSPISizeNone, 1},
				validTransform...,
			)),
			wantErr: "invalid proposal substructure tag",
		},
		{
			name: "proposal tag says more without next proposal",
			body: proposalSubstructure(t, payloadTypeProposal, append(
				[]byte{1, protocolIDIKE, proposalSPISizeNone, 1},
				validTransform...,
			)),
			wantErr: "proposal substructure chain is truncated",
		},
		{
			name: "invalid transform tag",
			body: proposalSubstructure(t, payloadTypeNone, append(
				[]byte{1, protocolIDIKE, proposalSPISizeNone, 1},
				transformSubstructure(t, 7, []byte{transformTypeENCR, 0, 0, 12})...,
			)),
			wantErr: "invalid transform substructure tag",
		},
		{
			name: "transform tag says more without next transform",
			body: proposalSubstructure(t, payloadTypeNone, append(
				[]byte{1, protocolIDIKE, proposalSPISizeNone, 1},
				transformSubstructure(t, payloadTypeTransform, []byte{transformTypeENCR, 0, 0, 12})...,
			)),
			wantErr: "transform substructure chain is truncated",
		},
		{
			name: "valid single proposal",
			body: proposalSubstructure(t, payloadTypeNone, append(
				[]byte{1, protocolIDIKE, proposalSPISizeNone, 1},
				validTransform...,
			)),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got SecurityAssociationPayload
			err := got.UnmarshalBinary(tt.body)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
		})
	}
}

func TestSecurityAssociationMarshalPreservesAcceptedProposalNumber(t *testing.T) {
	const transformTypeENCR = 1
	payload := &SecurityAssociationPayload{
		Proposals: []Proposal{
			{
				Number:     2,
				ProtocolID: protocolIDIKE,
				Transforms: []Transform{{TransformType: transformTypeENCR, ID: 12}},
			},
		},
	}

	wire, err := payload.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var got SecurityAssociationPayload
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got.Proposals[0].Number != 2 {
		t.Fatalf("proposal number = %d, want 2", got.Proposals[0].Number)
	}
}

func TestSecurityAssociationMarshalRejectsNonSequentialRequestProposals(t *testing.T) {
	const transformTypeENCR = 1
	payload := &SecurityAssociationPayload{
		Proposals: []Proposal{
			{
				Number:     1,
				ProtocolID: protocolIDIKE,
				Transforms: []Transform{{TransformType: transformTypeENCR, ID: 12}},
			},
			{
				Number:     3,
				ProtocolID: protocolIDIKE,
				Transforms: []Transform{{TransformType: transformTypeENCR, ID: 12}},
			},
		},
	}

	_, err := payload.MarshalBinary()
	if err == nil || !strings.Contains(err.Error(), "proposal number = 3, want 2") {
		t.Fatalf("MarshalBinary() error = %v, want non-sequential proposal number", err)
	}
}

func TestNotifyPayloadValidatesProtocolSPIShape(t *testing.T) {
	tests := []struct {
		name    string
		payload NotifyPayload
		wantErr string
	}{
		{
			name:    "ike notify has no spi",
			payload: NotifyPayload{NotifyType: 14},
		},
		{
			name: "esp rekey has four byte spi",
			payload: NotifyPayload{
				ProtocolID: protocolIDESP,
				NotifyType: notifyTypeRekeySA,
				SPI:        uint32Bytes(0x01020304),
			},
		},
		{
			name: "notify without spi rejects protocol id",
			payload: NotifyPayload{
				ProtocolID: protocolIDESP,
				NotifyType: 14,
			},
			wantErr: "without spi requires protocol id 0",
		},
		{
			name: "invalid selectors requires spi",
			payload: NotifyPayload{
				NotifyType: notifyTypeInvalidSelectors,
			},
			wantErr: "requires child sa spi",
		},
		{
			name: "rekey sa requires spi",
			payload: NotifyPayload{
				NotifyType: notifyTypeRekeySA,
			},
			wantErr: "requires child sa spi",
		},
		{
			name: "spi rejects unsupported protocol id",
			payload: NotifyPayload{
				ProtocolID: 99,
				NotifyType: notifyTypeRekeySA,
				SPI:        uint32Bytes(0x01020304),
			},
			wantErr: "requires protocol AH or ESP",
		},
		{
			name: "spi rejects ike notify type",
			payload: NotifyPayload{
				ProtocolID: protocolIDESP,
				NotifyType: 14,
				SPI:        uint32Bytes(0x01020304),
			},
			wantErr: "requires existing child sa notify type",
		},
		{
			name: "spi rejects invalid size",
			payload: NotifyPayload{
				ProtocolID: protocolIDESP,
				NotifyType: notifyTypeRekeySA,
				SPI:        []byte{0x01, 0x02},
			},
			wantErr: "invalid spi size 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.payload.MarshalBinary()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got NotifyPayload
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.ProtocolID != tt.payload.ProtocolID || got.NotifyType != tt.payload.NotifyType || string(got.SPI) != string(tt.payload.SPI) {
				t.Fatalf("UnmarshalBinary() = %+v, want %+v", got, tt.payload)
			}
		})
	}
}

func TestNotifyPayloadRejectsMalformedWire(t *testing.T) {
	tests := []struct {
		name    string
		wire    []byte
		wantErr string
	}{
		{
			name:    "invalid spi size",
			wire:    notifyPayloadWire(protocolIDESP, notifyTypeRekeySA, []byte{0x01, 0x02}, nil),
			wantErr: "invalid spi size 2",
		},
		{
			name:    "spi without ah or esp protocol is invalid",
			wire:    notifyPayloadWire(0, notifyTypeRekeySA, uint32Bytes(0x01020304), nil),
			wantErr: "requires protocol AH or ESP",
		},
		{
			name:    "spi with ike notify type is invalid",
			wire:    notifyPayloadWire(protocolIDESP, 14, uint32Bytes(0x01020304), nil),
			wantErr: "requires existing child sa notify type",
		},
		{
			name:    "child sa not found without spi is invalid",
			wire:    notifyPayloadWire(0, notifyTypeChildSANotFound, nil, nil),
			wantErr: "requires child sa spi",
		},
		{
			name:    "rekey sa without spi is invalid",
			wire:    notifyPayloadWire(0, notifyTypeRekeySA, nil, nil),
			wantErr: "requires child sa spi",
		},
		{
			name:    "truncated spi",
			wire:    []byte{protocolIDESP, 4, 0x40, 0x09, 0x01, 0x02},
			wantErr: "invalid spi length 4",
		},
		{
			name: "protocol id without spi is ignored on receipt",
			wire: notifyPayloadWire(protocolIDESP, 14, nil, []byte{0x01}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got NotifyPayload
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.ProtocolID != 0 {
				t.Fatalf("ProtocolID = %d, want ignored zero value", got.ProtocolID)
			}
		})
	}
}

func TestDecodePayloadChainRejectsDuplicateNonRepeatablePayloads(t *testing.T) {
	tests := []struct {
		name     string
		payloads []Payload
		wantErr  string
	}{
		{
			name: "duplicate nonce is invalid",
			payloads: []Payload{
				&NoncePayload{Data: bytes.Repeat([]byte{0x01}, nonceDataMinLen)},
				&NoncePayload{Data: bytes.Repeat([]byte{0x02}, nonceDataMinLen)},
			},
			wantErr: "duplicate payload type 40",
		},
		{
			name: "duplicate notify is repeatable",
			payloads: []Payload{
				&NotifyPayload{NotifyType: 14},
				&NotifyPayload{NotifyType: 24},
			},
		},
		{
			name: "duplicate delete is repeatable",
			payloads: []Payload{
				&DeletePayload{ProtocolID: deleteProtocolIDESP, SPIs: [][]byte{uint32Bytes(0x01020304)}},
				&DeletePayload{ProtocolID: deleteProtocolIDESP, SPIs: [][]byte{uint32Bytes(0x11121314)}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			first, wire, err := MarshalPayloadChain(tt.payloads)
			if err != nil {
				t.Fatalf("MarshalPayloadChain() error = %v", err)
			}

			_, err = DecodePayloadChain(first, wire)

			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("DecodePayloadChain() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("DecodePayloadChain() error = %v", err)
			}
		})
	}
}

func TestMarshalPayloadChainRejectsEncryptedPayloadBeforeLast(t *testing.T) {
	tests := []struct {
		name     string
		payloads []Payload
		wantErr  string
	}{
		{
			name: "encrypted payload followed by outer payload",
			payloads: []Payload{
				&EncryptedPayload{NextPayload: payloadTypeNone, Raw: []byte{0x01}},
				&NotifyPayload{NotifyType: 14},
			},
			wantErr: "encrypted payload must be last",
		},
		{
			name: "encrypted payload last",
			payloads: []Payload{
				&EncryptedPayload{NextPayload: payloadTypeNone, Raw: []byte{0x01}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := MarshalPayloadChain(tt.payloads)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MarshalPayloadChain() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalPayloadChain() error = %v", err)
			}
		})
	}
}

func TestEAPPayloadValidatesMessageLength(t *testing.T) {
	const (
		eapCodeRequest = 1
		eapCodeSuccess = 3
		eapTypeAKA     = 23
	)
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name: "request length matches payload body",
			data: []byte{eapCodeRequest, 1, 0, 5, eapTypeAKA},
		},
		{
			name: "success length matches payload body",
			data: []byte{eapCodeSuccess, 1, 0, 4},
		},
		{
			name:    "shorter than eap header",
			data:    []byte{eapCodeSuccess, 1, 0},
			wantErr: "shorter than header",
		},
		{
			name:    "declared length shorter than payload body",
			data:    []byte{eapCodeRequest, 1, 0, 5, eapTypeAKA, 0x00},
			wantErr: "does not match payload body length",
		},
		{
			name:    "declared length longer than payload body",
			data:    []byte{eapCodeRequest, 1, 0, 6, eapTypeAKA},
			wantErr: "does not match payload body length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := EAPPayload{Data: tt.data}
			_, marshalErr := payload.MarshalBinary()
			var decoded EAPPayload
			unmarshalErr := decoded.UnmarshalBinary(tt.data)
			if tt.wantErr != "" {
				if marshalErr == nil || unmarshalErr == nil {
					t.Fatalf("eap payload errors = (%v, %v), want %q", marshalErr, unmarshalErr, tt.wantErr)
				}
				return
			}
			if marshalErr != nil || unmarshalErr != nil {
				t.Fatalf("eap payload errors = (%v, %v), want nil", marshalErr, unmarshalErr)
			}
		})
	}
}

func TestIDPayloadRequiresIdentificationData(t *testing.T) {
	const idTypeRFC822Addr = 3

	tests := []struct {
		name    string
		payload IDPayload
		wire    []byte
		wantErr bool
	}{
		{
			name:    "rfc822 identity",
			payload: IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte("001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org")},
			wire:    append([]byte{idTypeRFC822Addr, 0, 0, 0}, []byte("001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org")...),
		},
		{
			name:    "empty identity",
			payload: IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr},
			wire:    []byte{idTypeRFC822Addr, 0, 0, 0},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, marshalErr := tt.payload.MarshalBinary()
			var decoded IDPayload
			unmarshalErr := decoded.UnmarshalBinary(tt.wire)
			if tt.wantErr {
				if marshalErr == nil || unmarshalErr == nil {
					t.Fatalf("identity errors = (%v, %v), want empty data", marshalErr, unmarshalErr)
				}
				return
			}
			if marshalErr != nil || unmarshalErr != nil {
				t.Fatalf("identity errors = (%v, %v), want nil", marshalErr, unmarshalErr)
			}
		})
	}
}

func TestConfigPayloadUsesConfigurationAttributeEncoding(t *testing.T) {
	tests := []struct {
		name    string
		payload ConfigPayload
		want    []byte
	}{
		{
			name: "preserves duplicate multivalued attributes",
			payload: ConfigPayload{ConfigType: configTypeReply, Attributes: []Attribute{
				NewTLVAttribute(configAttrInternalIPv4DNS, net.IPv4(10, 0, 0, 1).To4()),
				NewTLVAttribute(configAttrInternalIPv4DNS, net.IPv4(10, 0, 0, 2).To4()),
			}},
			want: append(
				[]byte{configTypeReply, 0, 0, 0},
				append(
					configAttributeWire(configAttrInternalIPv4DNS, net.IPv4(10, 0, 0, 1).To4()),
					configAttributeWire(configAttrInternalIPv4DNS, net.IPv4(10, 0, 0, 2).To4())...,
				)...,
			),
		},
		{
			name: "high bit in type is not encoded as TV format",
			payload: ConfigPayload{ConfigType: configTypeRequest, Attributes: []Attribute{
				NewTVAttribute(0x8000|configAttrIPv4PCSCF, 0),
			}},
			want: append(
				[]byte{configTypeRequest, 0, 0, 0},
				configAttributeWire(configAttrIPv4PCSCF, nil)...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.payload.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(wire) != string(tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", wire, tt.want)
			}

			var got ConfigPayload
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.ConfigType != tt.payload.ConfigType || len(got.Attributes) != len(tt.payload.Attributes) {
				t.Fatalf("UnmarshalBinary() = %+v, want config type %d and %d attrs", got, tt.payload.ConfigType, len(tt.payload.Attributes))
			}
		})
	}
}

func TestConfigPayloadRejectsMalformedAttributes(t *testing.T) {
	tests := []struct {
		name        string
		body        []byte
		skipMarshal bool
		wantErr     string
	}{
		{
			name:        "unsupported config type is decoded for compatibility",
			body:        []byte{99, 0, 0, 0},
			skipMarshal: true,
		},
		{
			name: "ignores reserved bit on receipt",
			body: append(
				[]byte{configTypeRequest, 0, 0, 0},
				configAttributeWire(0x8000|configAttrIPv4PCSCF, nil)...,
			),
		},
		{
			name: "ipv4 pcscf rejects wrong length",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrIPv4PCSCF, []byte{10, 0, 0, 1, 2})...,
			),
			wantErr: "invalid length",
		},
		{
			name: "ipv6 pcscf rejects prefix length form",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrIPv6PCSCF, append(net.ParseIP("2001:db8::1").To16(), 64))...,
			),
			wantErr: "invalid length",
		},
		{
			name: "internal ipv6 address requires address plus prefix length",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrInternalIPv6Address, net.ParseIP("2001:db8::1").To16())...,
			),
			wantErr: "invalid length",
		},
		{
			name: "liveness timeout rejects short value",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrLivenessTimeout, []byte{0, 1})...,
			),
			wantErr: "invalid length",
		},
		{
			name: "liveness timeout accepts empty support indication",
			body: append(
				[]byte{configTypeRequest, 0, 0, 0},
				configAttributeWire(configAttrLivenessTimeout, nil)...,
			),
		},
		{
			name: "liveness timeout accepts four byte value",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrLivenessTimeout, []byte{0, 0, 1, 44})...,
			),
		},
		{
			name: "supported attributes rejects odd length",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrSupportedAttributes, []byte{0, 1, 2})...,
			),
			wantErr: "invalid length",
		},
		{
			name: "reply rejects netmask without ipv4 address",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 255, 255, 0).To4())...,
			),
			wantErr: "netmask without internal ipv4 address",
		},
		{
			name: "request rejects non-empty netmask",
			body: append(
				[]byte{configTypeRequest, 0, 0, 0},
				configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 255, 255, 0).To4())...,
			),
			wantErr: "non-empty internal ipv4 netmask in request",
		},
		{
			name: "request accepts one empty netmask",
			body: append(
				[]byte{configTypeRequest, 0, 0, 0},
				configAttributeWire(configAttrInternalIPv4Netmask, nil)...,
			),
		},
		{
			name: "request rejects multiple netmasks",
			body: append(
				[]byte{configTypeRequest, 0, 0, 0},
				append(
					configAttributeWire(configAttrInternalIPv4Netmask, nil),
					configAttributeWire(configAttrInternalIPv4Netmask, nil)...,
				)...,
			),
			wantErr: "multiple internal ipv4 netmasks",
		},
		{
			name: "rejects non-contiguous netmask",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				append(
					configAttributeWire(configAttrInternalIPv4Address, net.IPv4(10, 0, 0, 1).To4()),
					configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 0, 255, 0).To4())...,
				)...,
			),
			wantErr: "invalid internal ipv4 netmask",
		},
		{
			name: "reply rejects multiple netmasks",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				append(
					configAttributeWire(configAttrInternalIPv4Address, net.IPv4(10, 0, 0, 1).To4()),
					append(
						configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 255, 255, 0).To4()),
						configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 255, 0, 0).To4())...,
					)...,
				)...,
			),
			wantErr: "multiple internal ipv4 netmasks",
		},
		{
			name: "reply accepts netmask with ipv4 address",
			body: append(
				[]byte{configTypeReply, 0, 0, 0},
				append(
					configAttributeWire(configAttrInternalIPv4Address, net.IPv4(10, 0, 0, 1).To4()),
					configAttributeWire(configAttrInternalIPv4Netmask, net.IPv4(255, 255, 255, 0).To4())...,
				)...,
			),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ConfigPayload
			err := got.UnmarshalBinary(tt.body)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if tt.skipMarshal {
				return
			}
			if _, err := got.MarshalBinary(); err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestConfigPayloadRejectsInvalidOutboundType(t *testing.T) {
	tests := []struct {
		name    string
		payload ConfigPayload
		wantErr string
	}{
		{
			name:    "zero value is not a valid outbound config type",
			payload: ConfigPayload{},
			wantErr: "invalid config type",
		},
		{
			name:    "unknown outbound config type",
			payload: ConfigPayload{ConfigType: 99},
			wantErr: "invalid config type",
		},
		{
			name:    "request is valid",
			payload: ConfigPayload{ConfigType: configTypeRequest},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tt.payload.MarshalBinary()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
		})
	}
}

func TestDeviceIdentityMarshalBinary(t *testing.T) {
	tests := []struct {
		name           string
		identity       string
		requestedType  byte
		mutate         func(DeviceIdentity) DeviceIdentity
		want           []byte
		wantNewErr     string
		wantMarshalErr string
	}{
		{
			name:          "imei matches android vector",
			identity:      "123456789123456",
			requestedType: deviceIdentityAuto,
			want:          []byte{0x00, 0x09, 0x01, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0xf6},
		},
		{
			name:          "imeisv matches android vector",
			identity:      "1234567891234567",
			requestedType: deviceIdentityAuto,
			want:          []byte{0x00, 0x09, 0x02, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0x76},
		},
		{
			name:     "empty request uses 24.302 length prefix",
			identity: "123456789123456",
			mutate: func(DeviceIdentity) DeviceIdentity {
				return DeviceIdentity{Type: deviceIdentityIMEI}
			},
			want: []byte{0x00, 0x01, 0x01},
		},
		{
			name:          "non numeric identity",
			identity:      "12345678912345A",
			requestedType: deviceIdentityAuto,
			wantNewErr:    "invalid digit",
		},
		{
			name:          "unsupported length",
			identity:      "12345678912345",
			requestedType: deviceIdentityAuto,
			wantNewErr:    "unsupported length",
		},
		{
			name:          "encoded value length must be full tbcd identity length",
			identity:      "123456789123456",
			requestedType: deviceIdentityAuto,
			mutate: func(identity DeviceIdentity) DeviceIdentity {
				identity.Value = identity.Value[:len(identity.Value)-1]
				return identity
			},
			wantMarshalErr: "value length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity, err := NewDeviceIdentity(tt.identity, tt.requestedType)
			if tt.wantNewErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantNewErr) {
					t.Fatalf("NewDeviceIdentity() error = %v, want %q", err, tt.wantNewErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewDeviceIdentity() error = %v", err)
			}
			if tt.mutate != nil {
				identity = tt.mutate(identity)
			}
			got, err := identity.MarshalBinary()
			if tt.wantMarshalErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantMarshalErr) {
					t.Fatalf("MarshalBinary() error = %v, want %q", err, tt.wantMarshalErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if string(got) != string(tt.want) {
				t.Fatalf("MarshalBinary() = % X, want % X", got, tt.want)
			}
		})
	}
}

func TestDeviceIdentityUnmarshalBinary(t *testing.T) {
	tests := []struct {
		name      string
		wire      []byte
		wantType  byte
		wantValue []byte
		wantErr   string
	}{
		{
			name:     "android informational request carries only requested type",
			wire:     []byte{deviceIdentityIMEI},
			wantType: deviceIdentityIMEI,
		},
		{
			name:      "length prefixed identity value",
			wire:      []byte{0x00, 0x09, 0x01, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0xf6},
			wantType:  deviceIdentityIMEI,
			wantValue: []byte{0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0xf6},
		},
		{
			name:    "unsupported type",
			wire:    []byte{0x03},
			wantErr: "unsupported type",
		},
		{
			name:    "bad length",
			wire:    []byte{0x00, 0x09, 0x01},
			wantErr: "does not match",
		},
		{
			name:    "invalid value length",
			wire:    []byte{0x00, 0x02, 0x01, 0x21},
			wantErr: "value length",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got DeviceIdentity
			err := got.UnmarshalBinary(tt.wire)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("UnmarshalBinary() error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Type != tt.wantType || string(got.Value) != string(tt.wantValue) {
				t.Fatalf("UnmarshalBinary() = %+v, want type %d value % X", got, tt.wantType, tt.wantValue)
			}
		})
	}
}

func uint32Bytes(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

func deletePayloadWire(protocolID byte, spis [][]byte) []byte {
	spiSize := 0
	if len(spis) != 0 {
		spiSize = len(spis[0])
	}
	wire := []byte{protocolID, byte(spiSize), 0x00, 0x00}
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(spis)))
	for _, spi := range spis {
		wire = append(wire, spi...)
	}
	return wire
}

func notifyPayloadWire(protocolID byte, notifyType uint16, spi, data []byte) []byte {
	wire := []byte{protocolID, byte(len(spi)), 0x00, 0x00}
	binary.BigEndian.PutUint16(wire[2:4], notifyType)
	wire = append(wire, spi...)
	wire = append(wire, data...)
	return wire
}

func keyExchangePayloadWire(group uint16, data []byte) []byte {
	wire := make([]byte, keyExchangeBodyHeaderLen, keyExchangeBodyHeaderLen+len(data))
	binary.BigEndian.PutUint16(wire[0:2], group)
	wire = append(wire, data...)
	return wire
}

func bytesOfLen(length int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(i + 1)
	}
	return out
}

func proposalSubstructure(t *testing.T, next byte, body []byte) []byte {
	t.Helper()
	wire, err := marshalPayloadBlock(next, body)
	if err != nil {
		t.Fatalf("marshalPayloadBlock() error = %v", err)
	}
	return wire
}

func transformSubstructure(t *testing.T, next byte, body []byte) []byte {
	t.Helper()
	wire, err := marshalPayloadBlock(next, body)
	if err != nil {
		t.Fatalf("marshalPayloadBlock() error = %v", err)
	}
	return wire
}

func trafficSelectorWire(tsType, protocolID byte, startPort, endPort uint16, startAddress, endAddress []byte) []byte {
	wire := []byte{tsType, protocolID, 0x00, 0x00}
	binary.BigEndian.PutUint16(wire[2:4], uint16(trafficSelectorHeaderLen+trafficSelectorPortsLen+len(startAddress)+len(endAddress)))
	wire = binary.BigEndian.AppendUint16(wire, startPort)
	wire = binary.BigEndian.AppendUint16(wire, endPort)
	wire = append(wire, startAddress...)
	wire = append(wire, endAddress...)
	return wire
}

func transformTVAttribute(attrType, value uint16) []byte {
	wire := make([]byte, 4)
	binary.BigEndian.PutUint16(wire[0:2], uint16(attributeFormatTV)<<15|attrType)
	binary.BigEndian.PutUint16(wire[2:4], value)
	return wire
}

func transformTLVAttribute(attrType uint16, value []byte) []byte {
	wire := make([]byte, 4)
	binary.BigEndian.PutUint16(wire[0:2], uint16(attributeFormatTLV)<<15|attrType)
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(value)))
	wire = append(wire, value...)
	return wire
}

func configAttributeWire(attrType uint16, value []byte) []byte {
	wire := make([]byte, 4)
	binary.BigEndian.PutUint16(wire[0:2], attrType)
	binary.BigEndian.PutUint16(wire[2:4], uint16(len(value)))
	wire = append(wire, value...)
	return wire
}
