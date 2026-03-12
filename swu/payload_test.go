package swu

import (
	"bytes"
	"testing"
)

func TestIKEPacketRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		payloads []Payload
	}{
		{
			name: "sa-init-like",
			payloads: []Payload{
				&SecurityAssociationPayload{Proposals: []Proposal{{ProtocolID: proposalProtocolIKE, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}, {TransformType: transformTypePRF, ID: transformPRFHMACSHA1}, {TransformType: transformTypeDH, ID: transformDH1024MODP}}}}},
				&KeyExchangePayload{DHGroup: transformDH1024MODP, Data: bytes.Repeat([]byte{0x11}, 128)},
				&NoncePayload{Data: bytes.Repeat([]byte{0x22}, 16)},
			},
		},
		{
			name: "auth-like",
			payloads: []Payload{
				&IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte("user@example.com")},
				&ConfigPayload{ConfigType: configTypeRequest, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, nil), NewTLVAttribute(configAttrPCSCFIPv4Address, nil)}},
				&EAPPayload{Data: []byte{0x03, 0x01, 0x00, 0x04}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := IKEPacket{Header: IKEHeader{InitiatorSPI: 1, ResponderSPI: 2, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: 7}, Payloads: tt.payloads}
			wire, err := packet.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var parsed IKEPacket
			if err := parsed.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if parsed.Header.MessageID != 7 || parsed.Header.ExchangeType != exchangeTypeIKEAuth {
				t.Fatalf("parsed header = %+v", parsed.Header)
			}
			if len(parsed.Payloads) != len(tt.payloads) {
				t.Fatalf("payload count = %d, want %d", len(parsed.Payloads), len(tt.payloads))
			}
		})
	}
}

func TestEncodeDeviceIdentity(t *testing.T) {
	tests := []struct {
		name          string
		identity      string
		requestedType byte
		wantType      byte
		wantValueLen  int
	}{
		{name: "imei", identity: "356789012345678", requestedType: 0, wantType: deviceIdentityIMEI, wantValueLen: 8},
		{name: "imeisv", identity: "3567890123456789", requestedType: 0, wantType: deviceIdentityIMEISV, wantValueLen: 8},
		{name: "fallback to imei", identity: "356789012345678", requestedType: deviceIdentityIMEISV, wantType: deviceIdentityIMEI, wantValueLen: 8},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := encodeDeviceIdentityForType(tt.identity, tt.requestedType)
			if err != nil {
				t.Fatalf("encodeDeviceIdentityForType() error = %v", err)
			}
			identityType, value, err := decodeDeviceIdentity(data)
			if err != nil {
				t.Fatalf("decodeDeviceIdentity() error = %v", err)
			}
			if identityType != tt.wantType {
				t.Fatalf("identityType = %d, want %d", identityType, tt.wantType)
			}
			if len(value) != tt.wantValueLen {
				t.Fatalf("len(value) = %d, want %d", len(value), tt.wantValueLen)
			}
		})
	}
}

func TestParseDeviceIdentity(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{name: "request imei", data: []byte{0x00, 0x01, deviceIdentityIMEI}},
		{name: "request imeisv", data: []byte{0x00, 0x01, deviceIdentityIMEISV}},
		{name: "short", data: []byte{0x00, 0x01}, wantErr: true},
		{name: "bad length", data: []byte{0x00, 0x02, deviceIdentityIMEI}, wantErr: true},
		{name: "bad type", data: []byte{0x00, 0x01, 0x09}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeDeviceIdentity(tt.data)
			if tt.wantErr && err == nil {
				t.Fatal("decodeDeviceIdentity() error = nil, want non-nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("decodeDeviceIdentity() error = %v", err)
			}
		})
	}
}

func TestValueObjectMarshalBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "attribute tv",
			run: func(t *testing.T) {
				want := NewTVAttribute(transformAttrKeyLength, 128)
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got Attribute
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if !attributeEqual(got, want) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "transform",
			run: func(t *testing.T) {
				want := Transform{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got Transform
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if !transformEqual(got, want) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "proposal",
			run: func(t *testing.T) {
				want := Proposal{Number: 1, ProtocolID: proposalProtocolESP, SPI: []byte{0x01, 0x02, 0x03, 0x04}, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got Proposal
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if !proposalEqual(got, want) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "traffic selector",
			run: func(t *testing.T) {
				want := TrafficSelector{Type: trafficSelectorIPv4Range, ProtocolID: protocolIDESP, Data: []byte{0x00, 0x00, 0xff, 0xff, 10, 0, 0, 1, 10, 0, 0, 2}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got TrafficSelector
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Type != want.Type || got.ProtocolID != want.ProtocolID || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestPayloadMarshalBinaryRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "security association",
			run: func(t *testing.T) {
				want := &SecurityAssociationPayload{Proposals: []Proposal{{Number: 1, ProtocolID: proposalProtocolESP, SPI: []byte{0x01, 0x02, 0x03, 0x04}, Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC, Attributes: []Attribute{NewTVAttribute(transformAttrKeyLength, 128)}}, {TransformType: transformTypeINTEG, ID: transformINTEGHMACSHA196}}}}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got SecurityAssociationPayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if len(got.Proposals) != len(want.Proposals) || !proposalEqual(got.Proposals[0], want.Proposals[0]) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "key exchange",
			run: func(t *testing.T) {
				want := &KeyExchangePayload{DHGroup: transformDH1024MODP, Data: []byte{0x11, 0x22, 0x33}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got KeyExchangePayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.DHGroup != want.DHGroup || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "notify",
			run: func(t *testing.T) {
				want := &NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeDeviceIdentity, SPI: []byte{0x01, 0x02, 0x03, 0x04}, Data: []byte{0xaa, 0xbb}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got NotifyPayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.ProtocolID != want.ProtocolID || got.NotifyType != want.NotifyType || !bytes.Equal(got.SPI, want.SPI) || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "delete",
			run: func(t *testing.T) {
				want := &DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{{0x01, 0x02, 0x03, 0x04}, {0x05, 0x06, 0x07, 0x08}}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got DeletePayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.ProtocolID != want.ProtocolID || len(got.SPIs) != len(want.SPIs) || !bytes.Equal(got.SPIs[0], want.SPIs[0]) || !bytes.Equal(got.SPIs[1], want.SPIs[1]) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "id",
			run: func(t *testing.T) {
				want := &IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte("user@example.com")}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				got := IDPayload{Tag: payloadTypeIDi}
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Tag != want.Tag || got.IDType != want.IDType || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "auth",
			run: func(t *testing.T) {
				want := &AuthPayload{Method: authMethodSharedKeyMIC, Data: []byte{0xde, 0xad, 0xbe, 0xef}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got AuthPayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Method != want.Method || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "config",
			run: func(t *testing.T) {
				want := &ConfigPayload{ConfigType: configTypeRequest, Attributes: []Attribute{NewTLVAttribute(configAttrInternalIPv4Address, []byte{10, 0, 0, 10}), NewTLVAttribute(configAttrPCSCFIPv4Address, []byte{10, 0, 0, 1})}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got ConfigPayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.ConfigType != want.ConfigType || len(got.Attributes) != len(want.Attributes) || !attributeEqual(got.Attributes[0], want.Attributes[0]) || !attributeEqual(got.Attributes[1], want.Attributes[1]) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "traffic selector payload",
			run: func(t *testing.T) {
				want := &TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: []TrafficSelector{{Type: trafficSelectorIPv4Range, ProtocolID: protocolIDESP, Data: []byte{0x00, 0x00, 0xff, 0xff, 10, 0, 0, 1, 10, 0, 0, 2}}}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				got := TrafficSelectorPayload{Tag: payloadTypeTSi}
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Tag != want.Tag || len(got.Selectors) != len(want.Selectors) || got.Selectors[0].Type != want.Selectors[0].Type || got.Selectors[0].ProtocolID != want.Selectors[0].ProtocolID || !bytes.Equal(got.Selectors[0].Data, want.Selectors[0].Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "eap",
			run: func(t *testing.T) {
				want := &EAPPayload{Data: []byte{0x01, 0x02, 0x03}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got EAPPayload
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
		{
			name: "encrypted",
			run: func(t *testing.T) {
				want := &EncryptedPayload{NextPayload: payloadTypeNonce, Raw: []byte{0xaa, 0xbb, 0xcc}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				got := EncryptedPayload{NextPayload: payloadTypeNonce}
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.NextPayload != want.NextPayload || !bytes.Equal(got.Raw, want.Raw) {
					t.Fatalf("round trip = %+v, want %+v", got, *want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestParseProposalRejectsTransformCountMismatch(t *testing.T) {
	encoded, err := (Proposal{
		Number:     1,
		ProtocolID: proposalProtocolESP,
		Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC}},
	}).marshalBinary(payloadTypeNone)
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	encoded[7] = 2
	var proposal Proposal
	if err := proposal.UnmarshalBinary(encoded[4:]); err == nil {
		t.Fatal("UnmarshalBinary() error = nil, want non-nil")
	}
}

func TestParseSecurityAssociationRejectsTrailingBytes(t *testing.T) {
	encoded, err := (&SecurityAssociationPayload{Proposals: []Proposal{{
		ProtocolID: proposalProtocolESP,
		Transforms: []Transform{{TransformType: transformTypeENCR, ID: transformENCRAESCBC}},
	}}}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	encoded = append(encoded, 0x00)
	if _, err := decodeSecurityAssociationPayload(encoded); err == nil {
		t.Fatal("decodeSecurityAssociationPayload() error = nil, want non-nil")
	}
}

func TestParseTrafficSelectorPayloadRejectsCountMismatch(t *testing.T) {
	selector, err := (TrafficSelector{Type: 7, ProtocolID: 0, Data: []byte{0x00, 0x01, 0x02, 0x03}}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	data := append([]byte{2, 0, 0, 0}, selector...)
	if _, err := decodeTrafficSelectorPayload(payloadTypeTSi, data); err == nil {
		t.Fatal("decodeTrafficSelectorPayload() error = nil, want non-nil")
	}
}

func attributeEqual(got, want Attribute) bool {
	return got.Format == want.Format && got.Type == want.Type && got.Value16 == want.Value16 && bytes.Equal(got.Value, want.Value)
}

func transformEqual(got, want Transform) bool {
	if got.TransformType != want.TransformType || got.ID != want.ID || len(got.Attributes) != len(want.Attributes) {
		return false
	}
	for i := range got.Attributes {
		if !attributeEqual(got.Attributes[i], want.Attributes[i]) {
			return false
		}
	}
	return true
}

func proposalEqual(got, want Proposal) bool {
	if got.Number != want.Number || got.ProtocolID != want.ProtocolID || !bytes.Equal(got.SPI, want.SPI) || len(got.Transforms) != len(want.Transforms) {
		return false
	}
	for i := range got.Transforms {
		if !transformEqual(got.Transforms[i], want.Transforms[i]) {
			return false
		}
	}
	return true
}

func TestParsePayloadLengthUnderflow(t *testing.T) {
	tests := []struct {
		name string
		fn   func() error
	}{
		{
			name: "proposal transform length underflow",
			fn: func() error {
				var proposal Proposal
				return proposal.UnmarshalBinary([]byte{1, proposalProtocolIKE, 0, 1, payloadTypeNone, 0, 0, 3})
			},
		},
		{
			name: "security association proposal length underflow",
			fn: func() error {
				_, err := decodeSecurityAssociationPayload([]byte{payloadTypeNone, 0, 0, 3})
				return err
			},
		},
		{
			name: "traffic selector length underflow",
			fn: func() error {
				_, err := decodeTrafficSelectors([]byte{7, 0, 0, 3})
				return err
			},
		},
		{
			name: "payload chain length underflow",
			fn: func() error {
				_, err := decodePayloadChain(payloadTypeNonce, []byte{payloadTypeNone, 0, 0, 3})
				return err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.fn(); err == nil {
				t.Fatal("error = nil, want non-nil")
			}
		})
	}
}
