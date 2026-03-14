package eapaka

import (
	"bytes"
	"testing"
)

func TestAKAMessageRoundTrip(t *testing.T) {
	tests := []struct {
		name    string
		message AKAMessage
	}{
		{
			name: "identity request",
			message: AKAMessage{
				Code:       CodeRequest,
				Identifier: 7,
				Subtype:    SubtypeIdentity,
				Attributes: []AKAAttribute{{Type: AttrRAND, Value: []byte{0x00, 0x00}}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.message.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != tt.message.Code || got.Identifier != tt.message.Identifier || got.Subtype != tt.message.Subtype {
				t.Fatalf("AKAMessage = %+v, want %+v", got, tt.message)
			}
		})
	}
}

func TestBuildAKAIdentityResponse(t *testing.T) {
	tests := []struct {
		name     string
		id       byte
		identity string
		wantErr  bool
	}{
		{name: "success", id: 3, identity: "001010123456789"},
		{name: "empty", id: 3, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := BuildAKAIdentityResponse(tt.id, tt.identity)
			if tt.wantErr {
				if err == nil {
					t.Fatal("BuildAKAIdentityResponse() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("BuildAKAIdentityResponse() error = %v", err)
			}
			var got AKAMessage
			if err := got.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if got.Code != CodeResponse || got.Subtype != SubtypeIdentity {
				t.Fatalf("AKAMessage = %+v", got)
			}
		})
	}
}

func TestParseAKAChallenge(t *testing.T) {
	randValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)
	autnValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x22}, 16)...)
	macValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x55}, 16)...)
	ivValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x33}, 16)...)
	encryptedValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x44}, 16)...)
	checkcodeValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, 20)...)
	invalidCheckcodeValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, 4)...)
	resultIndValue := []byte{0x00, 0x00}
	shortRandValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 12)...)
	invalidEncryptedValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x44}, 12)...)

	tests := []struct {
		name    string
		attrs   []AKAAttribute
		wantErr bool
	}{
		{
			name: "valid",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
		},
		{
			name: "valid with result indication",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
			},
		},
		{
			name: "duplicate rand",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "missing mac",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate autn",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "short rand",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: shortRandValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
			},
			wantErr: true,
		},
		{
			name: "unexpected identity request attribute",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
			},
			wantErr: true,
		},
		{
			name: "valid with checkcode",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrCheckcode, Value: checkcodeValue},
			},
		},
		{
			name: "invalid checkcode length",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrCheckcode, Value: invalidCheckcodeValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate result indication",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
				{Type: akaAttrResultInd, Value: resultIndValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate iv",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "duplicate encrypted data",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "iv without encrypted data",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
			},
			wantErr: true,
		},
		{
			name: "encrypted data without iv",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrEncryptedData, Value: encryptedValue},
			},
			wantErr: true,
		},
		{
			name: "invalid encrypted data length",
			attrs: []AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				{Type: akaAttrMAC, Value: macValue},
				{Type: akaAttrIV, Value: ivValue},
				{Type: akaAttrEncryptedData, Value: invalidEncryptedValue},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 5,
				Subtype:    akaSubtypeChallenge,
				Attributes: tt.attrs,
			}.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			challenge, err := ParseAKAChallenge(wire)
			if tt.wantErr {
				if err == nil {
					t.Fatal("ParseAKAChallenge() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAKAChallenge() error = %v", err)
			}
			if len(challenge.RAND) != 16 || len(challenge.AUTN) != 16 {
				t.Fatalf("challenge = %+v", challenge)
			}
		})
	}
}
