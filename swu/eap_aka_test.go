package swu

import (
	"bytes"
	"testing"
)

func TestEAPAKAValueObjectRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "eap packet",
			run: func(t *testing.T) {
				want := EAPPacket{Code: eapCodeRequest, Identifier: 0x09, Type: eapTypeAKA, HasType: true, Data: []byte{akaSubtypeIdentity, 0x00, 0x00}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got EAPPacket
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Code != want.Code || got.Identifier != want.Identifier || got.Type != want.Type || got.HasType != want.HasType || !bytes.Equal(got.Data, want.Data) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "aka attribute",
			run: func(t *testing.T) {
				want := AKAAttribute{Type: akaAttrCounter, Value: []byte{0x00, 0x07}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got AKAAttribute
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Type != want.Type || !bytes.Equal(got.Value, want.Value) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
		{
			name: "aka message",
			run: func(t *testing.T) {
				want := AKAMessage{Code: eapCodeResponse, Identifier: 0x23, Subtype: akaSubtypeIdentity, Attributes: []AKAAttribute{buildAKAStringAttribute(akaAttrIdentity, "user@ims")}}
				data, err := want.MarshalBinary()
				if err != nil {
					t.Fatalf("MarshalBinary() error = %v", err)
				}
				var got AKAMessage
				if err := got.UnmarshalBinary(data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if got.Code != want.Code || got.Identifier != want.Identifier || got.Subtype != want.Subtype || len(got.Attributes) != len(want.Attributes) || got.Attributes[0].Type != want.Attributes[0].Type || !bytes.Equal(got.Attributes[0].Value, want.Attributes[0].Value) {
					t.Fatalf("round trip = %+v, want %+v", got, want)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestParseAKAChallenge(t *testing.T) {
	tests := []struct {
		name string
		rand []byte
		autn []byte
	}{
		{"basic", bytes.Repeat([]byte{0x01}, 16), bytes.Repeat([]byte{0x02}, 16)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 0x09,
				Subtype:    akaSubtypeChallenge,
				Attributes: []AKAAttribute{
					{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, tt.rand...)},
					{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, tt.autn...)},
				},
			}
			packet, err := msg.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			challenge, err := ParseAKAChallenge(packet)
			if err != nil {
				t.Fatalf("ParseAKAChallenge() error = %v", err)
			}
			if !bytes.Equal(challenge.RAND, tt.rand) || !bytes.Equal(challenge.AUTN, tt.autn) || challenge.Identifier != 0x09 {
				t.Fatalf("ParseAKAChallenge() = %+v", challenge)
			}
		})
	}
}

func TestBuildAKAResponseChallenge(t *testing.T) {
	tests := []struct {
		name string
		res  []byte
	}{
		{"basic", []byte{0x11, 0x22, 0x33, 0x44}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := BuildAKAResponse(0x0A, tt.res, nil)
			if err != nil {
				t.Fatalf("BuildAKAResponse() error = %v", err)
			}
			eap := mustUnmarshalAKAMessage(t, "eap", packet)
			if eap.Code != eapCodeResponse || eap.Identifier != 0x0A || eap.Subtype != akaSubtypeChallenge {
				t.Fatalf("AKAMessage.UnmarshalBinary() = %+v", eap)
			}
		})
	}
}

func TestBuildAKAResponseWithMAC(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x55}, 16)
	packet, err := BuildAKAResponse(0x0B, []byte{0x10, 0x20, 0x30, 0x40}, autKey)
	if err != nil {
		t.Fatalf("BuildAKAResponse() error = %v", err)
	}
	msg := mustUnmarshalAKAMessage(t, "msg", packet)
	foundMAC := false
	for _, attr := range msg.Attributes {
		if attr.Type == akaAttrMAC {
			foundMAC = true
			if len(attr.Value) != 18 {
				t.Fatalf("AT_MAC length = %d, want 18", len(attr.Value))
			}
		}
	}
	if !foundMAC {
		t.Fatal("AT_MAC not found")
	}
}

func TestBuildAKAIdentityResponse(t *testing.T) {
	tests := []struct {
		name     string
		identity string
	}{
		{name: "permanent", identity: "0530011120348761"},
		{name: "pseudonym", identity: "pseudonym-1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := BuildAKAIdentityResponse(0x23, tt.identity)
			if err != nil {
				t.Fatalf("BuildAKAIdentityResponse() error = %v", err)
			}
			message := mustUnmarshalAKAMessage(t, "message", packet)
			if message.Code != eapCodeResponse || message.Identifier != 0x23 || message.Subtype != akaSubtypeIdentity {
				t.Fatalf("AKAMessage.UnmarshalBinary() = %+v", message)
			}
			identity, err := akaStringValue(findAKAAttribute(message.Attributes, akaAttrIdentity))
			if err != nil {
				t.Fatalf("akaStringValue() error = %v", err)
			}
			if identity != tt.identity {
				t.Fatalf("identity = %q, want %q", identity, tt.identity)
			}
		})
	}
}

func TestEncryptDecryptAKAAttributes(t *testing.T) {
	tests := []struct {
		name  string
		attrs []AKAAttribute
	}{
		{
			name: "counter and pseudonym",
			attrs: []AKAAttribute{
				buildAKAUint16Attribute(akaAttrCounter, 7),
				buildAKAStringAttribute(akaAttrNextPseudonym, "pseudo-1"),
			},
		},
		{
			name: "counter and reauth id",
			attrs: []AKAAttribute{
				buildAKAUint16Attribute(akaAttrCounter, 9),
				buildAKAStringAttribute(akaAttrNextReauthID, "reauth-1"),
			},
		},
	}
	key := bytes.Repeat([]byte{0x5a}, 16)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := encryptAKAAttributes(tt.attrs, key)
			if err != nil {
				t.Fatalf("encryptAKAAttributes() error = %v", err)
			}
			decrypted, err := decryptAKAAttributes(encrypted, key)
			if err != nil {
				t.Fatalf("decryptAKAAttributes() error = %v", err)
			}
			if len(decrypted) != len(tt.attrs) {
				t.Fatalf("len(decrypted) = %d, want %d", len(decrypted), len(tt.attrs))
			}
			for i := range decrypted {
				if decrypted[i].Type != tt.attrs[i].Type || !bytes.Equal(decrypted[i].Value, tt.attrs[i].Value) {
					t.Fatalf("decrypted[%d] = %+v, want %+v", i, decrypted[i], tt.attrs[i])
				}
			}
		})
	}
}

func TestAKAExtValueHelpers(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T)
	}{
		{
			name: "signed message verify",
			run: func(t *testing.T) {
				autKey := bytes.Repeat([]byte{0x55}, 16)
				msg := AKAMessage{Code: eapCodeResponse, Identifier: 0x33, Subtype: akaSubtypeChallenge, Attributes: []AKAAttribute{{Type: akaAttrRES, Value: []byte{0x00, 0x20, 0x10, 0x20, 0x30, 0x40}}}}
				packet, err := msg.MarshalSigned(autKey, nil)
				if err != nil {
					t.Fatalf("MarshalSigned() error = %v", err)
				}
				var parsed AKAMessage
				if err := parsed.UnmarshalBinary(packet); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				if err := parsed.VerifyMAC(autKey, nil); err != nil {
					t.Fatalf("VerifyMAC() error = %v", err)
				}
			},
		},
		{
			name: "notification attributes",
			run: func(t *testing.T) {
				var notification AKANotification
				if err := notification.UnmarshalAttributes([]AKAAttribute{buildAKAUint16Attribute(akaAttrNotification, akaNotificationSuccess)}); err != nil {
					t.Fatalf("UnmarshalAttributes() error = %v", err)
				}
				if !notification.Success || !notification.Protected || notification.Code != akaNotificationSuccess {
					t.Fatalf("notification = %+v", notification)
				}
			},
		},
		{
			name: "reauthentication message",
			run: func(t *testing.T) {
				encrKey := bytes.Repeat([]byte{0x22}, 16)
				nonceS := bytes.Repeat([]byte{0x33}, 16)
				encrypted, err := encryptAKAAttributes([]AKAAttribute{buildAKAUint16Attribute(akaAttrCounter, 7), {Type: akaAttrNonceS, Value: append([]byte{0x00, 0x00}, nonceS...)}, buildAKAStringAttribute(akaAttrNextReauthID, "reauth-1")}, encrKey)
				if err != nil {
					t.Fatalf("encryptAKAAttributes() error = %v", err)
				}
				msg := AKAMessage{Code: eapCodeRequest, Identifier: 0x44, Subtype: akaSubtypeReauthentication, Attributes: append(encrypted, buildAKAUint16Attribute(akaAttrResultInd, 0))}
				var req AKAReauthentication
				if err := req.UnmarshalMessage(msg, encrKey); err != nil {
					t.Fatalf("UnmarshalMessage() error = %v", err)
				}
				if req.Identifier != 0x44 || req.Counter != 7 || !req.UseResultInd || req.NextReauthID != "reauth-1" || !bytes.Equal(req.NonceS, nonceS) {
					t.Fatalf("reauth = %+v", req)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestBuildAKAReauthenticationResponsePacket(t *testing.T) {
	tests := []struct {
		name            string
		counter         uint16
		counterTooSmall bool
		useResultInd    bool
	}{
		{name: "basic", counter: 3, counterTooSmall: false, useResultInd: false},
		{name: "counter too small", counter: 5, counterTooSmall: true, useResultInd: true},
	}
	autKey := bytes.Repeat([]byte{0x11}, 16)
	encrKey := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := buildAKAReauthenticationResponsePacket(0x31, tt.counter, tt.counterTooSmall, tt.useResultInd, autKey, encrKey, nonceS)
			if err != nil {
				t.Fatalf("buildAKAReauthenticationResponsePacket() error = %v", err)
			}
			message := mustUnmarshalAKAMessage(t, "message", packet)
			if err := verifyAKAMessageMAC(packet, autKey, nonceS); err != nil {
				t.Fatalf("verifyAKAMessageMAC() error = %v", err)
			}
			if got := hasAKAAttribute(message.Attributes, akaAttrResultInd); got != tt.useResultInd {
				t.Fatalf("hasAKAAttribute(AT_RESULT_IND) = %t, want %t", got, tt.useResultInd)
			}
			decrypted, err := decryptAKAAttributes(message.Attributes, encrKey)
			if err != nil {
				t.Fatalf("decryptAKAAttributes() error = %v", err)
			}
			counter, err := akaUint16Value(findAKAAttribute(decrypted, akaAttrCounter))
			if err != nil {
				t.Fatalf("akaUint16Value(AT_COUNTER) error = %v", err)
			}
			if counter != tt.counter {
				t.Fatalf("counter = %d, want %d", counter, tt.counter)
			}
			if got := hasAKAAttribute(decrypted, akaAttrCounterTooSmall); got != tt.counterTooSmall {
				t.Fatalf("hasAKAAttribute(AT_COUNTER_TOO_SMALL) = %t, want %t", got, tt.counterTooSmall)
			}
		})
	}
}

func TestDeriveFastReauthKeys(t *testing.T) {
	tests := []struct {
		name     string
		identity []byte
		counter  uint16
		nonceS   []byte
		mk       []byte
	}{
		{
			name:     "deterministic",
			identity: []byte("reauth-identity"),
			counter:  9,
			nonceS:   bytes.Repeat([]byte{0x44}, 16),
			mk:       bytes.Repeat([]byte{0x55}, 20),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mskA, emskA, err := deriveFastReauthKeys(tt.identity, tt.counter, tt.nonceS, tt.mk)
			if err != nil {
				t.Fatalf("deriveFastReauthKeys() error = %v", err)
			}
			mskB, emskB, err := deriveFastReauthKeys(tt.identity, tt.counter, tt.nonceS, tt.mk)
			if err != nil {
				t.Fatalf("deriveFastReauthKeys() second error = %v", err)
			}
			if len(mskA) != 64 || len(emskA) != 64 {
				t.Fatalf("len(msk/emsk) = %d/%d, want 64/64", len(mskA), len(emskA))
			}
			if !bytes.Equal(mskA, mskB) || !bytes.Equal(emskA, emskB) {
				t.Fatal("deriveFastReauthKeys() is not deterministic")
			}
		})
	}
}

func TestBuildAKAAuthenticationReject(t *testing.T) {
	packet, err := BuildAKAAuthenticationReject(0x44)
	if err != nil {
		t.Fatalf("BuildAKAAuthenticationReject() error = %v", err)
	}
	message := mustUnmarshalAKAMessage(t, "message", packet)
	if message.Code != eapCodeResponse || message.Identifier != 0x44 || message.Subtype != akaSubtypeAuthenticationReject {
		t.Fatalf("AKAMessage.UnmarshalBinary() = %+v", message)
	}
	if len(message.Attributes) != 0 {
		t.Fatalf("len(message.Attributes) = %d, want 0", len(message.Attributes))
	}
}

func TestBuildAKASynchronizationFailure(t *testing.T) {
	auts := bytes.Repeat([]byte{0x66}, 14)
	packet, err := BuildAKASynchronizationFailure(0x45, auts)
	if err != nil {
		t.Fatalf("BuildAKASynchronizationFailure() error = %v", err)
	}
	message := mustUnmarshalAKAMessage(t, "message", packet)
	if message.Code != eapCodeResponse || message.Identifier != 0x45 || message.Subtype != akaSubtypeSynchronizationFailure {
		t.Fatalf("AKAMessage.UnmarshalBinary() = %+v", message)
	}
	autsAttr := findAKAAttribute(message.Attributes, akaAttrAUTS)
	if autsAttr == nil {
		t.Fatal("findAKAAttribute(AT_AUTS) = nil")
	}
	if !bytes.Equal(autsAttr.Value, auts) {
		t.Fatalf("AT_AUTS = %X, want %X", autsAttr.Value, auts)
	}
}

func TestParseEAPPacketFailure(t *testing.T) {
	packet, err := (EAPPacket{Code: eapCodeFailure, Identifier: 0x46}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var got EAPPacket
	if err := got.UnmarshalBinary(packet); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got.Code != eapCodeFailure || got.Identifier != 0x46 || got.HasType {
		t.Fatalf("EAPPacket.UnmarshalBinary() = %+v", got)
	}
}
