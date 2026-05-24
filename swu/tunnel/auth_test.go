package tunnel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"
	"testing"

	"github.com/damonto/ims-client/swu/eapaka"
	"github.com/damonto/ims-client/swu/ike"
	"github.com/damonto/ims-client/usim"
)

const akaAttrNonceSTest byte = 21

type akaChallengeTestCard struct {
	sessionTestCard
	result usim.AKAResult
}

type twoDigitMNCCard struct {
	sessionTestCard
}

func (twoDigitMNCCard) IMSI() string { return "204020123456789" }
func (twoDigitMNCCard) MCC() string  { return "204" }
func (twoDigitMNCCard) MNC() string  { return "02" }

func (c akaChallengeTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return c.result, nil
}

func buildSignedAKAChallenge(t *testing.T, identifier byte, identity string, rand, autn []byte, result usim.AKAResult, extraAttrs ...eapaka.AKAAttribute) []byte {
	t.Helper()

	keys, err := deriveEAPKeys([]byte(identity), result.IK, result.CK)
	if err != nil {
		t.Fatalf("deriveEAPKeys() error = %v", err)
	}
	attrs := []eapaka.AKAAttribute{
		{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, rand...)},
		{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, autn...)},
	}
	attrs = append(attrs, extraAttrs...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapaka.CodeRequest,
		Identifier: identifier,
		Subtype:    eapaka.SubtypeChallenge,
		Attributes: attrs,
	}).MarshalSigned(keys.AUT, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	return wire
}

func encryptAKAAttributesForTest(t *testing.T, attrs []eapaka.AKAAttribute, encrKey, iv []byte) []eapaka.AKAAttribute {
	t.Helper()

	plain := make([]byte, 0)
	for _, attr := range attrs {
		encoded, err := attr.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() error = %v", err)
		}
		plain = append(plain, encoded...)
	}
	if rem := len(plain) % aes.BlockSize; rem != 0 {
		padLen := aes.BlockSize - rem
		padding, err := (eapaka.AKAAttribute{Type: eapaka.AttrPadding, Value: make([]byte, padLen-2)}).MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary() error = %v", err)
		}
		plain = append(plain, padding...)
	}
	block, err := aes.NewCipher(encrKey)
	if err != nil {
		t.Fatalf("NewCipher() error = %v", err)
	}
	ciphertext := make([]byte, len(plain))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
	return []eapaka.AKAAttribute{
		{Type: akaAttrIV, Value: append([]byte{0x00, 0x00}, iv...)},
		{Type: akaAttrEncryptedData, Value: append([]byte{0x00, 0x00}, ciphertext...)},
	}
}

func buildSignedAKAReauthRequest(t *testing.T, identifier byte, counter uint16, nonceS, autKey, encrKey []byte) []byte {
	t.Helper()

	counterValue := make([]byte, 2)
	binary.BigEndian.PutUint16(counterValue, counter)
	encrypted := encryptAKAAttributesForTest(t, []eapaka.AKAAttribute{
		{Type: akaAttrCounter, Value: counterValue},
		{Type: akaAttrNonceSTest, Value: append([]byte{0x00, 0x00}, nonceS...)},
	}, encrKey, bytes.Repeat([]byte{0x55}, aes.BlockSize))
	wire, err := (eapaka.AKAMessage{
		Code:       eapaka.CodeRequest,
		Identifier: identifier,
		Subtype:    eapaka.SubtypeReauthentication,
		Attributes: encrypted,
	}).MarshalSigned(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	return wire
}

func buildIdentityResponseForTest(t *testing.T, flow *akaAuthFlow, message eapaka.AKAMessage) akaResponse {
	t.Helper()
	if message.Code == 0 {
		message.Code = eapaka.CodeRequest
	}
	if message.Subtype == 0 {
		message.Subtype = eapaka.SubtypeIdentity
	}
	wire, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	response, err := flow.buildIdentityResponse(message, wire)
	if err != nil {
		t.Fatalf("buildIdentityResponse() error = %v", err)
	}
	return response
}

func checkcodeForTest(packets [][]byte) []byte {
	sum := sha1.New()
	for _, packet := range packets {
		_, _ = sum.Write(packet)
	}
	return append([]byte{0x00, 0x00}, sum.Sum(nil)...)
}

func TestInitialAKAIdentityPadsTwoDigitMNC(t *testing.T) {
	identity, realm, _, err := initialAKAIdentity(twoDigitMNCCard{})
	if err != nil {
		t.Fatalf("initialAKAIdentity() error = %v", err)
	}

	if realm != "nai.epc.mnc002.mcc204.3gppnetwork.org" {
		t.Fatalf("realm = %q, want %q", realm, "nai.epc.mnc002.mcc204.3gppnetwork.org")
	}
	if identity != "0204020123456789@nai.epc.mnc002.mcc204.3gppnetwork.org" {
		t.Fatalf("identity = %q, want %q", identity, "0204020123456789@nai.epc.mnc002.mcc204.3gppnetwork.org")
	}
}

func TestAKAAuthFlowBuildIdentityResponse(t *testing.T) {
	tests := []struct {
		name               string
		flow               akaAuthFlow
		attrs              []eapaka.AKAAttribute
		wantIdentity       string
		wantClientError    bool
		wantIdentityRounds int
		wantLastRequest    byte
	}{
		{
			name:               "first any identity request succeeds",
			flow:               akaAuthFlow{card: sessionTestCard{}, realm: "nai.epc.mnc001.mcc001.3gppnetwork.org"},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}}},
			wantIdentity:       "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrAnyIDReq,
		},
		{
			name: "fullauth uses pseudonym identity with realm",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
				currentState: usim.AKAIdentityState{
					Pseudonym: "pseudonym123",
				},
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrFullAuthIDReq, Value: []byte{0x00, 0x00}}},
			wantIdentity:       "pseudonym123@nai.epc.mnc001.mcc001.3gppnetwork.org",
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrFullAuthIDReq,
		},
		{
			name: "any identity prefers fast reauth nai",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
				currentState: usim.AKAIdentityState{
					ReauthIdentity: "reauth123@aaa.example.net",
					MK:             []byte{0x01},
					KAut:           []byte{0x02},
					KEncr:          []byte{0x03},
				},
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}}},
			wantIdentity:       "reauth123@aaa.example.net",
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrAnyIDReq,
		},
		{
			name: "fullauth after permanent returns client error",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  1,
				lastIdentityReq: akaAttrPermanentIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrFullAuthIDReq, Value: []byte{0x00, 0x00}}},
			wantClientError:    true,
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrPermanentIDReq,
		},
		{
			name: "fourth identity round returns client error",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  3,
				lastIdentityReq: akaAttrPermanentIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
			wantClientError:    true,
			wantIdentityRounds: 3,
			wantLastRequest:    akaAttrPermanentIDReq,
		},
		{
			name: "duplicate any identity request returns client error",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
			},
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
			},
			wantClientError:    true,
			wantIdentityRounds: 0,
			wantLastRequest:    0,
		},
		{
			name: "identity request with checkcode returns client error",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
			},
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
				{Type: akaAttrCheckcode, Value: []byte{0x00, 0x00}},
			},
			wantClientError:    true,
			wantIdentityRounds: 0,
			wantLastRequest:    0,
		},
		{
			name: "identity request with forbidden mac returns client error",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
			},
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
				{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			},
			wantClientError:    true,
			wantIdentityRounds: 0,
			wantLastRequest:    0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			message := eapaka.AKAMessage{
				Identifier: 7,
				Attributes: tt.attrs,
			}

			response := buildIdentityResponseForTest(t, &tt.flow, message)

			if tt.wantClientError {
				if response.afterSend == nil {
					t.Fatal("buildIdentityResponse() afterSend = nil, want client error")
				}
				want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
				if err != nil {
					t.Fatalf("BuildClientErrorPacket() error = %v", err)
				}
				if string(response.data) != string(want) {
					t.Fatalf("client error response mismatch")
				}
			} else {
				if response.afterSend != nil {
					t.Fatalf("buildIdentityResponse() afterSend = %v, want nil", response.afterSend)
				}
				var got eapaka.AKAMessage
				if err := got.UnmarshalBinary(response.data); err != nil {
					t.Fatalf("UnmarshalBinary() error = %v", err)
				}
				identityAttr := eapaka.FindAttribute(got.Attributes, akaAttrIdentity)
				if identityAttr == nil {
					t.Fatal("identity attribute is missing")
				}
				identity, err := eapaka.StringValue(identityAttr)
				if err != nil {
					t.Fatalf("StringValue() error = %v", err)
				}
				if identity != tt.wantIdentity {
					t.Fatalf("identity = %q, want %q", identity, tt.wantIdentity)
				}
			}

			if tt.flow.identityRounds != tt.wantIdentityRounds {
				t.Fatalf("identityRounds = %d, want %d", tt.flow.identityRounds, tt.wantIdentityRounds)
			}
			if tt.flow.lastIdentityReq != tt.wantLastRequest {
				t.Fatalf("lastIdentityReq = %d, want %d", tt.flow.lastIdentityReq, tt.wantLastRequest)
			}
		})
	}
}

func TestAKAAuthFlowRepeatedAnyIdentityRequestReturnsClientError(t *testing.T) {
	flow := akaAuthFlow{card: sessionTestCard{}, realm: "nai.epc.mnc001.mcc001.3gppnetwork.org"}
	message := eapaka.AKAMessage{
		Identifier: 9,
		Attributes: []eapaka.AKAAttribute{{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}}},
	}

	first := buildIdentityResponseForTest(t, &flow, message)
	if first.afterSend != nil {
		t.Fatalf("first buildIdentityResponse() afterSend = %v, want nil", first.afterSend)
	}

	second := buildIdentityResponseForTest(t, &flow, message)
	if second.afterSend == nil {
		t.Fatal("second buildIdentityResponse() afterSend = nil, want client error")
	}
	want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorPacket() error = %v", err)
	}
	if string(second.data) != string(want) {
		t.Fatal("second buildIdentityResponse() did not return client error packet")
	}
	if flow.identityRounds != 1 {
		t.Fatalf("identityRounds = %d, want 1", flow.identityRounds)
	}
}

func TestAKAAuthFlowDuplicateIdentityRequestReturnsClientError(t *testing.T) {
	flow := akaAuthFlow{card: sessionTestCard{}, realm: "nai.epc.mnc001.mcc001.3gppnetwork.org"}
	message := eapaka.AKAMessage{
		Identifier: 10,
		Attributes: []eapaka.AKAAttribute{
			{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
			{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
		},
	}

	response := buildIdentityResponseForTest(t, &flow, message)
	if response.afterSend == nil {
		t.Fatal("buildIdentityResponse() afterSend = nil, want client error")
	}
	want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorPacket() error = %v", err)
	}
	if string(response.data) != string(want) {
		t.Fatal("buildIdentityResponse() did not return client error packet")
	}
}

func TestAKAAuthFlowBuildChallengeResponseMalformedRequestReturnsClientError(t *testing.T) {
	flow := akaAuthFlow{}
	message := eapaka.AKAMessage{Identifier: 11}

	response, err := flow.buildChallengeResponse(message, []byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend == nil {
		t.Fatal("buildChallengeResponse() afterSend = nil, want client error")
	}
	want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorPacket() error = %v", err)
	}
	if string(response.data) != string(want) {
		t.Fatal("buildChallengeResponse() did not return client error packet")
	}
}

func TestAKAAuthFlowBuildChallengeResponseDuplicateRANDReturnsClientError(t *testing.T) {
	flow := akaAuthFlow{}
	message := eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: 12,
		Subtype:    akaSubtypeChallenge,
		Attributes: []eapaka.AKAAttribute{
			{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
		},
	}
	wire, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend == nil {
		t.Fatal("buildChallengeResponse() afterSend = nil, want client error")
	}
	want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorPacket() error = %v", err)
	}
	if string(response.data) != string(want) {
		t.Fatal("buildChallengeResponse() did not return client error packet")
	}
}

func TestAKAAuthFlowBuildChallengeResponseUnexpectedAttributeReturnsClientError(t *testing.T) {
	flow := akaAuthFlow{}
	message := eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: 13,
		Subtype:    akaSubtypeChallenge,
		Attributes: []eapaka.AKAAttribute{
			{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrMAC, Value: append([]byte{0x00, 0x00}, make([]byte, 16)...)},
			{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
		},
	}
	wire, err := message.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend == nil {
		t.Fatal("buildChallengeResponse() afterSend = nil, want client error")
	}
	want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		t.Fatalf("BuildClientErrorPacket() error = %v", err)
	}
	if string(response.data) != string(want) {
		t.Fatal("buildChallengeResponse() did not return client error packet")
	}
}

func TestAKAAuthFlowBuildChallengeResponseUsesCurrentEAPIdentity(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}

	tests := []struct {
		name            string
		identity        string
		identityRequest []eapaka.AKAAttribute
		challengeID     string
	}{
		{
			name:        "challenge without identity round uses initial identity",
			identity:    "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			challengeID: "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name:            "challenge after identity round uses last at_identity value",
			identity:        "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			identityRequest: []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
			challengeID:     "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := akaAuthFlow{
				session:     &Session{logger: slog.Default()},
				card:        akaChallengeTestCard{result: akaResult},
				identity:    tt.identity,
				eapIdentity: tt.identity,
				realm:       "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:      &ikeCrypto{},
			}
			if len(tt.identityRequest) != 0 {
				response := buildIdentityResponseForTest(t, &flow, eapaka.AKAMessage{
					Identifier: 7,
					Attributes: tt.identityRequest,
				})
				if response.afterSend != nil {
					t.Fatalf("buildIdentityResponse() afterSend = %v, want nil", response.afterSend)
				}
			}

			wire := buildSignedAKAChallenge(t, 8, tt.challengeID, rand, autn, akaResult)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}

			var got eapaka.AKAMessage
			if err := got.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			if got.Subtype != eapaka.SubtypeChallenge {
				t.Fatalf("response subtype = %d, want %d", got.Subtype, eapaka.SubtypeChallenge)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseVerifiesCheckcode(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"

	tests := []struct {
		name           string
		checkcodeValue func([][]byte) []byte
		wantClientErr  bool
	}{
		{
			name: "valid checkcode succeeds",
			checkcodeValue: func(packets [][]byte) []byte {
				return checkcodeForTest(packets)
			},
		},
		{
			name: "invalid checkcode returns client error",
			checkcodeValue: func([][]byte) []byte {
				return append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x66}, sha1.Size)...)
			},
			wantClientErr: true,
		},
		{
			name: "empty checkcode after identity round returns client error",
			checkcodeValue: func([][]byte) []byte {
				return []byte{0x00, 0x00}
			},
			wantClientErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := akaAuthFlow{
				session:     &Session{logger: slog.Default()},
				card:        akaChallengeTestCard{result: akaResult},
				identity:    identity,
				eapIdentity: identity,
				realm:       "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:      &ikeCrypto{},
			}
			identityRequest := eapaka.AKAMessage{
				Code:       eapaka.CodeRequest,
				Identifier: 7,
				Subtype:    eapaka.SubtypeIdentity,
				Attributes: []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
			}
			if response := buildIdentityResponseForTest(t, &flow, identityRequest); response.afterSend != nil {
				t.Fatalf("buildIdentityResponse() afterSend = %v, want nil", response.afterSend)
			}

			wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult, eapaka.AKAAttribute{
				Type:  akaAttrCheckcode,
				Value: tt.checkcodeValue(flow.identityPackets),
			})
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			response, err := flow.buildChallengeResponse(message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if tt.wantClientErr {
				if response.afterSend == nil {
					t.Fatal("buildChallengeResponse() afterSend = nil, want client error")
				}
				return
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}
		})
	}
}

func TestAKAAuthFlowBuildReauthenticationResponseUsesCurrentEAPIdentity(t *testing.T) {
	identity := "reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
	mk := bytes.Repeat([]byte{0x77}, 20)
	kAut := bytes.Repeat([]byte{0x11}, 16)
	kEncr := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	counter := uint16(5)

	wantMSK, wantEMSK, err := eapaka.DeriveFastReauthKeys([]byte(identity), counter, nonceS, mk)
	if err != nil {
		t.Fatalf("DeriveFastReauthKeys() error = %v", err)
	}

	flow := akaAuthFlow{
		eapIdentity: identity,
		currentState: usim.AKAIdentityState{
			ReauthIdentity: identity,
			Counter:        1,
			MK:             mk,
			KAut:           kAut,
			KEncr:          kEncr,
		},
		crypto: &ikeCrypto{},
	}

	wire := buildSignedAKAReauthRequest(t, 9, counter, nonceS, kAut, kEncr)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildReauthenticationResponse(message, wire)
	if err != nil {
		t.Fatalf("buildReauthenticationResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("buildReauthenticationResponse() afterSend = %v, want nil", response.afterSend)
	}
	if !bytes.Equal(flow.crypto.eap.MSK, wantMSK) {
		t.Fatalf("MSK = %X, want %X", flow.crypto.eap.MSK, wantMSK)
	}
	if !bytes.Equal(flow.crypto.eap.EMSK, wantEMSK) {
		t.Fatalf("EMSK = %X, want %X", flow.crypto.eap.EMSK, wantEMSK)
	}
}

func TestAKAAuthFlowRejectsStaleReauthenticationCounter(t *testing.T) {
	tests := []struct {
		name    string
		current uint16
		request uint16
	}{
		{name: "lower", current: 5, request: 4},
		{name: "equal", current: 5, request: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := "reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
			mk := bytes.Repeat([]byte{0x77}, 20)
			kAut := bytes.Repeat([]byte{0x11}, 16)
			kEncr := bytes.Repeat([]byte{0x22}, 16)
			nonceS := bytes.Repeat([]byte{0x33}, 16)
			flow := akaAuthFlow{
				eapIdentity: identity,
				currentState: usim.AKAIdentityState{
					ReauthIdentity: identity,
					Counter:        tt.current,
					MK:             mk,
					KAut:           kAut,
					KEncr:          kEncr,
				},
				crypto: &ikeCrypto{},
			}

			wire := buildSignedAKAReauthRequest(t, 9, tt.request, nonceS, kAut, kEncr)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildReauthenticationResponse(message, wire)
			if err != nil {
				t.Fatalf("buildReauthenticationResponse() error = %v", err)
			}
			if len(response.data) == 0 {
				t.Fatal("buildReauthenticationResponse() data is empty")
			}
			if response.afterSend == nil {
				t.Fatal("buildReauthenticationResponse() afterSend = nil, want stale counter error")
			}
		})
	}
}

func TestOpenIKEAuthResponsePlaintextNotify(t *testing.T) {
	tests := []struct {
		name       string
		notifyType uint16
		want       string
	}{
		{
			name:       "invalid syntax",
			notifyType: 7,
			want:       "INVALID_SYNTAX (7)",
		},
		{
			name:       "authentication failed",
			notifyType: 24,
			want:       "AUTHENTICATION_FAILED (24)",
		},
		{
			name:       "unknown notify",
			notifyType: 65000,
			want:       "UNKNOWN_NOTIFY (65000)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := (ike.IKEPacket{
				Header: ike.IKEHeader{
					InitiatorSPI: 1,
					ResponderSPI: 2,
					Version:      ike.Version20,
					ExchangeType: ike.ExchangeTypeIKEAuth,
					Flags:        ike.FlagResponse,
					MessageID:    3,
				},
				Payloads: []ike.Payload{
					&ike.NotifyPayload{NotifyType: tt.notifyType},
				},
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var packet ike.IKEPacket
			if err := packet.UnmarshalBinary(raw); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			_, err = openIKEAuthResponse(packet, &ikeCrypto{}, "opening aka response message")
			if err == nil {
				t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
			}
			if !strings.Contains(err.Error(), "unencrypted ike_auth notify") {
				t.Fatalf("openIKEAuthResponse() error = %v, want unencrypted notify context", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("openIKEAuthResponse() error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBuildInformationalResponsePayloadsDeleteHandling(t *testing.T) {
	tests := []struct {
		name            string
		state           informationalState
		payloads        []ike.Payload
		wantDeleteIKE   bool
		wantDeleteChild bool
		wantSPI         uint32
	}{
		{
			name: "ike delete",
			state: informationalState{
				inboundSPI:  0x10203040,
				outboundSPI: 0x50607080,
			},
			payloads:      []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}},
			wantDeleteIKE: true,
		},
		{
			name: "child delete",
			state: informationalState{
				inboundSPI:  0x10203040,
				outboundSPI: 0x50607080,
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{
					ProtocolID: protocolIDESP,
					SPIs:       [][]byte{uint32Bytes(0x50607080)},
				},
			},
			wantDeleteChild: true,
			wantSPI:         0x10203040,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			responsePayloads, action, err := buildInformationalResponsePayloads(tt.state, tt.payloads, "")
			if err != nil {
				t.Fatalf("buildInformationalResponsePayloads() error = %v", err)
			}
			if action.deleteIKE != tt.wantDeleteIKE {
				t.Fatalf("deleteIKE = %t, want %t", action.deleteIKE, tt.wantDeleteIKE)
			}
			if action.deleteChild != tt.wantDeleteChild {
				t.Fatalf("deleteChild = %t, want %t", action.deleteChild, tt.wantDeleteChild)
			}
			if !tt.wantDeleteChild {
				if len(responsePayloads) != 0 {
					t.Fatalf("response payload count = %d, want 0", len(responsePayloads))
				}
				return
			}

			if len(responsePayloads) != 1 {
				t.Fatalf("response payload count = %d, want 1", len(responsePayloads))
			}
			deletePayload, ok := responsePayloads[0].(*ike.DeletePayload)
			if !ok {
				t.Fatalf("response payload type = %T, want *ike.DeletePayload", responsePayloads[0])
			}
			if deletePayload.ProtocolID != protocolIDESP {
				t.Fatalf("response protocol id = %d, want %d", deletePayload.ProtocolID, protocolIDESP)
			}
			if len(deletePayload.SPIs) != 1 {
				t.Fatalf("response spi count = %d, want 1", len(deletePayload.SPIs))
			}
			if got := binary.BigEndian.Uint32(deletePayload.SPIs[0]); got != tt.wantSPI {
				t.Fatalf("response spi = %#x, want %#x", got, tt.wantSPI)
			}
		})
	}
}

func TestInformationalStateCanSendDeleteWithoutChildSA(t *testing.T) {
	state := informationalState{
		ike:  &ikeCrypto{},
		peer: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500},
	}
	if !state.canSendDelete() {
		t.Fatal("canSendDelete() = false, want true when IKE state is still available")
	}
}
