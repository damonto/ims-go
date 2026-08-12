package tunnel

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/damonto/ims-go/eapaka"
	"github.com/damonto/ims-go/swu/ike"
	usim "github.com/damonto/wwan-go/sim"
)

const (
	akaAttrNonceSTest byte = 21

	deviceIdentityTypeIMEISVTest byte = 0x02
)

type akaChallengeTestCard struct {
	sessionTestCard
	result usim.AKAResult
}

type akaCountingChallengeTestCard struct {
	sessionTestCard
	result usim.AKAResult
	calls  int
}

type akaFailTestCard struct {
	sessionTestCard
	err error
}

type twoDigitMNCCard struct {
	sessionTestCard
}

type akaStateTestCard struct {
	sessionTestCard
	state usim.AKAIdentityState
}

type akaReadOnlyStateTestCard struct {
	sessionTestCard
	state usim.AKAIdentityState
}

type plmnTestCard struct {
	sessionTestCard
	mcc string
	mnc string
}

func (twoDigitMNCCard) IMSI() string { return "204020123456789" }
func (twoDigitMNCCard) MCC() string  { return "204" }
func (twoDigitMNCCard) MNC() string  { return "02" }

func (c plmnTestCard) MCC() string { return c.mcc }
func (c plmnTestCard) MNC() string { return c.mnc }

func (c *akaStateTestCard) AKAIdentityState() usim.AKAIdentityState {
	return cloneAKAIdentityState(c.state)
}
func (c *akaStateTestCard) SetAKAIdentityState(state usim.AKAIdentityState) {
	c.state = cloneAKAIdentityState(state)
}

func (c akaReadOnlyStateTestCard) AKAIdentityState() usim.AKAIdentityState {
	return cloneAKAIdentityState(c.state)
}

func assertAKAIdentityState(t *testing.T, got, want usim.AKAIdentityState) {
	t.Helper()
	if got.Pseudonym != want.Pseudonym ||
		got.ReauthIdentity != want.ReauthIdentity ||
		got.Counter != want.Counter ||
		!slices.Equal(got.MK, want.MK) ||
		!slices.Equal(got.KEncr, want.KEncr) ||
		!slices.Equal(got.KAut, want.KAut) {
		t.Fatalf("AKA identity state = %+v, want %+v", got, want)
	}
}

func (c akaChallengeTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return c.result, nil
}

func (c *akaCountingChallengeTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	c.calls++
	return c.result, nil
}

func (c akaFailTestCard) AKA(context.Context, []byte, []byte) (usim.AKAResult, error) {
	return usim.AKAResult{}, c.err
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
		Code:       eapCodeRequest,
		Identifier: identifier,
		Subtype:    akaSubtypeChallenge,
		Attributes: attrs,
	}).MarshalSigned(keys.AUT, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	return wire
}

func buildSignedAKAPrimeChallenge(t *testing.T, identifier byte, identity string, rand, autn, networkName []byte, result usim.AKAResult, extraAttrs ...eapaka.AKAAttribute) []byte {
	t.Helper()

	keys, err := eapaka.DeriveAKAPrimeKeys([]byte(identity), result.CK, result.IK, networkName, autn[:akaPrimeSQNXorAKLen])
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	kdfInputAttr := akaAttributeFromBinaryForTest(t, eapaka.KDFInput{NetworkName: networkName})
	kdfAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault})
	attrs := []eapaka.AKAAttribute{
		{Type: akaAttrRAND, Value: append([]byte{0x00, 0x00}, rand...)},
		{Type: akaAttrAUTN, Value: append([]byte{0x00, 0x00}, autn...)},
		kdfInputAttr,
		kdfAttr,
	}
	attrs = append(attrs, extraAttrs...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: identifier,
		EAPType:    eapTypeAKAPrime,
		Subtype:    akaSubtypeChallenge,
		Attributes: attrs,
	}).MarshalSignedSHA256(keys.AUT, nil)
	if err != nil {
		t.Fatalf("MarshalSignedSHA256() error = %v", err)
	}
	return wire
}

func buildAKAPrimeChallengeWithAttrs(t *testing.T, identifier byte, attrs []eapaka.AKAAttribute) []byte {
	t.Helper()
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: identifier,
		EAPType:    eapTypeAKAPrime,
		Subtype:    akaSubtypeChallenge,
		Attributes: attrs,
	}).MarshalSignedSHA256(bytes.Repeat([]byte{0x44}, 32), nil)
	if err != nil {
		t.Fatalf("MarshalSignedSHA256() error = %v", err)
	}
	return wire
}

func akaAttributeFromBinaryForTest(t *testing.T, marshaler interface{ MarshalBinary() ([]byte, error) }) eapaka.AKAAttribute {
	t.Helper()
	wire, err := marshaler.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var attr eapaka.AKAAttribute
	if err := attr.UnmarshalBinary(wire); err != nil {
		t.Fatalf("AKAAttribute.UnmarshalBinary() error = %v", err)
	}
	return attr
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
		padding, err := (eapaka.AKAAttribute{Type: akaAttrPadding, Value: make([]byte, padLen-2)}).MarshalBinary()
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

func akaStringValueForTest(value string) []byte {
	wire := make([]byte, 2, 2+len(value)+3)
	binary.BigEndian.PutUint16(wire, uint16(len(value)))
	wire = append(wire, value...)
	for (len(wire)+2)%4 != 0 {
		wire = append(wire, 0)
	}
	return wire
}

func buildSignedAKAReauthRequest(t *testing.T, identifier byte, counter uint16, nonceS, autKey, encrKey []byte, extraAttrs ...eapaka.AKAAttribute) []byte {
	t.Helper()

	counterValue := make([]byte, 2)
	binary.BigEndian.PutUint16(counterValue, counter)
	encrypted := encryptAKAAttributesForTest(t, []eapaka.AKAAttribute{
		{Type: akaAttrCounter, Value: counterValue},
		{Type: akaAttrNonceSTest, Value: append([]byte{0x00, 0x00}, nonceS...)},
	}, encrKey, bytes.Repeat([]byte{0x55}, aes.BlockSize))
	encrypted = append(encrypted, extraAttrs...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: identifier,
		Subtype:    akaSubtypeReauthentication,
		Attributes: encrypted,
	}).MarshalSigned(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	return wire
}

func buildSignedAKAPrimeReauthRequest(t *testing.T, identifier byte, counter uint16, nonceS, autKey, encrKey []byte, extraAttrs ...eapaka.AKAAttribute) []byte {
	t.Helper()

	counterValue := make([]byte, 2)
	binary.BigEndian.PutUint16(counterValue, counter)
	encrypted := encryptAKAAttributesForTest(t, []eapaka.AKAAttribute{
		{Type: akaAttrCounter, Value: counterValue},
		{Type: akaAttrNonceSTest, Value: append([]byte{0x00, 0x00}, nonceS...)},
	}, encrKey, bytes.Repeat([]byte{0x55}, aes.BlockSize))
	encrypted = append(encrypted, extraAttrs...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: identifier,
		EAPType:    eapTypeAKAPrime,
		Subtype:    akaSubtypeReauthentication,
		Attributes: encrypted,
	}).MarshalSignedSHA256(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSignedSHA256() error = %v", err)
	}
	return wire
}

func buildSignedNotificationForTest(t *testing.T, identifier byte, code uint16, autKey []byte, extraAttrs ...eapaka.AKAAttribute) ([]byte, eapaka.AKAMessage) {
	t.Helper()
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, code)
	attrs := []eapaka.AKAAttribute{{Type: akaAttrNotification, Value: value}}
	attrs = append(attrs, extraAttrs...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: identifier,
		Subtype:    akaSubtypeNotification,
		Attributes: attrs,
	}).MarshalSigned(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	return wire, message
}

func buildIdentityResponseForTest(t *testing.T, flow *akaAuthFlow, message eapaka.AKAMessage) akaResponse {
	t.Helper()
	if message.Code == 0 {
		message.Code = eapCodeRequest
	}
	if message.Subtype == 0 {
		message.Subtype = akaSubtypeIdentity
	}
	wire := marshalAKAMessageUncheckedForTest(t, message)
	response, err := flow.buildIdentityResponse(message, wire)
	if err != nil {
		t.Fatalf("buildIdentityResponse() error = %v", err)
	}
	return response
}

func marshalAKAMessageUncheckedForTest(t *testing.T, message eapaka.AKAMessage) []byte {
	t.Helper()
	payload := []byte{message.Subtype, 0x00, 0x00}
	for _, attr := range message.Attributes {
		wire, err := attr.MarshalBinary()
		if err != nil {
			t.Fatalf("AKAAttribute.MarshalBinary() error = %v", err)
		}
		payload = append(payload, wire...)
	}
	eapType := message.EAPType
	if eapType == 0 {
		eapType = eapTypeAKA
	}
	wire, err := (eapaka.EAPPacket{
		Code:       message.Code,
		Identifier: message.Identifier,
		Type:       eapType,
		HasType:    true,
		Data:       payload,
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("EAPPacket.MarshalBinary() error = %v", err)
	}
	return wire
}

func checkcodeForTest(packets [][]byte) []byte {
	sum := sha1.New()
	for _, packet := range packets {
		_, _ = sum.Write(packet)
	}
	return append([]byte{0x00, 0x00}, sum.Sum(nil)...)
}

func TestSelectInitialAKAIdentity(t *testing.T) {
	const realm = "nai.epc.mnc001.mcc001.3gppnetwork.org"
	validReauthState := usim.AKAIdentityState{
		Pseudonym:      "pseudonym123",
		ReauthIdentity: "reauth123",
		Counter:        7,
		MK:             []byte{0x01},
		KEncr:          []byte{0x02},
		KAut:           []byte{0x03},
	}
	tests := []struct {
		name         string
		card         Card
		wantIdentity string
		wantRealm    string
		wantType     akaIdentityType
		wantState    usim.AKAIdentityState
	}{
		{
			name:         "fast reauthentication",
			card:         &akaStateTestCard{state: cloneAKAIdentityState(validReauthState)},
			wantIdentity: "reauth123@" + realm,
			wantRealm:    realm,
			wantType:     akaIdentityFastReauth,
			wantState:    cloneAKAIdentityState(validReauthState),
		},
		{
			name:         "pseudonym",
			card:         &akaStateTestCard{state: usim.AKAIdentityState{Pseudonym: "pseudonym123"}},
			wantIdentity: "pseudonym123@" + realm,
			wantRealm:    realm,
			wantType:     akaIdentityPseudonym,
			wantState:    usim.AKAIdentityState{Pseudonym: "pseudonym123"},
		},
		{
			name: "blank reauthentication identity falls back to pseudonym",
			card: &akaStateTestCard{state: usim.AKAIdentityState{
				Pseudonym:      "pseudonym123",
				ReauthIdentity: " \t ",
				MK:             []byte{0x01},
				KEncr:          []byte{0x02},
				KAut:           []byte{0x03},
			}},
			wantIdentity: "pseudonym123@" + realm,
			wantRealm:    realm,
			wantType:     akaIdentityPseudonym,
			wantState: usim.AKAIdentityState{
				Pseudonym:      "pseudonym123",
				ReauthIdentity: " \t ",
				MK:             []byte{0x01},
				KEncr:          []byte{0x02},
				KAut:           []byte{0x03},
			},
		},
		{
			name:         "blank pseudonym falls back to permanent identity",
			card:         &akaStateTestCard{state: usim.AKAIdentityState{Pseudonym: " \t "}},
			wantIdentity: "0001010123456789@" + realm,
			wantRealm:    realm,
			wantType:     akaIdentityPermanent,
			wantState:    usim.AKAIdentityState{Pseudonym: " \t "},
		},
		{
			name:         "read-only temporary state is unavailable",
			card:         akaReadOnlyStateTestCard{state: cloneAKAIdentityState(validReauthState)},
			wantIdentity: "0001010123456789@" + realm,
			wantRealm:    realm,
			wantType:     akaIdentityPermanent,
		},
		{
			name:         "permanent identity pads two-digit mnc",
			card:         twoDigitMNCCard{},
			wantIdentity: "0204020123456789@nai.epc.mnc002.mcc204.3gppnetwork.org",
			wantRealm:    "nai.epc.mnc002.mcc204.3gppnetwork.org",
			wantType:     akaIdentityPermanent,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectInitialAKAIdentity(tt.card)
			if err != nil {
				t.Fatalf("selectInitialAKAIdentity() error = %v", err)
			}
			if got.identity != tt.wantIdentity || got.realm != tt.wantRealm || got.identityType != tt.wantType {
				t.Fatalf("selectInitialAKAIdentity() = {%q, %q, %q}, want {%q, %q, %q}", got.identity, got.realm, got.identityType, tt.wantIdentity, tt.wantRealm, tt.wantType)
			}
			assertAKAIdentityState(t, got.state, tt.wantState)
		})
	}
}

func TestAKAIdentityTypeString(t *testing.T) {
	tests := []struct {
		name         string
		identityType akaIdentityType
		want         string
	}{
		{name: "unknown", identityType: akaIdentityUnknown, want: "unknown"},
		{name: "permanent", identityType: akaIdentityPermanent, want: "permanent"},
		{name: "pseudonym", identityType: akaIdentityPseudonym, want: "pseudonym"},
		{name: "fast reauthentication", identityType: akaIdentityFastReauth, want: "fast_reauth"},
		{name: "invalid", identityType: akaIdentityType(255), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.identityType.String(); got != tt.want {
				t.Fatalf("akaIdentityType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSelectInitialAKAIdentityRejectsInvalidPLMN(t *testing.T) {
	tests := []struct {
		name string
		mcc  string
		mnc  string
	}{
		{name: "short mcc", mcc: "01", mnc: "001"},
		{name: "non-digit mcc", mcc: "00x", mnc: "001"},
		{name: "short mnc", mcc: "001", mnc: "1"},
		{name: "non-digit two-digit mnc", mcc: "001", mnc: "0x"},
		{name: "non-digit three-digit mnc", mcc: "001", mnc: "00x"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := selectInitialAKAIdentity(plmnTestCard{mcc: tt.mcc, mnc: tt.mnc})
			if err == nil {
				t.Fatal("selectInitialAKAIdentity() error = nil, want error")
			}
		})
	}
}

func TestAKAAuthFlowBuildEAPIdentityResponse(t *testing.T) {
	tests := []struct {
		name     string
		flow     akaAuthFlow
		wantErr  bool
		wantData string
	}{
		{
			name:     "uses selected aka identity",
			flow:     akaAuthFlow{eapIdentity: "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"},
			wantData: "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name:    "empty identity fails",
			flow:    akaAuthFlow{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, err := tt.flow.buildEAPIdentityResponse(9)
			if tt.wantErr {
				if err == nil {
					t.Fatal("buildEAPIdentityResponse() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("buildEAPIdentityResponse() error = %v", err)
			}
			var packet eapaka.EAPPacket
			if err := packet.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			if packet.Code != eapCodeResponse || packet.Identifier != 9 || !packet.HasType || packet.Type != eapTypeIdentity {
				t.Fatalf("EAPPacket = %+v", packet)
			}
			if string(packet.Data) != tt.wantData {
				t.Fatalf("identity = %q, want %q", string(packet.Data), tt.wantData)
			}
		})
	}
}

func TestAKAAuthFlowBuildEAPNakResponse(t *testing.T) {
	flow := &akaAuthFlow{}
	response, err := flow.buildEAPNakResponse(0x10)
	if err != nil {
		t.Fatalf("buildEAPNakResponse() error = %v", err)
	}
	var packet eapaka.EAPPacket
	if err := packet.UnmarshalBinary(response.data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if packet.Code != eapCodeResponse || packet.Identifier != 0x10 || !packet.HasType || packet.Type != eapTypeNak {
		t.Fatalf("EAPPacket = %+v", packet)
	}
	wantTypes := []byte{eapTypeAKAPrime, eapTypeAKA}
	if !bytes.Equal(packet.Data, wantTypes) {
		t.Fatalf("desired types = % X, want % X", packet.Data, wantTypes)
	}
}

func TestAKAAuthFlowBuildEAPNotificationResponse(t *testing.T) {
	flow := &akaAuthFlow{}
	response, err := flow.buildEAPNotificationResponse(0x22)
	if err != nil {
		t.Fatalf("buildEAPNotificationResponse() error = %v", err)
	}
	var packet eapaka.EAPPacket
	if err := packet.UnmarshalBinary(response.data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if packet.Code != eapCodeResponse || packet.Identifier != 0x22 || !packet.HasType || packet.Type != eapTypeNotification {
		t.Fatalf("EAPPacket = %+v", packet)
	}
}

func TestAKAAuthFlowBuildIdentityResponse(t *testing.T) {
	const unknownSkippableAttribute byte = 200

	tests := []struct {
		name               string
		flow               akaAuthFlow
		attrs              []eapaka.AKAAttribute
		wantIdentity       string
		wantReauthIdentity string
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
			name: "unknown skippable attribute is ignored",
			flow: akaAuthFlow{
				card:  sessionTestCard{},
				realm: "nai.epc.mnc001.mcc001.3gppnetwork.org",
			},
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
				{Type: unknownSkippableAttribute, Value: []byte{0x00, 0x00}},
			},
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
			wantReauthIdentity: "reauth123@aaa.example.net",
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
			name: "any after permanent returns client error",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  1,
				lastIdentityReq: akaAttrPermanentIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}}},
			wantClientError:    true,
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrPermanentIDReq,
		},
		{
			name: "permanent after permanent returns client error",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  1,
				lastIdentityReq: akaAttrPermanentIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
			wantClientError:    true,
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrPermanentIDReq,
		},
		{
			name: "fullauth after fullauth returns client error",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  1,
				lastIdentityReq: akaAttrFullAuthIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrFullAuthIDReq, Value: []byte{0x00, 0x00}}},
			wantClientError:    true,
			wantIdentityRounds: 1,
			wantLastRequest:    akaAttrFullAuthIDReq,
		},
		{
			name: "permanent after fullauth is allowed",
			flow: akaAuthFlow{
				card:            sessionTestCard{},
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				identityRounds:  1,
				lastIdentityReq: akaAttrFullAuthIDReq,
			},
			attrs:              []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
			wantIdentity:       "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			wantIdentityRounds: 2,
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
			if tt.flow.reauthIdentity != tt.wantReauthIdentity {
				t.Fatalf("reauthIdentity = %q, want %q", tt.flow.reauthIdentity, tt.wantReauthIdentity)
			}
		})
	}
}

func TestAKAAuthFlowDiscardsStoredReauthStateWhenUsed(t *testing.T) {
	realm := "nai.epc.mnc001.mcc001.3gppnetwork.org"
	reauthIdentity := "reauth123@" + realm
	mk := bytes.Repeat([]byte{0x77}, 20)
	kAut := bytes.Repeat([]byte{0x11}, 16)
	kEncr := bytes.Repeat([]byte{0x22}, 16)
	state := usim.AKAIdentityState{
		Pseudonym:      "pseudonym123",
		ReauthIdentity: reauthIdentity,
		Counter:        4,
		MK:             mk,
		KAut:           kAut,
		KEncr:          kEncr,
	}
	tests := []struct {
		name string
		run  func(t *testing.T, flow *akaAuthFlow)
	}{
		{
			name: "identity response",
			run: func(t *testing.T, flow *akaAuthFlow) {
				response := buildIdentityResponseForTest(t, flow, eapaka.AKAMessage{
					Identifier: 7,
					Attributes: []eapaka.AKAAttribute{
						{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
					},
				})
				if response.afterSend != nil {
					t.Fatalf("buildIdentityResponse() afterSend = %v, want nil", response.afterSend)
				}
			},
		},
		{
			name: "reauthentication response",
			run: func(t *testing.T, flow *akaAuthFlow) {
				nonceS := bytes.Repeat([]byte{0x33}, 16)
				wire := buildSignedAKAReauthRequest(t, 9, 5, nonceS, kAut, kEncr)
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
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := &akaStateTestCard{state: state}
			flow := akaAuthFlow{
				card:             card,
				realm:            realm,
				reauthIdentity:   reauthIdentity,
				currentState:     cloneAKAIdentityState(state),
				pendingState:     cloneAKAIdentityState(state),
				currentAuthKey:   append([]byte(nil), kAut...),
				currentEncrKey:   append([]byte(nil), kEncr...),
				currentEAPType:   eapTypeAKA,
				currentCounter:   state.Counter,
				fastReauth:       true,
				akaAuthenticated: true,
				crypto:           &ikeCrypto{},
			}

			tt.run(t, &flow)

			if card.state.Pseudonym != state.Pseudonym {
				t.Fatalf("stored pseudonym = %q, want %q", card.state.Pseudonym, state.Pseudonym)
			}
			if card.state.HasReauth() {
				t.Fatalf("stored reauth state still available: %+v", card.state)
			}
			if card.state.Counter != 0 {
				t.Fatalf("stored counter = %d, want 0", card.state.Counter)
			}
			if len(card.state.MK) != 0 || len(card.state.KAut) != 0 || len(card.state.KEncr) != 0 {
				t.Fatalf("stored keys were not cleared")
			}
			if !flow.currentState.HasReauth() {
				t.Fatalf("flow current reauth state was cleared during active exchange")
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

	response, err := flow.buildChallengeResponse(t.Context(), message, []byte{0x01, 0x02, 0x03})
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
	wire := marshalAKAMessageUncheckedForTest(t, message)

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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
	card := akaChallengeTestCard{result: usim.AKAResult{
		RES: bytes.Repeat([]byte{0x11}, 8),
		IK:  bytes.Repeat([]byte{0x22}, 16),
		CK:  bytes.Repeat([]byte{0x33}, 16),
	}}
	flow := akaAuthFlow{
		session:         &Session{logger: slog.Default()},
		card:            card,
		authenticateAKA: card.AKA,
		crypto:          &ikeCrypto{},
	}
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

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        tt.identity,
				eapIdentity:     tt.identity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
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

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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
			if got.Subtype != akaSubtypeChallenge {
				t.Fatalf("response subtype = %d, want %d", got.Subtype, akaSubtypeChallenge)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseRejectsBiddingDown(t *testing.T) {
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}
	card := akaChallengeTestCard{result: akaResult}
	flow := akaAuthFlow{
		session:         &Session{logger: slog.Default()},
		card:            card,
		authenticateAKA: card.AKA,
		identity:        identity,
		eapIdentity:     identity,
		realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:          &ikeCrypto{},
	}
	wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult, eapaka.AKAAttribute{
		Type:  akaAttrBidding,
		Value: []byte{0x80, 0x00},
	})
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	want, err := eapaka.BuildAKAAuthenticationReject(message.Identifier)
	if err != nil {
		t.Fatalf("BuildAKAAuthenticationReject() error = %v", err)
	}
	if !bytes.Equal(response.data, want) {
		t.Fatalf("response = % X, want % X", response.data, want)
	}
}

func TestAKAAuthFlowBuildChallengeResponseHonorsTrustIndication(t *testing.T) {
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: bytes.Repeat([]byte{0x33}, 8),
		IK:  bytes.Repeat([]byte{0x44}, 16),
		CK:  bytes.Repeat([]byte{0x55}, 16),
	}
	tests := []struct {
		name            string
		relationship    eapaka.TrustRelationship
		wantClientError bool
	}{
		{name: "trusted access terminates SWu", relationship: eapaka.TrustRelationshipTrusted, wantClientError: true},
		{name: "untrusted access continues SWu", relationship: eapaka.TrustRelationshipUntrusted},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        identity,
				eapIdentity:     identity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
			}
			wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult, eapaka.AKAAttribute{
				Type:  akaAttrTrustInd,
				Value: []byte{0x00, byte(tt.relationship)},
			})
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if got := response.afterSend != nil; got != tt.wantClientError {
				t.Fatalf("client error = %t, want %t", got, tt.wantClientError)
			}
			var got eapaka.AKAMessage
			if err := got.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			wantSubtype := akaSubtypeChallenge
			if tt.wantClientError {
				wantSubtype = akaSubtypeClientError
			}
			if got.Subtype != wantSubtype {
				t.Fatalf("response subtype = %d, want %d", got.Subtype, wantSubtype)
			}
		})
	}
}

func TestAKAAuthFlowProcessesAKAPrimeChallengeInAuthenticatedStages(t *testing.T) {
	startIdentity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	keyIdentity := "6001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0x80, 0x00,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("WLAN")
	akaResult := usim.AKAResult{
		RES: bytes.Repeat([]byte{0x33}, 8),
		IK:  bytes.Repeat([]byte{0x44}, 16),
		CK:  bytes.Repeat([]byte{0x55}, 16),
	}
	tests := []struct {
		name        string
		extraAttr   *eapaka.AKAAttribute
		nestedAttrs []eapaka.AKAAttribute
		corruptMAC  bool
	}{
		{
			name: "authenticated wrong attribute is rejected after USIM",
			extraAttr: &eapaka.AKAAttribute{
				Type:  akaAttrNextPseudonym,
				Value: akaStringValueForTest("pseudonym"),
			},
		},
		{
			name: "invalid encrypted identity does not commit partial pending state",
			nestedAttrs: []eapaka.AKAAttribute{
				{Type: akaAttrNextPseudonym, Value: akaStringValueForTest("new-pseudonym")},
				{Type: akaAttrNextReauthID, Value: []byte{0x00, 0x05, 'x', 'x', 'x', 'x'}},
			},
		},
		{name: "invalid mac does not commit derived state", corruptMAC: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := &akaCountingChallengeTestCard{result: akaResult}
			initialPending := usim.AKAIdentityState{Pseudonym: "old-pseudonym", ReauthIdentity: "old-reauth@example.net", Counter: 7}
			flow := akaAuthFlow{
				session:             &Session{logger: slog.Default()},
				card:                card,
				authenticateAKA:     card.AKA,
				identity:            startIdentity,
				eapIdentity:         startIdentity,
				realm:               "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:              &ikeCrypto{},
				akaPrimeNetworkName: "WLAN",
				pendingState:        cloneAKAIdentityState(initialPending),
			}
			extraAttrs := []eapaka.AKAAttribute(nil)
			if tt.extraAttr != nil {
				extraAttrs = append(extraAttrs, *tt.extraAttr)
			}
			if len(tt.nestedAttrs) != 0 {
				keys, err := eapaka.DeriveAKAPrimeKeys([]byte(keyIdentity), akaResult.CK, akaResult.IK, networkName, autn[:akaPrimeSQNXorAKLen])
				if err != nil {
					t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
				}
				extraAttrs = append(extraAttrs, encryptAKAAttributesForTest(t, tt.nestedAttrs, keys.ENCR, bytes.Repeat([]byte{0x66}, aes.BlockSize))...)
			}
			wire := buildSignedAKAPrimeChallenge(t, 8, keyIdentity, rand, autn, networkName, akaResult, extraAttrs...)
			if tt.corruptMAC {
				wire[len(wire)-1] ^= 0x01
			}
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if response.afterSend == nil {
				t.Fatal("buildChallengeResponse() afterSend = nil, want client error")
			}
			if card.calls != 1 {
				t.Fatalf("AKA() calls = %d, want 1", card.calls)
			}
			if flow.eapIdentity != startIdentity {
				t.Fatalf("eapIdentity = %q, want unchanged %q", flow.eapIdentity, startIdentity)
			}
			if len(flow.crypto.eap.AUT) != 0 || len(flow.crypto.eap.MSK) != 0 {
				t.Fatal("derived EAP state was committed before authenticated challenge validation")
			}
			if flow.pendingState.Pseudonym != initialPending.Pseudonym || flow.pendingState.ReauthIdentity != initialPending.ReauthIdentity || flow.pendingState.Counter != initialPending.Counter {
				t.Fatalf("pending state = %+v, want unchanged %+v", flow.pendingState, initialPending)
			}
		})
	}
}

func TestAKAAuthFlowFullAuthStoresUnusedReauthCounter(t *testing.T) {
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	reauthIdentity := "reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}
	keys, err := deriveEAPKeys([]byte(identity), akaResult.IK, akaResult.CK)
	if err != nil {
		t.Fatalf("deriveEAPKeys() error = %v", err)
	}
	encrypted := encryptAKAAttributesForTest(t, []eapaka.AKAAttribute{
		{Type: akaAttrNextReauthID, Value: akaStringValueForTest(reauthIdentity)},
	}, keys.ENCR, bytes.Repeat([]byte{0x55}, aes.BlockSize))
	wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult, encrypted...)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	card := akaChallengeTestCard{result: akaResult}
	flow := akaAuthFlow{
		session:         &Session{logger: slog.Default()},
		card:            card,
		authenticateAKA: card.AKA,
		identity:        identity,
		eapIdentity:     identity,
		realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:          &ikeCrypto{},
	}
	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
	}
	if flow.pendingState.ReauthIdentity != reauthIdentity {
		t.Fatalf("pending reauth identity = %q, want %q", flow.pendingState.ReauthIdentity, reauthIdentity)
	}
	if flow.pendingState.Counter != 0 {
		t.Fatalf("pending reauth counter = %d, want 0", flow.pendingState.Counter)
	}
}

func TestAKAAuthFlowBuildChallengeResponseSupportsAKAPrime(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("foo:bar")
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
	wantKeys, err := eapaka.DeriveAKAPrimeKeys([]byte(identity), akaResult.CK, akaResult.IK, networkName, autn[:akaPrimeSQNXorAKLen])
	if err != nil {
		t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
	}
	card := akaChallengeTestCard{result: akaResult}
	flow := akaAuthFlow{
		session:         &Session{logger: slog.Default()},
		card:            card,
		authenticateAKA: card.AKA,
		identity:        identity,
		eapIdentity:     identity,
		realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:          &ikeCrypto{},
	}
	wire := buildSignedAKAPrimeChallenge(t, 8, identity, rand, autn, networkName, akaResult)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
	}
	if flow.currentEAPType != eapTypeAKAPrime {
		t.Fatalf("currentEAPType = %d, want %d", flow.currentEAPType, eapTypeAKAPrime)
	}
	if !bytes.Equal(flow.crypto.eap.MSK, wantKeys.MSK) {
		t.Fatalf("MSK = % X, want % X", flow.crypto.eap.MSK, wantKeys.MSK)
	}
	if err := eapaka.VerifyMessageMACSHA256(response.data, flow.crypto.eap.AUT, nil); err != nil {
		t.Fatalf("response VerifyMessageMACSHA256() error = %v", err)
	}
	var got eapaka.AKAMessage
	if err := got.UnmarshalBinary(response.data); err != nil {
		t.Fatalf("response UnmarshalBinary() error = %v", err)
	}
	if got.EAPType != eapTypeAKAPrime {
		t.Fatalf("response EAPType = %d, want %d", got.EAPType, eapTypeAKAPrime)
	}
}

func TestAKAAuthFlowBuildChallengeResponseUsesAKAPrimePermanentIdentity(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("foo:bar")
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	tests := []struct {
		name          string
		startIdentity string
		wantIdentity  string
	}{
		{
			name:          "direct challenge upgrades aka permanent identity",
			startIdentity: "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			wantIdentity:  "6001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
		},
		{
			name:          "aka prime permanent identity stays unchanged",
			startIdentity: "6001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
			wantIdentity:  "6001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wantKeys, err := eapaka.DeriveAKAPrimeKeys([]byte(tt.wantIdentity), akaResult.CK, akaResult.IK, networkName, autn[:akaPrimeSQNXorAKLen])
			if err != nil {
				t.Fatalf("DeriveAKAPrimeKeys() error = %v", err)
			}
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        tt.startIdentity,
				eapIdentity:     tt.startIdentity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
			}
			wire := buildSignedAKAPrimeChallenge(t, 8, tt.wantIdentity, rand, autn, networkName, akaResult)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}
			if flow.eapIdentity != tt.wantIdentity {
				t.Fatalf("eapIdentity = %q, want %q", flow.eapIdentity, tt.wantIdentity)
			}
			if !bytes.Equal(flow.crypto.eap.MSK, wantKeys.MSK) {
				t.Fatalf("MSK = % X, want % X", flow.crypto.eap.MSK, wantKeys.MSK)
			}
			if err := eapaka.VerifyMessageMACSHA256(response.data, flow.crypto.eap.AUT, nil); err != nil {
				t.Fatalf("response VerifyMessageMACSHA256() error = %v", err)
			}
		})
	}
}

func TestAKAPrimeNetworkNamesMatch(t *testing.T) {
	tests := []struct {
		name   string
		peer   string
		server string
		want   bool
	}{
		{name: "exact", peer: "WLAN", server: "WLAN", want: true},
		{name: "peer prefix", peer: "WLAN", server: "WLAN:foo", want: true},
		{name: "server prefix", peer: "WLAN:foo", server: "WLAN", want: true},
		{name: "empty peer follows reference behavior", peer: "", server: "WLAN", want: true},
		{name: "mismatch", peer: "WLAN", server: "HRPD", want: false},
		{name: "later field mismatch", peer: "WLAN:foo", server: "WLAN:bar", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := akaPrimeNetworkNamesMatch(tt.peer, tt.server); got != tt.want {
				t.Fatalf("akaPrimeNetworkNamesMatch(%q, %q) = %t, want %t", tt.peer, tt.server, got, tt.want)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseRejectsAKAPrimeNetworkNameMismatch(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	serverNetworkName := []byte("HRPD")
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
	card := akaFailTestCard{err: errors.New("AKA should not be called")}
	flow := akaAuthFlow{
		session:             &Session{logger: slog.Default()},
		card:                card,
		authenticateAKA:     card.AKA,
		identity:            identity,
		eapIdentity:         identity,
		realm:               "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:              &ikeCrypto{},
		akaPrimeNetworkName: "WLAN",
	}
	wire := buildSignedAKAPrimeChallenge(t, 8, identity, rand, autn, serverNetworkName, akaResult)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
	}
	want, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
	if err != nil {
		t.Fatalf("BuildAKAPrimeAuthenticationReject() error = %v", err)
	}
	if !bytes.Equal(response.data, want) {
		t.Fatalf("response = % X, want authentication reject % X", response.data, want)
	}
}

func TestAKAAuthFlowBuildChallengeResponseRejectsInvalidAKAPrimeKDFAttributes(t *testing.T) {
	randValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)
	autnValue := []byte{
		0x00, 0x00,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	kdfInputAttr := akaAttributeFromBinaryForTest(t, eapaka.KDFInput{NetworkName: []byte("WLAN")})
	emptyKDFInputAttr := eapaka.AKAAttribute{Type: akaAttrKDFInput, Value: []byte{0x00, 0x00}}
	kdfAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault})
	unsupportedKDFAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault + 1})

	tests := []struct {
		name  string
		attrs []eapaka.AKAAttribute
	}{
		{
			name: "missing kdf",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				kdfInputAttr,
			},
		},
		{
			name: "unsupported kdf",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				kdfInputAttr,
				unsupportedKDFAttr,
			},
		},
		{
			name: "missing kdf input",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				kdfAttr,
			},
		},
		{
			name: "empty network name",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				emptyKDFInputAttr,
				kdfAttr,
			},
		},
		{
			name: "duplicate kdf",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				kdfInputAttr,
				kdfAttr,
				kdfAttr,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
			card := akaFailTestCard{err: errors.New("AKA should not be called")}
			flow := akaAuthFlow{
				session:             &Session{logger: slog.Default()},
				card:                card,
				authenticateAKA:     card.AKA,
				identity:            identity,
				eapIdentity:         identity,
				realm:               "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:              &ikeCrypto{},
				akaPrimeNetworkName: "WLAN",
			}
			wire := buildAKAPrimeChallengeWithAttrs(t, 8, tt.attrs)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}
			want, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
			if err != nil {
				t.Fatalf("BuildAKAPrimeAuthenticationReject() error = %v", err)
			}
			if !bytes.Equal(response.data, want) {
				t.Fatalf("response = % X, want authentication reject % X", response.data, want)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseNegotiatesAKAPrimeKDF(t *testing.T) {
	randValue := append([]byte{0x00, 0x00}, bytes.Repeat([]byte{0x11}, 16)...)
	autnValue := []byte{
		0x00, 0x00,
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	kdfInputAttr := akaAttributeFromBinaryForTest(t, eapaka.KDFInput{NetworkName: []byte("WLAN")})
	kdfAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault})
	unsupportedKDFAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault + 1})
	tests := []struct {
		name  string
		attrs []eapaka.AKAAttribute
	}{
		{
			name: "selects supported alternative",
			attrs: []eapaka.AKAAttribute{
				{Type: akaAttrRAND, Value: randValue},
				{Type: akaAttrAUTN, Value: autnValue},
				kdfInputAttr,
				unsupportedKDFAttr,
				kdfAttr,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := akaFailTestCard{err: errors.New("AKA should not be called")}
			flow := akaAuthFlow{
				session:             &Session{logger: slog.Default()},
				card:                card,
				authenticateAKA:     card.AKA,
				crypto:              &ikeCrypto{},
				akaPrimeNetworkName: "WLAN",
			}
			wire := buildAKAPrimeChallengeWithAttrs(t, 8, tt.attrs)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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
			if got.EAPType != eapTypeAKAPrime || got.Subtype != akaSubtypeChallenge {
				t.Fatalf("response = %+v, want AKA' Challenge response", got)
			}
			if len(got.Attributes) != 1 || got.Attributes[0].Type != akaAttrKDF {
				t.Fatalf("response attrs = %+v, want only AT_KDF", got.Attributes)
			}
			selected, err := eapaka.KDFFromAttribute(&got.Attributes[0])
			if err != nil {
				t.Fatalf("KDFFromAttribute() error = %v", err)
			}
			if selected.Version != akaPrimeKDFDefault {
				t.Fatalf("selected KDF = %d, want %d", selected.Version, akaPrimeKDFDefault)
			}
			if len(flow.akaPrimeKDFOffer) != 2 || flow.akaPrimeKDFOffer[0] != akaPrimeKDFDefault+1 || flow.akaPrimeKDFOffer[1] != akaPrimeKDFDefault {
				t.Fatalf("akaPrimeKDFOffer = %v, want [%d %d]", flow.akaPrimeKDFOffer, akaPrimeKDFDefault+1, akaPrimeKDFDefault)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseAcceptsNegotiatedAKAPrimeKDF(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("WLAN")
	identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	unsupportedKDFAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault + 1})
	kdfAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault})
	tests := []struct {
		name      string
		offer     []uint16
		extraKDFs []eapaka.AKAAttribute
		wantErr   bool
	}{
		{
			name:      "accepts requested change",
			offer:     []uint16{akaPrimeKDFDefault + 1, akaPrimeKDFDefault},
			extraKDFs: []eapaka.AKAAttribute{unsupportedKDFAttr, kdfAttr},
		},
		{
			name:      "rejects changed offer",
			offer:     []uint16{akaPrimeKDFDefault + 2, akaPrimeKDFDefault},
			extraKDFs: []eapaka.AKAAttribute{unsupportedKDFAttr, kdfAttr},
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:             &Session{logger: slog.Default()},
				card:                card,
				authenticateAKA:     card.AKA,
				identity:            identity,
				eapIdentity:         identity,
				realm:               "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:              &ikeCrypto{},
				akaPrimeNetworkName: "WLAN",
				akaPrimeKDFOffer:    append([]uint16(nil), tt.offer...),
			}
			wire := buildSignedAKAPrimeChallenge(t, 8, identity, rand, autn, networkName, akaResult, tt.extraKDFs...)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if tt.wantErr {
				want, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
				if err != nil {
					t.Fatalf("BuildAKAPrimeAuthenticationReject() error = %v", err)
				}
				if !bytes.Equal(response.data, want) {
					t.Fatalf("response = % X, want authentication reject % X", response.data, want)
				}
				return
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}
			var got eapaka.AKAMessage
			if err := got.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			if got.EAPType != eapTypeAKAPrime || got.Subtype != akaSubtypeChallenge {
				t.Fatalf("response = %+v, want AKA' Challenge response", got)
			}
		})
	}
}

func TestAKAAuthFlowBuildChallengeResponseCopiesNegotiatedKDFsOnAKAPrimeSyncFailure(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0xcd, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("WLAN")
	identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	auts := bytes.Repeat([]byte{0x44}, 14)
	unsupportedKDFAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault + 1})
	kdfAttr := akaAttributeFromBinaryForTest(t, eapaka.KDF{Version: akaPrimeKDFDefault})
	card := akaChallengeTestCard{result: usim.AKAResult{AUTS: auts}}
	flow := akaAuthFlow{
		session:             &Session{logger: slog.Default()},
		card:                card,
		authenticateAKA:     card.AKA,
		identity:            identity,
		eapIdentity:         identity,
		realm:               "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:              &ikeCrypto{},
		akaPrimeNetworkName: "WLAN",
		akaPrimeKDFOffer:    []uint16{akaPrimeKDFDefault + 1, akaPrimeKDFDefault},
	}
	wire := buildSignedAKAPrimeChallenge(t, 8, identity, rand, autn, networkName, akaResult, unsupportedKDFAttr, kdfAttr)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	var got eapaka.AKAMessage
	if err := got.UnmarshalBinary(response.data); err != nil {
		t.Fatalf("response UnmarshalBinary() error = %v", err)
	}
	if got.EAPType != eapTypeAKAPrime || got.Subtype != akaSubtypeSynchronizationFailure {
		t.Fatalf("response = %+v, want AKA' Synchronization-Failure", got)
	}
	if attr := eapaka.FindAttribute(got.Attributes, akaAttrAUTS); attr == nil || !bytes.Equal(attr.Value, auts) {
		t.Fatalf("AT_AUTS = %+v, want % X", attr, auts)
	}
	kdfs, err := akaPrimeKDFValues(got.Attributes)
	if err != nil {
		t.Fatalf("akaPrimeKDFValues() error = %v", err)
	}
	wantKDFs := []uint16{akaPrimeKDFDefault, akaPrimeKDFDefault + 1, akaPrimeKDFDefault}
	if !uint16sEqual(kdfs, wantKDFs) {
		t.Fatalf("response KDFs = %v, want %v", kdfs, wantKDFs)
	}
}

func TestAKAAuthFlowBuildChallengeResponseRejectsAKAPrimeWithoutAMFSeparationBit(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := []byte{
		0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
		0x4d, 0xef,
		0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
	}
	networkName := []byte("foo:bar")
	akaResult := usim.AKAResult{
		RES: []byte{0x11, 0x22, 0x33, 0x44, 0x55},
		IK:  []byte{0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00},
		CK:  []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}
	identity := "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org"
	card := akaFailTestCard{err: errors.New("AKA should not be called")}
	flow := akaAuthFlow{
		session:         &Session{logger: slog.Default()},
		card:            card,
		authenticateAKA: card.AKA,
		identity:        identity,
		eapIdentity:     identity,
		realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
		crypto:          &ikeCrypto{},
	}
	wire := buildSignedAKAPrimeChallenge(t, 8, identity, rand, autn, networkName, akaResult)
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := flow.buildChallengeResponse(t.Context(), message, wire)
	if err != nil {
		t.Fatalf("buildChallengeResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
	}
	want, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
	if err != nil {
		t.Fatalf("BuildAKAPrimeAuthenticationReject() error = %v", err)
	}
	if !bytes.Equal(response.data, want) {
		t.Fatalf("response = % X, want % X", response.data, want)
	}
	if len(flow.crypto.eap.MSK) != 0 {
		t.Fatalf("MSK length = %d, want 0", len(flow.crypto.eap.MSK))
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
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        identity,
				eapIdentity:     identity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
			}
			identityRequest := eapaka.AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 7,
				Subtype:    akaSubtypeIdentity,
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
			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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
			var got eapaka.AKAMessage
			if err := got.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			attr := eapaka.FindAttribute(got.Attributes, akaAttrCheckcode)
			if attr == nil {
				t.Fatal("response AT_CHECKCODE is missing")
			}
			if want := checkcodeForTest(flow.identityPackets); !bytes.Equal(attr.Value, want) {
				t.Fatalf("response AT_CHECKCODE = % X, want % X", attr.Value, want)
			}
		})
	}
}

func TestAKAAuthFlowRequiresCheckcodeAfterExtendedIdentityRequest(t *testing.T) {
	const unknownSkippableAttribute byte = 200

	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"

	tests := []struct {
		name          string
		identityAttrs []eapaka.AKAAttribute
		wantClientErr bool
	}{
		{
			name:          "plain identity request can omit checkcode",
			identityAttrs: []eapaka.AKAAttribute{{Type: akaAttrPermanentIDReq, Value: []byte{0x00, 0x00}}},
		},
		{
			name: "extended identity request requires checkcode",
			identityAttrs: []eapaka.AKAAttribute{
				{Type: akaAttrAnyIDReq, Value: []byte{0x00, 0x00}},
				{Type: unknownSkippableAttribute, Value: []byte{0x00, 0x00}},
			},
			wantClientErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        identity,
				eapIdentity:     identity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
			}
			identityRequest := eapaka.AKAMessage{
				Code:       eapCodeRequest,
				Identifier: 7,
				Subtype:    akaSubtypeIdentity,
				Attributes: tt.identityAttrs,
			}
			if response := buildIdentityResponseForTest(t, &flow, identityRequest); response.afterSend != nil {
				t.Fatalf("buildIdentityResponse() afterSend = %v, want nil", response.afterSend)
			}

			wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult)
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}
			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
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

func TestAKAAuthFlowBuildReauthenticationResponseUsesFastReauthIdentity(t *testing.T) {
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	reauthIdentity := "reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
	mk := bytes.Repeat([]byte{0x77}, 20)
	kAut := bytes.Repeat([]byte{0x11}, 16)
	kEncr := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	counter := uint16(5)

	wantMSK, wantEMSK, err := eapaka.DeriveFastReauthKeys([]byte(reauthIdentity), counter, nonceS, mk)
	if err != nil {
		t.Fatalf("DeriveFastReauthKeys() error = %v", err)
	}

	flow := akaAuthFlow{
		eapIdentity:    identity,
		reauthIdentity: reauthIdentity,
		currentState: usim.AKAIdentityState{
			ReauthIdentity: reauthIdentity,
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

func TestAKAAuthFlowRejectsInvalidReauthenticationWithoutDiscardingState(t *testing.T) {
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	reauthIdentity := "reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
	mk := bytes.Repeat([]byte{0x77}, 20)
	kAut := bytes.Repeat([]byte{0x11}, 16)
	kEncr := bytes.Repeat([]byte{0x22}, 16)
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	counter := uint16(5)
	state := usim.AKAIdentityState{
		ReauthIdentity: reauthIdentity,
		Counter:        1,
		MK:             mk,
		KAut:           kAut,
		KEncr:          kEncr,
	}
	tests := []struct {
		name       string
		extraAttrs []eapaka.AKAAttribute
		corruptMAC bool
	}{
		{
			name: "bidding is invalid outside challenge",
			extraAttrs: []eapaka.AKAAttribute{{
				Type:  akaAttrBidding,
				Value: []byte{0x80, 0x00},
			}},
		},
		{name: "invalid mac", corruptMAC: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := &akaStateTestCard{state: cloneAKAIdentityState(state)}
			flow := akaAuthFlow{
				card:             card,
				eapIdentity:      identity,
				reauthIdentity:   reauthIdentity,
				currentState:     cloneAKAIdentityState(state),
				currentAuthKey:   append([]byte(nil), kAut...),
				currentEncrKey:   append([]byte(nil), kEncr...),
				currentEAPType:   eapTypeAKA,
				currentCounter:   state.Counter,
				fastReauth:       true,
				akaAuthenticated: true,
				crypto:           &ikeCrypto{},
			}
			wire := buildSignedAKAReauthRequest(t, 9, counter, nonceS, kAut, kEncr, tt.extraAttrs...)
			if tt.corruptMAC {
				wire[len(wire)-1] ^= 0x01
			}
			var message eapaka.AKAMessage
			if err := message.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			response, err := flow.buildReauthenticationResponse(message, wire)
			if err != nil {
				t.Fatalf("buildReauthenticationResponse() error = %v", err)
			}
			if response.afterSend == nil {
				t.Fatal("buildReauthenticationResponse() afterSend = nil, want client error")
			}
			want, err := eapaka.BuildClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
			if err != nil {
				t.Fatalf("BuildClientErrorPacket() error = %v", err)
			}
			if !bytes.Equal(response.data, want) {
				t.Fatalf("response = % X, want client error % X", response.data, want)
			}
			if card.state.ReauthIdentity != state.ReauthIdentity || card.state.Counter != state.Counter {
				t.Fatalf("stored reauth state was discarded: %+v", card.state)
			}
			if !bytes.Equal(card.state.MK, state.MK) || !bytes.Equal(card.state.KAut, state.KAut) || !bytes.Equal(card.state.KEncr, state.KEncr) {
				t.Fatal("stored reauth keys changed after invalid request")
			}
		})
	}
}

func TestAKAAuthFlowBuildReauthenticationResponseSupportsAKAPrime(t *testing.T) {
	reauthIdentity := "8reauth123@nai.epc.mnc001.mcc001.3gppnetwork.org"
	nonceS := bytes.Repeat([]byte{0x33}, 16)
	counter := uint16(5)
	keys := eapaka.AKAPrimeKeys{
		MK:   bytes.Repeat([]byte{0x77}, akaPrimeMKLen),
		ENCR: bytes.Repeat([]byte{0x22}, 16),
		AUT:  bytes.Repeat([]byte{0x11}, 32),
	}
	copy(keys.MK[akaPrimeKReOffset:akaPrimeKReOffset+akaPrimeKReLen], bytes.Repeat([]byte{0x44}, akaPrimeKReLen))
	wantMSK, wantEMSK, err := eapaka.DeriveAKAPrimeFastReauthKeysFromMK([]byte(reauthIdentity), counter, nonceS, keys.MK)
	if err != nil {
		t.Fatalf("DeriveAKAPrimeFastReauthKeysFromMK() error = %v", err)
	}

	flow := akaAuthFlow{
		eapIdentity:    "6123456789012345@nai.epc.mnc001.mcc001.3gppnetwork.org",
		reauthIdentity: reauthIdentity,
		currentState: usim.AKAIdentityState{
			ReauthIdentity: reauthIdentity,
			Counter:        1,
			MK:             keys.MK,
			KAut:           keys.AUT,
			KEncr:          keys.ENCR,
		},
		crypto: &ikeCrypto{},
	}

	wire := buildSignedAKAPrimeReauthRequest(t, 9, counter, nonceS, keys.AUT, keys.ENCR)
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
	if flow.currentEAPType != eapTypeAKAPrime {
		t.Fatalf("currentEAPType = %d, want %d", flow.currentEAPType, eapTypeAKAPrime)
	}
	if !bytes.Equal(flow.crypto.eap.MSK, wantMSK) {
		t.Fatalf("MSK = %X, want %X", flow.crypto.eap.MSK, wantMSK)
	}
	if !bytes.Equal(flow.crypto.eap.EMSK, wantEMSK) {
		t.Fatalf("EMSK = %X, want %X", flow.crypto.eap.EMSK, wantEMSK)
	}
	if err := eapaka.VerifyMessageMACSHA256(response.data, keys.AUT, nonceS); err != nil {
		t.Fatalf("response VerifyMessageMACSHA256() error = %v", err)
	}
	var got eapaka.AKAMessage
	if err := got.UnmarshalBinary(response.data); err != nil {
		t.Fatalf("response UnmarshalBinary() error = %v", err)
	}
	if got.EAPType != eapTypeAKAPrime {
		t.Fatalf("response EAPType = %d, want %d", got.EAPType, eapTypeAKAPrime)
	}
}

func TestAKAAuthFlowProtectedResultIndRequiresSuccessNotification(t *testing.T) {
	rand := bytes.Repeat([]byte{0x11}, 16)
	autn := bytes.Repeat([]byte{0x22}, 16)
	akaResult := usim.AKAResult{
		RES: []byte{0x01, 0x02, 0x03, 0x04},
		IK:  bytes.Repeat([]byte{0x33}, 16),
		CK:  bytes.Repeat([]byte{0x44}, 16),
	}
	identity := "0001010123456789@nai.epc.mnc001.mcc001.3gppnetwork.org"
	wire := buildSignedAKAChallenge(t, 8, identity, rand, autn, akaResult, eapaka.AKAAttribute{
		Type:  akaAttrResultInd,
		Value: []byte{0x00, 0x00},
	})
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	tests := []struct {
		name              string
		ipmsIndication    bool
		wantIPMSInd       bool
		notificationAttrs []eapaka.AKAAttribute
	}{
		{name: "default without ipms indication"},
		{
			name:           "configured ipms indication",
			ipmsIndication: true,
			wantIPMSInd:    true,
			notificationAttrs: []eapaka.AKAAttribute{{
				Type:  akaAttrIPMSRes,
				Value: []byte{0x00, byte(eapaka.IPMSSelectionNBM)},
			}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			card := akaChallengeTestCard{result: akaResult}
			flow := akaAuthFlow{
				session:         &Session{logger: slog.Default()},
				card:            card,
				authenticateAKA: card.AKA,
				identity:        identity,
				eapIdentity:     identity,
				realm:           "nai.epc.mnc001.mcc001.3gppnetwork.org",
				crypto:          &ikeCrypto{},
				ipmsIndication:  tt.ipmsIndication,
			}
			response, err := flow.buildChallengeResponse(t.Context(), message, wire)
			if err != nil {
				t.Fatalf("buildChallengeResponse() error = %v", err)
			}
			if response.afterSend != nil {
				t.Fatalf("buildChallengeResponse() afterSend = %v, want nil", response.afterSend)
			}
			var responseMessage eapaka.AKAMessage
			if err := responseMessage.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			if eapaka.FindAttribute(responseMessage.Attributes, akaAttrResultInd) == nil {
				t.Fatal("response AT_RESULT_IND is missing")
			}
			ipmsAttr := eapaka.FindAttribute(responseMessage.Attributes, akaAttrIPMSInd)
			if !tt.wantIPMSInd {
				if ipmsAttr != nil {
					t.Fatalf("response AT_IPMS_IND = % X, want missing", ipmsAttr.Value)
				}
			} else {
				if ipmsAttr == nil {
					t.Fatal("response AT_IPMS_IND is missing")
				}
				if !bytes.Equal(ipmsAttr.Value, []byte{0x00, byte(eapaka.IPMSSupportNBMOnly)}) {
					t.Fatalf("response AT_IPMS_IND = % X, want 00 02", ipmsAttr.Value)
				}
			}
			if err := flow.validateEAPSuccess(); err == nil || !strings.Contains(err.Error(), "before protected success notification") {
				t.Fatalf("validateEAPSuccess() error = %v, want protected success notification error", err)
			}

			notificationWire, notification := buildSignedNotificationForTest(t, 9, akaNotificationSuccess, flow.currentAuthKey, tt.notificationAttrs...)
			notificationResponse, err := flow.buildNotificationResponse(notification, notificationWire)
			if err != nil {
				t.Fatalf("buildNotificationResponse() error = %v", err)
			}
			if notificationResponse.afterSend != nil {
				t.Fatalf("buildNotificationResponse() afterSend = %v, want nil", notificationResponse.afterSend)
			}
			if err := flow.validateEAPSuccess(); err != nil {
				t.Fatalf("validateEAPSuccess() error = %v", err)
			}
		})
	}
}

func TestAKAAuthFlowValidatesIPMSResult(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	tests := []struct {
		name      string
		attr      *eapaka.AKAAttribute
		wantAfter string
	}{
		{
			name:      "missing result",
			wantAfter: "AT_IPMS_RES is missing",
		},
		{
			name: "nbm selected",
			attr: &eapaka.AKAAttribute{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(eapaka.IPMSSelectionNBM)}},
		},
		{
			name:      "dsmipv6 unsupported",
			attr:      &eapaka.AKAAttribute{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(eapaka.IPMSSelectionDSMIPv6)}},
			wantAfter: "unsupported",
		},
		{
			name:      "mipv4 unsupported",
			attr:      &eapaka.AKAAttribute{Type: akaAttrIPMSRes, Value: []byte{0x00, byte(eapaka.IPMSSelectionMIPv4)}},
			wantAfter: "unsupported",
		},
		{
			name:      "malformed result",
			attr:      &eapaka.AKAAttribute{Type: akaAttrIPMSRes, Value: []byte{0x01, byte(eapaka.IPMSSelectionNBM)}},
			wantAfter: "reserved octet",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := akaAuthFlow{
				akaAuthenticated:         true,
				protectedSuccessExpected: true,
				ipmsIndicated:            true,
				currentAuthKey:           autKey,
			}
			extraAttrs := []eapaka.AKAAttribute(nil)
			if tt.attr != nil {
				extraAttrs = append(extraAttrs, *tt.attr)
			}
			wire, message := buildSignedNotificationForTest(t, 7, akaNotificationSuccess, autKey, extraAttrs...)
			response, err := flow.buildNotificationResponse(message, wire)
			if err != nil {
				t.Fatalf("buildNotificationResponse() error = %v", err)
			}
			if tt.wantAfter == "" {
				if response.afterSend != nil {
					t.Fatalf("buildNotificationResponse() afterSend = %v, want nil", response.afterSend)
				}
				if !flow.notificationReceived {
					t.Fatal("valid notification was not marked received")
				}
				return
			}
			if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), tt.wantAfter) {
				t.Fatalf("buildNotificationResponse() afterSend = %v, want %q", response.afterSend, tt.wantAfter)
			}
			if flow.notificationReceived {
				t.Fatal("invalid notification was marked received")
			}
		})
	}
}

func TestAKAAuthFlowAuthenticatesNotificationBeforeOtherAttributes(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	tests := []struct {
		name       string
		corruptMAC bool
		wantAfter  string
	}{
		{name: "invalid mac is reported first", corruptMAC: true, wantAfter: "verifying notification mac"},
		{name: "authenticated wrong attribute is rejected", wantAfter: "unexpected attribute"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow := akaAuthFlow{
				akaAuthenticated:         true,
				protectedSuccessExpected: true,
				currentAuthKey:           autKey,
			}
			wire, message := buildSignedNotificationForTest(t, 7, akaNotificationSuccess, autKey, eapaka.AKAAttribute{
				Type:  akaAttrResultInd,
				Value: []byte{0x00, 0x00},
			})
			if tt.corruptMAC {
				wire[len(wire)-1] ^= 0x01
			}
			response, err := flow.buildNotificationResponse(message, wire)
			if err != nil {
				t.Fatalf("buildNotificationResponse() error = %v", err)
			}
			if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), tt.wantAfter) {
				t.Fatalf("buildNotificationResponse() afterSend = %v, want %q", response.afterSend, tt.wantAfter)
			}
			if flow.notificationReceived {
				t.Fatal("notification was marked received before authenticated validation")
			}
		})
	}
}

func TestAKAAuthFlowRejectsUnnegotiatedSuccessNotification(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	flow := akaAuthFlow{
		akaAuthenticated: true,
		currentAuthKey:   autKey,
	}
	wire, message := buildSignedNotificationForTest(t, 7, akaNotificationSuccess, autKey)
	response, err := flow.buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("buildNotificationResponse() error = %v", err)
	}
	if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), "protected success was not negotiated") {
		t.Fatalf("buildNotificationResponse() afterSend = %v, want unnegotiated protected success error", response.afterSend)
	}
	if flow.notificationReceived {
		t.Fatal("unnegotiated success notification was marked received")
	}
}

func TestAKAAuthFlowRejectsInvalidSuccessNotification(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	flow := akaAuthFlow{
		akaAuthenticated:         true,
		protectedSuccessExpected: true,
		currentAuthKey:           autKey,
	}
	wire, message := buildSignedNotificationForTest(t, 7, akaNotificationSuccess+1, autKey)
	response, err := flow.buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("buildNotificationResponse() error = %v", err)
	}
	if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), "unexpected success notification code") {
		t.Fatalf("buildNotificationResponse() afterSend = %v, want unexpected success notification code", response.afterSend)
	}
}

func TestAKAAuthFlowRejectsMultipleNotificationRounds(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	flow := akaAuthFlow{
		akaAuthenticated:         true,
		protectedSuccessExpected: true,
		currentAuthKey:           autKey,
	}
	wire, message := buildSignedNotificationForTest(t, 7, akaNotificationSuccess, autKey)
	response, err := flow.buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("first buildNotificationResponse() error = %v", err)
	}
	if response.afterSend != nil {
		t.Fatalf("first buildNotificationResponse() afterSend = %v, want nil", response.afterSend)
	}

	wire, message = buildSignedNotificationForTest(t, 8, akaNotificationSuccess, autKey)
	response, err = flow.buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("second buildNotificationResponse() error = %v", err)
	}
	if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), "multiple aka notification rounds") {
		t.Fatalf("second buildNotificationResponse() afterSend = %v, want multiple notification rounds", response.afterSend)
	}
}

func TestAKAAuthFlowRejectsPreChallengeNotificationWithMAC(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	value := make([]byte, 2)
	binary.BigEndian.PutUint16(value, 0x4000)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: 7,
		Subtype:    akaSubtypeNotification,
		Attributes: []eapaka.AKAAttribute{{Type: akaAttrNotification, Value: value}},
	}).MarshalSigned(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	response, err := (&akaAuthFlow{}).buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("buildNotificationResponse() error = %v", err)
	}
	if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), "must not include AT_MAC") {
		t.Fatalf("buildNotificationResponse() afterSend = %v, want AT_MAC rejection", response.afterSend)
	}
}

func TestAKAAuthFlowRejectsFastReauthNotificationExtraEncryptedAttributes(t *testing.T) {
	autKey := bytes.Repeat([]byte{0x11}, 16)
	encrKey := bytes.Repeat([]byte{0x22}, 16)
	counterValue := make([]byte, 2)
	binary.BigEndian.PutUint16(counterValue, 7)
	encrypted := encryptAKAAttributesForTest(t, []eapaka.AKAAttribute{
		{Type: akaAttrCounter, Value: counterValue},
		{Type: akaAttrNextReauthID, Value: []byte{0x00, 0x00}},
	}, encrKey, bytes.Repeat([]byte{0x55}, aes.BlockSize))

	notificationValue := make([]byte, 2)
	binary.BigEndian.PutUint16(notificationValue, akaNotificationSuccess)
	attrs := []eapaka.AKAAttribute{{Type: akaAttrNotification, Value: notificationValue}}
	attrs = append(attrs, encrypted...)
	wire, err := (eapaka.AKAMessage{
		Code:       eapCodeRequest,
		Identifier: 7,
		Subtype:    akaSubtypeNotification,
		Attributes: attrs,
	}).MarshalSigned(autKey, nil)
	if err != nil {
		t.Fatalf("MarshalSigned() error = %v", err)
	}
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	flow := akaAuthFlow{
		currentAuthKey:           autKey,
		currentEncrKey:           encrKey,
		currentCounter:           7,
		fastReauth:               true,
		akaAuthenticated:         true,
		protectedSuccessExpected: true,
	}
	response, err := flow.buildNotificationResponse(message, wire)
	if err != nil {
		t.Fatalf("buildNotificationResponse() error = %v", err)
	}
	if response.afterSend == nil || !strings.Contains(response.afterSend.Error(), "expected encrypted AT_COUNTER only") {
		t.Fatalf("buildNotificationResponse() afterSend = %v, want encrypted counter-only rejection", response.afterSend)
	}
}

func TestAKAAuthFlowVerifyResponderPostEAPAuth(t *testing.T) {
	idr := &ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("ims")}
	crypto := &ikeCrypto{
		prf: transformPRFHMACSHA1,
		keys: ikeKeys{
			SKPR: bytes.Repeat([]byte{0x21}, sha1.Size),
		},
		eap: eapKeys{
			MSK: bytes.Repeat([]byte{0x42}, 64),
		},
	}
	flow := akaAuthFlow{
		crypto:          crypto,
		ikeInitResponse: []byte("ike-sa-init-response"),
		initiatorNonce:  []byte("initiator nonce"),
	}
	idrRaw, err := idr.RawData()
	if err != nil {
		t.Fatalf("RawData() error = %v", err)
	}
	flow.idrRaw = idrRaw
	authData, err := crypto.ComputeResponderAuth(flow.ikeInitResponse, flow.initiatorNonce, idrRaw)
	if err != nil {
		t.Fatalf("ComputeResponderAuth() error = %v", err)
	}

	tests := []struct {
		name     string
		payloads []ike.Payload
		wantErr  string
	}{
		{
			name: "valid responder auth",
			payloads: []ike.Payload{
				&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: authData},
			},
		},
		{
			name:     "missing auth",
			payloads: []ike.Payload{},
			wantErr:  "auth is missing",
		},
		{
			name: "unexpected auth method",
			payloads: []ike.Payload{
				&ike.AuthPayload{Method: authMethodSharedKeyMIC + 1, Data: authData},
			},
			wantErr: "auth method",
		},
		{
			name: "bad signature",
			payloads: []ike.Payload{
				&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: append([]byte(nil), authData[:len(authData)-1]...)},
			},
			wantErr: "responder auth verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := flow.verifyResponderPostEAPAuth(tt.payloads)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("verifyResponderPostEAPAuth() error = %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("verifyResponderPostEAPAuth() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("verifyResponderPostEAPAuth() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestResponderIDRawFromPayloads(t *testing.T) {
	tests := []struct {
		name              string
		payloads          []ike.Payload
		requestedAPN      string
		requestDefaultAPN bool
		wantAPN           string
		wantErr           string
	}{
		{
			name: "fqdn idr",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("ims")},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "responder apn casing does not replace requested apn",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("IMS")},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "network selected default apn",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("internet")},
			},
			requestDefaultAPN: true,
			wantAPN:           "internet",
		},
		{
			name: "epdg fqdn differs from explicit apn",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("topon.nodes.epdg.ld.epc.mnc015.mcc234.3gppnetwork.org")},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "ipv4 idr",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeIPv4Addr, Data: []byte{198, 18, 0, 6}},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "rfc822 idr",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeRFC822Addr, Data: []byte("ims")},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "ipv6 idr",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeIPv6Addr, Data: bytes.Repeat([]byte{0x20}, 16)},
			},
			requestedAPN: "ims",
			wantAPN:      "ims",
		},
		{
			name: "network default apn is unknown for ipv4 idr",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeIPv4Addr, Data: []byte{198, 18, 0, 6}},
			},
			requestDefaultAPN: true,
		},
		{
			name:     "missing idr",
			payloads: []ike.Payload{},
			wantErr:  "idr is missing",
		},
		{
			name: "empty idr data",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN},
			},
			wantErr: "data is empty",
		},
		{
			name: "non-ascii fqdn",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("ims\x00")},
			},
			requestDefaultAPN: true,
			wantErr:           "non-printable or non-ASCII",
		},
		{
			name: "invalid ipv4 idr length",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeIPv4Addr, Data: []byte{198, 18, 0}},
			},
			requestedAPN: "ims",
			wantErr:      "ID_IPV4_ADDR length 3, want 4",
		},
		{
			name: "invalid ipv6 idr length",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeIPv6Addr, Data: bytes.Repeat([]byte{0x20}, 15)},
			},
			requestedAPN: "ims",
			wantErr:      "ID_IPV6_ADDR length 15, want 16",
		},
		{
			name: "unsupported idr type",
			payloads: []ike.Payload{
				&ike.IDPayload{Tag: payloadTypeIDr, IDType: 255, Data: []byte("ims")},
			},
			requestedAPN: "ims",
			wantErr:      "unsupported type 255",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotAPN, err := responderIDRawFromPayloads(tt.payloads, tt.requestedAPN, tt.requestDefaultAPN)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("responderIDRawFromPayloads() error = %v", err)
				}
				if len(got) == 0 {
					t.Fatal("responderIDRawFromPayloads() returned empty idr")
				}
				idr := ike.FindIDPayload(tt.payloads, payloadTypeIDr)
				wantRaw, rawErr := idr.RawData()
				if rawErr != nil {
					t.Fatalf("IDPayload.RawData() error = %v", rawErr)
				}
				if !bytes.Equal(got, wantRaw) {
					t.Fatalf("responderIDRawFromPayloads() raw = % X, want % X", got, wantRaw)
				}
				if gotAPN != tt.wantAPN {
					t.Fatalf("responderIDRawFromPayloads() APN = %q, want %q", gotAPN, tt.wantAPN)
				}
				return
			}
			if err == nil {
				t.Fatal("responderIDRawFromPayloads() error = nil, want error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("responderIDRawFromPayloads() error = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

func TestAKAAuthFlowRespondsCounterTooSmallWithoutAborting(t *testing.T) {
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
				eapIdentity:    identity,
				reauthIdentity: identity,
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
			if response.afterSend != nil {
				t.Fatalf("buildReauthenticationResponse() afterSend = %v, want nil", response.afterSend)
			}
			if flow.fastReauth || flow.akaAuthenticated || flow.currentCounter != 0 || len(flow.currentAuthKey) != 0 || len(flow.currentEncrKey) != 0 {
				t.Fatalf("flow marked stale reauth as successful: %+v", flow)
			}
			if err := eapaka.VerifyMessageMAC(response.data, kAut, nonceS); err != nil {
				t.Fatalf("response VerifyMessageMAC() error = %v", err)
			}
			var got eapaka.AKAMessage
			if err := got.UnmarshalBinary(response.data); err != nil {
				t.Fatalf("response UnmarshalBinary() error = %v", err)
			}
			nested, err := eapaka.DecryptAttributes(got.Attributes, kEncr)
			if err != nil {
				t.Fatalf("response DecryptAttributes() error = %v", err)
			}
			if eapaka.FindAttribute(nested, akaAttrCounterTooSmall) == nil {
				t.Fatal("response AT_COUNTER_TOO_SMALL is missing")
			}
			if len(nested) < 2 || nested[0].Type != akaAttrCounterTooSmall || nested[1].Type != akaAttrCounter {
				t.Fatalf("response nested attr order = %+v, want AT_COUNTER_TOO_SMALL then AT_COUNTER", nested)
			}
			counter, err := eapaka.Uint16Value(eapaka.FindAttribute(nested, akaAttrCounter))
			if err != nil {
				t.Fatalf("response AT_COUNTER error = %v", err)
			}
			if counter != tt.request {
				t.Fatalf("response counter = %d, want %d", counter, tt.request)
			}
		})
	}
}

func TestOpenIKEAuthResponsePlaintextNotify(t *testing.T) {
	tests := []struct {
		name         string
		notifyType   uint16
		want         string
		wantAccess   bool
		wantSentinel error
	}{
		{
			name:       "invalid syntax",
			notifyType: notifyTypeInvalidSyntax,
			want:       "INVALID_SYNTAX (7)",
		},
		{
			name:       "authentication failed",
			notifyType: notifyTypeAuthenticationFailed,
			want:       "AUTHENTICATION_FAILED (24)",
		},
		{
			name:       "unknown notify",
			notifyType: 65000,
			want:       "UNKNOWN_NOTIFY (65000)",
		},
		{
			name:         "pdn connection rejected",
			notifyType:   notifyTypePDNConnectionRejection,
			want:         "PDN_CONNECTION_REJECTION (8192)",
			wantAccess:   true,
			wantSentinel: ErrPDNConnectionRejected,
		},
		{
			name:         "max connection reached",
			notifyType:   notifyTypeMaxConnectionReached,
			want:         "MAX_CONNECTION_REACHED (8193)",
			wantAccess:   true,
			wantSentinel: ErrMaxConnectionReached,
		},
		{
			name:       "non 3gpp access rejected",
			notifyType: notifyTypeNon3GPPAccessToEPCNotAllowed,
			want:       "NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED (9000)",
			wantAccess: true,
		},
		{
			name:         "user unknown",
			notifyType:   notifyTypeUserUnknown,
			want:         "USER_UNKNOWN (9001)",
			wantAccess:   true,
			wantSentinel: ErrUserUnknown,
		},
		{
			name:         "no apn subscription",
			notifyType:   notifyTypeNoAPNSubscription,
			want:         "NO_APN_SUBSCRIPTION (9002)",
			wantAccess:   true,
			wantSentinel: ErrNoAPNSubscription,
		},
		{
			name:       "plmn not allowed",
			notifyType: notifyTypePLMNNotAllowed,
			want:       "PLMN_NOT_ALLOWED (11011)",
			wantAccess: true,
		},
		{
			name:         "imei not accepted",
			notifyType:   notifyTypeIMEINotAccepted,
			want:         "IMEI_NOT_ACCEPTED (11005)",
			wantAccess:   true,
			wantSentinel: ErrIMEINotAccepted,
		},
		{
			name:         "unauthenticated emergency not supported",
			notifyType:   notifyTypeUnauthenticatedEmergency,
			want:         "UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED (11055)",
			wantAccess:   true,
			wantSentinel: ErrUnauthenticatedEmergencyNotSupported,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := (ike.Packet{
				Header: ike.Header{
					InitiatorSPI: 1,
					ResponderSPI: 2,
					Version:      ikeVersion20,
					ExchangeType: exchangeTypeIKEAuth,
					Flags:        flagResponse,
					MessageID:    3,
				},
				Payloads: []ike.Payload{
					&ike.NotifyPayload{NotifyType: tt.notifyType},
				},
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var packet ike.Packet
			if err := packet.UnmarshalBinary(raw); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
			if err == nil {
				t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
			}
			if !strings.Contains(err.Error(), "unencrypted ike_auth notify") {
				t.Fatalf("openIKEAuthResponse() error = %v, want unencrypted notify context", err)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("openIKEAuthResponse() error = %v, want %q", err, tt.want)
			}
			if got := AccessRejected(err); got != tt.wantAccess {
				t.Fatalf("AccessRejected() = %t, want %t", got, tt.wantAccess)
			}
			if tt.wantSentinel != nil && !errors.Is(err, tt.wantSentinel) {
				t.Fatalf("errors.Is(%v) = false", tt.wantSentinel)
			}
			if isProtectedIKEAuthenticationFailed(err) {
				t.Fatal("plaintext AUTHENTICATION_FAILED marked as protected authentication failure")
			}
		})
	}
}

func TestOpenIKEAuthResponseProtectedNotify(t *testing.T) {
	tests := []struct {
		name         string
		payloads     []ike.Payload
		wantErr      string
		wantAccess   bool
		wantNetwork  bool
		wantAuthFail bool
		wantSentinel error
		wantBackoff  time.Duration
	}{
		{
			name: "authentication failure",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeAuthenticationFailed},
			},
			wantErr:      "AUTHENTICATION_FAILED (24)",
			wantAuthFail: true,
		},
		{
			name: "network failure with backoff",
			payloads: []ike.Payload{
				&ike.EAPPayload{Data: []byte{eapCodeRequest, 1, 0, 4}},
				&ike.NotifyPayload{NotifyType: notifyTypeNetworkFailure},
				&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}},
			},
			wantErr:     "NETWORK_FAILURE (10500)",
			wantNetwork: true,
			wantBackoff: 2 * time.Minute,
		},
		{
			name: "no apn subscription preserves access rejection",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeNoAPNSubscription},
				&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}},
			},
			wantErr:      "NO_APN_SUBSCRIPTION (9002)",
			wantAccess:   true,
			wantSentinel: ErrNoAPNSubscription,
			wantBackoff:  2 * time.Minute,
		},
		{
			name: "user unknown preserves precise rejection",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeUserUnknown},
			},
			wantErr:      "USER_UNKNOWN (9001)",
			wantAccess:   true,
			wantSentinel: ErrUserUnknown,
		},
		{
			name: "status notify is not an auth failure",
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeN1ModeInformation, Data: []byte{0x00}},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := testIKECrypto()
			wire := protectedIKEWire(t, crypto, exchangeTypeIKEAuth, flagResponse, 1, tt.payloads, false)
			var packet ike.Packet
			if err := packet.UnmarshalBinary(wire); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			payloads, err := openIKEAuthResponse(packet, crypto, ikeActionOpenAKAResponseMessage)

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("openIKEAuthResponse() error = %v, want nil", err)
				}
				if len(payloads) != len(tt.payloads) {
					t.Fatalf("payload count = %d, want %d", len(payloads), len(tt.payloads))
				}
				return
			}
			if err == nil {
				t.Fatal("openIKEAuthResponse() error = nil, want protected notify error")
			}
			if !strings.Contains(err.Error(), "protected ike_auth notify") {
				t.Fatalf("openIKEAuthResponse() error = %v, want protected notify context", err)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("openIKEAuthResponse() error = %v, want %q", err, tt.wantErr)
			}
			if got := AccessRejected(err); got != tt.wantAccess {
				t.Fatalf("AccessRejected() = %t, want %t", got, tt.wantAccess)
			}
			if got := NetworkFailure(err); got != tt.wantNetwork {
				t.Fatalf("NetworkFailure() = %t, want %t", got, tt.wantNetwork)
			}
			if got := isProtectedIKEAuthenticationFailed(err); got != tt.wantAuthFail {
				t.Fatalf("isProtectedIKEAuthenticationFailed() = %t, want %t", got, tt.wantAuthFail)
			}
			if tt.wantSentinel != nil && !errors.Is(err, tt.wantSentinel) {
				t.Fatalf("errors.Is(%v) = false", tt.wantSentinel)
			}
			if tt.wantBackoff > 0 {
				if delay, ok := BackoffDelay(err); !ok || delay != tt.wantBackoff {
					t.Fatalf("BackoffDelay() = %v, %v; want %v, true", delay, ok, tt.wantBackoff)
				}
			}
		})
	}
}

func TestExchangeProtectedIKEAuthNotify(t *testing.T) {
	tests := []struct {
		name       string
		action     ikeAction
		payloads   []ike.Payload
		wantErr    string
		wantAccess bool
	}{
		{
			name:   "user unknown stops ike auth challenge",
			action: ikeActionOpenIKEAuthChallenge,
			payloads: []ike.Payload{
				&ike.EAPPayload{Data: []byte{eapCodeRequest, 1, 0, 4}},
				&ike.NotifyPayload{NotifyType: notifyTypeUserUnknown},
			},
			wantErr:    "protected ike_auth notify USER_UNKNOWN (9001)",
			wantAccess: true,
		},
		{
			name:   "status notify passes during ike auth",
			action: ikeActionOpenFinalIKEAuthResponse,
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeMOBIKESupported},
			},
		},
		{
			name:   "non auth exchange keeps protected notify payload",
			action: ikeActionTestProtectedExchange,
			payloads: []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeUserUnknown},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			crypto := testIKECrypto()
			peer := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500}
			request := protectedIKEWire(t, crypto, exchangeTypeIKEAuth, flagInitiator, 1, []ike.Payload{
				&ike.NotifyPayload{NotifyType: notifyTypeCookie2, Data: []byte{1, 2, 3, 4}},
			}, true)
			response := protectedIKEWire(t, crypto, exchangeTypeIKEAuth, flagResponse, 1, tt.payloads, false)
			conn := &fakePacketConn{
				local:       &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 40000},
				readResults: []readResult{{data: response, addr: peer}},
			}
			session := mustDialSession(t, conn)
			session.cfg.IKERetransmitDelays = []time.Duration{time.Second}

			gotPayloads, gotPeer, err := session.exchangeProtectedIKE(t.Context(), protectedIKEExchange{
				peer:                   peer,
				requests:               [][]byte{request},
				messageID:              1,
				crypto:                 crypto,
				fragmentationSupported: true,
				action:                 tt.action,
			})

			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("exchangeProtectedIKE() error = %v, want nil", err)
				}
				if !sameUDPAddr(gotPeer, peer) {
					t.Fatalf("peer = %s, want %s", gotPeer, peer)
				}
				if len(gotPayloads) != len(tt.payloads) {
					t.Fatalf("payload count = %d, want %d", len(gotPayloads), len(tt.payloads))
				}
				return
			}
			if err == nil {
				t.Fatal("exchangeProtectedIKE() error = nil, want protected notify error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("exchangeProtectedIKE() error = %v, want %q", err, tt.wantErr)
			}
			if got := AccessRejected(err); got != tt.wantAccess {
				t.Fatalf("AccessRejected() = %t, want %t", got, tt.wantAccess)
			}
			if tt.wantAccess && !errors.Is(err, ErrAccessRejected) {
				t.Fatalf("errors.Is(ErrAccessRejected) = false for %v", err)
			}
		})
	}
}

func TestOpenIKEAuthResponseCarriesBackoffTimer(t *testing.T) {
	raw, err := (ike.Packet{
		Header: ike.Header{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKEAuth,
			Flags:        flagResponse,
			MessageID:    3,
		},
		Payloads: []ike.Payload{
			&ike.NotifyPayload{NotifyType: notifyTypeAuthenticationFailed},
			&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var packet ike.Packet
	if err := packet.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
	if err == nil {
		t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
	}
	if delay, ok := BackoffDelay(err); !ok || delay != 2*time.Minute {
		t.Fatalf("BackoffDelay() = %v, %v; want 2m, true", delay, ok)
	}
	if !strings.Contains(err.Error(), "BACKOFF_TIMER (41041)") {
		t.Fatalf("openIKEAuthResponse() error = %v, want BACKOFF_TIMER", err)
	}
}

func TestAppendDeviceIdentityResponsePayloadRequiresAuthenticatedNetwork(t *testing.T) {
	tests := []struct {
		name    string
		allowed bool
		request []byte
		want    []byte
	}{
		{
			name:    "not authenticated",
			allowed: false,
			request: []byte{deviceIdentityTypeIMEISVTest},
		},
		{
			name:    "authenticated",
			allowed: true,
			request: []byte{deviceIdentityTypeIMEISVTest},
			want:    []byte{0x00, 0x09, 0x02, 0x21, 0x43, 0x65, 0x87, 0x19, 0x32, 0x54, 0x76},
		},
		{
			name:    "no request",
			allowed: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverPayloads := []ike.Payload(nil)
			if tt.request != nil {
				serverPayloads = []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeDeviceIdentity, Data: tt.request}}
			}
			payloads, err := appendDeviceIdentityResponsePayload([]ike.Payload{&ike.EAPPayload{Data: []byte{0x01}}}, serverPayloads, "1234567891234567", tt.allowed)
			if err != nil {
				t.Fatalf("appendDeviceIdentityResponsePayload() error = %v", err)
			}
			notify := ike.FindNotifyPayload(payloads, notifyTypeDeviceIdentity)
			if tt.want == nil {
				if notify != nil {
					t.Fatalf("DEVICE_IDENTITY notify = %+v, want nil", notify)
				}
				return
			}
			if notify == nil {
				t.Fatal("DEVICE_IDENTITY notify = nil")
			}
			if !bytes.Equal(notify.Data, tt.want) {
				t.Fatalf("DEVICE_IDENTITY data = % X, want % X", notify.Data, tt.want)
			}
		})
	}
}

func TestOpenIKEAuthResponseCarriesDeactivatedBackoffTimer(t *testing.T) {
	raw, err := (ike.Packet{
		Header: ike.Header{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKEAuth,
			Flags:        flagResponse,
			MessageID:    3,
		},
		Payloads: []ike.Payload{
			&ike.NotifyPayload{NotifyType: notifyTypeNetworkFailure},
			&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xe1}},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var packet ike.Packet
	if err := packet.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
	if err == nil {
		t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
	}
	if !BackoffDeactivated(err) {
		t.Fatalf("BackoffDeactivated() = false for %v", err)
	}
	if delay, ok := BackoffDelay(err); ok || delay != 0 {
		t.Fatalf("BackoffDelay() = %v, %v; want 0, false", delay, ok)
	}
	policy, ok := BackoffPolicyFor(err)
	if !ok {
		t.Fatal("BackoffPolicyFor() ok = false, want true")
	}
	if policy.Scope != BackoffScopeEPDG || !policy.Deactivated || policy.Delay != 0 {
		t.Fatalf("BackoffPolicyFor() = %+v, want deactivated ePDG scope", policy)
	}
}

func TestOpenIKEAuthResponseCarriesZeroBackoffTimer(t *testing.T) {
	raw, err := (ike.Packet{
		Header: ike.Header{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKEAuth,
			Flags:        flagResponse,
			MessageID:    3,
		},
		Payloads: []ike.Payload{
			&ike.NotifyPayload{NotifyType: notifyTypeNetworkFailure},
			&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa0}},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var packet ike.Packet
	if err := packet.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
	if err == nil {
		t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
	}
	if delay, ok := BackoffDelay(err); ok || delay != 0 {
		t.Fatalf("BackoffDelay() = %v, %v; want 0, false", delay, ok)
	}
	if BackoffDeactivated(err) {
		t.Fatalf("BackoffDeactivated() = true for %v", err)
	}
	policy, ok := BackoffPolicyFor(err)
	if !ok {
		t.Fatal("BackoffPolicyFor() ok = false, want true")
	}
	if policy.Scope != BackoffScopeEPDG || policy.Deactivated || policy.Delay != 0 {
		t.Fatalf("BackoffPolicyFor() = %+v, want zero ePDG scope", policy)
	}
}

func TestOpenIKEAuthResponseIgnoresBackoffTimerWithoutErrorNotify(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "finite timer", data: []byte{0x01, 0xa2}},
		{name: "deactivated timer", data: []byte{0x01, 0xe1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := (ike.Packet{
				Header: ike.Header{
					InitiatorSPI: 1,
					ResponderSPI: 2,
					Version:      ikeVersion20,
					ExchangeType: exchangeTypeIKEAuth,
					Flags:        flagResponse,
					MessageID:    3,
				},
				Payloads: []ike.Payload{
					&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: tt.data},
				},
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var packet ike.Packet
			if err := packet.UnmarshalBinary(raw); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
			if err == nil {
				t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
			}
			if delay, ok := BackoffDelay(err); ok || delay != 0 {
				t.Fatalf("BackoffDelay() = %v, %v; want 0, false", delay, ok)
			}
			if BackoffDeactivated(err) {
				t.Fatalf("BackoffDeactivated() = true for %v", err)
			}
			if !strings.Contains(err.Error(), "BACKOFF_TIMER (41041)") {
				t.Fatalf("openIKEAuthResponse() error = %v, want BACKOFF_TIMER", err)
			}
		})
	}
}

func TestOpenIKEAuthResponseRejectsMalformedBackoffTimerWithErrorNotify(t *testing.T) {
	raw, err := (ike.Packet{
		Header: ike.Header{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKEAuth,
			Flags:        flagResponse,
			MessageID:    3,
		},
		Payloads: []ike.Payload{
			&ike.NotifyPayload{NotifyType: notifyTypeNoAPNSubscription},
			&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x02, 0xa2}},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var packet ike.Packet
	if err := packet.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
	if err == nil {
		t.Fatal("openIKEAuthResponse() error = nil, want malformed BACKOFF_TIMER error")
	}
	if !strings.Contains(err.Error(), "malformed BACKOFF_TIMER") {
		t.Fatalf("openIKEAuthResponse() error = %v, want malformed BACKOFF_TIMER", err)
	}
	if !errors.Is(err, ErrNoAPNSubscription) || !AccessRejected(err) {
		t.Fatalf("openIKEAuthResponse() error = %v, want no-apn access rejection", err)
	}
	if _, ok := BackoffPolicyFor(err); ok {
		t.Fatalf("BackoffPolicyFor() ok = true for malformed BACKOFF_TIMER")
	}
}

func TestOpenIKEAuthResponseCarriesAccessRejectionWithBackoffTimer(t *testing.T) {
	raw, err := (ike.Packet{
		Header: ike.Header{
			InitiatorSPI: 1,
			ResponderSPI: 2,
			Version:      ikeVersion20,
			ExchangeType: exchangeTypeIKEAuth,
			Flags:        flagResponse,
			MessageID:    3,
		},
		Payloads: []ike.Payload{
			&ike.NotifyPayload{NotifyType: notifyTypePDNConnectionRejection},
			&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}},
		},
	}).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}

	var packet ike.Packet
	if err := packet.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}

	_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
	if err == nil {
		t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
	}
	if !AccessRejected(err) {
		t.Fatalf("AccessRejected() = false for %v", err)
	}
	if !errors.Is(err, ErrPDNConnectionRejected) {
		t.Fatalf("errors.Is(ErrPDNConnectionRejected) = false for %v", err)
	}
	if delay, ok := BackoffDelay(err); !ok || delay != 2*time.Minute {
		t.Fatalf("BackoffDelay() = %v, %v; want 2m, true", delay, ok)
	}
}

func TestOpenIKEAuthResponseBackoffPolicyScope(t *testing.T) {
	tests := []struct {
		name       string
		notifyType uint16
		want       BackoffScope
	}{
		{name: "network failure scopes to epdg", notifyType: notifyTypeNetworkFailure, want: BackoffScopeEPDG},
		{name: "no apn subscription scopes to plmn apn", notifyType: notifyTypeNoAPNSubscription, want: BackoffScopePLMNAPN},
		{name: "generic error scopes to epdg", notifyType: notifyTypeAuthenticationFailed, want: BackoffScopeEPDG},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := (ike.Packet{
				Header: ike.Header{
					InitiatorSPI: 1,
					ResponderSPI: 2,
					Version:      ikeVersion20,
					ExchangeType: exchangeTypeIKEAuth,
					Flags:        flagResponse,
					MessageID:    3,
				},
				Payloads: []ike.Payload{
					&ike.NotifyPayload{NotifyType: tt.notifyType},
					&ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}},
				},
			}).MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}

			var packet ike.Packet
			if err := packet.UnmarshalBinary(raw); err != nil {
				t.Fatalf("UnmarshalBinary() error = %v", err)
			}

			_, err = openIKEAuthResponse(packet, &ikeCrypto{}, ikeActionOpenAKAResponseMessage)
			if err == nil {
				t.Fatal("openIKEAuthResponse() error = nil, want unencrypted notify error")
			}
			policy, ok := BackoffPolicyFor(err)
			if !ok {
				t.Fatal("BackoffPolicyFor() ok = false, want true")
			}
			if policy.Scope != tt.want || policy.Delay != 2*time.Minute || policy.Deactivated {
				t.Fatalf("BackoffPolicyFor() = %+v, want scope %v and 2m delay", policy, tt.want)
			}
		})
	}
}

func TestGPRSTimer3Duration(t *testing.T) {
	tests := []struct {
		name string
		raw  byte
		want time.Duration
		ok   bool
	}{
		{name: "ten minutes unit", raw: 0x01, want: 10 * time.Minute, ok: true},
		{name: "one hour unit", raw: 0x21, want: time.Hour, ok: true},
		{name: "ten hours unit", raw: 0x41, want: 10 * time.Hour, ok: true},
		{name: "two seconds unit", raw: 0x61, want: 2 * time.Second, ok: true},
		{name: "thirty seconds unit", raw: 0x81, want: 30 * time.Second, ok: true},
		{name: "one minute unit", raw: 0xa2, want: 2 * time.Minute, ok: true},
		{name: "three hundred twenty hours unit", raw: 0xc1, want: 320 * time.Hour, ok: true},
		{name: "zero timer", raw: 0xa0},
		{name: "deactivated", raw: 0xe1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := gprsTimer3Duration(tt.raw)
			if ok != tt.ok || got != tt.want {
				t.Fatalf("gprsTimer3Duration(%#x) = %v, %v; want %v, %v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestGPRSTimer3Deactivated(t *testing.T) {
	tests := []struct {
		name string
		raw  byte
		want bool
	}{
		{name: "deactivated unit", raw: 0xe1, want: true},
		{name: "zero timer", raw: 0xa0},
		{name: "finite timer", raw: 0x61},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := gprsTimer3Deactivated(tt.raw); got != tt.want {
				t.Fatalf("gprsTimer3Deactivated(%#x) = %t, want %t", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBackoffTimerDelayRequiresLengthPrefixedTimerValue(t *testing.T) {
	tests := []struct {
		name   string
		notify ike.NotifyPayload
		want   time.Duration
		ok     bool
	}{
		{name: "valid", notify: ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}}, want: 2 * time.Minute, ok: true},
		{name: "missing length byte", notify: ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0xa2}}},
		{name: "wrong value length", notify: ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x02, 0xa2}}},
		{name: "extra byte", notify: ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2, 0x00}}},
		{name: "esp protocol id", notify: ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeBackoffTimer, Data: []byte{0x01, 0xa2}}},
		{name: "non-empty spi", notify: ike.NotifyPayload{NotifyType: notifyTypeBackoffTimer, SPI: []byte{0, 0, 0, 1}, Data: []byte{0x01, 0xa2}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := backoffTimerDelay(&tt.notify)
			if got != tt.want || ok != tt.ok {
				t.Fatalf("backoffTimerDelay() = %v, %v; want %v, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}

func TestBackoffTimerNotifyDataBinary(t *testing.T) {
	tests := []struct {
		name      string
		wire      []byte
		value     byte
		wantWire  []byte
		wantErr   string
		wantDelay time.Duration
	}{
		{
			name:      "reference vector",
			wire:      []byte{0x01, 0xaf},
			value:     0xaf,
			wantWire:  []byte{0x01, 0xaf},
			wantDelay: 15 * time.Minute,
		},
		{
			name:    "long data",
			wire:    []byte{0x01, 0x02, 0x03},
			wantErr: "data length",
		},
		{
			name:    "invalid value length",
			wire:    []byte{0x02, 0xaf},
			wantErr: "value length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got backoffTimerNotifyData
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
			if got.Value != tt.value {
				t.Fatalf("UnmarshalBinary() value = %#x, want %#x", got.Value, tt.value)
			}
			delay, ok := got.Duration()
			if !ok || delay != tt.wantDelay {
				t.Fatalf("Duration() = %v, %t; want %v, true", delay, ok, tt.wantDelay)
			}
			wire, err := got.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary() error = %v", err)
			}
			if !bytes.Equal(wire, tt.wantWire) {
				t.Fatalf("MarshalBinary() = % X, want % X", wire, tt.wantWire)
			}
		})
	}
}

func TestIKEErrorNotify(t *testing.T) {
	tests := []struct {
		name       string
		notifyType uint16
		want       bool
	}{
		{name: "standard error", notifyType: notifyTypeAuthenticationFailed, want: true},
		{name: "private error", notifyType: notifyTypePDNConnectionRejection, want: true},
		{name: "first status notify", notifyType: notifyTypeStatusMin},
		{name: "backoff timer status", notifyType: notifyTypeBackoffTimer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ikeErrorNotify(tt.notifyType); got != tt.want {
				t.Fatalf("ikeErrorNotify(%d) = %t, want %t", tt.notifyType, got, tt.want)
			}
		})
	}
}

func TestReactivationRequestedErrorWrapsPeerDeleteCause(t *testing.T) {
	cause := errors.New("peer deleted child SA")
	err := reactivationRequestedError(cause)
	if !ReactivationRequested(err) {
		t.Fatalf("ReactivationRequested() = false for %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false for %v", err)
	}
}

func TestPDNDeactivatedErrorWrapsPeerDeleteCause(t *testing.T) {
	cause := errors.New("peer deleted child SA")
	err := pdnDeactivatedError(cause)
	if !PDNDeactivated(err) {
		t.Fatalf("PDNDeactivated() = false for %v", err)
	}
	if ReactivationRequested(err) {
		t.Fatalf("ReactivationRequested() = true for %v", err)
	}
	if !errors.Is(err, cause) {
		t.Fatalf("errors.Is(err, cause) = false for %v", err)
	}
}

func TestBuildInformationalResponsePayloadsDeleteHandling(t *testing.T) {
	tests := []struct {
		name             string
		state            informationalState
		payloads         []ike.Payload
		wantDeleteIKE    bool
		wantDeleteChild  bool
		wantReactivation bool
		wantPDNDeact     bool
		wantSPI          uint32
	}{
		{
			name: "ike delete",
			state: informationalState{
				inboundSPI:  0x10203040,
				outboundSPI: 0x50607080,
			},
			payloads:      []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}},
			wantDeleteIKE: true,
			wantPDNDeact:  true,
		},
		{
			name: "ike delete with reactivation requested",
			state: informationalState{
				inboundSPI:  0x10203040,
				outboundSPI: 0x50607080,
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{ProtocolID: protocolIDIKE},
				&ike.NotifyPayload{NotifyType: notifyTypeReactivationRequestedCause},
			},
			wantDeleteIKE:    true,
			wantReactivation: true,
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
			wantPDNDeact:    true,
			wantSPI:         0x10203040,
		},
		{
			name: "child delete with reactivation requested",
			state: informationalState{
				inboundSPI:  0x10203040,
				outboundSPI: 0x50607080,
			},
			payloads: []ike.Payload{
				&ike.DeletePayload{
					ProtocolID: protocolIDESP,
					SPIs:       [][]byte{uint32Bytes(0x50607080)},
				},
				&ike.NotifyPayload{NotifyType: notifyTypeReactivationRequestedCause},
			},
			wantDeleteChild:  true,
			wantReactivation: true,
			wantSPI:          0x10203040,
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
			if action.reactivationRequested != tt.wantReactivation {
				t.Fatalf("reactivationRequested = %t, want %t", action.reactivationRequested, tt.wantReactivation)
			}
			if action.pdnDeactivated != tt.wantPDNDeact {
				t.Fatalf("pdnDeactivated = %t, want %t", action.pdnDeactivated, tt.wantPDNDeact)
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
