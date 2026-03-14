package tunnel

import (
	"encoding/binary"
	"net"
	"testing"

	"github.com/damonto/ims-client/swu/eapaka"
	"github.com/damonto/ims-client/swu/ike"
)

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
			wantIdentity:       "0001010123456789",
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

			response, err := tt.flow.buildIdentityResponse(message)
			if err != nil {
				t.Fatalf("buildIdentityResponse() error = %v", err)
			}

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

	first, err := flow.buildIdentityResponse(message)
	if err != nil {
		t.Fatalf("first buildIdentityResponse() error = %v", err)
	}
	if first.afterSend != nil {
		t.Fatalf("first buildIdentityResponse() afterSend = %v, want nil", first.afterSend)
	}

	second, err := flow.buildIdentityResponse(message)
	if err != nil {
		t.Fatalf("second buildIdentityResponse() error = %v", err)
	}
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

	response, err := flow.buildIdentityResponse(message)
	if err != nil {
		t.Fatalf("buildIdentityResponse() error = %v", err)
	}
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
