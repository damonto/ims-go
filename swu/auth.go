package swu

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/damonto/ims-client/usim"
)

type akaIdentityStateProvider interface {
	AKAIdentityState() usim.AKAIdentityState
}

type akaIdentityStateStore interface {
	SetAKAIdentityState(usim.AKAIdentityState)
}

var ErrEAPFailure = errors.New("eap failure")

type akaAuthFlow struct {
	session        *Session
	ctx            context.Context
	card           Card
	imei           string
	identity       string
	realm          string
	crypto         *ikeCrypto
	initiatorSPI   uint64
	responderSPI   uint64
	ikeInitRequest []byte
	responderNonce []byte
	idiRaw         []byte

	currentState  usim.AKAIdentityState
	pendingState  usim.AKAIdentityState
	nextRequestID uint32

	currentAuthKey []byte
	currentEncrKey []byte
	currentCounter uint16
	fastReauth     bool
}

type akaResponse struct {
	data      []byte
	afterSend error
}

func cloneAKAIdentityState(state usim.AKAIdentityState) usim.AKAIdentityState {
	return usim.AKAIdentityState{
		Pseudonym:      state.Pseudonym,
		ReauthIdentity: state.ReauthIdentity,
		Counter:        state.Counter,
		MK:             append([]byte(nil), state.MK...),
		KEncr:          append([]byte(nil), state.KEncr...),
		KAut:           append([]byte(nil), state.KAut...),
	}
}

func loadAKAIdentityState(card Card) usim.AKAIdentityState {
	provider, ok := card.(akaIdentityStateProvider)
	if !ok {
		return usim.AKAIdentityState{}
	}
	return cloneAKAIdentityState(provider.AKAIdentityState())
}

func storeAKAIdentityState(card Card, state usim.AKAIdentityState) {
	storer, ok := card.(akaIdentityStateStore)
	if !ok {
		return
	}
	storer.SetAKAIdentityState(cloneAKAIdentityState(state))
}

func normalizeAKAIdentity(identity, realm string) string {
	identity = strings.TrimSpace(identity)
	if identity == "" || strings.Contains(identity, "@") {
		return identity
	}
	if realm == "" {
		return identity
	}
	return identity + "@" + realm
}

func initialAKAIdentity(card Card) (string, string, usim.AKAIdentityState) {
	realm := fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", card.MNC(), card.MCC())
	state := loadAKAIdentityState(card)
	if state.ReauthIdentity != "" && len(state.MK) != 0 && len(state.KAut) != 0 && len(state.KEncr) != 0 {
		return normalizeAKAIdentity(state.ReauthIdentity, realm), realm, state
	}
	if state.Pseudonym != "" {
		return normalizeAKAIdentity(state.Pseudonym, realm), realm, state
	}
	return fmt.Sprintf("0%s@%s", card.IMSI(), realm), realm, state
}

func undecoratedAKAIdentity(identity string) string {
	user, _, ok := strings.Cut(identity, "@")
	if ok {
		return user
	}
	return identity
}

func selectAKAIdentity(card Card, realm string, state usim.AKAIdentityState, attrs []AKAAttribute) (string, error) {
	requests := 0
	if hasAKAAttribute(attrs, akaAttrPermanentIDReq) {
		requests++
	}
	if hasAKAAttribute(attrs, akaAttrFullAuthIDReq) {
		requests++
	}
	if hasAKAAttribute(attrs, akaAttrAnyIDReq) {
		requests++
	}
	if requests != 1 {
		return "", fmt.Errorf("selecting aka identity: expected exactly one identity request attribute")
	}
	permanentIdentity := fmt.Sprintf("0%s", card.IMSI())
	if hasAKAAttribute(attrs, akaAttrPermanentIDReq) {
		return permanentIdentity, nil
	}
	if hasAKAAttribute(attrs, akaAttrFullAuthIDReq) {
		if state.Pseudonym != "" {
			return undecoratedAKAIdentity(normalizeAKAIdentity(state.Pseudonym, realm)), nil
		}
		return permanentIdentity, nil
	}
	if state.ReauthIdentity != "" && len(state.MK) != 0 && len(state.KAut) != 0 && len(state.KEncr) != 0 {
		return undecoratedAKAIdentity(normalizeAKAIdentity(state.ReauthIdentity, realm)), nil
	}
	if state.Pseudonym != "" {
		return undecoratedAKAIdentity(normalizeAKAIdentity(state.Pseudonym, realm)), nil
	}
	return permanentIdentity, nil
}

func (s *Session) authenticateEAPAKA(ctx context.Context, card Card, imei, identity, realm string, initialState usim.AKAIdentityState, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, ikeInitRequest []byte, responderNonce []byte, idiRaw []byte, firstServerPayloads []Payload) ([]Payload, uint32, error) {
	flow := akaAuthFlow{
		session:        s,
		ctx:            ctx,
		card:           card,
		imei:           imei,
		identity:       identity,
		realm:          realm,
		crypto:         crypto,
		initiatorSPI:   initiatorSPI,
		responderSPI:   responderSPI,
		ikeInitRequest: ikeInitRequest,
		responderNonce: responderNonce,
		idiRaw:         idiRaw,
		currentState:   cloneAKAIdentityState(initialState),
		pendingState:   cloneAKAIdentityState(initialState),
		nextRequestID:  2,
	}
	return flow.run(firstServerPayloads)
}

func (f *akaAuthFlow) run(serverPayloads []Payload) ([]Payload, uint32, error) {
	for {
		eapPayload := findEAPPayload(serverPayloads)
		if eapPayload == nil {
			return nil, 0, fmt.Errorf("connecting swu session: eap payload is missing")
		}
		var eapPacket EAPPacket
		if err := eapPacket.UnmarshalBinary(eapPayload.Data); err != nil {
			return nil, 0, fmt.Errorf("connecting swu session: parsing eap packet: %w", err)
		}
		switch eapPacket.Code {
		case eapCodeSuccess:
			return f.finishSuccess(serverPayloads)
		case eapCodeFailure:
			return nil, 0, fmt.Errorf("connecting swu session: %w", ErrEAPFailure)
		case eapCodeRequest:
			nextPayloads, err := f.handleRequest(serverPayloads, eapPayload.Data, eapPacket.Identifier)
			if err != nil {
				return nil, 0, err
			}
			serverPayloads = nextPayloads
		default:
			return nil, 0, fmt.Errorf("connecting swu session: unexpected eap code %d", eapPacket.Code)
		}
	}
}

func (f *akaAuthFlow) finishSuccess(serverPayloads []Payload) ([]Payload, uint32, error) {
	storeAKAIdentityState(f.card, f.pendingState)
	authValue, err := f.crypto.ComputeInitiatorAuth(f.ikeInitRequest, f.responderNonce, f.idiRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: computing initiator auth: %w", err)
	}
	finalAuthPayloads := []Payload{&AuthPayload{Method: authMethodSharedKeyMIC, Data: authValue}}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, f.imei)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: building final auth device identity: %w", err)
	}
	if ok {
		finalAuthPayloads = append(finalAuthPayloads, deviceIdentityPayload)
	}
	header := IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	request, err := f.crypto.SealIKE(header, finalAuthPayloads, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: sealing final ike_auth: %w", err)
	}
	responseRaw, _, err := f.session.exchangeIKE(f.ctx, f.session.outerNAT, request, true, f.nextRequestID)
	if err != nil {
		return nil, 0, err
	}
	var responsePacket IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: parsing final ike_auth response: %w", err)
	}
	payloads, err := f.crypto.OpenIKE(responsePacket, false)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: opening final ike_auth response: %w", err)
	}
	return payloads, f.nextRequestID + 1, nil
}

func (f *akaAuthFlow) handleRequest(serverPayloads []Payload, eapData []byte, identifier byte) ([]Payload, error) {
	var message AKAMessage
	if err := message.UnmarshalBinary(eapData); err != nil {
		clientError, buildErr := buildAKAClientErrorPacket(identifier, akaClientErrorUnableToProcessPacket)
		if buildErr == nil {
			_, _ = f.exchangeResponse(serverPayloads, clientError)
		}
		return nil, fmt.Errorf("connecting swu session: parsing aka message: %w", err)
	}

	response, err := f.buildResponse(message, eapData)
	if err != nil {
		return nil, err
	}
	nextPayloads, err := f.exchangeResponse(serverPayloads, response.data)
	if err != nil {
		return nil, err
	}
	f.nextRequestID++
	if response.afterSend != nil {
		return nil, response.afterSend
	}
	return nextPayloads, nil
}

func (f *akaAuthFlow) buildResponse(message AKAMessage, eapData []byte) (akaResponse, error) {
	switch message.Subtype {
	case akaSubtypeIdentity:
		return f.buildIdentityResponse(message)
	case akaSubtypeChallenge:
		return f.buildChallengeResponse(message, eapData)
	case akaSubtypeReauthentication:
		return f.buildReauthenticationResponse(message, eapData)
	case akaSubtypeNotification:
		return f.buildNotificationResponse(message, eapData)
	default:
		data, err := buildAKAClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building client error response: %w", err)
		}
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: unsupported aka subtype %d", message.Subtype)}, nil
	}
}

func (f *akaAuthFlow) buildIdentityResponse(message AKAMessage) (akaResponse, error) {
	identityResponse, err := selectAKAIdentity(f.card, f.realm, f.currentState, message.Attributes)
	if err != nil {
		data, buildErr := buildAKAClientErrorPacket(message.Identifier, akaClientErrorUnableToProcessPacket)
		if buildErr != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building identity client error response: %w", buildErr)
		}
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: selecting aka identity: %w", err)}, nil
	}
	data, err := BuildAKAIdentityResponse(message.Identifier, identityResponse)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka identity response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) buildChallengeResponse(message AKAMessage, eapData []byte) (akaResponse, error) {
	challenge, err := ParseAKAChallenge(eapData)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: parsing aka challenge: %w", err)
	}
	aka, err := f.card.AKA(f.ctx, challenge.RAND, challenge.AUTN)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: calculating aka response: %w", err)
	}
	if aka.IsSynchronizationFailure() {
		data, err := BuildAKASynchronizationFailure(message.Identifier, aka.AUTS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka synchronization failure: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if aka.IsAuthenticationReject() {
		data, err := BuildAKAAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if !aka.IsSuccess() {
		return akaResponse{}, fmt.Errorf("connecting swu session: aka result is incomplete")
	}
	if err := f.crypto.DeriveEAPKeys([]byte(f.identity), aka.RES, aka.IK, aka.CK); err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: deriving eap keys: %w", err)
	}
	if err := verifyAKAMessageMAC(eapData, f.crypto.eap.AUT, nil); err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: verifying aka challenge mac: %w", err)
	}
	nested, err := f.challengeAttributes(message)
	if err != nil {
		return akaResponse{}, err
	}
	f.pendingState = usim.AKAIdentityState{}
	if attr := findAKAAttribute(nested, akaAttrNextPseudonym); attr != nil {
		f.pendingState.Pseudonym, err = akaStringValue(attr)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: parsing next pseudonym: %w", err)
		}
	}
	if attr := findAKAAttribute(nested, akaAttrNextReauthID); attr != nil {
		f.pendingState.ReauthIdentity, err = akaStringValue(attr)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: parsing next reauth id: %w", err)
		}
		f.pendingState.Counter = 1
		f.pendingState.MK = append([]byte(nil), f.crypto.eap.MK...)
		f.pendingState.KEncr = append([]byte(nil), f.crypto.eap.ENCR...)
		f.pendingState.KAut = append([]byte(nil), f.crypto.eap.AUT...)
	}
	data, err := buildAKAChallengeResponsePacket(message.Identifier, aka.RES, f.crypto.eap.AUT, hasAKAAttribute(message.Attributes, akaAttrResultInd))
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka response: %w", err)
	}
	f.currentAuthKey = append([]byte(nil), f.crypto.eap.AUT...)
	f.currentEncrKey = append([]byte(nil), f.crypto.eap.ENCR...)
	f.currentCounter = 0
	f.fastReauth = false
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) challengeAttributes(message AKAMessage) ([]AKAAttribute, error) {
	if !hasAKAAttribute(message.Attributes, akaAttrIV) && !hasAKAAttribute(message.Attributes, akaAttrEncryptedData) {
		return nil, nil
	}
	nested, err := decryptAKAAttributes(message.Attributes, f.crypto.eap.ENCR)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: decrypting aka challenge attrs: %w", err)
	}
	return nested, nil
}

func (f *akaAuthFlow) buildReauthenticationResponse(message AKAMessage, eapData []byte) (akaResponse, error) {
	if f.currentState.ReauthIdentity == "" || len(f.currentState.MK) == 0 || len(f.currentState.KAut) == 0 || len(f.currentState.KEncr) == 0 {
		return akaResponse{}, fmt.Errorf("connecting swu session: reauth state is unavailable")
	}
	if err := verifyAKAMessageMAC(eapData, f.currentState.KAut, nil); err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: verifying reauth mac: %w", err)
	}
	reauth, err := decodeAKAReauthentication(eapData, f.currentState.KEncr)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: parsing reauth request: %w", err)
	}
	f.currentAuthKey = append([]byte(nil), f.currentState.KAut...)
	f.currentEncrKey = append([]byte(nil), f.currentState.KEncr...)
	f.currentCounter = reauth.Counter
	f.fastReauth = true
	if reauth.Counter < f.currentState.Counter {
		data, err := buildAKAReauthenticationResponsePacket(message.Identifier, reauth.Counter, true, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building reauth counter-too-small response: %w", err)
		}
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: reauth counter %d is stale (current %d)", reauth.Counter, f.currentState.Counter)}, nil
	}
	msk, emsk, err := deriveFastReauthKeys([]byte(undecoratedAKAIdentity(f.currentState.ReauthIdentity)), reauth.Counter, reauth.NonceS, f.currentState.MK)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: deriving fast reauth keys: %w", err)
	}
	f.crypto.eap.MK = append([]byte(nil), f.currentState.MK...)
	f.crypto.eap.AUT = append([]byte(nil), f.currentState.KAut...)
	f.crypto.eap.ENCR = append([]byte(nil), f.currentState.KEncr...)
	f.crypto.eap.MSK = msk
	f.crypto.eap.EMSK = emsk
	f.pendingState = cloneAKAIdentityState(f.currentState)
	f.pendingState.Counter = reauth.Counter
	if reauth.NextReauthID != "" {
		f.pendingState.ReauthIdentity = reauth.NextReauthID
	} else {
		f.pendingState.ReauthIdentity = ""
		f.pendingState.Counter = 0
		f.pendingState.MK = nil
		f.pendingState.KEncr = nil
		f.pendingState.KAut = nil
	}
	data, err := buildAKAReauthenticationResponsePacket(message.Identifier, reauth.Counter, false, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building reauth response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) buildNotificationResponse(message AKAMessage, eapData []byte) (akaResponse, error) {
	notification, err := decodeAKANotification(message.Attributes)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: parsing notification: %w", err)
	}
	if notification.Protected {
		if len(f.currentAuthKey) == 0 {
			return akaResponse{}, fmt.Errorf("connecting swu session: notification mac key is unavailable")
		}
		if err := verifyAKAMessageMAC(eapData, f.currentAuthKey, nil); err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: verifying notification mac: %w", err)
		}
		if f.fastReauth {
			nested, err := decryptAKAAttributes(message.Attributes, f.currentEncrKey)
			if err != nil {
				return akaResponse{}, fmt.Errorf("connecting swu session: decrypting notification attrs: %w", err)
			}
			counter, err := akaUint16Value(findAKAAttribute(nested, akaAttrCounter))
			if err != nil {
				return akaResponse{}, fmt.Errorf("connecting swu session: parsing notification counter: %w", err)
			}
			if counter != f.currentCounter {
				return akaResponse{}, fmt.Errorf("connecting swu session: notification counter %d does not match %d", counter, f.currentCounter)
			}
		}
	}
	data, err := buildAKANotificationResponsePacket(message.Identifier, notification, f.currentCounter, f.currentAuthKey, f.currentEncrKey)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building notification response: %w", err)
	}
	if !notification.Success {
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: notification code %d", notification.Code)}, nil
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) exchangeResponse(serverPayloads []Payload, responseData []byte) ([]Payload, error) {
	nextPayloads, err := f.session.exchangeAKAResponse(f.ctx, f.crypto, f.initiatorSPI, f.responderSPI, f.nextRequestID, serverPayloads, f.imei, responseData)
	if err != nil {
		return nil, err
	}
	return nextPayloads, nil
}

func (s *Session) exchangeAKAResponse(ctx context.Context, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, messageID uint32, serverPayloads []Payload, imei string, responseData []byte) ([]Payload, error) {
	requestPayloads := []Payload{&EAPPayload{Data: responseData}}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, imei)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: building device identity response: %w", err)
	}
	if ok {
		requestPayloads = append(requestPayloads, deviceIdentityPayload)
	}
	header := IKEHeader{InitiatorSPI: initiatorSPI, ResponderSPI: responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: messageID}
	request, err := crypto.SealIKE(header, requestPayloads, true)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: sealing aka response: %w", err)
	}
	responseRaw, _, err := s.exchangeIKE(ctx, s.outerNAT, request, true, messageID)
	if err != nil {
		return nil, err
	}
	var responsePacket IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, fmt.Errorf("connecting swu session: parsing aka response message: %w", err)
	}
	payloads, err := crypto.OpenIKE(responsePacket, false)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: opening aka response message: %w", err)
	}
	return payloads, nil
}
