package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/damonto/ims-client/swu/eapaka"
	"github.com/damonto/ims-client/swu/ike"
	"github.com/damonto/ims-client/usim"
)

type akaIdentityStateProvider interface {
	AKAIdentityState() usim.AKAIdentityState
}

type akaIdentityStateStore interface {
	SetAKAIdentityState(usim.AKAIdentityState)
}

type akaAuthFlow struct {
	session        *Session
	ctx            context.Context
	card           Card
	imei           string
	identity       string
	realm          string
	eapIdentity    string
	crypto         *ikeCrypto
	initiatorSPI   uint64
	responderSPI   uint64
	ikeInitRequest []byte
	responderNonce []byte
	idiRaw         []byte

	currentState  usim.AKAIdentityState
	pendingState  usim.AKAIdentityState
	nextRequestID uint32

	identityRounds  int
	lastIdentityReq byte

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

func identityRequestType(attrs []eapaka.AKAAttribute) (byte, error) {
	requestType := byte(0)
	requests := 0
	for _, attr := range attrs {
		switch attr.Type {
		case akaAttrPermanentIDReq, akaAttrFullAuthIDReq, akaAttrAnyIDReq:
			if len(attr.Value) != 2 {
				return 0, fmt.Errorf("selecting aka identity: invalid identity request attribute length %d", len(attr.Value))
			}
			requests++
			if requests == 1 {
				requestType = attr.Type
				continue
			}
			return 0, errors.New("selecting aka identity: duplicate or conflicting identity request attributes")
		default:
			return 0, fmt.Errorf("selecting aka identity: unexpected attribute %d", attr.Type)
		}
	}
	if requests != 1 {
		return 0, errors.New("selecting aka identity: expected exactly one identity request attribute")
	}
	return requestType, nil
}

func selectAKAIdentity(card Card, realm string, state usim.AKAIdentityState, requestType byte) (string, error) {
	permanentIdentity := fmt.Sprintf("0%s", card.IMSI())
	if requestType == akaAttrPermanentIDReq {
		return normalizeAKAIdentity(permanentIdentity, realm), nil
	}
	if requestType == akaAttrFullAuthIDReq {
		if state.Pseudonym != "" {
			return normalizeAKAIdentity(state.Pseudonym, realm), nil
		}
		return normalizeAKAIdentity(permanentIdentity, realm), nil
	}
	if requestType != akaAttrAnyIDReq {
		return "", fmt.Errorf("selecting aka identity: unsupported request type %d", requestType)
	}
	if state.ReauthIdentity != "" && len(state.MK) != 0 && len(state.KAut) != 0 && len(state.KEncr) != 0 {
		return normalizeAKAIdentity(state.ReauthIdentity, realm), nil
	}
	if state.Pseudonym != "" {
		return normalizeAKAIdentity(state.Pseudonym, realm), nil
	}
	return normalizeAKAIdentity(permanentIdentity, realm), nil
}

func (f *akaAuthFlow) validateIdentityRequest(requestType byte) error {
	switch {
	case f.identityRounds >= 3:
		return errors.New("validating aka identity request: too many identity rounds")
	case f.identityRounds > 0 && requestType == akaAttrAnyIDReq:
		return errors.New("validating aka identity request: AT_ANY_ID_REQ is only valid in the first round")
	case f.lastIdentityReq == akaAttrPermanentIDReq && requestType == akaAttrFullAuthIDReq:
		return errors.New("validating aka identity request: AT_FULLAUTH_ID_REQ cannot follow AT_PERMANENT_ID_REQ")
	default:
		return nil
	}
}

func (f *akaAuthFlow) recordIdentityRequest(requestType byte) {
	f.identityRounds++
	f.lastIdentityReq = requestType
}

func (f *akaAuthFlow) clientErrorResponse(identifier byte, action string, cause error) (akaResponse, error) {
	data, err := eapaka.BuildClientErrorPacket(identifier, akaClientErrorUnableToProcessPacket)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building client error response: %w", err)
	}
	return akaResponse{
		data:      data,
		afterSend: fmt.Errorf("connecting swu session: %s: %w", action, cause),
	}, nil
}

func (s *Session) authenticateEAPAKA(ctx context.Context, card Card, imei, identity, realm string, initialState usim.AKAIdentityState, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, ikeInitRequest []byte, responderNonce []byte, idiRaw []byte, firstServerPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	flow := akaAuthFlow{
		session:        s,
		ctx:            ctx,
		card:           card,
		imei:           imei,
		identity:       identity,
		realm:          realm,
		eapIdentity:    identity,
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

func (f *akaAuthFlow) run(serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	for {
		eapPayload := ike.FindEAPPayload(serverPayloads)
		if eapPayload == nil {
			return nil, 0, errors.New("connecting swu session: eap payload is missing")
		}
		var eapPacket eapaka.EAPPacket
		if err := eapPacket.UnmarshalBinary(eapPayload.Data); err != nil {
			return nil, 0, fmt.Errorf("connecting swu session: parsing eap packet: %w", err)
		}
		logEAPPacket(f.logger(), "received EAP packet", "inbound", f.nextRequestID-1, eapPayload.Data)
		switch eapPacket.Code {
		case eapCodeSuccess:
			return f.finishSuccess(serverPayloads)
		case eapCodeFailure:
			return nil, 0, fmt.Errorf("connecting swu session: %w", eapaka.ErrEAPFailure)
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

func (f *akaAuthFlow) finishSuccess(serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	storeAKAIdentityState(f.card, f.pendingState)
	authValue, err := f.crypto.ComputeInitiatorAuth(f.ikeInitRequest, f.responderNonce, f.idiRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: computing initiator auth: %w", err)
	}
	finalAuthPayloads := []ike.Payload{&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: authValue}}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, f.imei)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: building final auth device identity: %w", err)
	}
	if ok {
		finalAuthPayloads = append(finalAuthPayloads, deviceIdentityPayload)
	}
	header := ike.IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	request, err := f.crypto.SealIKE(header, finalAuthPayloads, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: sealing final ike_auth: %w", err)
	}
	responseRaw, _, err := f.session.exchangeIKE(f.ctx, f.session.outerNAT, request, true, f.nextRequestID)
	if err != nil {
		return nil, 0, err
	}
	var responsePacket ike.IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: parsing final ike_auth response: %w", err)
	}
	payloads, err := openIKEAuthResponse(responsePacket, f.crypto, "connecting swu session: opening final ike_auth response")
	if err != nil {
		return nil, 0, err
	}
	return payloads, f.nextRequestID + 1, nil
}

func (f *akaAuthFlow) handleRequest(serverPayloads []ike.Payload, eapData []byte, identifier byte) ([]ike.Payload, error) {
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(eapData); err != nil {
		response, buildErr := f.clientErrorResponse(identifier, "parsing aka message", err)
		if buildErr != nil {
			return nil, buildErr
		}
		nextPayloads, exchangeErr := f.exchangeResponse(serverPayloads, response.data)
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		f.nextRequestID++
		return nextPayloads, response.afterSend
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

func (f *akaAuthFlow) buildResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
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
		return f.clientErrorResponse(message.Identifier, "handling aka request", fmt.Errorf("unsupported aka subtype %d", message.Subtype))
	}
}

func (f *akaAuthFlow) buildIdentityResponse(message eapaka.AKAMessage) (akaResponse, error) {
	requestType, err := identityRequestType(message.Attributes)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "selecting aka identity", err)
	}
	if err := f.validateIdentityRequest(requestType); err != nil {
		return f.clientErrorResponse(message.Identifier, "validating aka identity request", err)
	}
	identityResponse, err := selectAKAIdentity(f.card, f.realm, f.currentState, requestType)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "selecting aka identity", err)
	}
	data, err := eapaka.BuildAKAIdentityResponse(message.Identifier, identityResponse)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka identity response: %w", err)
	}
	f.eapIdentity = identityResponse
	f.recordIdentityRequest(requestType)
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) buildChallengeResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	challenge, err := eapaka.ParseAKAChallenge(eapData)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "parsing aka challenge", err)
	}
	aka, err := f.card.AKA(f.ctx, challenge.RAND, challenge.AUTN)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: calculating aka response: %w", err)
	}
	if aka.IsSynchronizationFailure() {
		data, err := eapaka.BuildAKASynchronizationFailure(message.Identifier, aka.AUTS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka synchronization failure: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if aka.IsAuthenticationReject() {
		data, err := eapaka.BuildAKAAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if !aka.IsSuccess() {
		return f.clientErrorResponse(message.Identifier, "processing aka result", errors.New("aka result is incomplete"))
	}
	f.logger().Debug(
		"calculated AKA response",
		"res_len", len(aka.RES),
		"ck_len", len(aka.CK),
		"ik_len", len(aka.IK),
		"challenge_has_result_ind", eapaka.HasAttribute(message.Attributes, akaAttrResultInd),
		"challenge_has_checkcode", eapaka.HasAttribute(message.Attributes, akaAttrCheckcode),
	)
	if err := f.crypto.DeriveEAPKeys([]byte(f.eapIdentity), aka.RES, aka.IK, aka.CK); err != nil {
		return f.clientErrorResponse(message.Identifier, "deriving eap keys", err)
	}
	if err := eapaka.VerifyMessageMAC(eapData, f.crypto.eap.AUT, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying aka challenge mac", err)
	}
	nested, err := f.challengeAttributes(message)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "decrypting aka challenge attrs", err)
	}
	f.pendingState = usim.AKAIdentityState{}
	if attr := eapaka.FindAttribute(nested, akaAttrNextPseudonym); attr != nil {
		f.pendingState.Pseudonym, err = eapaka.StringValue(attr)
		if err != nil {
			return f.clientErrorResponse(message.Identifier, "parsing next pseudonym", err)
		}
	}
	if attr := eapaka.FindAttribute(nested, akaAttrNextReauthID); attr != nil {
		f.pendingState.ReauthIdentity, err = eapaka.StringValue(attr)
		if err != nil {
			return f.clientErrorResponse(message.Identifier, "parsing next reauth id", err)
		}
		f.pendingState.Counter = 1
		f.pendingState.MK = append([]byte(nil), f.crypto.eap.MK...)
		f.pendingState.KEncr = append([]byte(nil), f.crypto.eap.ENCR...)
		f.pendingState.KAut = append([]byte(nil), f.crypto.eap.AUT...)
	}
	data, err := eapaka.BuildChallengeResponsePacket(message.Identifier, aka.RES, f.crypto.eap.AUT, eapaka.HasAttribute(message.Attributes, akaAttrResultInd))
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka response: %w", err)
	}
	f.currentAuthKey = append([]byte(nil), f.crypto.eap.AUT...)
	f.currentEncrKey = append([]byte(nil), f.crypto.eap.ENCR...)
	f.currentCounter = 0
	f.fastReauth = false
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) challengeAttributes(message eapaka.AKAMessage) ([]eapaka.AKAAttribute, error) {
	if !eapaka.HasAttribute(message.Attributes, akaAttrIV) && !eapaka.HasAttribute(message.Attributes, akaAttrEncryptedData) {
		return nil, nil
	}
	nested, err := eapaka.DecryptAttributes(message.Attributes, f.crypto.eap.ENCR)
	if err != nil {
		return nil, err
	}
	return nested, nil
}

func (f *akaAuthFlow) buildReauthenticationResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	if f.currentState.ReauthIdentity == "" || len(f.currentState.MK) == 0 || len(f.currentState.KAut) == 0 || len(f.currentState.KEncr) == 0 {
		return f.clientErrorResponse(message.Identifier, "validating reauth state", errors.New("reauth state is unavailable"))
	}
	if err := eapaka.VerifyMessageMAC(eapData, f.currentState.KAut, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying reauth mac", err)
	}
	reauth, err := eapaka.DecodeReauthentication(eapData, f.currentState.KEncr)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "parsing reauth request", err)
	}
	f.currentAuthKey = append([]byte(nil), f.currentState.KAut...)
	f.currentEncrKey = append([]byte(nil), f.currentState.KEncr...)
	f.currentCounter = reauth.Counter
	f.fastReauth = true
	if reauth.Counter <= f.currentState.Counter {
		data, err := eapaka.BuildReauthenticationResponsePacket(message.Identifier, reauth.Counter, true, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building reauth counter-too-small response: %w", err)
		}
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: reauth counter %d is stale (current %d)", reauth.Counter, f.currentState.Counter)}, nil
	}
	msk, emsk, err := eapaka.DeriveFastReauthKeys([]byte(f.eapIdentity), reauth.Counter, reauth.NonceS, f.currentState.MK)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "deriving fast reauth keys", err)
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
	data, err := eapaka.BuildReauthenticationResponsePacket(message.Identifier, reauth.Counter, false, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building reauth response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) buildNotificationResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	notification, err := eapaka.DecodeNotification(message.Attributes)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "parsing notification", err)
	}
	if notification.Protected {
		if len(f.currentAuthKey) == 0 {
			return f.clientErrorResponse(message.Identifier, "verifying notification mac", errors.New("notification mac key is unavailable"))
		}
		if err := eapaka.VerifyMessageMAC(eapData, f.currentAuthKey, nil); err != nil {
			return f.clientErrorResponse(message.Identifier, "verifying notification mac", err)
		}
		if f.fastReauth {
			nested, err := eapaka.DecryptAttributes(message.Attributes, f.currentEncrKey)
			if err != nil {
				return f.clientErrorResponse(message.Identifier, "decrypting notification attrs", err)
			}
			counter, err := eapaka.Uint16Value(eapaka.FindAttribute(nested, akaAttrCounter))
			if err != nil {
				return f.clientErrorResponse(message.Identifier, "parsing notification counter", err)
			}
			if counter != f.currentCounter {
				return f.clientErrorResponse(message.Identifier, "validating notification counter", fmt.Errorf("counter %d does not match %d", counter, f.currentCounter))
			}
		}
	}
	data, err := eapaka.BuildNotificationResponsePacket(message.Identifier, notification, f.fastReauth, f.currentCounter, f.currentAuthKey, f.currentEncrKey)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building notification response: %w", err)
	}
	if !notification.Success {
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: notification code %d", notification.Code)}, nil
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) exchangeResponse(serverPayloads []ike.Payload, responseData []byte) ([]ike.Payload, error) {
	nextPayloads, err := f.session.exchangeAKAResponse(f.ctx, f.crypto, f.initiatorSPI, f.responderSPI, f.nextRequestID, serverPayloads, f.imei, responseData)
	if err != nil {
		return nil, err
	}
	return nextPayloads, nil
}

func (s *Session) exchangeAKAResponse(ctx context.Context, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, messageID uint32, serverPayloads []ike.Payload, imei string, responseData []byte) ([]ike.Payload, error) {
	requestPayloads := []ike.Payload{&ike.EAPPayload{Data: responseData}}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, imei)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: building device identity response: %w", err)
	}
	if ok {
		requestPayloads = append(requestPayloads, deviceIdentityPayload)
	}
	logEAPPacket(s.logger, "sending EAP packet", "outbound", messageID, responseData)
	header := ike.IKEHeader{InitiatorSPI: initiatorSPI, ResponderSPI: responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: messageID}
	request, err := crypto.SealIKE(header, requestPayloads, true)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: sealing aka response: %w", err)
	}
	responseRaw, _, err := s.exchangeIKE(ctx, s.outerNAT, request, true, messageID)
	if err != nil {
		return nil, err
	}
	var responsePacket ike.IKEPacket
	if err := responsePacket.UnmarshalBinary(responseRaw); err != nil {
		return nil, fmt.Errorf("connecting swu session: parsing aka response message: %w", err)
	}
	payloads, err := openIKEAuthResponse(responsePacket, crypto, "connecting swu session: opening aka response message")
	if err != nil {
		return nil, err
	}
	return payloads, nil
}

func openIKEAuthResponse(packet ike.IKEPacket, crypto *ikeCrypto, action string) ([]ike.Payload, error) {
	payloads, err := crypto.OpenIKE(packet, false)
	if err == nil {
		return payloads, nil
	}
	if errors.Is(err, errMissingEncryptedPayload) {
		if notifyErr := plaintextIKENotifyError(packet.Payloads); notifyErr != nil {
			return nil, fmt.Errorf("%s: %w", action, notifyErr)
		}
	}
	return nil, fmt.Errorf("%s: %w", action, err)
}

func (f *akaAuthFlow) logger() *slog.Logger {
	return f.session.logger
}

func plaintextIKENotifyError(payloads []ike.Payload) error {
	if len(payloads) == 0 {
		return errors.New("received unencrypted ike_auth response without payloads")
	}
	notifies := make([]string, 0, len(payloads))
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			return fmt.Errorf("received unencrypted ike_auth payload %T", payload)
		}
		notifies = append(notifies, fmt.Sprintf("%s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType))
	}
	return fmt.Errorf("received unencrypted ike_auth notify %s", strings.Join(notifies, ", "))
}

func logEAPPacket(logger *slog.Logger, msg, direction string, messageID uint32, data []byte) {
	var packet eapaka.EAPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		logger.Debug(msg, "direction", direction, "message_id", messageID, "parse_err", err)
		return
	}
	attrs := []string(nil)
	akaSubtype := ""
	if packet.HasType && packet.Type == eapaka.TypeAKA {
		var message eapaka.AKAMessage
		if err := message.UnmarshalBinary(data); err == nil {
			akaSubtype = akaSubtypeName(message.Subtype)
			attrs = summarizeAKAAttributes(message.Attributes)
		}
	}
	logger.Debug(
		msg,
		"direction", direction,
		"message_id", messageID,
		"eap_code", eapCodeName(packet.Code),
		"eap_identifier", packet.Identifier,
		"eap_type", eapTypeName(packet),
		"aka_subtype", akaSubtype,
		"aka_attrs", attrs,
	)
}

func eapCodeName(code byte) string {
	switch code {
	case eapCodeRequest:
		return "request"
	case 2:
		return "response"
	case eapCodeSuccess:
		return "success"
	case eapCodeFailure:
		return "failure"
	default:
		return fmt.Sprintf("unknown(%d)", code)
	}
}

func eapTypeName(packet eapaka.EAPPacket) string {
	if !packet.HasType {
		return ""
	}
	if packet.Type == eapaka.TypeAKA {
		return "aka"
	}
	return fmt.Sprintf("unknown(%d)", packet.Type)
}

func akaSubtypeName(subtype byte) string {
	switch subtype {
	case akaSubtypeChallenge:
		return "challenge"
	case 2:
		return "authentication_reject"
	case 4:
		return "synchronization_failure"
	case akaSubtypeIdentity:
		return "identity"
	case akaSubtypeNotification:
		return "notification"
	case akaSubtypeReauthentication:
		return "reauthentication"
	case 14:
		return "client_error"
	default:
		return fmt.Sprintf("unknown(%d)", subtype)
	}
}

func summarizeAKAAttributes(attrs []eapaka.AKAAttribute) []string {
	summary := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		summary = append(summary, fmt.Sprintf("%s(%d)", akaAttributeName(attr.Type), len(attr.Value)))
	}
	return summary
}

func akaAttributeName(attrType byte) string {
	switch attrType {
	case akaAttrRAND:
		return "AT_RAND"
	case akaAttrAUTN:
		return "AT_AUTN"
	case 3:
		return "AT_RES"
	case 4:
		return "AT_AUTS"
	case 6:
		return "AT_PADDING"
	case akaAttrPermanentIDReq:
		return "AT_PERMANENT_ID_REQ"
	case akaAttrMAC:
		return "AT_MAC"
	case 12:
		return "AT_NOTIFICATION"
	case akaAttrAnyIDReq:
		return "AT_ANY_ID_REQ"
	case akaAttrIdentity:
		return "AT_IDENTITY"
	case akaAttrFullAuthIDReq:
		return "AT_FULLAUTH_ID_REQ"
	case akaAttrCounter:
		return "AT_COUNTER"
	case 20:
		return "AT_COUNTER_TOO_SMALL"
	case 21:
		return "AT_NONCE_S"
	case 22:
		return "AT_CLIENT_ERROR_CODE"
	case akaAttrIV:
		return "AT_IV"
	case akaAttrEncryptedData:
		return "AT_ENCR_DATA"
	case akaAttrNextPseudonym:
		return "AT_NEXT_PSEUDONYM"
	case akaAttrNextReauthID:
		return "AT_NEXT_REAUTH_ID"
	case akaAttrCheckcode:
		return "AT_CHECKCODE"
	case akaAttrResultInd:
		return "AT_RESULT_IND"
	case 136:
		return "AT_BIDDING"
	default:
		return fmt.Sprintf("ATTR_%d", attrType)
	}
}

func ikeNotifyName(notifyType uint16) string {
	switch notifyType {
	case 1:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case 7:
		return "INVALID_SYNTAX"
	case 9:
		return "INVALID_MESSAGE_ID"
	case 14:
		return "NO_PROPOSAL_CHOSEN"
	case notifyTypeInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case 24:
		return "AUTHENTICATION_FAILED"
	case 34:
		return "SINGLE_PAIR_REQUIRED"
	case 35:
		return "NO_ADDITIONAL_SAS"
	case 36:
		return "INTERNAL_ADDRESS_FAILURE"
	case 37:
		return "FAILED_CP_REQUIRED"
	case 38:
		return "TS_UNACCEPTABLE"
	case 43:
		return "TEMPORARY_FAILURE"
	default:
		return "UNKNOWN_NOTIFY"
	}
}
