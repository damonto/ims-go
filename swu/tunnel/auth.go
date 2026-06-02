package tunnel

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/eapaka"
	"github.com/damonto/vowifi-go/swu/ike"
	"github.com/damonto/vowifi-go/usim"
)

type akaIdentityStateProvider interface {
	AKAIdentityState() usim.AKAIdentityState
}

type akaIdentityStateStore interface {
	SetAKAIdentityState(usim.AKAIdentityState)
}

const (
	mccDigitCount      = 3
	mncShortDigitCount = 2
	mncLongDigitCount  = 3
)

type akaAuthFlow struct {
	session         *Session
	card            Card
	imei            string
	identity        string
	realm           string
	eapIdentity     string
	reauthIdentity  string
	crypto          *ikeCrypto
	initiatorSPI    uint64
	responderSPI    uint64
	ikeInitRequest  []byte
	ikeInitResponse []byte
	initiatorNonce  []byte
	responderNonce  []byte
	idrRaw          []byte
	idiRaw          []byte

	currentState  usim.AKAIdentityState
	pendingState  usim.AKAIdentityState
	nextRequestID uint32

	identityRounds   int
	lastIdentityReq  byte
	identityPackets  [][]byte
	identityExtended bool

	currentAuthKey []byte
	currentEncrKey []byte
	currentEAPType byte
	currentCounter uint16
	fastReauth     bool

	akaPrimeNetworkName              string
	allowAKAPrimeNetworkNameMismatch bool
	akaPrimeKDFOffer                 []uint16

	akaAuthenticated         bool
	protectedSuccessExpected bool
	protectedSuccessReceived bool
	ipmsIndicated            bool
	notificationReceived     bool
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

func validAKAReauthState(state usim.AKAIdentityState) bool {
	return state.ReauthIdentity != "" && len(state.MK) != 0 && len(state.KAut) != 0 && len(state.KEncr) != 0
}

func normalizedAKAReauthIdentity(state usim.AKAIdentityState, realm string) (string, bool) {
	if !validAKAReauthState(state) {
		return "", false
	}
	return normalizeAKAIdentity(state.ReauthIdentity, realm), true
}

func storeAKAIdentityState(card Card, state usim.AKAIdentityState) {
	storer, ok := card.(akaIdentityStateStore)
	if !ok {
		return
	}
	storer.SetAKAIdentityState(cloneAKAIdentityState(state))
}

func withoutAKAReauthState(state usim.AKAIdentityState) usim.AKAIdentityState {
	state = cloneAKAIdentityState(state)
	state.ReauthIdentity = ""
	state.Counter = 0
	state.MK = nil
	state.KEncr = nil
	state.KAut = nil
	return state
}

func discardStoredAKAReauthState(card Card, state usim.AKAIdentityState) {
	storeAKAIdentityState(card, withoutAKAReauthState(state))
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

func normalizedPLMNDigits(card Card) (string, string, error) {
	mcc := strings.TrimSpace(card.MCC())
	if len(mcc) != mccDigitCount {
		return "", "", fmt.Errorf("mcc %q must be 3 digits", mcc)
	}

	mnc := strings.TrimSpace(card.MNC())
	switch len(mnc) {
	case mncShortDigitCount:
		mnc = "0" + mnc
	case mncLongDigitCount:
	default:
		return "", "", fmt.Errorf("mnc %q must be 2 or 3 digits", mnc)
	}
	return mcc, mnc, nil
}

func initialAKAIdentity(card Card) (string, string, usim.AKAIdentityState, error) {
	mcc, mnc, err := normalizedPLMNDigits(card)
	if err != nil {
		return "", "", usim.AKAIdentityState{}, err
	}
	realm := fmt.Sprintf("nai.epc.mnc%s.mcc%s.3gppnetwork.org", mnc, mcc)
	state := loadAKAIdentityState(card)
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return identity, realm, state, nil
	}
	if state.Pseudonym != "" {
		return normalizeAKAIdentity(state.Pseudonym, realm), realm, state, nil
	}
	return fmt.Sprintf("0%s@%s", card.IMSI(), realm), realm, state, nil
}

func identityRequestType(attrs []eapaka.AKAAttribute) (byte, bool, error) {
	requestType := byte(0)
	requests := 0
	extended := false
	for _, attr := range attrs {
		switch attr.Type {
		case akaAttrPermanentIDReq, akaAttrFullAuthIDReq, akaAttrAnyIDReq:
			if len(attr.Value) != 2 {
				return 0, false, fmt.Errorf("selecting aka identity: invalid identity request attribute length %d", len(attr.Value))
			}
			requests++
			if requests == 1 {
				requestType = attr.Type
				continue
			}
			return 0, false, errors.New("selecting aka identity: duplicate or conflicting identity request attributes")
		case akaAttrMAC, akaAttrIV, akaAttrEncryptedData:
			return 0, false, fmt.Errorf("selecting aka identity: forbidden attribute %d", attr.Type)
		default:
			if attr.Type >= akaSkippableAttributeStart && !isKnownAKAAttribute(attr.Type) {
				extended = true
				continue
			}
			return 0, false, fmt.Errorf("selecting aka identity: unexpected attribute %d", attr.Type)
		}
	}
	if requests != 1 {
		return 0, false, errors.New("selecting aka identity: expected exactly one identity request attribute")
	}
	return requestType, extended, nil
}

func isKnownAKAAttribute(attrType byte) bool {
	switch attrType {
	case akaAttrRAND,
		akaAttrAUTN,
		akaAttrRES,
		akaAttrAUTS,
		akaAttrPadding,
		akaAttrMAC,
		akaAttrNotification,
		akaAttrPermanentIDReq,
		akaAttrAnyIDReq,
		akaAttrIdentity,
		akaAttrFullAuthIDReq,
		akaAttrCounter,
		akaAttrCounterTooSmall,
		akaAttrNonceS,
		akaAttrClientErrorCode,
		akaAttrKDFInput,
		akaAttrKDF,
		akaAttrIV,
		akaAttrEncryptedData,
		akaAttrNextPseudonym,
		akaAttrNextReauthID,
		akaAttrCheckcode,
		akaAttrResultInd,
		akaAttrBidding,
		akaAttrIPMSInd,
		akaAttrIPMSRes:
		return true
	default:
		return false
	}
}

func selectAKAIdentity(card Card, realm string, state usim.AKAIdentityState, requestType, eapType byte) (string, error) {
	prefix := "0"
	if eapType == eapTypeAKAPrime {
		prefix = "6"
	}
	permanentIdentity := fmt.Sprintf("%s%s", prefix, card.IMSI())
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
	if identity, ok := normalizedAKAReauthIdentity(state, realm); ok {
		return identity, nil
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
	case f.lastIdentityReq == akaAttrPermanentIDReq:
		return errors.New("validating aka identity request: AT_PERMANENT_ID_REQ must be the final identity request")
	case f.lastIdentityReq == akaAttrAnyIDReq && requestType == akaAttrAnyIDReq:
		return errors.New("validating aka identity request: AT_ANY_ID_REQ is only valid in the first round")
	case f.lastIdentityReq == akaAttrFullAuthIDReq && (requestType == akaAttrAnyIDReq || requestType == akaAttrFullAuthIDReq):
		return errors.New("validating aka identity request: AT_ANY_ID_REQ or AT_FULLAUTH_ID_REQ cannot follow AT_FULLAUTH_ID_REQ")
	default:
		return nil
	}
}

func (f *akaAuthFlow) recordIdentityRequest(requestType byte, extended bool) {
	f.identityRounds++
	f.lastIdentityReq = requestType
	f.identityExtended = f.identityExtended || extended
}

func (f *akaAuthFlow) recordIdentityExchange(request, response []byte) {
	f.identityPackets = append(f.identityPackets, append([]byte(nil), request...), append([]byte(nil), response...))
}

func checkcodeValue(attrs []eapaka.AKAAttribute, eapType byte) ([]byte, bool, error) {
	attr := eapaka.FindAttribute(attrs, akaAttrCheckcode)
	if attr == nil {
		return nil, false, nil
	}
	wantLen := 2 + sha1.Size
	if eapType == eapTypeAKAPrime {
		wantLen = 2 + sha256.Size
	}
	if len(attr.Value) != 2 && len(attr.Value) != wantLen {
		return nil, true, fmt.Errorf("invalid checkcode length %d", len(attr.Value))
	}
	if len(attr.Value) == 2 {
		return nil, true, nil
	}
	return attr.Value[2:], true, nil
}

func (f *akaAuthFlow) verifyCheckcode(attrs []eapaka.AKAAttribute, eapType byte) error {
	got, ok, err := checkcodeValue(attrs, eapType)
	if err != nil {
		return err
	}
	if !ok {
		if f.identityExtended {
			return errors.New("checkcode is missing after extended aka identity request")
		}
		return nil
	}
	if len(got) == 0 {
		if len(f.identityPackets) == 0 {
			return nil
		}
		return errors.New("empty checkcode after aka identity exchange")
	}
	sum := sha1.New()
	if eapType == eapTypeAKAPrime {
		sum = sha256.New()
	}
	for _, packet := range f.identityPackets {
		_, _ = sum.Write(packet)
	}
	if !hmac.Equal(got, sum.Sum(nil)) {
		return errors.New("checkcode mismatch")
	}
	return nil
}

func (f *akaAuthFlow) challengeResponseCheckcode(attrs []eapaka.AKAAttribute, eapType byte) []byte {
	if !eapaka.HasAttribute(attrs, akaAttrCheckcode) || len(f.identityPackets) == 0 {
		return nil
	}
	sum := sha1.New()
	if eapType == eapTypeAKAPrime {
		sum = sha256.New()
	}
	for _, packet := range f.identityPackets {
		_, _ = sum.Write(packet)
	}
	return append([]byte{0x00, 0x00}, sum.Sum(nil)...)
}

func (f *akaAuthFlow) verifyMessageMAC(eapType byte, data, autKey, extra []byte) error {
	if eapType == eapTypeAKAPrime {
		return eapaka.VerifyMessageMACSHA256(data, autKey, extra)
	}
	return eapaka.VerifyMessageMAC(data, autKey, extra)
}

func (f *akaAuthFlow) clientErrorResponse(identifier byte, action string, cause error) (akaResponse, error) {
	eapType := eapTypeAKA
	if f.currentEAPType == eapTypeAKAPrime {
		eapType = eapTypeAKAPrime
	}
	data, err := eapaka.BuildClientErrorPacketForType(identifier, eapType, akaClientErrorUnableToProcessPacket)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building client error response: %w", err)
	}
	return akaResponse{
		data:      data,
		afterSend: fmt.Errorf("connecting swu session: %s: %w", action, cause),
	}, nil
}

func (s *Session) authenticateEAPAKA(ctx context.Context, card Card, imei, identity, realm string, initialState usim.AKAIdentityState, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, ikeInitRequest, ikeInitResponse, initiatorNonce, responderNonce []byte, idiRaw []byte, firstServerPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	idrRaw, err := responderIDRawFromPayloads(firstServerPayloads)
	if err != nil {
		return nil, 0, err
	}
	flow := akaAuthFlow{
		session:                          s,
		card:                             card,
		imei:                             imei,
		identity:                         identity,
		realm:                            realm,
		eapIdentity:                      identity,
		crypto:                           crypto,
		initiatorSPI:                     initiatorSPI,
		responderSPI:                     responderSPI,
		ikeInitRequest:                   ikeInitRequest,
		ikeInitResponse:                  ikeInitResponse,
		initiatorNonce:                   initiatorNonce,
		responderNonce:                   responderNonce,
		idrRaw:                           idrRaw,
		idiRaw:                           idiRaw,
		currentState:                     cloneAKAIdentityState(initialState),
		pendingState:                     cloneAKAIdentityState(initialState),
		nextRequestID:                    2,
		akaPrimeNetworkName:              s.cfg.AKAPrimeNetworkName,
		allowAKAPrimeNetworkNameMismatch: s.cfg.AllowAKAPrimeNetworkNameMismatch,
	}
	if reauthIdentity, ok := normalizedAKAReauthIdentity(initialState, realm); ok {
		flow.reauthIdentity = reauthIdentity
	}
	return flow.run(ctx, firstServerPayloads)
}

func responderIDRawFromPayloads(payloads []ike.Payload) ([]byte, error) {
	idr := ike.FindIDPayload(payloads, payloadTypeIDr)
	if idr == nil {
		return nil, errors.New("connecting swu session: ike_auth response idr is missing")
	}
	if err := validateResponderID(idr); err != nil {
		return nil, fmt.Errorf("connecting swu session: ike_auth response idr: %w", err)
	}
	idrRaw, err := idr.RawData()
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: ike_auth response idr: %w", err)
	}
	return idrRaw, nil
}

func validateResponderID(idr *ike.IDPayload) error {
	switch idr.IDType {
	case idTypeIPv4Addr:
		if len(idr.Data) != 4 {
			return fmt.Errorf("ID_IPV4_ADDR length %d, want 4", len(idr.Data))
		}
	case idTypeIPv6Addr:
		if len(idr.Data) != 16 {
			return fmt.Errorf("ID_IPV6_ADDR length %d, want 16", len(idr.Data))
		}
	case idTypeFQDN, idTypeRFC822Addr, idTypeDERASN1DN, idTypeKeyID:
		return nil
	default:
		return fmt.Errorf("unsupported type %d", idr.IDType)
	}
	return nil
}

func (f *akaAuthFlow) run(ctx context.Context, serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
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
			return f.finishSuccess(ctx, serverPayloads)
		case eapCodeFailure:
			return nil, 0, fmt.Errorf("connecting swu session: %w", eapaka.ErrEAPFailure)
		case eapCodeRequest:
			if eapPacket.IsIdentityRequest() {
				nextPayloads, err := f.handleEAPIdentityRequest(ctx, serverPayloads, eapPacket.Identifier)
				if err != nil {
					return nil, 0, err
				}
				serverPayloads = nextPayloads
				continue
			}
			if eapPacket.Type == eapTypeNak {
				return nil, 0, errors.New("connecting swu session: received invalid eap request nak")
			}
			if eapPacket.Type == eapTypeNotification {
				nextPayloads, err := f.handleEAPNotificationRequest(ctx, serverPayloads, eapPacket.Identifier)
				if err != nil {
					return nil, 0, err
				}
				serverPayloads = nextPayloads
				continue
			}
			if eapPacket.Type != eapTypeAKA && eapPacket.Type != eapTypeAKAPrime {
				nextPayloads, err := f.handleUnsupportedEAPRequest(ctx, serverPayloads, eapPacket.Identifier, eapPacket.Type)
				if err != nil {
					return nil, 0, err
				}
				serverPayloads = nextPayloads
				continue
			}
			nextPayloads, err := f.handleRequest(ctx, serverPayloads, eapPayload.Data, eapPacket.Identifier, eapPacket.Type)
			if err != nil {
				return nil, 0, err
			}
			serverPayloads = nextPayloads
		default:
			return nil, 0, fmt.Errorf("connecting swu session: unexpected eap code %d", eapPacket.Code)
		}
	}
}

func (f *akaAuthFlow) buildEAPNakResponse(identifier byte) (akaResponse, error) {
	data, err := eapaka.BuildEAPNakResponse(identifier, eapTypeAKAPrime, eapTypeAKA)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building eap nak response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) buildEAPNotificationResponse(identifier byte) (akaResponse, error) {
	data, err := eapaka.BuildEAPNotificationResponse(identifier)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building eap notification response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) handleEAPNotificationRequest(ctx context.Context, serverPayloads []ike.Payload, identifier byte) ([]ike.Payload, error) {
	response, err := f.buildEAPNotificationResponse(identifier)
	if err != nil {
		return nil, err
	}
	nextPayloads, err := f.exchangeResponse(ctx, serverPayloads, response.data)
	if err != nil {
		return nil, err
	}
	f.nextRequestID++
	return nextPayloads, response.afterSend
}

func (f *akaAuthFlow) handleUnsupportedEAPRequest(ctx context.Context, serverPayloads []ike.Payload, identifier, requestType byte) ([]ike.Payload, error) {
	f.logger().Debug("received unsupported EAP request type", "eap_type", requestType)
	response, err := f.buildEAPNakResponse(identifier)
	if err != nil {
		return nil, err
	}
	nextPayloads, err := f.exchangeResponse(ctx, serverPayloads, response.data)
	if err != nil {
		return nil, err
	}
	f.nextRequestID++
	return nextPayloads, response.afterSend
}

func (f *akaAuthFlow) buildEAPIdentityResponse(identifier byte) (akaResponse, error) {
	data, err := eapaka.BuildEAPIdentityResponse(identifier, f.eapIdentity)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building eap identity response: %w", err)
	}
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) handleEAPIdentityRequest(ctx context.Context, serverPayloads []ike.Payload, identifier byte) ([]ike.Payload, error) {
	response, err := f.buildEAPIdentityResponse(identifier)
	if err != nil {
		return nil, err
	}
	nextPayloads, err := f.exchangeResponse(ctx, serverPayloads, response.data)
	if err != nil {
		return nil, err
	}
	f.nextRequestID++
	return nextPayloads, response.afterSend
}

func (f *akaAuthFlow) finishSuccess(ctx context.Context, serverPayloads []ike.Payload) ([]ike.Payload, uint32, error) {
	if err := f.validateEAPSuccess(); err != nil {
		return nil, 0, err
	}
	storeAKAIdentityState(f.card, f.pendingState)
	authValue, err := f.crypto.ComputeInitiatorAuth(f.ikeInitRequest, f.responderNonce, f.idiRaw)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: computing initiator auth: %w", err)
	}
	finalAuthPayloads := []ike.Payload{&ike.AuthPayload{Method: authMethodSharedKeyMIC, Data: authValue}}
	finalAuthPayloads, err = appendDeviceIdentityResponsePayload(finalAuthPayloads, serverPayloads, f.imei, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: building final auth device identity: %w", err)
	}
	header := ike.IKEHeader{InitiatorSPI: f.initiatorSPI, ResponderSPI: f.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: f.nextRequestID}
	request, err := f.crypto.SealIKE(header, finalAuthPayloads, true)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting swu session: sealing final ike_auth: %w", err)
	}
	responseRaw, _, err := f.session.exchangeIKE(ctx, f.session.outerNAT, request, true, f.nextRequestID)
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
	if err := f.verifyResponderPostEAPAuth(payloads); err != nil {
		return nil, 0, err
	}
	return payloads, f.nextRequestID + 1, nil
}

func (f *akaAuthFlow) verifyResponderPostEAPAuth(payloads []ike.Payload) error {
	auth := findAuthPayload(payloads)
	if auth == nil {
		return errors.New("connecting swu session: final ike_auth response auth is missing")
	}
	if auth.Method != authMethodSharedKeyMIC {
		return fmt.Errorf("connecting swu session: final ike_auth response auth method %d", auth.Method)
	}
	want, err := f.crypto.ComputeResponderAuth(f.ikeInitResponse, f.initiatorNonce, f.idrRaw)
	if err != nil {
		return fmt.Errorf("connecting swu session: verifying responder auth: %w", err)
	}
	if !hmac.Equal(auth.Data, want) {
		return errors.New("connecting swu session: responder auth verification failed")
	}
	return nil
}

func findAuthPayload(payloads []ike.Payload) *ike.AuthPayload {
	for _, payload := range payloads {
		auth, ok := payload.(*ike.AuthPayload)
		if ok {
			return auth
		}
	}
	return nil
}

func (f *akaAuthFlow) handleRequest(ctx context.Context, serverPayloads []ike.Payload, eapData []byte, identifier, eapType byte) ([]ike.Payload, error) {
	f.currentEAPType = eapType
	var message eapaka.AKAMessage
	if err := message.UnmarshalBinary(eapData); err != nil {
		response, buildErr := f.clientErrorResponse(identifier, "parsing aka message", err)
		if buildErr != nil {
			return nil, buildErr
		}
		nextPayloads, exchangeErr := f.exchangeResponse(ctx, serverPayloads, response.data)
		if exchangeErr != nil {
			return nil, exchangeErr
		}
		f.nextRequestID++
		return nextPayloads, response.afterSend
	}

	response, err := f.buildResponse(ctx, message, eapData)
	if err != nil {
		return nil, err
	}
	nextPayloads, err := f.exchangeResponse(ctx, serverPayloads, response.data)
	if err != nil {
		return nil, err
	}
	f.nextRequestID++
	if response.afterSend != nil {
		return nil, response.afterSend
	}
	return nextPayloads, nil
}

func (f *akaAuthFlow) buildResponse(ctx context.Context, message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	switch message.Subtype {
	case akaSubtypeIdentity:
		return f.buildIdentityResponse(message, eapData)
	case akaSubtypeChallenge:
		return f.buildChallengeResponse(ctx, message, eapData)
	case akaSubtypeReauthentication:
		return f.buildReauthenticationResponse(message, eapData)
	case akaSubtypeNotification:
		return f.buildNotificationResponse(message, eapData)
	default:
		return f.clientErrorResponse(message.Identifier, "handling aka request", fmt.Errorf("unsupported aka subtype %d", message.Subtype))
	}
}

func (f *akaAuthFlow) buildIdentityResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	requestType, extended, err := identityRequestType(message.Attributes)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "selecting aka identity", err)
	}
	if err := f.validateIdentityRequest(requestType); err != nil {
		return f.clientErrorResponse(message.Identifier, "validating aka identity request", err)
	}
	identityResponse, err := selectAKAIdentity(f.card, f.realm, f.currentState, requestType, message.EAPType)
	if err != nil {
		return f.clientErrorResponse(message.Identifier, "selecting aka identity", err)
	}
	var data []byte
	if message.EAPType == eapTypeAKAPrime {
		data, err = eapaka.BuildAKAPrimeIdentityResponse(message.Identifier, identityResponse)
	} else {
		data, err = eapaka.BuildAKAIdentityResponse(message.Identifier, identityResponse)
	}
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka identity response: %w", err)
	}
	f.eapIdentity = identityResponse
	if reauthIdentity, ok := normalizedAKAReauthIdentity(f.currentState, f.realm); ok && requestType == akaAttrAnyIDReq && identityResponse == reauthIdentity {
		f.reauthIdentity = reauthIdentity
		discardStoredAKAReauthState(f.card, f.currentState)
	}
	f.recordIdentityRequest(requestType, extended)
	f.recordIdentityExchange(eapData, data)
	return akaResponse{data: data}, nil
}

func akaPrimeNetworkNamesMatch(peerNetworkName, serverNetworkName string) bool {
	if peerNetworkName == "" || serverNetworkName == "" {
		return true
	}
	peerFields := strings.Split(peerNetworkName, ":")
	serverFields := strings.Split(serverNetworkName, ":")
	for i := range min(len(peerFields), len(serverFields)) {
		if peerFields[i] != serverFields[i] {
			return false
		}
	}
	return true
}

func akaPrimeKDFValues(attrs []eapaka.AKAAttribute) ([]uint16, error) {
	values := make([]uint16, 0, 1)
	for _, attr := range attrs {
		if attr.Type != akaAttrKDF {
			continue
		}
		kdf, err := eapaka.KDFFromAttribute(&attr)
		if err != nil {
			return nil, err
		}
		values = append(values, kdf.Version)
	}
	return values, nil
}

func uint16sContain(values []uint16, value uint16) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}

func uint16sHaveDuplicate(values []uint16) bool {
	seen := make(map[uint16]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}
		seen[value] = struct{}{}
	}
	return false
}

func uint16sEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sanitizedAKAPrimeChallengeData(message eapaka.AKAMessage) ([]byte, bool, error) {
	if message.EAPType != eapTypeAKAPrime || message.Subtype != akaSubtypeChallenge {
		return nil, false, nil
	}
	seenKDF := false
	attrs := make([]eapaka.AKAAttribute, 0, len(message.Attributes))
	for _, attr := range message.Attributes {
		if attr.Type == akaAttrKDF {
			if seenKDF {
				continue
			}
			seenKDF = true
		}
		attrs = append(attrs, attr)
	}
	if !seenKDF {
		return nil, false, nil
	}
	message.Attributes = attrs
	data, err := message.MarshalBinary()
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

func (f *akaAuthFlow) validateAKAPrimeNetworkName(serverNetworkName []byte) bool {
	server := string(serverNetworkName)
	if akaPrimeNetworkNamesMatch(f.akaPrimeNetworkName, server) {
		return true
	}
	if f.allowAKAPrimeNetworkNameMismatch {
		f.logger().Warn("AKA' network name mismatch", "peer_network_name", f.akaPrimeNetworkName, "server_network_name", server)
		return true
	}
	return false
}

func (f *akaAuthFlow) akaPrimeKDFNegotiationResponse(message eapaka.AKAMessage) (akaResponse, bool, error) {
	if message.EAPType != eapTypeAKAPrime || message.Subtype != akaSubtypeChallenge {
		return akaResponse{}, false, nil
	}
	kdfs, err := akaPrimeKDFValues(message.Attributes)
	if err != nil {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	if len(kdfs) == 0 {
		return akaResponse{}, false, nil
	}
	if len(f.akaPrimeKDFOffer) != 0 {
		want := make([]uint16, 0, len(f.akaPrimeKDFOffer)+1)
		want = append(want, akaPrimeKDFDefault)
		want = append(want, f.akaPrimeKDFOffer...)
		if !uint16sEqual(kdfs, want) {
			return f.buildAKAPrimeAuthenticationReject(message.Identifier)
		}
		return akaResponse{}, false, nil
	}
	if uint16sHaveDuplicate(kdfs) {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	if kdfs[0] == akaPrimeKDFDefault {
		return akaResponse{}, false, nil
	}
	if !uint16sContain(kdfs[1:], akaPrimeKDFDefault) {
		return f.buildAKAPrimeAuthenticationReject(message.Identifier)
	}
	data, err := eapaka.BuildAKAPrimeKDFSelection(message.Identifier, akaPrimeKDFDefault)
	if err != nil {
		return akaResponse{}, false, fmt.Errorf("connecting swu session: building aka prime kdf selection: %w", err)
	}
	f.akaPrimeKDFOffer = append([]uint16(nil), kdfs...)
	return akaResponse{data: data}, true, nil
}

func (f *akaAuthFlow) buildAKAPrimeAuthenticationReject(identifier byte) (akaResponse, bool, error) {
	data, err := eapaka.BuildAKAPrimeAuthenticationReject(identifier)
	if err != nil {
		return akaResponse{}, false, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
	}
	return akaResponse{data: data}, true, nil
}

func (f *akaAuthFlow) buildChallengeResponse(ctx context.Context, message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	if response, ok, err := f.akaPrimeKDFNegotiationResponse(message); ok || err != nil {
		return response, err
	}
	challengeData := eapData
	if data, ok, err := sanitizedAKAPrimeChallengeData(message); err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: sanitizing aka prime challenge: %w", err)
	} else if ok {
		challengeData = data
	}
	var challenge eapaka.AKAChallenge
	if err := challenge.UnmarshalBinary(challengeData); err != nil {
		if errors.Is(err, eapaka.ErrAKAPrimeAuthenticationFailure) {
			data, buildErr := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
			if buildErr != nil {
				return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", buildErr)
			}
			return akaResponse{data: data}, nil
		}
		return f.clientErrorResponse(message.Identifier, "parsing aka challenge", err)
	}
	if message.EAPType == eapTypeAKAPrime && !f.validateAKAPrimeNetworkName(challenge.NetworkName) {
		data, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if message.EAPType == eapTypeAKAPrime && !challenge.AMFSeparationBitSet() {
		data, err := eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka prime authentication reject: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	aka, err := f.card.AKA(ctx, challenge.RAND, challenge.AUTN)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: calculating aka response: %w", err)
	}
	if aka.IsSynchronizationFailure() {
		var data []byte
		if message.EAPType == eapTypeAKAPrime {
			kdfs, parseErr := akaPrimeKDFValues(message.Attributes)
			if parseErr != nil {
				return f.clientErrorResponse(message.Identifier, "parsing aka prime kdf attributes", parseErr)
			}
			data, err = eapaka.BuildAKAPrimeSynchronizationFailure(message.Identifier, aka.AUTS, kdfs)
		} else {
			data, err = eapaka.BuildAKASynchronizationFailure(message.Identifier, aka.AUTS)
		}
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building aka synchronization failure: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	if aka.IsAuthenticationReject() {
		var data []byte
		if message.EAPType == eapTypeAKAPrime {
			data, err = eapaka.BuildAKAPrimeAuthenticationReject(message.Identifier)
		} else {
			data, err = eapaka.BuildAKAAuthenticationReject(message.Identifier)
		}
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
	if message.EAPType == eapTypeAKAPrime {
		sqnXorAK := challenge.AUTN[:akaPrimeSQNXorAKLen]
		if err := f.crypto.DeriveAKAPrimeEAPKeys([]byte(f.eapIdentity), aka.RES, aka.CK, aka.IK, challenge.NetworkName, sqnXorAK); err != nil {
			return f.clientErrorResponse(message.Identifier, "deriving aka prime eap keys", err)
		}
	} else if err := f.crypto.DeriveEAPKeys([]byte(f.eapIdentity), aka.RES, aka.IK, aka.CK); err != nil {
		return f.clientErrorResponse(message.Identifier, "deriving eap keys", err)
	}
	if err := f.verifyMessageMAC(message.EAPType, eapData, f.crypto.eap.AUT, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying aka challenge mac", err)
	}
	if err := f.verifyCheckcode(message.Attributes, message.EAPType); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying aka checkcode", err)
	}
	if response, ok, err := f.biddingDownRejectResponse(message); ok || err != nil {
		return response, err
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
		f.pendingState.Counter = 0
		f.pendingState.MK = append([]byte(nil), f.crypto.eap.MK...)
		f.pendingState.KEncr = append([]byte(nil), f.crypto.eap.ENCR...)
		f.pendingState.KAut = append([]byte(nil), f.crypto.eap.AUT...)
	}
	responseCheckcode := f.challengeResponseCheckcode(message.Attributes, message.EAPType)
	useResultInd := eapaka.HasAttribute(message.Attributes, akaAttrResultInd)
	ipmsSupport := eapaka.IPMSSupport(0)
	if useResultInd {
		ipmsSupport = eapaka.IPMSSupportNBMOnly
	}
	data, err := eapaka.BuildChallengeResponsePacketWithOptions(eapaka.ChallengeResponseOptions{
		Identifier:   message.Identifier,
		EAPType:      message.EAPType,
		RES:          aka.RES,
		AUTKey:       f.crypto.eap.AUT,
		UseResultInd: useResultInd,
		Checkcode:    responseCheckcode,
		IPMSSupport:  ipmsSupport,
	})
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building aka response: %w", err)
	}
	f.currentAuthKey = append([]byte(nil), f.crypto.eap.AUT...)
	f.currentEncrKey = append([]byte(nil), f.crypto.eap.ENCR...)
	f.currentEAPType = message.EAPType
	f.currentCounter = 0
	f.fastReauth = false
	f.ipmsIndicated = ipmsSupport != 0
	f.markAKAAuthenticated(useResultInd)
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
	if !validAKAReauthState(f.currentState) {
		return f.clientErrorResponse(message.Identifier, "validating reauth state", errors.New("reauth state is unavailable"))
	}
	if f.reauthIdentity == "" {
		return f.clientErrorResponse(message.Identifier, "validating reauth state", errors.New("reauth identity is unavailable"))
	}
	discardStoredAKAReauthState(f.card, f.currentState)
	if err := f.verifyMessageMAC(message.EAPType, eapData, f.currentState.KAut, nil); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying reauth mac", err)
	}
	if err := f.verifyCheckcode(message.Attributes, message.EAPType); err != nil {
		return f.clientErrorResponse(message.Identifier, "verifying reauth checkcode", err)
	}
	if response, ok, err := f.biddingDownRejectResponse(message); ok || err != nil {
		return response, err
	}
	var reauth eapaka.AKAReauthentication
	if err := reauth.UnmarshalMessage(message, f.currentState.KEncr); err != nil {
		return f.clientErrorResponse(message.Identifier, "parsing reauth request", err)
	}
	if reauth.Counter <= f.currentState.Counter {
		data, err := eapaka.BuildReauthenticationResponsePacketForType(message.Identifier, message.EAPType, reauth.Counter, true, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
		if err != nil {
			return akaResponse{}, fmt.Errorf("connecting swu session: building reauth counter-too-small response: %w", err)
		}
		return akaResponse{data: data}, nil
	}
	f.currentAuthKey = append([]byte(nil), f.currentState.KAut...)
	f.currentEncrKey = append([]byte(nil), f.currentState.KEncr...)
	f.currentEAPType = message.EAPType
	f.currentCounter = reauth.Counter
	f.fastReauth = true
	var msk, emsk []byte
	var err error
	if message.EAPType == eapTypeAKAPrime {
		msk, emsk, err = eapaka.DeriveAKAPrimeFastReauthKeysFromMK([]byte(f.reauthIdentity), reauth.Counter, reauth.NonceS, f.currentState.MK)
	} else {
		msk, emsk, err = eapaka.DeriveFastReauthKeys([]byte(f.reauthIdentity), reauth.Counter, reauth.NonceS, f.currentState.MK)
	}
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
	data, err := eapaka.BuildReauthenticationResponsePacketForType(message.Identifier, message.EAPType, reauth.Counter, false, reauth.UseResultInd, f.currentState.KAut, f.currentState.KEncr, reauth.NonceS)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building reauth response: %w", err)
	}
	f.markAKAAuthenticated(reauth.UseResultInd)
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) biddingDownRejectResponse(message eapaka.AKAMessage) (akaResponse, bool, error) {
	if message.EAPType != eapTypeAKA {
		return akaResponse{}, false, nil
	}
	attr := eapaka.FindAttribute(message.Attributes, akaAttrBidding)
	if attr == nil {
		return akaResponse{}, false, nil
	}
	bidding, err := eapaka.BiddingFromAttribute(attr)
	if err != nil {
		response, responseErr := f.clientErrorResponse(message.Identifier, "parsing aka bidding", err)
		return response, true, responseErr
	}
	if !bidding.SupportsAKAPrime {
		return akaResponse{}, false, nil
	}
	data, err := eapaka.BuildAKAAuthenticationReject(message.Identifier)
	if err != nil {
		return akaResponse{}, true, fmt.Errorf("connecting swu session: building aka authentication reject: %w", err)
	}
	return akaResponse{data: data}, true, nil
}

func (f *akaAuthFlow) markAKAAuthenticated(useProtectedSuccess bool) {
	f.akaAuthenticated = true
	f.protectedSuccessExpected = useProtectedSuccess
	f.protectedSuccessReceived = false
}

func (f *akaAuthFlow) validateEAPSuccess() error {
	if !f.akaAuthenticated {
		return errors.New("connecting swu session: eap success before aka authentication")
	}
	if f.protectedSuccessExpected && !f.protectedSuccessReceived {
		return errors.New("connecting swu session: eap success before protected success notification")
	}
	return nil
}

func (f *akaAuthFlow) buildNotificationResponse(message eapaka.AKAMessage, eapData []byte) (akaResponse, error) {
	var notification eapaka.AKANotification
	if err := notification.UnmarshalAttributes(message.Attributes); err != nil {
		return f.clientErrorResponse(message.Identifier, "parsing notification", err)
	}
	if f.notificationReceived {
		return f.clientErrorResponse(message.Identifier, "validating notification", errors.New("multiple aka notification rounds"))
	}
	f.notificationReceived = true
	if !notification.Protected && eapaka.HasAttribute(message.Attributes, akaAttrMAC) {
		return f.clientErrorResponse(message.Identifier, "validating notification", errors.New("pre-challenge notification must not include AT_MAC"))
	}
	if notification.Protected {
		if len(f.currentAuthKey) == 0 {
			return f.clientErrorResponse(message.Identifier, "verifying notification mac", errors.New("notification mac key is unavailable"))
		}
		if err := f.verifyMessageMAC(f.currentEAPType, eapData, f.currentAuthKey, nil); err != nil {
			return f.clientErrorResponse(message.Identifier, "verifying notification mac", err)
		}
		if err := f.validateIPMSResult(message, notification); err != nil {
			return f.clientErrorResponse(message.Identifier, "validating ipms result", err)
		}
		if f.fastReauth {
			nested, err := eapaka.DecryptAttributes(message.Attributes, f.currentEncrKey)
			if err != nil {
				return f.clientErrorResponse(message.Identifier, "decrypting notification attrs", err)
			}
			if len(nested) != 1 || nested[0].Type != akaAttrCounter {
				return f.clientErrorResponse(message.Identifier, "validating notification attrs", errors.New("expected encrypted AT_COUNTER only"))
			}
			counter, err := eapaka.Uint16Value(&nested[0])
			if err != nil {
				return f.clientErrorResponse(message.Identifier, "parsing notification counter", err)
			}
			if counter != f.currentCounter {
				return f.clientErrorResponse(message.Identifier, "validating notification counter", fmt.Errorf("counter %d does not match %d", counter, f.currentCounter))
			}
		}
	}
	data, err := eapaka.BuildNotificationResponsePacketForType(message.Identifier, f.currentEAPType, notification, f.fastReauth, f.currentCounter, f.currentAuthKey, f.currentEncrKey)
	if err != nil {
		return akaResponse{}, fmt.Errorf("connecting swu session: building notification response: %w", err)
	}
	if !notification.Success {
		return akaResponse{data: data, afterSend: fmt.Errorf("connecting swu session: notification code %d", notification.Code)}, nil
	}
	if notification.Code != akaNotificationSuccess {
		return f.clientErrorResponse(message.Identifier, "validating success notification", fmt.Errorf("unexpected success notification code %d", notification.Code))
	}
	if !f.akaAuthenticated {
		return f.clientErrorResponse(message.Identifier, "validating success notification", errors.New("aka authentication is incomplete"))
	}
	if !f.protectedSuccessExpected {
		return f.clientErrorResponse(message.Identifier, "validating success notification", errors.New("protected success was not negotiated"))
	}
	f.protectedSuccessReceived = true
	return akaResponse{data: data}, nil
}

func (f *akaAuthFlow) validateIPMSResult(message eapaka.AKAMessage, notification eapaka.AKANotification) error {
	selection, ok, err := eapaka.IPMSSelectionFromAttributes(message.Attributes)
	if err != nil {
		return err
	}
	if !notification.Success {
		return nil
	}
	if !f.ipmsIndicated {
		return nil
	}
	if !ok {
		return errors.New("AT_IPMS_RES is missing after AT_IPMS_IND")
	}
	if selection != eapaka.IPMSSelectionNBM {
		return fmt.Errorf("selected mobility protocol %d is unsupported", selection)
	}
	return nil
}

func (f *akaAuthFlow) exchangeResponse(ctx context.Context, serverPayloads []ike.Payload, responseData []byte) ([]ike.Payload, error) {
	nextPayloads, err := f.session.exchangeAKAResponse(ctx, f.crypto, f.initiatorSPI, f.responderSPI, f.nextRequestID, serverPayloads, f.imei, f.akaAuthenticated, responseData)
	if err != nil {
		return nil, err
	}
	return nextPayloads, nil
}

func (s *Session) exchangeAKAResponse(ctx context.Context, crypto *ikeCrypto, initiatorSPI, responderSPI uint64, messageID uint32, serverPayloads []ike.Payload, imei string, allowDeviceIdentity bool, responseData []byte) ([]ike.Payload, error) {
	requestPayloads := []ike.Payload{&ike.EAPPayload{Data: responseData}}
	requestPayloads, err := appendDeviceIdentityResponsePayload(requestPayloads, serverPayloads, imei, allowDeviceIdentity)
	if err != nil {
		return nil, fmt.Errorf("connecting swu session: building device identity response: %w", err)
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

func appendDeviceIdentityResponsePayload(payloads []ike.Payload, serverPayloads []ike.Payload, imei string, allowed bool) ([]ike.Payload, error) {
	if !allowed {
		return payloads, nil
	}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(serverPayloads, imei)
	if err != nil {
		return nil, err
	}
	if ok {
		payloads = append(payloads, deviceIdentityPayload)
	}
	return payloads, nil
}

func openIKEAuthResponse(packet ike.IKEPacket, crypto *ikeCrypto, action string) ([]ike.Payload, error) {
	payloads, err := crypto.OpenIKE(packet, false)
	if err == nil {
		if notifyErr := protectedIKENotifyError(payloads); notifyErr != nil {
			return nil, fmt.Errorf("%s: %w", action, notifyErr)
		}
		return payloads, nil
	}
	if !hasEncryptedPayload(packet.Payloads) {
		if notifyErr := plaintextIKENotifyError(packet.Payloads); notifyErr != nil {
			return nil, fmt.Errorf("%s: %w", action, notifyErr)
		}
	}
	return nil, fmt.Errorf("%s: %w", action, err)
}

func hasEncryptedPayload(payloads []ike.Payload) bool {
	for _, payload := range payloads {
		if _, ok := payload.(*ike.EncryptedPayload); ok {
			return true
		}
	}
	return false
}

func (f *akaAuthFlow) logger() *slog.Logger {
	return f.session.logger
}

func plaintextIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, "unencrypted", false)
}

func protectedIKENotifyError(payloads []ike.Payload) error {
	return ikeAuthNotifyError(payloads, "protected", true)
}

func ikeAuthNotifyError(payloads []ike.Payload, protection string, requireErrorNotify bool) error {
	if len(payloads) == 0 {
		if requireErrorNotify {
			return nil
		}
		return fmt.Errorf("received %s ike_auth response without payloads", protection)
	}
	notifies := make([]string, 0, len(payloads))
	var backoffDelay time.Duration
	var backoffDeactivated bool
	var backoffSeen bool
	var backoffMalformed bool
	var errorNotifySeen bool
	var networkFailureSeen bool
	var backoffCause uint16
	var accessRejection uint16
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			continue
		}
		if notify.NotifyType == notifyTypeBackoffTimer {
			delay, deactivated, ok := backoffTimerValue(notify)
			if ok {
				backoffDelay = delay
				backoffDeactivated = deactivated
				backoffSeen = true
			} else {
				backoffMalformed = true
			}
		}
		if ikeErrorNotify(notify.NotifyType) {
			errorNotifySeen = true
			if backoffCause == 0 {
				backoffCause = notify.NotifyType
			}
		}
		if notify.NotifyType == notifyTypeNetworkFailure {
			networkFailureSeen = true
		}
		if accessRejectedNotify(notify.NotifyType) {
			accessRejection = notify.NotifyType
		}
		notifies = append(notifies, fmt.Sprintf("%s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType))
	}
	if len(notifies) == 0 || requireErrorNotify && !errorNotifySeen {
		return nil
	}
	err := fmt.Errorf("received %s ike_auth notify %s", protection, strings.Join(notifies, ", "))
	if networkFailureSeen {
		err = networkFailureErrorFor(err)
	}
	if accessRejection != 0 {
		err = accessRejectionErrorFor(accessRejection, err)
	}
	if backoffMalformed && errorNotifySeen {
		return fmt.Errorf("received malformed BACKOFF_TIMER notify: %w", err)
	}
	if backoffSeen && errorNotifySeen {
		return &backoffTimerError{delay: backoffDelay, deactivated: backoffDeactivated, cause: backoffCause, err: err}
	}
	return err
}

func logEAPPacket(logger *slog.Logger, msg, direction string, messageID uint32, data []byte) {
	var packet eapaka.EAPPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		logger.Debug(msg, "direction", direction, "message_id", messageID, "parse_err", err)
		return
	}
	attrs := []string(nil)
	akaSubtype := ""
	if packet.HasType && (packet.Type == eapTypeAKA || packet.Type == eapTypeAKAPrime) {
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
	case eapCodeResponse:
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
	switch packet.Type {
	case eapTypeIdentity:
		return "identity"
	case eapTypeNotification:
		return "notification"
	case eapTypeNak:
		return "nak"
	case eapTypeAKA:
		return "aka"
	case eapTypeAKAPrime:
		return "aka_prime"
	default:
		return fmt.Sprintf("unknown(%d)", packet.Type)
	}
}

func akaSubtypeName(subtype byte) string {
	switch subtype {
	case akaSubtypeChallenge:
		return "challenge"
	case akaSubtypeAuthenticationReject:
		return "authentication_reject"
	case akaSubtypeSynchronizationFailure:
		return "synchronization_failure"
	case akaSubtypeIdentity:
		return "identity"
	case akaSubtypeNotification:
		return "notification"
	case akaSubtypeReauthentication:
		return "reauthentication"
	case akaSubtypeClientError:
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
	case akaAttrRES:
		return "AT_RES"
	case akaAttrAUTS:
		return "AT_AUTS"
	case akaAttrPadding:
		return "AT_PADDING"
	case akaAttrPermanentIDReq:
		return "AT_PERMANENT_ID_REQ"
	case akaAttrMAC:
		return "AT_MAC"
	case akaAttrNotification:
		return "AT_NOTIFICATION"
	case akaAttrAnyIDReq:
		return "AT_ANY_ID_REQ"
	case akaAttrIdentity:
		return "AT_IDENTITY"
	case akaAttrFullAuthIDReq:
		return "AT_FULLAUTH_ID_REQ"
	case akaAttrCounter:
		return "AT_COUNTER"
	case akaAttrCounterTooSmall:
		return "AT_COUNTER_TOO_SMALL"
	case akaAttrNonceS:
		return "AT_NONCE_S"
	case akaAttrClientErrorCode:
		return "AT_CLIENT_ERROR_CODE"
	case akaAttrKDFInput:
		return "AT_KDF_INPUT"
	case akaAttrKDF:
		return "AT_KDF"
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
	case akaAttrBidding:
		return "AT_BIDDING"
	case akaAttrIPMSInd:
		return "AT_IPMS_IND"
	case akaAttrIPMSRes:
		return "AT_IPMS_RES"
	default:
		return fmt.Sprintf("ATTR_%d", attrType)
	}
}

func ikeNotifyName(notifyType uint16) string {
	switch notifyType {
	case notifyTypeUnsupportedCriticalPayload:
		return "UNSUPPORTED_CRITICAL_PAYLOAD"
	case notifyTypeInvalidSyntax:
		return "INVALID_SYNTAX"
	case notifyTypeInvalidMessageID:
		return "INVALID_MESSAGE_ID"
	case notifyTypeInvalidSPI:
		return "INVALID_SPI"
	case notifyTypeNoProposalChosen:
		return "NO_PROPOSAL_CHOSEN"
	case notifyTypeInvalidKEPayload:
		return "INVALID_KE_PAYLOAD"
	case notifyTypeAuthenticationFailed:
		return "AUTHENTICATION_FAILED"
	case notifyTypeSinglePairRequired:
		return "SINGLE_PAIR_REQUIRED"
	case notifyTypeNoAdditionalSAs:
		return "NO_ADDITIONAL_SAS"
	case notifyTypeInternalAddressFailure:
		return "INTERNAL_ADDRESS_FAILURE"
	case notifyTypeFailedCPRequired:
		return "FAILED_CP_REQUIRED"
	case notifyTypeTSUnacceptable:
		return "TS_UNACCEPTABLE"
	case notifyTypeTemporaryFailure:
		return "TEMPORARY_FAILURE"
	case notifyTypeChildSANotFound:
		return "CHILD_SA_NOT_FOUND"
	case notifyTypePDNConnectionRejection:
		return "PDN_CONNECTION_REJECTION"
	case notifyTypeMaxConnectionReached:
		return "MAX_CONNECTION_REACHED"
	case notifyTypeNon3GPPAccessToEPCNotAllowed:
		return "NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED"
	case notifyTypeUserUnknown:
		return "USER_UNKNOWN"
	case notifyTypeNoAPNSubscription:
		return "NO_APN_SUBSCRIPTION"
	case notifyTypeAuthorizationRejected:
		return "AUTHORIZATION_REJECTED"
	case notifyTypeIllegalME:
		return "ILLEGAL_ME"
	case notifyTypeNetworkFailure:
		return "NETWORK_FAILURE"
	case notifyTypeRATTypeNotAllowed:
		return "RAT_TYPE_NOT_ALLOWED"
	case notifyTypeIMEINotAccepted:
		return "IMEI_NOT_ACCEPTED"
	case notifyTypePLMNNotAllowed:
		return "PLMN_NOT_ALLOWED"
	case notifyTypeUnauthenticatedEmergency:
		return "UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED"
	case notifyTypeReactivationRequestedCause:
		return "REACTIVATION_REQUESTED_CAUSE"
	case notifyTypeBackoffTimer:
		return "BACKOFF_TIMER"
	case notifyTypePCSCFReselectionSupport:
		return "P-CSCF_RESELECTION_SUPPORT"
	case notifyTypeN1ModeCapability:
		return "N1_MODE_CAPABILITY"
	case notifyTypeN1ModeInformation:
		return "N1_MODE_INFORMATION"
	case notifyTypeN1ModeSNSSAIPlmnID:
		return "N1_MODE_S_NSSAI_PLMN_ID"
	default:
		return "UNKNOWN_NOTIFY"
	}
}
