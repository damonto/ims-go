package tunnel

import (
	"context"
	"errors"
	"fmt"

	"github.com/damonto/uicc-go/usim"
	"github.com/damonto/vowifi-go/eapaka"
	"github.com/damonto/vowifi-go/swu/ike"
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
