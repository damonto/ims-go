package tunnel

import (
	"context"
	"fmt"

	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
)

func (s *Session) exchangeIKEAuth(ctx context.Context, state *connectState) error {
	request, idiData, err := buildIKEAuthRequest(state)
	if err != nil {
		return err
	}
	challengePayloads, err := s.readIKEAuthChallenge(ctx, state, request)
	if err != nil {
		return err
	}
	finalPayloads, nextMessageID, err := s.authenticateEAPAKA(ctx, state.card, state.imei, state.identity, state.realm, state.initialAKAState, state.crypto, state.initiatorSPI, state.responderSPI, state.ikeInitRequest, state.ikeInitResponse, state.nonceI, state.responderNonce, idiData, challengePayloads)
	if err != nil {
		return err
	}
	return finalizeIKEAuthState(state, finalPayloads, nextMessageID)
}

func buildIKEAuthRequest(state *connectState) ([]byte, []byte, error) {
	idi, err := (&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(state.identity)}).RawData()
	if err != nil {
		return nil, nil, fmt.Errorf("building ike_auth request idi: %w", err)
	}
	payloads, err := defaultIKEAuthInitPayloads(state.input.Config, state.identity, state.espInitiatorSPI)
	if err != nil {
		return nil, nil, fmt.Errorf("building ike_auth request: %w", err)
	}
	header := ike.IKEHeader{InitiatorSPI: state.initiatorSPI, ResponderSPI: state.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: 1}
	request, err := state.crypto.SealIKE(header, payloads, true)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing ike_auth request: %w", err)
	}
	return request, idi, nil
}

func (s *Session) readIKEAuthChallenge(ctx context.Context, state *connectState, request []byte) ([]ike.Payload, error) {
	challengeRaw, _, err := s.exchangeIKE(ctx, s.outerNAT, request, true, 1)
	if err != nil {
		return nil, err
	}
	var challengePacket ike.IKEPacket
	if err := challengePacket.UnmarshalBinary(challengeRaw); err != nil {
		return nil, fmt.Errorf("parsing ike_auth challenge: %w", err)
	}
	challengePayloads, err := openIKEAuthResponse(challengePacket, state.crypto, "opening ike_auth challenge")
	if err != nil {
		return nil, err
	}
	state.auth.ChallengeData = marshalPayloadCopies(challengePayloads)
	return challengePayloads, nil
}

func finalizeIKEAuthState(state *connectState, finalPayloads []ike.Payload, nextMessageID uint32) error {
	requestProposals := childSAProposals(state.input.Config, state.espInitiatorSPI)
	tunnel, err := tunnelInfoFromChildSA(finalPayloads, state.input.Config, requestProposals)
	if err != nil {
		return err
	}
	tunnel.ESPInitiatorSPI = state.espInitiatorSPI
	espKeys, err := state.crypto.DeriveESPKeys(tunnel.EncryptionKeyLen, tunnel.Integrity)
	if err != nil {
		return fmt.Errorf("deriving esp keys: %w", err)
	}
	state.finalPayloads = finalPayloads
	state.nextMessageID = nextMessageID
	state.tunnel = tunnel
	state.espKeys = espKeys
	state.auth.CurrentMessageID = nextMessageID
	state.auth.FinalPayloads = marshalPayloadCopies(finalPayloads)
	state.established = handshakeEstablished(state, tunnel, espKeys, nextMessageID)
	return nil
}

func handshakeEstablished(state *connectState, tunnel Info, espKeys ESPKeys, nextMessageID uint32) handshake.Established {
	return handshake.Established{
		Info:            handshakeInfo(tunnel),
		ESPKeys:         handshakeESPKeys(espKeys),
		NextMessageID:   nextMessageID,
		LivenessTimeout: livenessTimeout(state.finalPayloads),
		DeviceIdentity:  state.imei,
	}
}
