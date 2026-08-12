package tunnel

import (
	"context"
	"fmt"

	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

func (s *Session) exchangeIKEAuth(ctx context.Context, state *connectState) error {
	requests, idiData, err := buildIKEAuthRequest(state)
	if err != nil {
		return err
	}
	if state.consumeInitialAKAReauthIdentity() {
		s.logger.Debug("consumed one-time AKA re-authentication identity")
	}
	challengePayloads, err := s.readIKEAuthChallenge(ctx, state, requests)
	if err != nil {
		return err
	}
	auth, err := s.authenticateEAPAKA(ctx, state, idiData, challengePayloads)
	if err != nil {
		return err
	}
	state.responderAPN = auth.responderAPN
	return finalizeIKEAuthState(state, auth.finalPayloads, auth.nextMessageID)
}

func buildIKEAuthRequest(state *connectState) ([][]byte, []byte, error) {
	idi, err := (&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(state.identity)}).RawData()
	if err != nil {
		return nil, nil, fmt.Errorf("building ike_auth request idi: %w", err)
	}
	payloads, err := defaultIKEAuthInitPayloads(state.input.Config, state.identity, state.espInitiatorSPI)
	if err != nil {
		return nil, nil, fmt.Errorf("building ike_auth request: %w", err)
	}
	header := ike.Header{InitiatorSPI: state.initiatorSPI, ResponderSPI: state.responderSPI, Version: ikeVersion20, ExchangeType: exchangeTypeIKEAuth, Flags: flagInitiator, MessageID: 1}
	requests, err := sealIKEPackets(state.crypto, header, payloads, true, state.ikeFragmentationSupported)
	if err != nil {
		return nil, nil, fmt.Errorf("sealing ike_auth request: %w", err)
	}
	return requests, idi, nil
}

func (s *Session) readIKEAuthChallenge(ctx context.Context, state *connectState, requests [][]byte) ([]ike.Payload, error) {
	peer, useNATT := s.connectIKEPeer(state)
	challengePayloads, _, err := s.exchangeProtectedIKE(ctx, protectedIKEExchange{
		peer:                   peer,
		requests:               requests,
		useNATT:                useNATT,
		messageID:              1,
		crypto:                 state.crypto,
		fragmentationSupported: state.ikeFragmentationSupported,
		action:                 ikeActionOpenIKEAuthChallenge,
	})
	if err != nil {
		// Some ePDGs reject a stale pseudonym with generic Notify 24 instead
		// of requesting the permanent identity. Keep the failed IKE SA dead,
		// but advance the next full connection to the permanent identity.
		if state.discardRejectedAKAPseudonym(err) {
			s.logger.Info("discarded rejected AKA pseudonym for next connection attempt")
		}
		return nil, err
	}
	state.auth.ChallengeData = marshalPayloadCopies(challengePayloads)
	return challengePayloads, nil
}

func sealIKEPackets(crypto *ikeCrypto, header ike.Header, payloads []ike.Payload, initiator bool, fragmentationSupported bool) ([][]byte, error) {
	if !fragmentationSupported {
		wire, err := crypto.SealIKE(header, payloads, initiator)
		if err != nil {
			return nil, err
		}
		return [][]byte{wire}, nil
	}
	return crypto.SealIKEFragments(header, payloads, initiator, defaultIKEFragmentSize)
}

func finalizeIKEAuthState(state *connectState, finalPayloads []ike.Payload, nextMessageID uint32) error {
	requestProposals := childSAProposals(state.input.Config, state.espInitiatorSPI)
	tunnel, err := tunnelInfoFromChildSA(finalPayloads, state.input.Config, requestProposals)
	if err != nil {
		return err
	}
	tunnel.ESPInitiatorSPI = state.espInitiatorSPI
	tunnel.APN = state.responderAPN
	espKeys, err := state.crypto.DeriveESPKeys(tunnel.Encryption, tunnel.EncryptionKeyLen, tunnel.Integrity)
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
