package tunnel

import (
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/handshake"
	"github.com/damonto/vowifi-go/swu/ike"
	"github.com/damonto/vowifi-go/usim"
)

const (
	defaultIKENonceLength     = 32
	maxCookieNotifyDataLength = 64
	maxIKESAInitCookieRetries = 4
	ikeSPISeedLength          = 16
)

type connectState struct {
	input           handshake.ConnectInput
	saInit          handshake.SAInitState
	auth            handshake.AuthState
	established     handshake.Established
	card            Card
	imei            string
	identity        string
	realm           string
	initialAKAState usim.AKAIdentityState
	crypto          *ikeCrypto
	initiatorSPI    uint64
	responderSPI    uint64
	espInitiatorSPI uint32
	nonceI          []byte
	ikeInitCookie   []byte
	ikeInitRequest  []byte
	ikeInitResponse []byte
	responderNonce  []byte
	nattSupported   bool
	natDetected     bool
	nextMessageID   uint32
	finalPayloads   []ike.Payload
	tunnel          Info
	espKeys         ESPKeys
}

func (s *Session) Connect(ctx context.Context, imei string, card Card) error {
	state, finish, err := s.prepareConnect(imei, card)
	if err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	defer finish()
	s.logger.Info("starting SWu authentication", "remote_addr", s.outerRemote)
	if err := s.exchangeIKESAInit(ctx, state); err != nil {
		s.logger.Error("IKE_SA_INIT exchange", "err", err)
		return fmt.Errorf("connecting swu session: %w", err)
	}
	s.logger.Info("IKE_SA_INIT established", "initiator_spi", state.initiatorSPI, "responder_spi", state.responderSPI, "natt_supported", state.nattSupported, "nat_detected", state.natDetected)
	if err := s.exchangeIKEAuth(ctx, state); err != nil {
		s.logger.Error("IKE_AUTH exchange", "err", err)
		return fmt.Errorf("connecting swu session: %w", err)
	}
	s.commitConnect(state)
	s.startBackgroundLoops()
	s.logger.Info("SWu security associations established", "inner_ip", state.tunnel.InnerIP, "pcscf_ip", state.tunnel.PCSCFIP, "pcscf_ips", state.tunnel.PCSCFIPs, "esp_initiator_spi", state.tunnel.ESPInitiatorSPI, "esp_responder_spi", state.tunnel.ESPResponderSPI)
	return nil
}

func (s *Session) prepareConnect(imei string, card Card) (*connectState, func(), error) {
	input := handshake.ConnectInput{
		IMEI:        imei,
		Card:        card,
		OuterRemote: cloneUDPAddr(s.outerRemote),
		Logger:      s.logger,
		Config:      handshakeConfig(s.cfg),
	}
	if err := input.Validate(); err != nil {
		return nil, nil, err
	}
	finish, err := s.beginConnect()
	if err != nil {
		return nil, nil, err
	}
	state, err := newConnectState(input)
	if err != nil {
		finish()
		return nil, nil, err
	}
	return state, finish, nil
}

func (s *Session) beginConnect() (func(), error) {
	if s.isClosed() {
		return nil, errors.New("session is closed")
	}
	s.mu.Lock()
	if s.connected {
		s.mu.Unlock()
		return nil, errors.New("already connected")
	}
	if err := s.disconnectedTunnelErr(); err != nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("close and redial session: %w", err)
	}
	if s.connecting {
		s.mu.Unlock()
		return nil, errors.New("connect already in progress")
	}
	s.connecting = true
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.connecting = false
		s.mu.Unlock()
	}, nil
}

func newConnectState(input handshake.ConnectInput) (*connectState, error) {
	identity, realm, initialAKAState, err := initialAKAIdentity(input.Card)
	if err != nil {
		return nil, fmt.Errorf("building aka identity: %w", err)
	}
	dhGroup := transformDH2048MODP
	if len(input.Config.DHGroups) != 0 {
		dhGroup = input.Config.DHGroups[0]
	}
	crypto, initiatorSPI, espInitiatorSPI, nonceI, err := newConnectCryptoState(dhGroup)
	if err != nil {
		return nil, err
	}
	return &connectState{
		input:           input,
		saInit:          handshake.SAInitState{InitiatorSPI: initiatorSPI, DHGroup: dhGroup, NonceI: append([]byte(nil), nonceI...), ChildInitiatorSPI: espInitiatorSPI},
		auth:            handshake.AuthState{Identity: identity, Realm: realm, CurrentMessageID: 1},
		card:            input.Card,
		imei:            input.IMEI,
		identity:        identity,
		realm:           realm,
		initialAKAState: initialAKAState,
		crypto:          crypto,
		initiatorSPI:    initiatorSPI,
		espInitiatorSPI: espInitiatorSPI,
		nonceI:          nonceI,
	}, nil
}

func newConnectCryptoState(dhGroup uint16) (*ikeCrypto, uint64, uint32, []byte, error) {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return nil, 0, 0, nil, err
	}
	initiatorSPI, err := randomUint64()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating initiator spi: %w", err)
	}
	espInitiatorSPI, err := randomUint32()
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating child spi: %w", err)
	}
	nonceI, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return nil, 0, 0, nil, fmt.Errorf("generating nonce: %w", err)
	}
	crypto.SetSPIs(initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	return crypto, initiatorSPI, espInitiatorSPI, nonceI, nil
}

func (state *connectState) resetDHGroup(dhGroup uint16) error {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return err
	}
	nonceI, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return fmt.Errorf("generating nonce: %w", err)
	}
	crypto.SetSPIs(state.initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	state.crypto = crypto
	state.nonceI = nonceI
	state.saInit.DHGroup = dhGroup
	state.saInit.NonceI = append([]byte(nil), nonceI...)
	return nil
}

func (state *connectState) buildIKESAInitRequest(outerLocal, outerRemote *net.UDPAddr) ([]byte, error) {
	payloads := defaultIKESAInitPayloads(state.input.Config, state.crypto, outerLocal, outerRemote)
	if len(state.ikeInitCookie) != 0 {
		payloads = append([]ike.Payload{
			&ike.NotifyPayload{
				NotifyType: notifyTypeCookie,
				Data:       append([]byte(nil), state.ikeInitCookie...),
			},
		}, payloads...)
	}
	header := ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeIKESAInit,
		Flags:        flagInitiator,
		MessageID:    0,
	}
	request, err := (ike.IKEPacket{Header: header, Payloads: payloads}).MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("building ike_sa_init request: %w", err)
	}
	return request, nil
}

func decodeIKESAInitPacket(raw []byte) (ike.IKEPacket, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(raw); err != nil {
		return ike.IKEPacket{}, fmt.Errorf("parsing ike_sa_init response: %w", err)
	}
	return packet, nil
}

func (state *connectState) applyIKESAInitResponse(response ike.IKEPacket, request, responseRaw []byte, outerLocal, outerRemote *net.UDPAddr) error {
	if response.Header.ResponderSPI == 0 {
		return errors.New("responder spi is empty")
	}
	requestProposals := ikeSAProposals(state.input.Config, state.crypto.dhGroup)
	proposal, responderNonce, responderKE, err := negotiatedIKESAFromPayloads(response.Payloads, state.crypto.dhGroup, requestProposals)
	if err != nil {
		return err
	}
	nattSupported, natDetected, err := ikeSAInitNATDetection(response.Payloads, response.Header.InitiatorSPI, response.Header.ResponderSPI, outerLocal, outerRemote)
	if err != nil {
		return err
	}
	if !nattSupported {
		return errors.New("parsing ike_sa_init response: peer does not support nat traversal")
	}
	state.crypto.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	state.crypto.SetSPIs(state.initiatorSPI, response.Header.ResponderSPI)
	state.crypto.SetNonces(state.nonceI, responderNonce)
	if err := state.crypto.DeriveIKEKeys(responderKE); err != nil {
		return fmt.Errorf("deriving ike keys: %w", err)
	}
	state.responderSPI = response.Header.ResponderSPI
	state.ikeInitRequest = append([]byte(nil), request...)
	state.ikeInitResponse = append([]byte(nil), responseRaw...)
	state.responderNonce = append([]byte(nil), responderNonce...)
	state.nattSupported = nattSupported
	state.natDetected = natDetected
	state.saInit.InitiatorSPI = state.initiatorSPI
	state.saInit.ResponderSPI = state.responderSPI
	state.saInit.NonceI = append([]byte(nil), state.nonceI...)
	state.saInit.ResponderNonce = append([]byte(nil), responderNonce...)
	state.saInit.IKEInitRequest = append([]byte(nil), request...)
	state.saInit.ChildInitiatorSPI = state.espInitiatorSPI
	return nil
}

func (s *Session) exchangeIKESAInit(ctx context.Context, state *connectState) error {
	triedGroups := map[uint16]struct{}{state.crypto.dhGroup: {}}
	cookieRetries := 0
	for {
		outerLocal, err := resolveOuterLocalAddr(s.conn, s.outerRemote)
		if err != nil {
			s.logger.Debug("resolving local outer address failed", "err", err)
		}
		state.input.OuterLocal = cloneUDPAddr(outerLocal)
		request, err := state.buildIKESAInitRequest(outerLocal, s.outerRemote)
		if err != nil {
			return err
		}
		responseRaw, _, err := s.exchangeIKE(ctx, s.outerRemote, request, s.outerRemote.Port == s.cfg.NATTPort, 0)
		if err != nil {
			return err
		}
		response, err := decodeIKESAInitPacket(responseRaw)
		if err != nil {
			return err
		}
		cookie, retryCookie, err := cookiePayloadData(response.Payloads)
		if err != nil {
			return err
		}
		if retryCookie {
			cookieRetries++
			if cookieRetries > maxIKESAInitCookieRetries {
				return errors.New("parsing ike_sa_init response: too many COOKIE retries")
			}
			s.logger.Info("retrying IKE_SA_INIT with COOKIE", "attempt", cookieRetries)
			state.ikeInitCookie = cookie
			continue
		}
		group, retry, err := invalidKEPayloadGroup(response.Payloads)
		if err != nil {
			return err
		}
		if err := ikeSAInitNotifyError(response.Payloads); err != nil {
			return err
		}
		if !retry {
			return state.applyIKESAInitResponse(response, request, responseRaw, outerLocal, s.outerRemote)
		}
		if _, ok := triedGroups[group]; ok {
			return fmt.Errorf("parsing ike_sa_init response: repeated INVALID_KE_PAYLOAD group %d", group)
		}
		if !slices.Contains(state.input.Config.DHGroups, group) {
			return fmt.Errorf("parsing ike_sa_init response: invalid ke dh group %d was not requested", group)
		}
		s.logger.Info("retrying IKE_SA_INIT with responder DH group", "dh_group", group)
		if err := state.resetDHGroup(group); err != nil {
			return fmt.Errorf("updating ike_sa_init dh group: %w", err)
		}
		triedGroups[group] = struct{}{}
	}
}

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
	state.established = handshake.Established{
		Info:            handshakeInfo(tunnel),
		ESPKeys:         handshakeESPKeys(espKeys),
		NextMessageID:   nextMessageID,
		LivenessTimeout: livenessTimeout(finalPayloads),
		DeviceIdentity:  state.imei,
	}
	return nil
}

func marshalPayloadCopies(payloads []ike.Payload) [][]byte {
	out := make([][]byte, 0, len(payloads))
	for _, payload := range payloads {
		wire, err := payload.MarshalBinary()
		if err != nil {
			continue
		}
		out = append(out, append([]byte(nil), wire...))
	}
	return out
}

func (state *connectState) outboundESPCodec() esp.Codec {
	return outboundESPCodec(state.tunnel, state.espKeys)
}

func (state *connectState) inboundESPCodec() esp.Codec {
	return inboundESPCodec(state.tunnel, state.espKeys)
}

func outboundESPCodec(info Info, keys ESPKeys) esp.Codec {
	return esp.Codec{
		SPI:           info.ESPResponderSPI,
		Encryption:    esp.EncryptionAESCBC,
		Integrity:     integrityName(info.Integrity),
		EncryptionKey: append([]byte(nil), keys.EncryptionInitiator...),
		IntegrityKey:  append([]byte(nil), keys.IntegrityInitiator...),
	}
}

func inboundESPCodec(info Info, keys ESPKeys) esp.Codec {
	return esp.Codec{
		SPI:           info.ESPInitiatorSPI,
		Encryption:    esp.EncryptionAESCBC,
		Integrity:     integrityName(info.Integrity),
		EncryptionKey: append([]byte(nil), keys.EncryptionResponder...),
		IntegrityKey:  append([]byte(nil), keys.IntegrityResponder...),
	}
}

func (state *connectState) innerLocalAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), state.tunnel.InnerIP...), Port: port}
}

func (state *connectState) innerRemoteAddr(port int) *net.UDPAddr {
	return &net.UDPAddr{IP: append(net.IP(nil), state.tunnel.PCSCFIP...), Port: port}
}

func (state *connectState) sessionLivenessTimeout() time.Duration {
	timeout := livenessTimeout(state.finalPayloads)
	if timeout > 0 {
		return timeout
	}
	if state.input.Config.LivenessTimeout > 0 {
		return state.input.Config.LivenessTimeout
	}
	return defaultLivenessTimeout
}

func livenessTimeout(payloads []ike.Payload) time.Duration {
	config := ike.FindConfigPayload(payloads)
	if config == nil {
		return 0
	}
	for _, attr := range config.Attributes {
		if attr.Type != configAttrTimeoutPeriodForLivenessCheck {
			continue
		}
		if attr.Format != attributeFormatTLV || len(attr.Value) != 4 {
			return 0
		}
		seconds := binary.BigEndian.Uint32(attr.Value)
		if seconds == 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	return 0
}

type negotiatedIKESA struct {
	Encryption       uint16
	EncryptionKeyLen uint16
	Integrity        uint16
	PRF              uint16
}

func negotiatedIKESAFromPayloads(payloads []ike.Payload, dhGroup uint16, requestProposals []ike.Proposal) (negotiatedIKESA, []byte, []byte, error) {
	nonce := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	ke := ike.FindKEPayload(payloads, dhGroup)
	if nonce == nil || sa == nil || ke == nil {
		return negotiatedIKESA{}, nil, nil, errors.New("parsing ike_sa_init response: required payload is missing")
	}
	if err := validateNonceData("parsing ike_sa_init response", nonce.Data); err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	if len(sa.Proposals) != 1 {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: negotiated proposal count %d", len(sa.Proposals))
	}
	if len(sa.Proposals[0].SPI) != 0 {
		return negotiatedIKESA{}, nil, nil, fmt.Errorf("parsing ike_sa_init response: invalid negotiated ike spi length %d", len(sa.Proposals[0].SPI))
	}
	if err := validateNegotiatedProposalFromRequests("parsing ike_sa_init response", sa.Proposals[0], requestProposals); err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	proposal, err := negotiatedIKESAFromProposal(sa.Proposals[0], dhGroup)
	if err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	return proposal, nonce.Data, ke.Data, nil
}

func invalidKEPayloadGroup(payloads []ike.Payload) (uint16, bool, error) {
	return invalidKEPayloadGroupFor("parsing ike_sa_init response", payloads)
}

func invalidKEPayloadGroupFor(action string, payloads []ike.Payload) (uint16, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeInvalidKEPayload)
	if notify == nil {
		return 0, false, nil
	}
	if len(notify.Data) != 2 {
		return 0, false, fmt.Errorf("%s: invalid INVALID_KE_PAYLOAD length %d", action, len(notify.Data))
	}
	return binary.BigEndian.Uint16(notify.Data), true, nil
}

func cookiePayloadData(payloads []ike.Payload) ([]byte, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeCookie)
	if notify == nil {
		return nil, false, nil
	}
	if len(notify.SPI) != 0 {
		return nil, false, fmt.Errorf("parsing ike_sa_init response: invalid COOKIE spi length %d", len(notify.SPI))
	}
	if len(notify.Data) == 0 || len(notify.Data) > maxCookieNotifyDataLength {
		return nil, false, fmt.Errorf("parsing ike_sa_init response: invalid COOKIE length %d", len(notify.Data))
	}
	return append([]byte(nil), notify.Data...), true, nil
}

func ikeSAInitNotifyError(payloads []ike.Payload) error {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok || notify.NotifyType >= notifyTypeStatusMin || notify.NotifyType == notifyTypeInvalidKEPayload {
			continue
		}
		return fmt.Errorf("parsing ike_sa_init response: received %s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType)
	}
	return nil
}

func ikeSAInitNATDetection(payloads []ike.Payload, initiatorSPI, responderSPI uint64, local, remote *net.UDPAddr) (bool, bool, error) {
	natSources, natDest, err := ikeSAInitNATDetectionPayloads(payloads)
	if err != nil {
		return false, false, err
	}
	if len(natSources) == 0 && natDest == nil {
		return false, false, nil
	}
	if len(natSources) == 0 || natDest == nil {
		return false, false, errors.New("parsing ike_sa_init response: missing source or destination NAT detection notification")
	}
	for _, source := range natSources {
		if len(source.Data) != sha1.Size {
			return false, false, fmt.Errorf("parsing ike_sa_init response: invalid NAT_DETECTION_SOURCE_IP length %d", len(source.Data))
		}
	}
	if len(natDest.Data) != sha1.Size {
		return false, false, fmt.Errorf("parsing ike_sa_init response: invalid NAT_DETECTION_DESTINATION_IP length %d", len(natDest.Data))
	}
	expectedLocal := natDetectionHash(initiatorSPI, responderSPI, local)
	localNATDetected := !slices.Equal(expectedLocal[:], natDest.Data)
	expectedRemote := natDetectionHash(initiatorSPI, responderSPI, remote)
	remoteNATDetected := true
	for _, source := range natSources {
		if slices.Equal(expectedRemote[:], source.Data) {
			remoteNATDetected = false
			break
		}
	}
	return true, localNATDetected || remoteNATDetected, nil
}

func ikeSAInitNATDetectionPayloads(payloads []ike.Payload) ([]*ike.NotifyPayload, *ike.NotifyPayload, error) {
	var natSources []*ike.NotifyPayload
	var natDest *ike.NotifyPayload
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok {
			continue
		}
		switch notify.NotifyType {
		case notifyTypeNATDetectionSourceIP:
			natSources = append(natSources, notify)
		case notifyTypeNATDetectionDestIP:
			if natDest != nil {
				return nil, nil, errors.New("parsing ike_sa_init response: multiple NAT_DETECTION_DESTINATION_IP notifications")
			}
			natDest = notify
		}
	}
	return natSources, natDest, nil
}

func negotiatedIKESAFromProposal(proposal ike.Proposal, dhGroup uint16) (negotiatedIKESA, error) {
	if proposal.ProtocolID != proposalProtocolIKE {
		return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: invalid protocol id %d", proposal.ProtocolID)
	}
	parsed := negotiatedIKESA{}
	negotiatedDH := uint16(0)
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if parsed.Encryption != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate encryption transform")
			}
			parsed.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						parsed.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			if parsed.Integrity != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate integrity transform")
			}
			parsed.Integrity = transform.ID
		case transformTypePRF:
			if parsed.PRF != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate prf transform")
			}
			parsed.PRF = transform.ID
		case transformTypeDH:
			if negotiatedDH != 0 {
				return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: duplicate dh transform")
			}
			negotiatedDH = transform.ID
		default:
			return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: unsupported transform type %d", transform.TransformType)
		}
	}
	if parsed.Encryption == 0 || parsed.EncryptionKeyLen == 0 || parsed.Integrity == 0 || parsed.PRF == 0 {
		return negotiatedIKESA{}, errors.New("parsing negotiated ike proposal: transform is incomplete")
	}
	if negotiatedDH != dhGroup {
		return negotiatedIKESA{}, fmt.Errorf("parsing negotiated ike proposal: dh group %d does not match ke group %d", negotiatedDH, dhGroup)
	}
	return parsed, nil
}

func tunnelInfoFromChildSA(payloads []ike.Payload, cfg handshake.Config, requestProposals []ike.Proposal) (Info, error) {
	config, proposal, tsi, tsr, err := childSAConfig(payloads, requestProposals)
	if err != nil {
		return Info{}, err
	}
	tunnel, err := tunnelInfoFromProposal(proposal)
	if err != nil {
		return Info{}, err
	}
	tunnel.InitiatorTrafficSelectors = cloneTrafficSelectors(tsi.Selectors)
	tunnel.ResponderTrafficSelectors = cloneTrafficSelectors(tsr.Selectors)
	if err := applyTunnelAddresses(&tunnel, *config, cfg); err != nil {
		return Info{}, err
	}
	if err := applyN1ModeInfo(&tunnel, payloads, cfg); err != nil {
		return Info{}, err
	}
	return tunnel, nil
}

func applyN1ModeInfo(tunnel *Info, payloads []ike.Payload, cfg handshake.Config) error {
	if cfg.PDUSessionID == 0 {
		return nil
	}
	tunnel.PDUSessionID = cfg.PDUSessionID
	if notify := ike.FindNotifyPayload(payloads, notifyTypeN1ModeInformation); notify != nil {
		var data n1ModeInformationNotifyData
		if err := data.UnmarshalBinary(notify.Data); err != nil {
			return err
		}
		tunnel.SNSSAI = data.SNSSAI
	}
	if notify := ike.FindNotifyPayload(payloads, notifyTypeN1ModeSNSSAIPlmnID); notify != nil {
		var data n1ModeSNSSAIPlmnIDNotifyData
		if err := data.UnmarshalBinary(notify.Data); err != nil {
			return err
		}
		tunnel.SNSSAIPlmnID = data.PLMNID
	}
	return nil
}

func childSAConfig(payloads []ike.Payload, requestProposals []ike.Proposal) (*ike.ConfigPayload, ike.Proposal, *ike.TrafficSelectorPayload, *ike.TrafficSelectorPayload, error) {
	config := ike.FindConfigPayload(payloads)
	sa := ike.FindSAPayload(payloads)
	if config == nil || sa == nil {
		return nil, ike.Proposal{}, nil, nil, errors.New("parsing ike_auth response: missing child sa or configuration")
	}
	if config.ConfigType != configTypeReply {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: unexpected configuration type %d", config.ConfigType)
	}
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsr := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr)
	if tsi == nil || tsr == nil {
		return nil, ike.Proposal{}, nil, nil, errors.New("parsing ike_auth response: missing traffic selectors")
	}
	if len(sa.Proposals) != 1 {
		return nil, ike.Proposal{}, nil, nil, fmt.Errorf("parsing ike_auth response: negotiated proposal count %d", len(sa.Proposals))
	}
	if err := validateNegotiatedProposalFromRequests("parsing ike_auth response", sa.Proposals[0], requestProposals); err != nil {
		return nil, ike.Proposal{}, nil, nil, err
	}
	proposal, err := negotiatedChildSAProposal("parsing ike_auth response", sa.Proposals[0], 0)
	if err != nil {
		return nil, ike.Proposal{}, nil, nil, err
	}
	return config, proposal, tsi, tsr, nil
}

func negotiatedChildSAProposal(action string, proposal ike.Proposal, dhGroup uint16) (ike.Proposal, error) {
	if proposal.ProtocolID != proposalProtocolESP {
		return ike.Proposal{}, fmt.Errorf("%s: invalid negotiated protocol id %d", action, proposal.ProtocolID)
	}
	seenENCR := false
	seenINTEG := false
	seenESN := false
	seenDH := false
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if seenENCR {
				return ike.Proposal{}, fmt.Errorf("%s: duplicate encryption transform", action)
			}
			seenENCR = true
		case transformTypeINTEG:
			if seenINTEG {
				return ike.Proposal{}, fmt.Errorf("%s: duplicate integrity transform", action)
			}
			seenINTEG = true
		case transformTypeESN:
			if seenESN {
				return ike.Proposal{}, fmt.Errorf("%s: duplicate esn transform", action)
			}
			if transform.ID != transformESNNoESN {
				return ike.Proposal{}, fmt.Errorf("%s: unsupported esn transform %d", action, transform.ID)
			}
			seenESN = true
		case transformTypeDH:
			if seenDH {
				return ike.Proposal{}, fmt.Errorf("%s: duplicate dh transform", action)
			}
			if dhGroup == 0 {
				return ike.Proposal{}, fmt.Errorf("%s: unexpected dh group %d", action, transform.ID)
			}
			if transform.ID != dhGroup {
				return ike.Proposal{}, fmt.Errorf("%s: dh group = %d, want %d", action, transform.ID, dhGroup)
			}
			seenDH = true
		default:
			return ike.Proposal{}, fmt.Errorf("%s: unsupported negotiated transform type %d", action, transform.TransformType)
		}
	}
	if !seenENCR || !seenINTEG || !seenESN {
		return ike.Proposal{}, fmt.Errorf("%s: negotiated esp transform is incomplete", action)
	}
	if dhGroup != 0 && !seenDH {
		return ike.Proposal{}, fmt.Errorf("%s: dh group = 0, want %d", action, dhGroup)
	}
	return proposal, nil
}

func tunnelInfoFromProposal(proposal ike.Proposal) (Info, error) {
	tunnel := Info{}
	if len(proposal.SPI) != 4 {
		return Info{}, fmt.Errorf("parsing ike_auth response: invalid responder esp spi length %d", len(proposal.SPI))
	}
	tunnel.ESPResponderSPI = binary.BigEndian.Uint32(proposal.SPI)
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if transform.ID != transformENCRAESCBC {
				return Info{}, fmt.Errorf("parsing ike_auth response: unsupported encryption transform %d", transform.ID)
			}
			tunnel.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						tunnel.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			tunnel.Integrity = transform.ID
		}
	}
	if tunnel.Encryption == 0 || tunnel.EncryptionKeyLen == 0 || tunnel.Integrity == 0 {
		return Info{}, errors.New("parsing ike_auth response: negotiated esp transform is incomplete")
	}
	return tunnel, nil
}

func applyTunnelAddresses(tunnel *Info, config ike.ConfigPayload, cfg handshake.Config) error {
	addresses := tunnelAddresses(config.Attributes, cfg.PCSCFIPv4ConfigAttribute, cfg.PCSCFIPv6ConfigAttribute)
	switch {
	case addresses.internalIPv6 != nil && len(addresses.pcscfIPv6) != 0:
		tunnel.InnerIP = addresses.internalIPv6
		tunnel.PCSCFIP = append(net.IP(nil), addresses.pcscfIPv6[0]...)
		tunnel.PCSCFIPs = cloneIPList(addresses.pcscfIPv6)
	case addresses.internalIPv4 != nil && len(addresses.pcscfIPv4) != 0:
		tunnel.InnerIP = addresses.internalIPv4
		tunnel.PCSCFIP = append(net.IP(nil), addresses.pcscfIPv4[0]...)
		tunnel.PCSCFIPs = cloneIPList(addresses.pcscfIPv4)
	default:
		return errors.New("parsing ike_auth response: p-cscf and internal ip families do not match")
	}
	return nil
}

type tunnelAddressSet struct {
	internalIPv4 net.IP
	internalIPv6 net.IP
	pcscfIPv4    []net.IP
	pcscfIPv6    []net.IP
}

const (
	configAttrInternalIPv6AddressLen = net.IPv6len + 1
	configAttrInternalIPv6SubnetLen  = net.IPv6len + 1
)

func tunnelAddresses(attrs []ike.Attribute, pcscfIPv4Attr, pcscfIPv6Attr uint16) tunnelAddressSet {
	if pcscfIPv4Attr == 0 {
		pcscfIPv4Attr = configAttrPCSCFIPv4Address
	}
	if pcscfIPv6Attr == 0 {
		pcscfIPv6Attr = configAttrPCSCFIPv6Address
	}
	var addresses tunnelAddressSet
	for _, attr := range attrs {
		switch attr.Type {
		case configAttrInternalIPv4Address:
			if len(attr.Value) == net.IPv4len {
				addresses.internalIPv4 = append(net.IP(nil), attr.Value...)
			}
		case configAttrInternalIPv6Address:
			if len(attr.Value) == configAttrInternalIPv6AddressLen {
				addresses.internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		case configAttrInternalIPv6Subnet:
			if addresses.internalIPv6 == nil && len(attr.Value) == configAttrInternalIPv6SubnetLen {
				addresses.internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		}

		matchesPCSCFIPv4 := attr.Type == pcscfIPv4Attr || attr.Type == configAttrPCSCFIPv4Address
		matchesPCSCFIPv6 := attr.Type == pcscfIPv6Attr || attr.Type == configAttrPCSCFIPv6Address
		switch {
		case matchesPCSCFIPv4 && matchesPCSCFIPv6 && len(attr.Value) == net.IPv6len:
			addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, attr.Value)
		case matchesPCSCFIPv4:
			if len(attr.Value) == net.IPv4len {
				addresses.pcscfIPv4 = appendUniqueIP(addresses.pcscfIPv4, attr.Value)
			}
		case matchesPCSCFIPv6:
			if len(attr.Value) == net.IPv6len {
				addresses.pcscfIPv6 = appendUniqueIP(addresses.pcscfIPv6, attr.Value)
			}
		}
	}
	return addresses
}

func appendUniqueIP(ips []net.IP, ip net.IP) []net.IP {
	for _, existing := range ips {
		if existing.Equal(ip) {
			return ips
		}
	}
	return append(ips, append(net.IP(nil), ip...))
}

func ikeSAProposals(cfg handshake.Config, dhGroup uint16) []ike.Proposal {
	keyLens := uint16ValuesOrDefault(cfg.IKEEncryptionKeyLens, defaultEncryptionKeyLens)
	integrity := uint16ValuesOrDefault(cfg.IKEIntegrity, defaultIKEIntegrity)
	prfs := uint16ValuesOrDefault(cfg.IKEPRF, defaultIKEPRF)
	proposals := make([]ike.Proposal, 0, len(keyLens)*len(integrity)*len(prfs))
	for _, keyLen := range keyLens {
		for _, integ := range integrity {
			for _, prf := range prfs {
				proposals = append(proposals, ike.Proposal{
					Number:     byte(len(proposals) + 1),
					ProtocolID: proposalProtocolIKE,
					Transforms: []ike.Transform{
						aesCBCTransform(keyLen),
						{TransformType: transformTypeINTEG, ID: integ},
						{TransformType: transformTypePRF, ID: prf},
						{TransformType: transformTypeDH, ID: dhGroup},
					},
				})
			}
		}
	}
	return proposals
}

func childSAProposals(cfg handshake.Config, espSPI uint32) []ike.Proposal {
	return childSAProposalsWithDH(cfg, espSPI, 0)
}

func childSAProposalsWithDH(cfg handshake.Config, espSPI uint32, dhGroup uint16) []ike.Proposal {
	keyLens := uint16ValuesOrDefault(cfg.ChildEncryptionKeyLens, defaultEncryptionKeyLens)
	integrity := uint16ValuesOrDefault(cfg.ChildIntegrity, defaultChildIntegrity)
	proposals := make([]ike.Proposal, 0, len(keyLens)*len(integrity))
	for _, keyLen := range keyLens {
		for _, integ := range integrity {
			transforms := []ike.Transform{
				aesCBCTransform(keyLen),
				{TransformType: transformTypeINTEG, ID: integ},
			}
			if dhGroup != 0 {
				transforms = append(transforms, ike.Transform{TransformType: transformTypeDH, ID: dhGroup})
			}
			transforms = append(transforms, ike.Transform{TransformType: transformTypeESN, ID: transformESNNoESN})
			proposals = append(proposals, ike.Proposal{
				Number:     byte(len(proposals) + 1),
				ProtocolID: proposalProtocolESP,
				SPI:        uint32Bytes(espSPI),
				Transforms: transforms,
			})
		}
	}
	return proposals
}

func aesCBCTransform(keyLen uint16) ike.Transform {
	return ike.Transform{
		TransformType: transformTypeENCR,
		ID:            transformENCRAESCBC,
		Attributes:    []ike.Attribute{ike.NewTVAttribute(transformAttrKeyLength, keyLen)},
	}
}

func uint16ValuesOrDefault(values, defaults []uint16) []uint16 {
	if len(values) == 0 {
		return defaults
	}
	return values
}

func defaultIKESAInitPayloads(cfg handshake.Config, crypto *ikeCrypto, local, remote *net.UDPAddr) []ike.Payload {
	proposals := ikeSAProposals(cfg, crypto.dhGroup)
	natSourceHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, local)
	natDestHash := natDetectionHash(crypto.initiatorSPI, crypto.responderSPI, remote)
	return []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: proposals},
		&ike.KeyExchangePayload{DHGroup: crypto.dhGroup, Data: crypto.PublicKey()},
		&ike.NoncePayload{Data: append([]byte(nil), crypto.nonceI...)},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeNATDetectionSourceIP, Data: natSourceHash[:]},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeNATDetectionDestIP, Data: natDestHash[:]},
	}
}

func defaultIKEAuthInitPayloads(cfg handshake.Config, identity string, espSPI uint32) ([]ike.Payload, error) {
	if identity == "" {
		return nil, errors.New("identity is empty")
	}
	apn := strings.TrimSpace(cfg.APN)
	if apn == "" {
		apn = DefaultAPN
	}
	childSA := &ike.SecurityAssociationPayload{Proposals: childSAProposals(cfg, espSPI)}
	config := &ike.ConfigPayload{ConfigType: configTypeRequest, Attributes: []ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv4Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv4DNS, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6DNS, nil),
		ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
	}}
	for _, attr := range pcscfRequestAttributes(cfg) {
		config.Attributes = append(config.Attributes, ike.NewTLVAttribute(attr, nil))
	}
	selectors := ike.TrafficSelectorsAny()
	payloads := []ike.Payload{
		&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(identity)},
		&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte(apn)},
		config,
		childSA,
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: selectors},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: selectors},
		&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeEAPOnlyAuthentication},
	}
	if cfg.PCSCFRestoration {
		payloads = append(payloads, &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypePCSCFReselectionSupport})
	}
	if cfg.PDUSessionID != 0 {
		data, err := (n1ModeCapabilityNotifyData{PDUSessionID: cfg.PDUSessionID}).MarshalBinary()
		if err != nil {
			return nil, err
		}
		payloads = append(payloads, &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeN1ModeCapability, Data: data})
	}
	return payloads, nil
}

func pcscfConfigAttributes(cfg handshake.Config) (uint16, uint16) {
	pcscfIPv4Attr := cfg.PCSCFIPv4ConfigAttribute
	if pcscfIPv4Attr == 0 {
		pcscfIPv4Attr = configAttrPCSCFIPv4Address
	}
	pcscfIPv6Attr := cfg.PCSCFIPv6ConfigAttribute
	if pcscfIPv6Attr == 0 {
		pcscfIPv6Attr = configAttrPCSCFIPv6Address
	}
	return pcscfIPv4Attr, pcscfIPv6Attr
}

func pcscfRequestAttributes(cfg handshake.Config) []uint16 {
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(cfg)
	candidates := []uint16{
		pcscfIPv4Attr,
		pcscfIPv6Attr,
		configAttrPCSCFIPv4Address,
		configAttrPCSCFIPv6Address,
	}

	attrs := make([]uint16, 0, len(candidates))
	for _, candidate := range candidates {
		if slices.Contains(attrs, candidate) {
			continue
		}
		attrs = append(attrs, candidate)
	}
	return attrs
}

func resolveOuterLocalAddr(conn net.PacketConn, remote *net.UDPAddr) (*net.UDPAddr, error) {
	if conn == nil {
		return nil, errors.New("resolving outer local addr: conn is nil")
	}
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("resolving outer local addr: local addr has type %T", conn.LocalAddr())
	}
	resolved := cloneUDPAddr(local)
	if resolved != nil && resolved.IP != nil && !resolved.IP.IsUnspecified() {
		return resolved, nil
	}
	if remote == nil {
		return resolved, nil
	}
	discovered, err := discoverOutboundIP(remote)
	if err != nil {
		return resolved, fmt.Errorf("resolving outer local addr: discovering outbound ip: %w", err)
	}
	if len(discovered) == 0 {
		return resolved, nil
	}
	resolved.IP = discovered
	return resolved, nil
}

func discoverOutboundIP(remote *net.UDPAddr) (net.IP, error) {
	if remote == nil {
		return nil, nil
	}
	conn, err := net.DialUDP("udp", nil, remote)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || local == nil {
		return nil, nil
	}
	return append(net.IP(nil), local.IP...), nil
}

func natDetectionHash(initiatorSPI, responderSPI uint64, addr *net.UDPAddr) [sha1.Size]byte {
	seed := make([]byte, ikeSPISeedLength)
	binary.BigEndian.PutUint64(seed[0:8], initiatorSPI)
	binary.BigEndian.PutUint64(seed[8:16], responderSPI)
	if addr != nil {
		ip := addr.IP
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		} else {
			ip = ip.To16()
		}
		if len(ip) != 0 {
			seed = append(seed, ip...)
			seed = append(seed, byte(addr.Port>>8), byte(addr.Port))
		}
	}
	return sha1.Sum(seed)
}

func uint32Bytes(value uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)
	return buf
}

func integrityName(transform uint16) string {
	switch transform {
	case transformINTEGHMACMD596:
		return esp.IntegrityHMACMD596
	case transformINTEGHMACSHA196:
		return esp.IntegrityHMACSHA196
	case transformINTEGHMACSHA256:
		return esp.IntegrityHMACSHA256128
	default:
		return esp.IntegrityNone
	}
}

func randomUint64() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := crand.Read(buf); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(buf), nil
}

func randomUint32() (uint32, error) {
	buf := make([]byte, 4)
	if _, err := crand.Read(buf); err != nil {
		return 0, err
	}
	value := binary.BigEndian.Uint32(buf)
	if value == 0 {
		value = 1
	}
	return value, nil
}

func randomBytes(n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := crand.Read(buf)
	return buf, err
}
