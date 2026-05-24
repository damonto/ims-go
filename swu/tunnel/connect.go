package tunnel

import (
	"context"
	crand "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-client/swu/esp"
	"github.com/damonto/ims-client/swu/handshake"
	"github.com/damonto/ims-client/swu/ike"
	"github.com/damonto/ims-client/usim"
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
	responderNonce  []byte
	nextMessageID   uint32
	finalPayloads   []ike.Payload
	tunnel          Info
	espKeys         ESPKeys
}

func (s *Session) Connect(ctx context.Context, imei string, card Card) error {
	ctx = normalizeContext(ctx)
	state, finish, err := s.prepareConnect(imei, card)
	if err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	defer finish()
	if err := s.exchangeIKESAInit(ctx, state); err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	if err := s.exchangeIKEAuth(ctx, state); err != nil {
		return fmt.Errorf("connecting swu session: %w", err)
	}
	s.commitConnect(state)
	s.startBackgroundLoops()
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
	if err := s.disconnectedTunnelErrLocked(); err != nil {
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
	nonceI, err := randomBytes(32)
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
	nonceI, err := randomBytes(32)
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

func (state *connectState) applyIKESAInitResponse(response ike.IKEPacket, request []byte) error {
	if response.Header.ResponderSPI == 0 {
		return errors.New("responder spi is empty")
	}
	proposal, responderNonce, responderKE, err := negotiatedIKESAFromPayloads(response.Payloads, state.crypto.dhGroup)
	if err != nil {
		return err
	}
	state.crypto.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	state.crypto.SetSPIs(state.initiatorSPI, response.Header.ResponderSPI)
	state.crypto.SetNonces(state.nonceI, responderNonce)
	if err := state.crypto.DeriveIKEKeys(responderKE); err != nil {
		return fmt.Errorf("deriving ike keys: %w", err)
	}
	state.responderSPI = response.Header.ResponderSPI
	state.ikeInitRequest = append([]byte(nil), request...)
	state.responderNonce = append([]byte(nil), responderNonce...)
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
		responseRaw, _, err := s.exchangeIKE(ctx, s.outerRemote, request, false, 0)
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
			if cookieRetries > 4 {
				return errors.New("parsing ike_sa_init response: too many COOKIE retries")
			}
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
			return state.applyIKESAInitResponse(response, request)
		}
		if _, ok := triedGroups[group]; ok {
			return fmt.Errorf("parsing ike_sa_init response: repeated INVALID_KE_PAYLOAD group %d", group)
		}
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
	finalPayloads, nextMessageID, err := s.authenticateEAPAKA(ctx, state.card, state.imei, state.identity, state.realm, state.initialAKAState, state.crypto, state.initiatorSPI, state.responderSPI, state.ikeInitRequest, state.responderNonce, idiData, challengePayloads)
	if err != nil {
		return err
	}
	return finalizeIKEAuthState(state, finalPayloads, nextMessageID)
}

func buildIKEAuthRequest(state *connectState) ([]byte, []byte, error) {
	idi := (&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(state.identity)}).RawData()
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
	tunnel, err := tunnelInfoFromChildSA(finalPayloads, state.input.Config)
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
	return esp.Codec{
		SPI:           state.tunnel.ESPResponderSPI,
		Encryption:    esp.EncryptionAESCBC,
		Integrity:     integrityName(state.tunnel.Integrity),
		EncryptionKey: append([]byte(nil), state.espKeys.EncryptionInitiator...),
		IntegrityKey:  append([]byte(nil), state.espKeys.IntegrityInitiator...),
	}
}

func (state *connectState) inboundESPCodec() esp.Codec {
	return esp.Codec{
		SPI:           state.tunnel.ESPInitiatorSPI,
		Encryption:    esp.EncryptionAESCBC,
		Integrity:     integrityName(state.tunnel.Integrity),
		EncryptionKey: append([]byte(nil), state.espKeys.EncryptionResponder...),
		IntegrityKey:  append([]byte(nil), state.espKeys.IntegrityResponder...),
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
	if timeout <= 0 {
		return 60 * time.Second
	}
	return timeout
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

func negotiatedIKESAFromPayloads(payloads []ike.Payload, dhGroup uint16) (negotiatedIKESA, []byte, []byte, error) {
	nonce := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	ke := ike.FindKEPayload(payloads, dhGroup)
	if nonce == nil || sa == nil || ke == nil {
		return negotiatedIKESA{}, nil, nil, errors.New("parsing ike_sa_init response: required payload is missing")
	}
	if len(sa.Proposals) == 0 {
		return negotiatedIKESA{}, nil, nil, errors.New("parsing ike_sa_init response: security association is empty")
	}
	proposal, err := negotiatedIKESAFromProposal(sa.Proposals[0])
	if err != nil {
		return negotiatedIKESA{}, nil, nil, err
	}
	return proposal, nonce.Data, ke.Data, nil
}

func invalidKEPayloadGroup(payloads []ike.Payload) (uint16, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeInvalidKEPayload)
	if notify == nil {
		return 0, false, nil
	}
	if len(notify.Data) != 2 {
		return 0, false, fmt.Errorf("parsing ike_sa_init response: invalid INVALID_KE_PAYLOAD length %d", len(notify.Data))
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
	if len(notify.Data) == 0 || len(notify.Data) > 64 {
		return nil, false, fmt.Errorf("parsing ike_sa_init response: invalid COOKIE length %d", len(notify.Data))
	}
	return append([]byte(nil), notify.Data...), true, nil
}

func ikeSAInitNotifyError(payloads []ike.Payload) error {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok || notify.NotifyType >= 16384 || notify.NotifyType == notifyTypeInvalidKEPayload {
			continue
		}
		return fmt.Errorf("parsing ike_sa_init response: received %s (%d)", ikeNotifyName(notify.NotifyType), notify.NotifyType)
	}
	return nil
}

func negotiatedIKESAFromProposal(proposal ike.Proposal) (negotiatedIKESA, error) {
	parsed := negotiatedIKESA{}
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			parsed.Encryption = transform.ID
			for _, attr := range transform.Attributes {
				if attr.Type == transformAttrKeyLength {
					if value, ok := attr.Uint16(); ok {
						parsed.EncryptionKeyLen = value
					}
				}
			}
		case transformTypeINTEG:
			parsed.Integrity = transform.ID
		case transformTypePRF:
			parsed.PRF = transform.ID
		}
	}
	if parsed.Encryption == 0 || parsed.EncryptionKeyLen == 0 || parsed.Integrity == 0 || parsed.PRF == 0 {
		return negotiatedIKESA{}, errors.New("parsing ike_sa_init response: negotiated transform is incomplete")
	}
	return parsed, nil
}

func tunnelInfoFromChildSA(payloads []ike.Payload, cfg handshake.Config) (Info, error) {
	config, proposal, err := childSAConfig(payloads)
	if err != nil {
		return Info{}, err
	}
	tunnel, err := tunnelInfoFromProposal(proposal)
	if err != nil {
		return Info{}, err
	}
	if err := applyTunnelAddresses(&tunnel, config, cfg); err != nil {
		return Info{}, err
	}
	return tunnel, nil
}

func childSAConfig(payloads []ike.Payload) (*ike.ConfigPayload, ike.Proposal, error) {
	config := ike.FindConfigPayload(payloads)
	sa := ike.FindSAPayload(payloads)
	if config == nil || sa == nil || len(sa.Proposals) == 0 {
		return nil, ike.Proposal{}, errors.New("parsing ike_auth response: missing child sa or configuration")
	}
	return config, sa.Proposals[0], nil
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

func applyTunnelAddresses(tunnel *Info, config *ike.ConfigPayload, cfg handshake.Config) error {
	if tunnel == nil || config == nil {
		return errors.New("parsing ike_auth response: missing child sa or configuration")
	}
	internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6 := tunnelAddresses(config.Attributes, cfg.PCSCFIPv4ConfigAttribute, cfg.PCSCFIPv6ConfigAttribute)
	switch {
	case internalIPv6 != nil && pcscfIPv6 != nil:
		tunnel.InnerIP = internalIPv6
		tunnel.PCSCFIP = pcscfIPv6
	case internalIPv4 != nil && pcscfIPv4 != nil:
		tunnel.InnerIP = internalIPv4
		tunnel.PCSCFIP = pcscfIPv4
	default:
		return errors.New("parsing ike_auth response: p-cscf and internal ip families do not match")
	}
	return nil
}

func tunnelAddresses(attrs []ike.Attribute, pcscfIPv4Attr, pcscfIPv6Attr uint16) (internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6 net.IP) {
	if pcscfIPv4Attr == 0 {
		pcscfIPv4Attr = configAttrPCSCFIPv4Address
	}
	if pcscfIPv6Attr == 0 {
		pcscfIPv6Attr = configAttrPCSCFIPv6Address
	}
	for _, attr := range attrs {
		switch attr.Type {
		case configAttrInternalIPv4Address:
			if len(attr.Value) >= net.IPv4len {
				internalIPv4 = append(net.IP(nil), attr.Value[:net.IPv4len]...)
			}
		case configAttrInternalIPv6Address:
			if len(attr.Value) >= net.IPv6len {
				internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		case configAttrInternalIPv6Subnet:
			if internalIPv6 == nil && len(attr.Value) >= net.IPv6len {
				internalIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		case pcscfIPv4Attr:
			if pcscfIPv4 == nil && len(attr.Value) >= net.IPv4len {
				pcscfIPv4 = append(net.IP(nil), attr.Value[:net.IPv4len]...)
			}
		case pcscfIPv6Attr:
			if pcscfIPv6 == nil && len(attr.Value) >= net.IPv6len {
				pcscfIPv6 = append(net.IP(nil), attr.Value[:net.IPv6len]...)
			}
		}
	}
	return internalIPv4, internalIPv6, pcscfIPv4, pcscfIPv6
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
	keyLens := uint16ValuesOrDefault(cfg.ChildEncryptionKeyLens, defaultEncryptionKeyLens)
	integrity := uint16ValuesOrDefault(cfg.ChildIntegrity, defaultChildIntegrity)
	proposals := make([]ike.Proposal, 0, len(keyLens)*len(integrity))
	for _, keyLen := range keyLens {
		for _, integ := range integrity {
			proposals = append(proposals, ike.Proposal{
				ProtocolID: proposalProtocolESP,
				SPI:        uint32Bytes(espSPI),
				Transforms: []ike.Transform{
					aesCBCTransform(keyLen),
					{TransformType: transformTypeINTEG, ID: integ},
					{TransformType: transformTypeESN, ID: 0},
				},
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
		&ike.NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeNATDetectionSourceIP, Data: natSourceHash[:]},
		&ike.NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeNATDetectionDestIP, Data: natDestHash[:]},
	}
}

func defaultIKEAuthInitPayloads(cfg handshake.Config, identity string, espSPI uint32) ([]ike.Payload, error) {
	childSA := &ike.SecurityAssociationPayload{Proposals: childSAProposals(cfg, espSPI)}
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(cfg)
	config := &ike.ConfigPayload{ConfigType: configTypeRequest, Attributes: []ike.Attribute{
		ike.NewTLVAttribute(configAttrInternalIPv4Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv4DNS, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6Address, nil),
		ike.NewTLVAttribute(configAttrInternalIPv6DNS, nil),
		ike.NewTLVAttribute(pcscfIPv4Attr, nil),
		ike.NewTLVAttribute(pcscfIPv6Attr, nil),
		ike.NewTLVAttribute(configAttrTimeoutPeriodForLivenessCheck, nil),
	}}
	selectors := ike.TrafficSelectorsAny()
	return []ike.Payload{
		&ike.IDPayload{Tag: payloadTypeIDi, IDType: idTypeRFC822Addr, Data: []byte(identity)},
		&ike.IDPayload{Tag: payloadTypeIDr, IDType: idTypeFQDN, Data: []byte("ims")},
		config,
		childSA,
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: selectors},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: selectors},
		&ike.NotifyPayload{ProtocolID: 0, NotifyType: notifyTypeEAPOnlyAuthentication},
	}, nil
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

func natDetectionHash(initiatorSPI, responderSPI uint64, addr *net.UDPAddr) [20]byte {
	seed := make([]byte, 16)
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
