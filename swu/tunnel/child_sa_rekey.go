package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/damonto/ims-go/swu/esp"
	"github.com/damonto/ims-go/swu/handshake"
	"github.com/damonto/ims-go/swu/ike"
)

var (
	errChildSARekeyInProgress = errors.New("child sa rekey already in progress")
	errChildSANotFound        = errors.New("child sa not found")
	errIKETemporaryFailure    = errors.New("ike temporary failure")
)

type childSARekeyState struct {
	connected                 bool
	ike                       *ikeCrypto
	cfg                       handshake.Config
	info                      Info
	initiatorSPI              uint64
	responderSPI              uint64
	peer                      *net.UDPAddr
	localInitiator            bool
	ikeFragmentationSupported bool
	useNATT                   bool
	inboundSPI                uint32
	outboundSPI               uint32
	addKE                     bool
}

type childSARekeyResult struct {
	info       Info
	keys       ESPKeys
	outbound   esp.Codec
	inbound    esp.Codec
	oldInbound uint32
	nonceI     []byte
	nonceR     []byte
}

type childAssociation struct {
	outboundESP         esp.Codec
	inboundESP          esp.Codec
	espSeq              uint32
	inboundReplay       esp.ReplayWindow
	retiredChildSAs     []retiredChildSA
	pendingChildSA      pendingChildSA
	childSARekeying     bool
	simultaneousChildSA simultaneousChildSARekey
}

type retiredChildSA struct {
	inbound        esp.Codec
	info           Info
	outboundSPI    uint32
	replay         esp.ReplayWindow
	expiresAt      time.Time
	protectedBytes uint64
	byteExpiresAt  uint64
}

type pendingChildSA struct {
	ready      bool
	info       Info
	outbound   esp.Codec
	oldInbound uint32
}

type simultaneousChildSARekey struct {
	ready bool
	peer  childSARekeyResult
}

func (s *Session) RekeyChildSA(ctx context.Context) error {
	state, release, err := s.beginChildSARekey()
	if err != nil {
		return err
	}
	defer release()

	pfs, err := childSARekeyPFS(state)
	if err != nil {
		return err
	}
	result, err := s.initiatedChildSARekeyResult(ctx, state, pfs, s.exchangeInitiatedChildSARekey)
	if err != nil {
		if errors.Is(err, errChildSANotFound) {
			if s.childSANotFoundKnownSimultaneous() {
				return nil
			}
			return s.createChildSAReplacement(ctx, state)
		}
		return fmt.Errorf("rekeying child sa: %w", err)
	}
	decision := s.finishInitiatedChildSARekey(result)
	if decision.installLocal {
		s.installChildSecurityAssociations(result)
	}
	if decision.deleteSPI != 0 {
		if _, err := s.sendInformational(ctx, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDESP, SPIs: [][]byte{uint32Bytes(decision.deleteSPI)}}}); err != nil {
			s.logger.Debug("deleting child sa failed", "err", err, "inbound_spi", decision.deleteSPI)
		}
	}
	return nil
}

type childSARekeyExchange func(context.Context, childSARekeyState, uint32, []byte, *ikeCrypto) ([]ike.Payload, error)

func (s *Session) initiatedChildSARekeyResult(ctx context.Context, state childSARekeyState, pfs *ikeCrypto, exchange childSARekeyExchange) (childSARekeyResult, error) {
	triedGroups := childSARekeyTriedGroups(pfs)
	for {
		newInboundSPI, err := randomESPSPI()
		if err != nil {
			return childSARekeyResult{}, fmt.Errorf("generating child spi: %w", err)
		}
		nonceI, err := randomBytes(defaultIKENonceLength)
		if err != nil {
			return childSARekeyResult{}, fmt.Errorf("generating nonce: %w", err)
		}
		payloads, err := exchange(ctx, state, newInboundSPI, nonceI, pfs)
		if err != nil {
			return childSARekeyResult{}, err
		}
		group, retry, err := invalidKEPayloadGroupFor(payloads)
		if err != nil {
			return childSARekeyResult{}, fmt.Errorf("parsing create_child_sa response: %w", err)
		}
		if retry {
			if pfs == nil {
				return childSARekeyResult{}, errors.New("received INVALID_KE_PAYLOAD for child sa rekey without pfs")
			}
			if _, ok := triedGroups[group]; ok {
				return childSARekeyResult{}, fmt.Errorf("repeated INVALID_KE_PAYLOAD group %d", group)
			}
			next, err := newIKECrypto(group)
			if err != nil {
				return childSARekeyResult{}, fmt.Errorf("creating child pfs dh: %w", err)
			}
			pfs = next
			triedGroups[group] = struct{}{}
			continue
		}
		requestProposals := currentChildSARekeyProposals(state.info, newInboundSPI, childSARekeyDHGroup(pfs))
		return state.childSARekeyResult(payloads, newInboundSPI, nonceI, pfs, requestProposals)
	}
}

func childSARekeyTriedGroups(pfs *ikeCrypto) map[uint16]struct{} {
	if pfs == nil {
		return nil
	}
	return map[uint16]struct{}{pfs.dhGroup: {}}
}

func (s *Session) childSANotFoundKnownSimultaneous() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.simultaneousChildSA.ready
}

func (s *Session) exchangeInitiatedChildSARekey(ctx context.Context, state childSARekeyState, newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto) ([]ike.Payload, error) {
	releaseRequest, err := s.acquireIKERequest(ctx, ikeActionRekeyChildSA)
	if err != nil {
		return nil, err
	}
	defer releaseRequest()

	messageID, err := s.allocateMessageID()
	if err != nil {
		return nil, fmt.Errorf("rekeying child sa: %w", err)
	}
	key := ikeMessageKeyForSPIs(state.initiatorSPI, state.responderSPI, exchangeTypeCreateChildSA, ikeMessageFlags(!state.localInitiator, true), messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)

	wires, err := state.sealChildSARekeyRequest(messageID, newInboundSPI, nonceI, pfs)
	if err != nil {
		return nil, fmt.Errorf("rekeying child sa: %w", err)
	}
	return s.exchangeProtected(ctx, protectedExchange{
		action:          ikeActionRekeyChildSA,
		peer:            state.peer,
		crypto:          state.ike,
		senderInitiator: !state.localInitiator,
		messageID:       messageID,
		exchangeType:    exchangeTypeCreateChildSA,
		useNATT:         state.useNATT,
		wires:           wires,
		waiter:          waiter,
	})
}

func (s *Session) createChildSAReplacement(ctx context.Context, state childSARekeyState) error {
	newInboundSPI, err := randomESPSPI()
	if err != nil {
		return fmt.Errorf("creating child sa: generating child spi: %w", err)
	}
	nonceI, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return fmt.Errorf("creating child sa: generating nonce: %w", err)
	}
	payloads, err := s.exchangeInitiatedChildSACreate(ctx, state, newInboundSPI, nonceI)
	if err != nil {
		return err
	}
	result, err := state.childSARekeyResult(payloads, newInboundSPI, nonceI, nil, childSAProposals(state.cfg, newInboundSPI))
	if err != nil {
		return fmt.Errorf("creating child sa: %w", err)
	}
	s.installChildSecurityAssociations(result)
	return nil
}

func (s *Session) exchangeInitiatedChildSACreate(ctx context.Context, state childSARekeyState, newInboundSPI uint32, nonceI []byte) ([]ike.Payload, error) {
	releaseRequest, err := s.acquireIKERequest(ctx, ikeActionCreateChildSA)
	if err != nil {
		return nil, err
	}
	defer releaseRequest()

	messageID, err := s.allocateMessageID()
	if err != nil {
		return nil, fmt.Errorf("creating child sa: %w", err)
	}
	key := ikeMessageKeyForSPIs(state.initiatorSPI, state.responderSPI, exchangeTypeCreateChildSA, ikeMessageFlags(!state.localInitiator, true), messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)

	wires, err := state.sealChildSACreateRequest(messageID, newInboundSPI, nonceI)
	if err != nil {
		return nil, fmt.Errorf("creating child sa: %w", err)
	}
	return s.exchangeProtected(ctx, protectedExchange{
		action:          ikeActionCreateChildSA,
		peer:            state.peer,
		crypto:          state.ike,
		senderInitiator: !state.localInitiator,
		messageID:       messageID,
		exchangeType:    exchangeTypeCreateChildSA,
		useNATT:         state.useNATT,
		wires:           wires,
		waiter:          waiter,
	})
}

func (s *Session) beginChildSARekey() (childSARekeyState, func(), error) {
	if s.isClosed() {
		return childSARekeyState{}, nil, errors.New("rekeying child sa: session is closed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.ikeSAState(); state == ikeSAStateRekeying || state == ikeSAStatePendingInstall {
		return childSARekeyState{}, nil, errIKESARekeyInProgress
	}
	switch state := s.childSAState(); state {
	case childSAStateRekeying, childSAStatePendingOutbound:
		return childSARekeyState{}, nil, errChildSARekeyInProgress
	case childSAStateNone:
		if err := s.disconnectedTunnelErr(); err != nil {
			return childSARekeyState{}, nil, fmt.Errorf("rekeying child sa: %w", err)
		}
		return childSARekeyState{}, nil, errors.New("rekeying child sa: child sa is not established")
	}
	if s.ikeSAExpired(time.Now()) {
		return childSARekeyState{}, nil, fmt.Errorf("rekeying child sa: %w", errIKESAExpired)
	}
	if s.childSAExpired(time.Now()) {
		return childSARekeyState{}, nil, fmt.Errorf("rekeying child sa: %w", errChildSAExpired)
	}
	state := childSARekeyState{
		connected:                 s.connected,
		ike:                       s.ike,
		cfg:                       handshakeConfig(s.cfg),
		info:                      cloneInfo(s.tunnel),
		initiatorSPI:              s.initiatorSPI,
		responderSPI:              s.responderSPI,
		peer:                      outerIKEPeer(s.useNATT, s.outerRemote, s.outerNAT),
		localInitiator:            s.ikeLocalInitiator,
		ikeFragmentationSupported: s.ikeFragmentationSupported,
		useNATT:                   s.useNATT,
		inboundSPI:                s.tunnel.ESPInitiatorSPI,
		outboundSPI:               s.tunnel.ESPResponderSPI,
		addKE:                     s.cfg.AddKEToChildSARekey,
	}
	if !state.available() {
		return childSARekeyState{}, nil, errors.New("rekeying child sa: ike or child sa state is unavailable")
	}
	s.childSARekeying = true
	s.simultaneousChildSA = simultaneousChildSARekey{}
	return state, func() {
		s.mu.Lock()
		s.childSARekeying = false
		s.simultaneousChildSA = simultaneousChildSARekey{}
		s.mu.Unlock()
		s.notifyRekeyStateChanged()
	}, nil
}

func (state childSARekeyState) available() bool {
	return state.connected && state.ike != nil && state.peer != nil && state.inboundSPI != 0 && state.outboundSPI != 0
}

func (state childSARekeyState) sealChildSARekeyRequest(messageID, newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto) ([][]byte, error) {
	header := ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeCreateChildSA,
		Flags:        state.initiatorFlag(),
		MessageID:    messageID,
	}
	wires, err := sealIKEPackets(state.ike, header, state.childSARekeyRequestPayloads(newInboundSPI, nonceI, pfs), state.localInitiator, state.ikeFragmentationSupported)
	if err != nil {
		return nil, fmt.Errorf("sealing create_child_sa request: %w", err)
	}
	return wires, nil
}

func (state childSARekeyState) sealChildSACreateRequest(messageID, newInboundSPI uint32, nonceI []byte) ([][]byte, error) {
	header := ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeCreateChildSA,
		Flags:        state.initiatorFlag(),
		MessageID:    messageID,
	}
	wires, err := sealIKEPackets(state.ike, header, childSACreateRequestPayloads(state.cfg, newInboundSPI, nonceI), state.localInitiator, state.ikeFragmentationSupported)
	if err != nil {
		return nil, fmt.Errorf("sealing create_child_sa request: %w", err)
	}
	return wires, nil
}

func (state childSARekeyState) initiatorFlag() byte {
	if state.localInitiator {
		return flagInitiator
	}
	return 0
}

func childSACreateRequestPayloads(cfg handshake.Config, newInboundSPI uint32, nonceI []byte) []ike.Payload {
	selectors := ike.TrafficSelectorsAny()
	return []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: childSAProposals(cfg, newInboundSPI)},
		&ike.NoncePayload{Data: append([]byte(nil), nonceI...)},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: selectors},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: selectors},
	}
}

func childSARekeyRequestPayloads(cfg handshake.Config, oldInboundSPI, newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto) []ike.Payload {
	return childSARekeyRequestPayloadsWithProposals(oldInboundSPI, nonceI, pfs, childSAProposalsWithDH(cfg, newInboundSPI, childSARekeyDHGroup(pfs)))
}

func (state childSARekeyState) childSARekeyRequestPayloads(newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto) []ike.Payload {
	return childSARekeyRequestPayloadsWithTrafficSelectors(
		state.inboundSPI,
		nonceI,
		pfs,
		currentChildSARekeyProposals(state.info, newInboundSPI, childSARekeyDHGroup(pfs)),
		state.info.InitiatorTrafficSelectors,
		state.info.ResponderTrafficSelectors,
	)
}

func childSARekeyRequestPayloadsWithProposals(oldInboundSPI uint32, nonceI []byte, pfs *ikeCrypto, proposals []ike.Proposal) []ike.Payload {
	selectors := ike.TrafficSelectorsAny()
	return childSARekeyRequestPayloadsWithTrafficSelectors(oldInboundSPI, nonceI, pfs, proposals, selectors, selectors)
}

func childSARekeyRequestPayloadsWithTrafficSelectors(oldInboundSPI uint32, nonceI []byte, pfs *ikeCrypto, proposals []ike.Proposal, tsi, tsr []ike.TrafficSelector) []ike.Payload {
	payloads := []ike.Payload{
		&ike.NotifyPayload{ProtocolID: protocolIDESP, NotifyType: notifyTypeRekeySA, SPI: uint32Bytes(oldInboundSPI)},
		&ike.SecurityAssociationPayload{Proposals: proposals},
		&ike.NoncePayload{Data: append([]byte(nil), nonceI...)},
	}
	if pfs != nil {
		payloads = append(payloads, &ike.KeyExchangePayload{DHGroup: pfs.dhGroup, Data: pfs.PublicKey()})
	}
	payloads = append(payloads,
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: cloneTrafficSelectors(tsi)},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: cloneTrafficSelectors(tsr)},
	)
	return payloads
}

func currentChildSARekeyProposals(info Info, newInboundSPI uint32, dhGroup uint16) []ike.Proposal {
	return []ike.Proposal{childSAResponseProposal(acceptedChildSA{
		Info: Info{
			Encryption:       info.Encryption,
			EncryptionKeyLen: info.EncryptionKeyLen,
			Integrity:        info.Integrity,
		},
		DHGroup:        dhGroup,
		ProposalNumber: 1,
	}, newInboundSPI)}
}

func childSARekeyDHGroup(pfs *ikeCrypto) uint16 {
	if pfs == nil {
		return 0
	}
	return pfs.dhGroup
}

func childSARekeyPFS(state childSARekeyState) (*ikeCrypto, error) {
	if !state.addKE {
		return nil, nil
	}
	dhGroup := transformDH2048MODP
	if len(state.cfg.DHGroups) != 0 {
		dhGroup = state.cfg.DHGroups[0]
	}
	pfs, err := newIKECrypto(dhGroup)
	if err != nil {
		return nil, fmt.Errorf("rekeying child sa: creating child pfs dh: %w", err)
	}
	return pfs, nil
}

func (state childSARekeyState) childSARekeyResult(payloads []ike.Payload, newInboundSPI uint32, nonceI []byte, pfs *ikeCrypto, requestProposals []ike.Proposal) (childSARekeyResult, error) {
	dhGroup := childSARekeyDHGroup(pfs)
	info, nonceR, peerPublic, err := childSAFromCreateChildResponseWithRequests(payloads, state.info, newInboundSPI, dhGroup, requestProposals)
	if err != nil {
		return childSARekeyResult{}, err
	}
	var keys ESPKeys
	if pfs != nil {
		keys, err = state.ike.DeriveESPKeysWithDH(info.EncryptionKeyLen, info.Integrity, nonceI, nonceR, pfs, peerPublic)
	} else {
		keys, err = state.ike.DeriveESPKeysWithNonces(info.EncryptionKeyLen, info.Integrity, nonceI, nonceR)
	}
	if err != nil {
		return childSARekeyResult{}, fmt.Errorf("deriving esp keys: %w", err)
	}
	return childSARekeyResult{
		info:       info,
		keys:       keys,
		outbound:   outboundESPCodec(info, keys),
		inbound:    inboundESPCodec(info, keys),
		oldInbound: state.inboundSPI,
		nonceI:     append([]byte(nil), nonceI...),
		nonceR:     append([]byte(nil), nonceR...),
	}, nil
}

type childSARekeyDecision struct {
	installLocal bool
	deleteSPI    uint32
}

func (s *Session) finishInitiatedChildSARekey(result childSARekeyResult) childSARekeyDecision {
	s.mu.RLock()
	simultaneous := s.simultaneousChildSA
	s.mu.RUnlock()
	if !simultaneous.ready {
		return childSARekeyDecision{installLocal: true, deleteSPI: result.oldInbound}
	}
	if childSARekeyLocalCreatedSAWins(result, simultaneous.peer) {
		return childSARekeyDecision{installLocal: true, deleteSPI: result.oldInbound}
	}
	return childSARekeyDecision{deleteSPI: result.info.ESPInitiatorSPI}
}

func childSARekeyLocalCreatedSAWins(local, peer childSARekeyResult) bool {
	return lowestNonceBelongsToPeerExchange(local.nonceI, local.nonceR, peer.nonceI, peer.nonceR)
}

func lowestNonceBelongsToPeerExchange(localNonceI, localNonceR, peerNonceI, peerNonceR []byte) bool {
	lowest := localNonceI
	local := true
	for _, candidate := range []struct {
		nonce []byte
		local bool
	}{
		{nonce: localNonceR, local: true},
		{nonce: peerNonceI, local: false},
		{nonce: peerNonceR, local: false},
	} {
		if bytes.Compare(candidate.nonce, lowest) < 0 {
			lowest = candidate.nonce
			local = candidate.local
		}
	}
	return !local
}

func childSAFromCreateChildResponse(payloads []ike.Payload, previous Info, newInboundSPI uint32, dhGroup uint16) (Info, []byte, []byte, error) {
	return childSAFromCreateChildResponseWithRequests(payloads, previous, newInboundSPI, dhGroup, nil)
}

func childSAFromCreateChildResponseWithRequests(payloads []ike.Payload, previous Info, newInboundSPI uint32, dhGroup uint16, requestProposals []ike.Proposal) (Info, []byte, []byte, error) {
	if err := createChildSAResponseNotifyError(payloads); err != nil {
		return Info{}, nil, nil, err
	}
	nonce := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsr := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr)
	if nonce == nil || sa == nil || tsi == nil || tsr == nil {
		return Info{}, nil, nil, errors.New("parsing create_child_sa response: required payload is missing")
	}
	if err := validateNonceData(nonce.Data); err != nil {
		return Info{}, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	if err := validateRekeyTrafficSelectors(tsi.Selectors, tsr.Selectors, previous); err != nil {
		return Info{}, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	if len(sa.Proposals) != 1 {
		return Info{}, nil, nil, fmt.Errorf("parsing create_child_sa response: negotiated proposal count %d", len(sa.Proposals))
	}
	if err := validateNegotiatedProposalFromRequests(sa.Proposals[0], requestProposals); err != nil {
		return Info{}, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	proposal, err := negotiatedChildSAProposal(sa.Proposals[0], dhGroup)
	if err != nil {
		return Info{}, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	info, err := tunnelInfoFromProposal(proposal)
	if err != nil {
		return Info{}, nil, nil, err
	}
	if dhGroup == 0 {
		if ike.FindKEPayload(payloads, 0) != nil {
			return Info{}, nil, nil, errors.New("parsing create_child_sa response: unexpected key exchange payload")
		}
	}
	var peerPublic []byte
	if dhGroup != 0 {
		ke := ike.FindKEPayload(payloads, dhGroup)
		if ke == nil {
			return Info{}, nil, nil, errors.New("parsing create_child_sa response: key exchange payload is missing")
		}
		peerPublic = append([]byte(nil), ke.Data...)
	}
	info.InnerIPv4 = append(net.IP(nil), previous.InnerIPv4...)
	info.InnerIPv6 = cloneIPAddress(previous.InnerIPv6)
	info.InnerIPv6Prefix = cloneIPPrefix(previous.InnerIPv6Prefix)
	info.PDNTypeRestriction = previous.PDNTypeRestriction
	info.PCSCFIPs = cloneIPList(previous.PCSCFIPs)
	info.InitiatorTrafficSelectors = cloneTrafficSelectors(tsi.Selectors)
	info.ResponderTrafficSelectors = cloneTrafficSelectors(tsr.Selectors)
	info.ESPInitiatorSPI = newInboundSPI
	return info, append([]byte(nil), nonce.Data...), peerPublic, nil
}

func validateRekeyTrafficSelectors(tsi, tsr []ike.TrafficSelector, current Info) error {
	if len(current.InitiatorTrafficSelectors) != 0 && !trafficSelectorsContainAll(tsi, current.InitiatorTrafficSelectors) {
		return errors.New("initiator traffic selectors are narrower than current child sa")
	}
	if len(current.ResponderTrafficSelectors) != 0 && !trafficSelectorsContainAll(tsr, current.ResponderTrafficSelectors) {
		return errors.New("responder traffic selectors are narrower than current child sa")
	}
	return nil
}

func trafficSelectorsContainAll(selectors, subset []ike.TrafficSelector) bool {
	for _, sub := range subset {
		contained := false
		for _, selector := range selectors {
			if selector.Contains(sub) {
				contained = true
				break
			}
		}
		if !contained {
			return false
		}
	}
	return true
}

func (s *Session) installChildSecurityAssociations(result childSARekeyResult) {
	now := time.Now()
	s.mu.Lock()
	s.retireInboundChildSA(now)
	s.connected = true
	s.tunnelErr = nil
	s.tunnel = cloneInfo(result.info)
	s.outboundESP = result.outbound
	s.inboundESP = result.inbound
	s.pendingChildSA = pendingChildSA{}
	s.espSeq = 0
	s.inboundReplay.Reset()
	s.lastProtectedRx = now
	s.lastProtectedTx = now
	s.childSAExpiresAt = childSAExpiry(now, s.cfg.ChildSALifetime)
	s.childSARekeyAt = childSARekeyTime(now, s.cfg.ChildSALifetime, s.cfg.ChildSARekeyMargin)
	s.childSAByteExpiresAt = saByteExpiry(s.cfg.ChildSAByteLifetime)
	s.childSAByteRekeyAt = saByteRekeyLimit(s.cfg.ChildSAByteLifetime, s.cfg.ChildSAByteRekeyMargin)
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.mu.Unlock()
}

func (s *Session) stageResponderChildSecurityAssociations(result childSARekeyResult) {
	now := time.Now()
	s.mu.Lock()
	s.retireInboundChildSA(now)
	s.connected = true
	s.tunnelErr = nil
	s.tunnel = cloneInfo(result.info)
	s.tunnel.ESPResponderSPI = s.outboundESP.SPI
	s.inboundESP = result.inbound
	s.pendingChildSA = pendingChildSA{
		ready:      true,
		info:       cloneInfo(result.info),
		outbound:   result.outbound,
		oldInbound: result.oldInbound,
	}
	s.inboundReplay.Reset()
	s.lastProtectedRx = now
	s.childSAExpiresAt = childSAExpiry(now, s.cfg.ChildSALifetime)
	s.childSARekeyAt = childSARekeyTime(now, s.cfg.ChildSALifetime, s.cfg.ChildSARekeyMargin)
	s.childSAByteExpiresAt = saByteExpiry(s.cfg.ChildSAByteLifetime)
	s.childSAByteRekeyAt = saByteRekeyLimit(s.cfg.ChildSAByteLifetime, s.cfg.ChildSAByteRekeyMargin)
	s.childSAInboundBytes = 0
	s.childSAOutboundBytes = 0
	s.mu.Unlock()
}

func (s *Session) noteSimultaneousChildSARekey(result childSARekeyResult) {
	s.mu.Lock()
	if s.childSARekeying {
		s.simultaneousChildSA = simultaneousChildSARekey{ready: true, peer: result}
	}
	s.mu.Unlock()
}

func (s *Session) promotePendingChildSecurityAssociation() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pendingChildSA.ready {
		return false
	}
	s.outboundESP = s.pendingChildSA.outbound
	s.tunnel.ESPResponderSPI = s.pendingChildSA.info.ESPResponderSPI
	s.espSeq = 0
	s.pendingChildSA = pendingChildSA{}
	return true
}

func (s *Session) retireInboundChildSA(now time.Time) {
	if s.inboundESP.SPI == 0 {
		return
	}
	outboundSPI := s.outboundESP.SPI
	if s.pendingChildSA.ready && s.pendingChildSA.info.ESPInitiatorSPI == s.inboundESP.SPI {
		// A responder-side rekey defers outbound switching until the initiator
		// proves it can receive on the new SA. If that SA loses a simultaneous
		// rekey race first, its peer inbound SPI is still the pending outbound SPI.
		outboundSPI = s.pendingChildSA.outbound.SPI
	}
	expiresAt := now.Add(childSADrainWindow)
	if !s.childSAExpiresAt.IsZero() && s.childSAExpiresAt.Before(expiresAt) {
		expiresAt = s.childSAExpiresAt
	}
	s.retiredChildSAs = append(s.retiredChildSAs, retiredChildSA{
		inbound:        s.inboundESP,
		info:           cloneInfo(s.tunnel),
		outboundSPI:    outboundSPI,
		expiresAt:      expiresAt,
		protectedBytes: s.childSAInboundBytes,
		byteExpiresAt:  s.childSAByteExpiresAt,
	})
	s.pruneRetiredChildSAs(now)
}

func (s *Session) removeRetiredChildSA(inboundSPI uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeRetiredChildSAState(inboundSPI)
}

func (s *Session) removeRetiredChildSAState(inboundSPI uint32) {
	s.retiredChildSAs = slices.DeleteFunc(s.retiredChildSAs, func(child retiredChildSA) bool {
		return child.inbound.SPI == inboundSPI
	})
}

func (s *Session) pruneRetiredChildSAs(now time.Time) {
	kept := s.retiredChildSAs[:0]
	for _, child := range s.retiredChildSAs {
		timeLive := child.expiresAt.IsZero() || now.Before(child.expiresAt)
		byteLive := child.byteExpiresAt == 0 || child.protectedBytes < child.byteExpiresAt
		if timeLive && byteLive {
			kept = append(kept, child)
		}
	}
	s.retiredChildSAs = kept
}

type protectedExchange struct {
	action          ikeAction
	peer            *net.UDPAddr
	crypto          *ikeCrypto
	skipIKESABytes  bool
	senderInitiator bool
	messageID       uint32
	exchangeType    byte
	useNATT         bool
	wires           [][]byte
	waiter          <-chan inboundIKE
}

func (s *Session) exchangeProtected(ctx context.Context, exchange protectedExchange) ([]ike.Payload, error) {
	for attempt, delay := range s.ikeRetransmitDelays() {
		if err := s.writeProtectedRequest(ctx, exchange); err != nil {
			return nil, err
		}
		payloads, received, err := s.awaitProtectedResponse(ctx, exchange, delay)
		if err != nil {
			return nil, err
		}
		if received {
			return payloads, nil
		}
		s.logger.Debug("retransmitting protected ike message", "exchange_type", exchange.exchangeType, "message_id", exchange.messageID, "attempt", attempt+1)
	}
	return nil, fmt.Errorf("%s: waiting message %d: %w", exchange.action, exchange.messageID, errIKERequestIncomplete)
}

func (s *Session) writeProtectedRequest(ctx context.Context, exchange protectedExchange) error {
	return s.writeProtectedWires(ctx, exchange.action, exchange.crypto, buildIKEWires(exchange.wires, exchange.useNATT), exchange.peer, exchange.skipIKESABytes)
}

func (s *Session) awaitProtectedResponse(ctx context.Context, exchange protectedExchange, delay time.Duration) ([]ike.Payload, bool, error) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false, fmt.Errorf("%w: %w", errIKERequestIncomplete, ctx.Err())
	case <-s.closeDone():
		return nil, false, fmt.Errorf("%s: session is closed", exchange.action)
	case response := <-exchange.waiter:
		if response.err != nil {
			return nil, false, fmt.Errorf("%s: %w", exchange.action, response.err)
		}
		if response.payloads != nil {
			return response.payloads, true, nil
		}
		payloads, err := openProtectedResponse(exchange.crypto, response.data, exchange.exchangeType, exchange.action, exchange.senderInitiator)
		if err != nil {
			return nil, false, err
		}
		return payloads, true, nil
	case <-timer.C:
		return nil, false, nil
	}
}

func openProtectedResponse(crypto *ikeCrypto, data []byte, exchangeType byte, action ikeAction, senderInitiator bool) ([]ike.Payload, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("%s: parsing response: %w", action, err)
	}
	if packet.Header.ExchangeType != exchangeType {
		return nil, fmt.Errorf("%s: unexpected exchange type %d", action, packet.Header.ExchangeType)
	}
	payloads, err := crypto.OpenIKE(packet, senderInitiator)
	if err != nil {
		return nil, fmt.Errorf("%s: opening response: %w", action, err)
	}
	return payloads, nil
}

func (s *Session) childSARekeyLoop() {
	defer s.wg.Done()
	var temporaryFailure rekeyTemporaryFailureBackoff
	for {
		rekeyAt, expiresAt, ok := s.waitForRekeyDeadline(s.childSALifetimeState, temporaryFailure)
		if !ok {
			return
		}
		now := time.Now()
		if rekeyHardLifetimeExpired(expiresAt, now) {
			cause := fmt.Errorf("child sa rekey: %w", errChildSAExpired)
			s.tryDeliverError(cause)
			s.failSecurityAssociations(cause)
			return
		}
		if rekeyAt.IsZero() || now.Before(rekeyAt) {
			continue
		}
		if temporaryFailure.waiting(now) {
			continue
		}
		ctx, cancel := s.timeoutContext(30 * time.Second)
		err := s.RekeyChildSA(ctx)
		cancel()
		if err == nil {
			temporaryFailure.reset()
			continue
		}
		if errors.Is(err, errChildSARekeyInProgress) || errors.Is(err, errIKESARekeyInProgress) {
			temporaryFailure.reset()
			if !s.waitForRekeyStateChange() {
				return
			}
			continue
		}
		if errors.Is(err, errIKETemporaryFailure) {
			if !temporaryFailure.record(now) {
				cause := fmt.Errorf("child sa rekey: %w", err)
				s.tryDeliverError(cause)
				s.failSecurityAssociations(cause)
				return
			}
			s.logger.Debug("child sa rekey deferred after temporary failure", "retry_at", temporaryFailure.retryAt, "err", err)
			continue
		}
		if errors.Is(err, errChildSANotFound) {
			cause := fmt.Errorf("child sa rekey: %w", err)
			s.tryDeliverError(cause)
			s.failSecurityAssociations(cause)
			return
		}
		if errors.Is(err, errIKERequestIncomplete) {
			cause := fmt.Errorf("child sa rekey: %w", err)
			s.tryDeliverError(cause)
			s.failSecurityAssociations(cause)
			return
		}
		if rekeyHardLifetimeExpired(expiresAt, time.Now()) {
			cause := fmt.Errorf("child sa rekey: %w", err)
			s.tryDeliverError(cause)
			s.failSecurityAssociations(cause)
			return
		}
		retryAt := s.deferChildSARekey(time.Now(), expiresAt)
		s.logger.Debug("child sa rekey deferred after error", "retry_at", retryAt, "err", err)
	}
}

func (s *Session) childSALifetimeState() (time.Time, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.connected {
		return time.Time{}, time.Time{}
	}
	return s.childSARekeyAt, s.childSAExpiresAt
}

func cloneInfo(info Info) Info {
	return Info{
		InnerIPv4:                 append(net.IP(nil), info.InnerIPv4...),
		InnerIPv6:                 cloneIPAddress(info.InnerIPv6),
		InnerIPv6Prefix:           cloneIPPrefix(info.InnerIPv6Prefix),
		PDNTypeRestriction:        info.PDNTypeRestriction,
		PCSCFIPs:                  cloneIPList(info.PCSCFIPs),
		ESPInitiatorSPI:           info.ESPInitiatorSPI,
		ESPResponderSPI:           info.ESPResponderSPI,
		Encryption:                info.Encryption,
		EncryptionKeyLen:          info.EncryptionKeyLen,
		Integrity:                 info.Integrity,
		InitiatorTrafficSelectors: cloneTrafficSelectors(info.InitiatorTrafficSelectors),
		ResponderTrafficSelectors: cloneTrafficSelectors(info.ResponderTrafficSelectors),
		PDUSessionID:              info.PDUSessionID,
		SNSSAI:                    append([]byte(nil), info.SNSSAI...),
		SNSSAIPlmnID:              append([]byte(nil), info.SNSSAIPlmnID...),
	}
}

func cloneTrafficSelectors(selectors []ike.TrafficSelector) []ike.TrafficSelector {
	if selectors == nil {
		return nil
	}
	cloned := make([]ike.TrafficSelector, len(selectors))
	for i, selector := range selectors {
		cloned[i] = selector
		cloned[i].Data = append([]byte(nil), selector.Data...)
	}
	return cloned
}
