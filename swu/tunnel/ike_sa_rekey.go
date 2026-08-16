package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

var (
	errIKESAExpired         = errors.New("ike sa lifetime expired")
	errIKESARekeyInProgress = errors.New("ike sa rekey already in progress")
)

type ikeSARekeyState struct {
	ike                       *ikeCrypto
	initiatorSPI              uint64
	responderSPI              uint64
	peer                      *net.UDPAddr
	localInitiator            bool
	ikeFragmentationSupported bool
	useNATT                   bool
}

type ikeSARekeyResult struct {
	crypto         *ikeCrypto
	initiatorSPI   uint64
	responderSPI   uint64
	nonceI         []byte
	nonceR         []byte
	localInitiator bool
}

type ikeAssociation struct {
	ike               *ikeCrypto
	pendingIKESA      ikeSARekeyResult
	pendingIKESAReady bool
	retiredIKESAs     []retiredIKESA
	ikeLocalInitiator bool
	initiatorSPI      uint64
	responderSPI      uint64
	deviceIdentity    string
	ikeSARekeying     bool
	simultaneousIKESA simultaneousIKESARekey
}

type retiredIKESA struct {
	ike               *ikeCrypto
	localInitiator    bool
	initiatorSPI      uint64
	responderSPI      uint64
	peer              *net.UDPAddr
	useNATT           bool
	nextPeerMessageID uint32
	responses         map[uint32][][]byte
	responseReqs      map[uint32][]byte
	expiresAt         time.Time
}

type simultaneousIKESARekey struct {
	ready bool
	peer  ikeSARekeyResult
}

func (s *Session) RekeyIKESA(ctx context.Context) (retErr error) {
	defer func() {
		if retErr != nil {
			retErr = fmt.Errorf("rekeying ike sa: %w", retErr)
		}
	}()

	state, release, err := s.beginIKESARekey()
	if err != nil {
		return err
	}
	defer release()

	result, err := s.initiatedIKESARekeyResult(ctx, state, s.exchangeInitiatedIKESARekey)
	if err != nil {
		return err
	}
	decision := s.finishInitiatedIKESARekey(result)
	if decision.installLocal {
		if err := s.installInitiatedIKESARekey(ctx, state, result, decision); err != nil {
			s.logger.Debug("deleting old ike sa failed", "err", err, "initiator_spi", state.initiatorSPI, "responder_spi", state.responderSPI)
		}
		return nil
	}
	if err := s.deleteRedundantIKESA(ctx, state.peer, result); err != nil {
		s.logger.Debug("deleting redundant ike sa failed", "err", err, "initiator_spi", result.initiatorSPI, "responder_spi", result.responderSPI)
	}
	return nil
}

type ikeSARekeyExchange func(context.Context, ikeSARekeyState, *ikeCrypto) ([]ike.Payload, error)

func (s *Session) initiatedIKESARekeyResult(ctx context.Context, state ikeSARekeyState, exchange ikeSARekeyExchange) (ikeSARekeyResult, error) {
	dhGroup := initialIKESARekeyDHGroup(state.ike)
	triedGroups := make(map[uint16]struct{})
	for {
		if _, ok := triedGroups[dhGroup]; ok {
			return ikeSARekeyResult{}, fmt.Errorf("repeated INVALID_KE_PAYLOAD group %d", dhGroup)
		}
		triedGroups[dhGroup] = struct{}{}
		next, err := newIKESARekeyCrypto(dhGroup, state.initiatorSPI, state.responderSPI)
		if err != nil {
			return ikeSARekeyResult{}, err
		}
		payloads, err := exchange(ctx, state, next)
		if err != nil {
			return ikeSARekeyResult{}, err
		}
		group, retry, err := invalidKEPayloadGroupFor(payloads)
		if err != nil {
			return ikeSARekeyResult{}, fmt.Errorf("parsing create_child_sa response: %w", err)
		}
		if retry {
			dhGroup = group
			continue
		}
		return state.ikeSARekeyResult(payloads, next)
	}
}

func (s *Session) exchangeInitiatedIKESARekey(ctx context.Context, state ikeSARekeyState, next *ikeCrypto) ([]ike.Payload, error) {
	releaseRequest, err := s.acquireIKERequest(ctx, ikeActionRekeyIKESA)
	if err != nil {
		return nil, err
	}
	defer releaseRequest()

	messageID, err := s.allocateMessageID()
	if err != nil {
		return nil, fmt.Errorf("allocating message id: %w", err)
	}
	key := ikeMessageKeyForSPIs(state.initiatorSPI, state.responderSPI, exchangeTypeCreateChildSA, ikeMessageFlags(!state.localInitiator, true), messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)

	wires, err := state.sealIKESARekeyRequest(messageID, next)
	if err != nil {
		return nil, err
	}
	return s.exchangeProtected(ctx, protectedExchange{
		action:          ikeActionRekeyIKESA,
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

func (s *Session) installInitiatedIKESARekey(ctx context.Context, state ikeSARekeyState, result ikeSARekeyResult, decision ikeSARekeyDecision) error {
	releaseRequest, err := s.acquireIKERequest(ctx, ikeActionDeleteOldIKESA)
	if err != nil {
		return err
	}
	defer releaseRequest()

	deleteMessageID, err := s.allocateMessageID()
	if err != nil {
		return fmt.Errorf("allocating old ike sa delete message id: %w", err)
	}
	deleteWires, err := state.sealOldIKESADelete(deleteMessageID)
	if err != nil {
		return fmt.Errorf("sealing old ike sa delete: %w", err)
	}
	s.installSurvivingIKESARekey(result, decision, state.peer)
	key := state.informationalState().responseMessageKey(deleteMessageID, exchangeTypeInformational)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	payloads, err := s.exchangeInformationalRequest(ctx, state.informationalState(), deleteMessageID, deleteWires, waiter, ikeActionDeleteOldIKESA, true)
	if err != nil {
		return err
	}
	if err := validateIKEDeleteResponsePayloads(payloads); err != nil {
		return fmt.Errorf("deleting old ike sa: %w", err)
	}
	return nil
}

func (s *Session) beginIKESARekey() (ikeSARekeyState, func(), error) {
	if s.isClosed() {
		return ikeSARekeyState{}, nil, errors.New("session is closed")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if state := s.ikeSAState(); state == ikeSAStateRekeying || state == ikeSAStatePendingInstall {
		return ikeSARekeyState{}, nil, errIKESARekeyInProgress
	}
	if state := s.childSAState(); state == childSAStateRekeying || state == childSAStatePendingOutbound {
		return ikeSARekeyState{}, nil, errChildSARekeyInProgress
	}
	if s.ikeSAExpired(time.Now()) {
		return ikeSARekeyState{}, nil, errIKESAExpired
	}
	state := ikeSARekeyState{
		ike:                       s.ike,
		initiatorSPI:              s.initiatorSPI,
		responderSPI:              s.responderSPI,
		peer:                      outerIKEPeer(s.useNATT, s.outerRemote, s.outerNAT),
		localInitiator:            s.ikeLocalInitiator,
		ikeFragmentationSupported: s.ikeFragmentationSupported,
		useNATT:                   s.useNATT,
	}
	if !state.available() {
		return ikeSARekeyState{}, nil, errors.New("ike state is unavailable")
	}
	s.ikeSARekeying = true
	s.simultaneousIKESA = simultaneousIKESARekey{}
	return state, func() {
		s.mu.Lock()
		s.ikeSARekeying = false
		s.simultaneousIKESA = simultaneousIKESARekey{}
		s.mu.Unlock()
		s.notifyRekeyStateChanged()
	}, nil
}

func (rs ikeSARekeyState) available() bool {
	return rs.ike != nil && rs.peer != nil && rs.initiatorSPI != 0 && rs.responderSPI != 0
}

func (rs ikeSARekeyState) informationalState() informationalState {
	return informationalState{
		ike:                       rs.ike,
		localInitiator:            rs.localInitiator,
		retiredIKESA:              true,
		initiatorSPI:              rs.initiatorSPI,
		responderSPI:              rs.responderSPI,
		peer:                      cloneUDPAddr(rs.peer),
		ikeFragmentationSupported: rs.ikeFragmentationSupported,
		useNATT:                   rs.useNATT,
	}
}

func initialIKESARekeyDHGroup(current *ikeCrypto) uint16 {
	return current.dhGroup
}

func newIKESARekeyCrypto(dhGroup uint16, existingSPIs ...uint64) (*ikeCrypto, error) {
	crypto, err := newIKECrypto(dhGroup)
	if err != nil {
		return nil, err
	}
	var initiatorSPI uint64
	for {
		initiatorSPI = randomIKESPI()
		if !ikeSPIInUse(initiatorSPI, existingSPIs...) {
			break
		}
	}
	nonceI := randomBytes(defaultIKENonceLength)
	crypto.SetSPIs(initiatorSPI, 0)
	crypto.SetNonces(nonceI, nil)
	return crypto, nil
}

func (rs ikeSARekeyState) sealIKESARekeyRequest(messageID uint32, next *ikeCrypto) ([][]byte, error) {
	header := ike.Header{
		InitiatorSPI: rs.initiatorSPI,
		ResponderSPI: rs.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeCreateChildSA,
		Flags:        rs.initiatorFlag(),
		MessageID:    messageID,
	}
	wires, err := sealIKEPackets(rs.ike, header, ikeSARekeyRequestPayloads(rs.ike, next), rs.localInitiator, rs.ikeFragmentationSupported)
	if err != nil {
		return nil, fmt.Errorf("sealing create_child_sa request: %w", err)
	}
	return wires, nil
}

func (rs ikeSARekeyState) initiatorFlag() byte {
	if rs.localInitiator {
		return flagInitiator
	}
	return 0
}

func ikeSARekeyRequestPayloads(current, next *ikeCrypto) []ike.Payload {
	return []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: currentIKESARekeyProposals(current, next.dhGroup, next.initiatorSPI)},
		&ike.NoncePayload{Data: append([]byte(nil), next.nonceI...)},
		&ike.KeyExchangePayload{DHGroup: next.dhGroup, Data: next.PublicKey()},
	}
}

func currentIKESARekeyProposals(current *ikeCrypto, dhGroup uint16, initiatorSPI uint64) []ike.Proposal {
	return []ike.Proposal{
		{
			Number:     1,
			ProtocolID: proposalProtocolIKE,
			SPI:        uint64Bytes(initiatorSPI),
			Transforms: []ike.Transform{
				{
					TransformType: transformTypeENCR,
					ID:            current.encr,
					Attributes:    []ike.Attribute{ike.NewTVAttribute(transformAttrKeyLength, current.encrKeyBits)},
				},
				{TransformType: transformTypeINTEG, ID: current.integ},
				{TransformType: transformTypePRF, ID: current.prf},
				{TransformType: transformTypeDH, ID: dhGroup},
			},
		},
	}
}

func (rs ikeSARekeyState) ikeSARekeyResult(payloads []ike.Payload, next *ikeCrypto) (ikeSARekeyResult, error) {
	requestProposals := currentIKESARekeyProposals(rs.ike, next.dhGroup, next.initiatorSPI)
	proposal, responderSPI, nonceR, responderKE, err := negotiatedIKESARekeyFromPayloadsWithRequests(payloads, next.dhGroup, requestProposals)
	if err != nil {
		return ikeSARekeyResult{}, err
	}
	if ikeSPIInUse(responderSPI, rs.initiatorSPI, rs.responderSPI, next.initiatorSPI) {
		return ikeSARekeyResult{}, errors.New("parsing create_child_sa response: responder ike spi conflicts with an existing ike spi")
	}
	next.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	next.SetSPIs(next.initiatorSPI, responderSPI)
	next.SetNonces(next.nonceI, nonceR)
	if err := next.DeriveRekeyedIKEKeys(rs.ike, responderKE); err != nil {
		return ikeSARekeyResult{}, fmt.Errorf("deriving ike keys: %w", err)
	}
	return ikeSARekeyResult{
		crypto:         next,
		initiatorSPI:   next.initiatorSPI,
		responderSPI:   responderSPI,
		nonceI:         append([]byte(nil), next.nonceI...),
		nonceR:         append([]byte(nil), nonceR...),
		localInitiator: true,
	}, nil
}

type ikeSARekeyDecision struct {
	installLocal              bool
	retainPeerCreatedLosingSA bool
	peerCreatedLosingSA       ikeSARekeyResult
}

func (s *Session) finishInitiatedIKESARekey(result ikeSARekeyResult) ikeSARekeyDecision {
	s.mu.RLock()
	simultaneous := s.simultaneousIKESA
	s.mu.RUnlock()
	if !simultaneous.ready {
		return ikeSARekeyDecision{installLocal: true}
	}
	if ikeSARekeyLocalCreatedSAWins(result, simultaneous.peer) {
		return ikeSARekeyDecision{
			installLocal:              true,
			retainPeerCreatedLosingSA: true,
			peerCreatedLosingSA:       simultaneous.peer,
		}
	}
	return ikeSARekeyDecision{}
}

func ikeSARekeyLocalCreatedSAWins(local, peer ikeSARekeyResult) bool {
	return lowestNonceBelongsToPeerExchange(local.nonceI, local.nonceR, peer.nonceI, peer.nonceR)
}

func negotiatedIKESARekeyFromPayloads(payloads []ike.Payload, dhGroup uint16) (negotiatedIKESA, uint64, []byte, []byte, error) {
	return negotiatedIKESARekeyFromPayloadsWithRequests(payloads, dhGroup, nil)
}

func negotiatedIKESARekeyFromPayloadsWithRequests(payloads []ike.Payload, dhGroup uint16, requestProposals []ike.Proposal) (negotiatedIKESA, uint64, []byte, []byte, error) {
	if err := createChildSAResponseNotifyError(payloads); err != nil {
		return negotiatedIKESA{}, 0, nil, nil, err
	}
	nonce := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	ke := ike.FindKEPayload(payloads, dhGroup)
	if nonce == nil || sa == nil || ke == nil {
		return negotiatedIKESA{}, 0, nil, nil, errors.New("parsing create_child_sa response: required ike sa rekey payload is missing")
	}
	if err := validateNonceData(nonce.Data); err != nil {
		return negotiatedIKESA{}, 0, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	if len(sa.Proposals) != 1 {
		return negotiatedIKESA{}, 0, nil, nil, fmt.Errorf("parsing create_child_sa response: negotiated proposal count %d", len(sa.Proposals))
	}
	if err := validateNegotiatedProposalFromRequests(sa.Proposals[0], requestProposals); err != nil {
		return negotiatedIKESA{}, 0, nil, nil, fmt.Errorf("parsing create_child_sa response: %w", err)
	}
	if len(sa.Proposals[0].SPI) != 8 {
		return negotiatedIKESA{}, 0, nil, nil, fmt.Errorf("parsing create_child_sa response: invalid responder ike spi length %d", len(sa.Proposals[0].SPI))
	}
	responderSPI := binary.BigEndian.Uint64(sa.Proposals[0].SPI)
	if !validIKESPI(responderSPI) {
		return negotiatedIKESA{}, 0, nil, nil, errors.New("parsing create_child_sa response: responder ike spi is zero")
	}
	proposal, err := negotiatedIKESAFromProposal(sa.Proposals[0], dhGroup)
	if err != nil {
		return negotiatedIKESA{}, 0, nil, nil, err
	}
	return proposal, responderSPI, append([]byte(nil), nonce.Data...), append([]byte(nil), ke.Data...), nil
}

func (rs ikeSARekeyState) sealOldIKESADelete(messageID uint32) ([][]byte, error) {
	header := ike.Header{
		InitiatorSPI: rs.initiatorSPI,
		ResponderSPI: rs.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        rs.initiatorFlag(),
		MessageID:    messageID,
	}
	wires, err := sealIKEPackets(rs.ike, header, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}}, rs.localInitiator, rs.ikeFragmentationSupported)
	if err != nil {
		return nil, err
	}
	return wires, nil
}

func (r ikeSARekeyResult) sealSelfDelete(messageID uint32, fragmentationSupported bool) ([][]byte, error) {
	header := ike.Header{
		InitiatorSPI: r.initiatorSPI,
		ResponderSPI: r.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        r.initiatorFlag(),
		MessageID:    messageID,
	}
	wires, err := sealIKEPackets(r.crypto, header, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}}, r.localInitiator, fragmentationSupported)
	if err != nil {
		return nil, err
	}
	return wires, nil
}

func (r ikeSARekeyResult) initiatorFlag() byte {
	if r.localInitiator {
		return flagInitiator
	}
	return 0
}

func (s *Session) deleteRedundantIKESA(ctx context.Context, peer *net.UDPAddr, result ikeSARekeyResult) error {
	releaseRequest, err := s.acquireIKERequest(ctx, ikeActionDeleteRedundantIKESA)
	if err != nil {
		return err
	}
	defer releaseRequest()
	state := s.stageRedundantIKESAForDelete(peer, result)
	defer s.removeRetiredIKESA(state)
	wires, err := result.sealSelfDelete(0, state.ikeFragmentationSupported)
	if err != nil {
		return fmt.Errorf("sealing redundant ike delete: %w", err)
	}
	key := state.responseMessageKey(0, exchangeTypeInformational)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	payloads, err := s.exchangeInformationalRequest(ctx, state, 0, wires, waiter, ikeActionDeleteRedundantIKESA, true)
	if err != nil {
		return err
	}
	if err := validateIKEDeleteResponsePayloads(payloads); err != nil {
		return fmt.Errorf("deleting redundant ike sa: %w", err)
	}
	return nil
}

func (s *Session) installIKESecurityAssociation(result ikeSARekeyResult) {
	now := time.Now()
	s.mu.Lock()
	waiters := s.informWaiters
	s.retireIKESA(now)
	s.ike = result.crypto
	s.ikeLocalInitiator = result.localInitiator
	s.initiatorSPI = result.initiatorSPI
	s.responderSPI = result.responderSPI
	s.nextMessageID = 0
	s.nextPeerMessageID = 0
	s.lastProtectedRx = now
	s.lastProtectedTx = now
	s.ikeSAExpiresAt = childSAExpiry(now, s.cfg.IKESALifetime)
	s.ikeSARekeyAt = childSARekeyTime(now, s.cfg.IKESALifetime, s.cfg.IKESARekeyMargin)
	s.ikeSAByteExpiresAt = saByteExpiry(s.cfg.IKESAByteLifetime)
	s.ikeSAByteRekeyAt = saByteRekeyLimit(s.cfg.IKESAByteLifetime, s.cfg.IKESAByteRekeyMargin)
	s.ikeSAInboundBytes = 0
	s.ikeSAOutboundBytes = 0
	s.pendingIKESA = ikeSARekeyResult{}
	s.pendingIKESAReady = false
	s.pruneRetiredIKESAs(now)
	s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	s.informResponses = make(map[uint32][][]byte)
	s.informResponseReqs = make(map[uint32][]byte)
	s.ikeFragments = make(map[ikeMessageKey]*ikeFragmentReassembly)
	s.mu.Unlock()
	notifyInformationalWaiters(waiters, errIKESASuperseded)
}

func (s *Session) installSurvivingIKESARekey(result ikeSARekeyResult, decision ikeSARekeyDecision, peer *net.UDPAddr) {
	s.installIKESecurityAssociation(result)
	if decision.retainPeerCreatedLosingSA {
		s.retainPeerCreatedLosingIKESA(peer, decision.peerCreatedLosingSA)
	}
}

func (s *Session) stageIKESecurityAssociation(result ikeSARekeyResult) {
	s.mu.Lock()
	s.pendingIKESA = result
	s.pendingIKESAReady = true
	s.mu.Unlock()
}

func (s *Session) noteSimultaneousIKESARekey(result ikeSARekeyResult) {
	s.mu.Lock()
	if s.ikeSARekeying {
		s.simultaneousIKESA = simultaneousIKESARekey{ready: true, peer: result}
	}
	s.mu.Unlock()
}

func (s *Session) promotePendingIKESecurityAssociation() bool {
	s.mu.RLock()
	ready := s.pendingIKESAReady
	result := s.pendingIKESA
	s.mu.RUnlock()
	if !ready {
		return false
	}
	s.installIKESecurityAssociation(result)
	s.mu.Lock()
	s.pendingIKESA = ikeSARekeyResult{}
	s.pendingIKESAReady = false
	s.ikeSARekeying = false
	s.simultaneousIKESA = simultaneousIKESARekey{}
	s.mu.Unlock()
	return true
}

func (s *Session) retireIKESA(now time.Time) {
	if s.ike == nil || s.initiatorSPI == 0 || s.responderSPI == 0 {
		return
	}
	expiresAt := now.Add(ikeSADrainWindow)
	if !s.ikeSAExpiresAt.IsZero() && s.ikeSAExpiresAt.Before(expiresAt) {
		expiresAt = s.ikeSAExpiresAt
	}
	s.retiredIKESAs = append(s.retiredIKESAs, retiredIKESA{
		ike:               s.ike,
		localInitiator:    s.ikeLocalInitiator,
		initiatorSPI:      s.initiatorSPI,
		responderSPI:      s.responderSPI,
		peer:              outerIKEPeer(s.useNATT, s.outerRemote, s.outerNAT),
		useNATT:           s.useNATT,
		nextPeerMessageID: s.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(s.informResponses),
		responseReqs:      cloneIKEMessageRequests(s.informResponseReqs),
		expiresAt:         expiresAt,
	})
}

func (s *Session) stageRedundantIKESAForDelete(peer *net.UDPAddr, result ikeSARekeyResult) informationalState {
	s.mu.Lock()
	fragmentationSupported := s.ikeFragmentationSupported
	useNATT := s.useNATT
	s.retiredIKESAs = append(s.retiredIKESAs, retiredIKESA{
		ike:               result.crypto,
		localInitiator:    result.localInitiator,
		initiatorSPI:      result.initiatorSPI,
		responderSPI:      result.responderSPI,
		peer:              cloneUDPAddr(peer),
		useNATT:           useNATT,
		nextPeerMessageID: 0,
		expiresAt:         time.Now().Add(ikeSADrainWindow),
	})
	s.mu.Unlock()
	state := informationalState{
		ike:                       result.crypto,
		localInitiator:            result.localInitiator,
		retiredIKESA:              true,
		initiatorSPI:              result.initiatorSPI,
		responderSPI:              result.responderSPI,
		peer:                      cloneUDPAddr(peer),
		ikeFragmentationSupported: fragmentationSupported,
		useNATT:                   useNATT,
	}
	return state
}

func (s *Session) retainPeerCreatedLosingIKESA(peer *net.UDPAddr, result ikeSARekeyResult) {
	s.mu.Lock()
	s.retiredIKESAs = append(s.retiredIKESAs, retiredIKESA{
		ike:               result.crypto,
		localInitiator:    result.localInitiator,
		initiatorSPI:      result.initiatorSPI,
		responderSPI:      result.responderSPI,
		peer:              cloneUDPAddr(peer),
		useNATT:           s.useNATT,
		nextPeerMessageID: 0,
		expiresAt:         time.Now().Add(ikeSADrainWindow),
	})
	s.mu.Unlock()
}

func (s *Session) removeRetiredIKESA(state informationalState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			s.retiredIKESAs = append(s.retiredIKESAs[:i], s.retiredIKESAs[i+1:]...)
			return
		}
	}
}

func (s *Session) pruneRetiredIKESAs(now time.Time) {
	kept := s.retiredIKESAs[:0]
	for _, retired := range s.retiredIKESAs {
		if retired.expiresAt.IsZero() || now.Before(retired.expiresAt) {
			kept = append(kept, retired)
		}
	}
	s.retiredIKESAs = kept
}

func cloneIKEMessageResponses(responses map[uint32][][]byte) map[uint32][][]byte {
	if len(responses) == 0 {
		return nil
	}
	cloned := make(map[uint32][][]byte, len(responses))
	for messageID, wires := range responses {
		cloned[messageID] = cloneIKEPackets(wires)
	}
	return cloned
}

func cloneIKEMessageRequests(requests map[uint32][]byte) map[uint32][]byte {
	if len(requests) == 0 {
		return nil
	}
	cloned := make(map[uint32][]byte, len(requests))
	for messageID, request := range requests {
		cloned[messageID] = append([]byte(nil), request...)
	}
	return cloned
}

func cloneIKEPackets(packets [][]byte) [][]byte {
	if len(packets) == 0 {
		return nil
	}
	cloned := make([][]byte, len(packets))
	for i, packet := range packets {
		cloned[i] = append([]byte(nil), packet...)
	}
	return cloned
}

func retiredIKESAMatches(retired retiredIKESA, initiatorSPI, responderSPI uint64) bool {
	return retired.initiatorSPI == initiatorSPI && retired.responderSPI == responderSPI
}

func (s *Session) ikeSARekeyLoop() {
	defer s.wg.Done()
	var temporaryFailure rekeyTemporaryFailureBackoff
	for {
		rekeyAt, expiresAt, ok := s.waitForRekeyDeadline(s.ikeSALifetimeState, temporaryFailure)
		if !ok {
			return
		}
		now := time.Now()
		if rekeyHardLifetimeExpired(expiresAt, now) {
			cause := fmt.Errorf("ike sa rekey: %w", errIKESAExpired)
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
		err := s.RekeyIKESA(ctx)
		cancel()
		if err == nil {
			temporaryFailure.reset()
			continue
		}
		if errors.Is(err, errIKESARekeyInProgress) || errors.Is(err, errChildSARekeyInProgress) {
			temporaryFailure.reset()
			if !s.waitForRekeyStateChange() {
				return
			}
			continue
		}
		if errors.Is(err, errIKETemporaryFailure) {
			if !temporaryFailure.record(now) {
				s.failSecurityAssociations(err)
				return
			}
			s.logger.Debug("ike sa rekey deferred after temporary failure", "retry_at", temporaryFailure.retryAt, "err", err)
			continue
		}
		if errors.Is(err, errIKERequestIncomplete) {
			s.failSecurityAssociations(err)
			return
		}
		if rekeyHardLifetimeExpired(expiresAt, time.Now()) {
			s.failSecurityAssociations(err)
			return
		}
		retryAt := s.deferIKESARekey(time.Now(), expiresAt)
		s.logger.Debug("ike sa rekey deferred after error", "retry_at", retryAt, "err", err)
	}
}

func (s *Session) ikeSALifetimeState() (time.Time, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ike == nil {
		return time.Time{}, time.Time{}
	}
	return s.ikeSARekeyAt, s.ikeSAExpiresAt
}

func (s *Session) ikeSARekeyActive() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	state := s.ikeSAState()
	return state == ikeSAStateRekeying || state == ikeSAStatePendingInstall
}

func uint64Bytes(value uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, value)
	return buf
}
