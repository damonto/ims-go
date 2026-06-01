package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	"github.com/damonto/vowifi-go/swu/esp"
	"github.com/damonto/vowifi-go/swu/ike"
)

type createChildSARequestState struct {
	ike               *ikeCrypto
	localInitiator    bool
	ikeRekeying       bool
	pendingIKESA      bool
	retiredIKESA      bool
	childRekeying     bool
	nextPeerMessageID uint32
	responses         map[uint32][]byte
	responseReqs      map[uint32][]byte
	cfg               Config
	info              Info
	initiatorSPI      uint64
	responderSPI      uint64
	peer              *net.UDPAddr
	inboundSPI        uint32
	outboundSPI       uint32
	promoteIKESA      bool
}

func (state createChildSARequestState) informationalState() informationalState {
	return informationalState{
		ike:               state.ike,
		localInitiator:    state.localInitiator,
		initiatorSPI:      state.initiatorSPI,
		responderSPI:      state.responderSPI,
		peer:              cloneUDPAddr(state.peer),
		retiredIKESA:      state.retiredIKESA,
		nextPeerMessageID: state.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(state.responses),
		responseReqs:      cloneIKEMessageResponses(state.responseReqs),
	}
}

func (state createChildSARequestState) available() bool {
	return state.ike != nil && state.initiatorSPI != 0 && state.responderSPI != 0
}

func (s *Session) handleCreateChildSARequest(state createChildSARequestState, packet ike.IKEPacket, addr net.Addr) (bool, error) {
	if !state.available() {
		return true, errors.New("handling create_child_sa request: ike state is unavailable")
	}
	payloads, err := state.ike.OpenIKE(packet, !state.localInitiator)
	if err != nil {
		if responsePayloads, ok := ikeErrorNotifyResponse(err); ok {
			return s.writeIKEErrorNotifyCreateChildSAResponse(state, packet, addr, responsePayloads)
		}
		return true, fmt.Errorf("opening create_child_sa request: %w", err)
	}
	if state.promoteIKESA {
		s.promotePendingIKESecurityAssociation()
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state.informationalState(), packet.Raw, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state.informationalState(), now)
	expireAfterRequest := accept.expired
	defer func() {
		if expireAfterRequest {
			s.failSecurityAssociations(errIKESAExpired)
		}
	}()
	if wire, ok := s.cachedInformationalResponseForState(state.informationalState(), packet.Header.MessageID, packet.Raw); ok {
		return true, s.writeCreateChildSAResponseWire(state, packet.Header.MessageID, 0, wire, addr)
	}
	switch s.peerRequestMessageIDRelationForState(state.informationalState(), packet.Header.MessageID) {
	case ikeMessageIDCurrent:
	case ikeMessageIDFuture:
		s.logger.Debug("ignoring create_child_sa request outside message id window", "message_id", packet.Header.MessageID)
		if err := s.sendInvalidMessageIDNotification(state.informationalState(), packet.Header.MessageID); err != nil {
			s.logger.Debug("sending invalid message id notification failed", "message_id", packet.Header.MessageID, "err", err)
		}
		return true, nil
	default:
		s.logger.Debug("ignoring old create_child_sa request without cached response", "message_id", packet.Header.MessageID)
		return true, nil
	}
	if state.pendingIKESA {
		err := s.writeCreateChildSAResponse(state, packet.Header.MessageID, packet.Raw, createChildSAErrorNotify(notifyTypeTemporaryFailure, nil), addr)
		if err == nil {
			err = s.advancePeerRequestMessageIDForState(state.informationalState(), packet.Header.MessageID)
			if err != nil {
				s.failSecurityAssociations(err)
			}
		}
		return true, err
	}
	responsePayloads, action, err := buildCreateChildSAResponsePayloads(state, payloads)
	if err != nil {
		return true, err
	}
	if action.installChild {
		// RFC 7296 §2.8 requires the responder to accept the new SA before sending
		// the CREATE_CHILD_SA response.
		s.stageResponderChildSecurityAssociations(action.child)
		if action.simultaneousChild {
			s.noteSimultaneousChildSARekey(action.child)
		}
	}
	if action.installIKE {
		// RFC 7296 §2.8 applies to CREATE_CHILD_SA-created SAs in general:
		// the responder must be ready before the response can be lost.
		s.stageIKESecurityAssociation(action.ike)
		if action.simultaneousIKE {
			s.noteSimultaneousIKESARekey(action.ike)
		}
	}
	if err := s.writeCreateChildSAResponse(state, packet.Header.MessageID, packet.Raw, responsePayloads, addr); err != nil {
		return true, err
	}
	if err := s.advancePeerRequestMessageIDForState(state.informationalState(), packet.Header.MessageID); err != nil {
		s.failSecurityAssociations(err)
		return true, err
	}
	if action.fatalIKE {
		s.failSecurityAssociations(action.fatalErr)
		return true, nil
	}
	if expireAfterRequest && action.installIKE && s.promotePendingIKESecurityAssociation() {
		expireAfterRequest = false
	}
	return true, nil
}

func (s *Session) writeIKEErrorNotifyCreateChildSAResponse(state createChildSARequestState, packet ike.IKEPacket, addr net.Addr, payloads []ike.Payload) (bool, error) {
	if state.promoteIKESA {
		s.promotePendingIKESecurityAssociation()
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state.informationalState(), packet.Raw, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state.informationalState(), now)
	expireAfterRequest := accept.expired
	defer func() {
		if expireAfterRequest {
			s.failSecurityAssociations(errIKESAExpired)
		}
	}()
	switch s.peerRequestMessageIDRelationForState(state.informationalState(), packet.Header.MessageID) {
	case ikeMessageIDCurrent:
	case ikeMessageIDFuture:
		if err := s.sendInvalidMessageIDNotification(state.informationalState(), packet.Header.MessageID); err != nil {
			s.logger.Debug("sending invalid message id notification failed", "message_id", packet.Header.MessageID, "err", err)
		}
		return true, nil
	default:
		return true, nil
	}
	if err := s.writeCreateChildSAResponse(state, packet.Header.MessageID, packet.Raw, payloads, addr); err != nil {
		return true, err
	}
	if err := s.advancePeerRequestMessageIDForState(state.informationalState(), packet.Header.MessageID); err != nil {
		s.failSecurityAssociations(err)
		return true, err
	}
	return true, nil
}

func buildCreateChildSAResponsePayloads(state createChildSARequestState, payloads []ike.Payload) ([]ike.Payload, createChildSAAction, error) {
	sa := ike.FindSAPayload(payloads)
	if sa == nil || len(sa.Proposals) == 0 {
		err := ike.InvalidSyntaxError{Err: errors.New("create_child_sa request missing SA payload")}
		return createChildSAErrorNotify(notifyTypeInvalidSyntax, nil), createChildSAAction{fatalIKE: true, fatalErr: err}, nil
	}
	if err := validateRequestProposalNumbers(sa.Proposals); err != nil {
		err := ike.InvalidSyntaxError{Err: err}
		return createChildSAErrorNotify(notifyTypeInvalidSyntax, nil), createChildSAAction{fatalIKE: true, fatalErr: err}, nil
	}
	// Match platform reference subtype selection: the first SA proposal decides
	// IKE-vs-Child rekey, so an accidental REKEY_SA notify does not turn an IKE
	// rekey into a Child rekey.
	if sa.Proposals[0].ProtocolID == proposalProtocolIKE {
		return buildIKESARekeyResponsePayloads(state, payloads)
	}
	if rekeyNotify := ike.FindNotifyPayload(payloads, notifyTypeRekeySA); rekeyNotify != nil {
		return buildChildSARekeyResponsePayloads(state, payloads, rekeyNotify)
	}
	return buildChildSACreateResponsePayloads(state, payloads)
}

type createChildSAAction struct {
	installChild      bool
	simultaneousChild bool
	child             childSARekeyResult
	installIKE        bool
	simultaneousIKE   bool
	ike               ikeSARekeyResult
	fatalIKE          bool
	fatalErr          error
}

type acceptedChildSA struct {
	Info
	DHGroup        uint16
	ProposalNumber byte
}

func buildChildSARekeyResponsePayloads(state createChildSARequestState, payloads []ike.Payload, rekeyNotify *ike.NotifyPayload) ([]ike.Payload, createChildSAAction, error) {
	if state.ikeRekeying || state.pendingIKESA || state.retiredIKESA {
		return createChildSAErrorNotify(notifyTypeTemporaryFailure, nil), createChildSAAction{}, nil
	}
	oldInboundSPI, ok := validRekeySANotifySPI(rekeyNotify)
	if !ok {
		return createChildSAErrorNotify(notifyTypeChildSANotFound, rekeyNotify.SPI), createChildSAAction{}, nil
	}
	if oldInboundSPI != state.outboundSPI {
		return createChildSAErrorNotify(notifyTypeChildSANotFound, rekeyNotify.SPI), createChildSAAction{}, nil
	}
	return buildChildSAResponsePayloads(state, payloads, state.childRekeying)
}

func buildChildSACreateResponsePayloads(state createChildSARequestState, payloads []ike.Payload) ([]ike.Payload, createChildSAAction, error) {
	if state.ikeRekeying || state.pendingIKESA || state.retiredIKESA || state.childRekeying {
		return createChildSAErrorNotify(notifyTypeTemporaryFailure, nil), createChildSAAction{}, nil
	}
	return createChildSAErrorNotify(notifyTypeNoAdditionalSAs, nil), createChildSAAction{}, nil
}

func buildChildSAResponsePayloads(state createChildSARequestState, payloads []ike.Payload, simultaneous bool) ([]ike.Payload, createChildSAAction, error) {
	nonceI := ike.FindNoncePayload(payloads)
	sa := ike.FindSAPayload(payloads)
	tsi := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSi)
	tsr := ike.FindTrafficSelectorPayload(payloads, payloadTypeTSr)
	if nonceI == nil || sa == nil || tsi == nil || tsr == nil || len(sa.Proposals) == 0 {
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	if err := validateNonceData("building create_child_sa child response", nonceI.Data); err != nil {
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	if err := validateRekeyTrafficSelectors("building create_child_sa child response", tsi.Selectors, tsr.Selectors, state.info); err != nil {
		return createChildSAErrorNotify(notifyTypeTSUnacceptable, nil), createChildSAAction{}, nil
	}
	keI := ike.FindKEPayload(payloads, 0)
	dhGroup, ok := childSARequestDHGroup(keI)
	if !ok {
		return createChildSAInvalidKEPayloadNotify(preferredChildSADHGroup(state.cfg)), createChildSAAction{}, nil
	}
	if dhGroup != 0 && !slices.Contains(preferredChildSADHGroups(state.cfg), dhGroup) {
		if preferred, ok := preferredChildSAProposalDHGroup(sa.Proposals, state.cfg, state.info, dhGroup); ok {
			return createChildSAInvalidKEPayloadNotify(preferred), createChildSAAction{}, nil
		}
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	peerInboundSPI, proposal, err := acceptedChildSAProposal(sa.Proposals, state.info, dhGroup)
	if err != nil {
		if preferred, ok := preferredChildSAProposalDHGroup(sa.Proposals, state.cfg, state.info, dhGroup); ok {
			return createChildSAInvalidKEPayloadNotify(preferred), createChildSAAction{}, nil
		}
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	localInboundSPI, err := randomUint32()
	if err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa child response: generating child spi: %w", err)
	}
	nonceR, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa child response: generating nonce: %w", err)
	}
	var pfs *ikeCrypto
	var keR *ike.KeyExchangePayload
	if keI != nil {
		pfs, err = newIKECrypto(dhGroup)
		if err != nil {
			return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa child response: creating child pfs dh: %w", err)
		}
		keR = &ike.KeyExchangePayload{DHGroup: pfs.dhGroup, Data: pfs.PublicKey()}
	}
	info := cloneInfo(state.info)
	info.ESPInitiatorSPI = localInboundSPI
	info.ESPResponderSPI = peerInboundSPI
	info.Encryption = proposal.Encryption
	info.EncryptionKeyLen = proposal.EncryptionKeyLen
	info.Integrity = proposal.Integrity
	responseTSi, responseTSr := childSARekeyResponseTrafficSelectors(state.info, tsi.Selectors, tsr.Selectors)
	info.InitiatorTrafficSelectors = cloneTrafficSelectors(responseTSi)
	info.ResponderTrafficSelectors = cloneTrafficSelectors(responseTSr)
	var keys ESPKeys
	if pfs != nil {
		keys, err = state.ike.DeriveESPKeysWithDH(info.EncryptionKeyLen, info.Integrity, nonceI.Data, nonceR, pfs, keI.Data)
	} else {
		keys, err = state.ike.DeriveESPKeysWithNonces(info.EncryptionKeyLen, info.Integrity, nonceI.Data, nonceR)
	}
	if err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa child response: deriving esp keys: %w", err)
	}
	responsePayloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{childSAResponseProposal(proposal, localInboundSPI)}},
		&ike.NoncePayload{Data: nonceR},
	}
	if keR != nil {
		responsePayloads = append(responsePayloads, keR)
	}
	responsePayloads = append(responsePayloads,
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSi, Selectors: responseTSi},
		&ike.TrafficSelectorPayload{Tag: payloadTypeTSr, Selectors: responseTSr},
	)
	action := createChildSAAction{
		installChild: true,
		child: childSARekeyResult{
			info: info,
			keys: keys,
			outbound: esp.Codec{
				SPI:           peerInboundSPI,
				Encryption:    esp.EncryptionAESCBC,
				Integrity:     integrityName(info.Integrity),
				EncryptionKey: append([]byte(nil), keys.EncryptionResponder...),
				IntegrityKey:  append([]byte(nil), keys.IntegrityResponder...),
			},
			inbound: esp.Codec{
				SPI:           localInboundSPI,
				Encryption:    esp.EncryptionAESCBC,
				Integrity:     integrityName(info.Integrity),
				EncryptionKey: append([]byte(nil), keys.EncryptionInitiator...),
				IntegrityKey:  append([]byte(nil), keys.IntegrityInitiator...),
			},
			oldInbound: state.inboundSPI,
			nonceI:     append([]byte(nil), nonceI.Data...),
			nonceR:     append([]byte(nil), nonceR...),
		},
	}
	if simultaneous {
		action.simultaneousChild = true
	}
	return responsePayloads, action, nil
}

func childSARekeyResponseTrafficSelectors(info Info, requestTSi, requestTSr []ike.TrafficSelector) ([]ike.TrafficSelector, []ike.TrafficSelector) {
	if len(info.InitiatorTrafficSelectors) != 0 && len(info.ResponderTrafficSelectors) != 0 {
		return cloneTrafficSelectors(info.InitiatorTrafficSelectors), cloneTrafficSelectors(info.ResponderTrafficSelectors)
	}
	return cloneTrafficSelectors(requestTSi), cloneTrafficSelectors(requestTSr)
}

func buildIKESARekeyResponsePayloads(state createChildSARequestState, payloads []ike.Payload) ([]ike.Payload, createChildSAAction, error) {
	if state.pendingIKESA || state.retiredIKESA || state.childRekeying {
		return createChildSAErrorNotify(notifyTypeTemporaryFailure, nil), createChildSAAction{}, nil
	}
	sa := ike.FindSAPayload(payloads)
	nonceI := ike.FindNoncePayload(payloads)
	keI := ike.FindKEPayload(payloads, 0)
	if sa == nil || nonceI == nil || keI == nil || len(sa.Proposals) == 0 {
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	if err := validateNonceData("building create_child_sa ike response", nonceI.Data); err != nil {
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	proposal, peerSPI, err := acceptedIKESARekeyProposal(sa.Proposals, state.ike)
	if err != nil {
		return createChildSAErrorNotify(notifyTypeNoProposalChosen, nil), createChildSAAction{}, nil
	}
	if keI.DHGroup != proposal.DHGroup {
		return createChildSAInvalidKEPayloadNotify(proposal.DHGroup), createChildSAAction{}, nil
	}
	next, err := newIKECrypto(proposal.DHGroup)
	if err != nil {
		return nil, createChildSAAction{}, err
	}
	responderSPI, err := randomUint64()
	if err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa ike response: generating responder spi: %w", err)
	}
	nonceR, err := randomBytes(defaultIKENonceLength)
	if err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa ike response: generating nonce: %w", err)
	}
	next.SetProposal(proposal.Encryption, proposal.EncryptionKeyLen, proposal.Integrity, proposal.PRF)
	next.SetSPIs(peerSPI, responderSPI)
	next.SetNonces(nonceI.Data, nonceR)
	if err := next.DeriveRekeyedIKEKeys(state.ike, keI.Data); err != nil {
		return nil, createChildSAAction{}, fmt.Errorf("building create_child_sa ike response: deriving ike keys: %w", err)
	}
	responsePayloads := []ike.Payload{
		&ike.SecurityAssociationPayload{Proposals: []ike.Proposal{ikeSARekeyResponseProposal(proposal, responderSPI)}},
		&ike.NoncePayload{Data: nonceR},
		&ike.KeyExchangePayload{DHGroup: proposal.DHGroup, Data: next.PublicKey()},
	}
	action := createChildSAAction{
		installIKE: true,
		ike: ikeSARekeyResult{
			crypto:         next,
			initiatorSPI:   peerSPI,
			responderSPI:   responderSPI,
			nonceI:         append([]byte(nil), nonceI.Data...),
			nonceR:         append([]byte(nil), nonceR...),
			localInitiator: false,
		},
	}
	if state.ikeRekeying {
		action.simultaneousIKE = true
	}
	return responsePayloads, action, nil
}

type acceptedIKESAProposal struct {
	negotiatedIKESA
	DHGroup        uint16
	ProposalNumber byte
}

func acceptedIKESARekeyProposal(proposals []ike.Proposal, current *ikeCrypto) (acceptedIKESAProposal, uint64, error) {
	for _, proposal := range proposals {
		if proposal.ProtocolID != proposalProtocolIKE || len(proposal.SPI) != 8 {
			continue
		}
		negotiated, err := negotiatedIKESAFromProposal(proposal, current.dhGroup)
		if err != nil {
			continue
		}
		if negotiated.Encryption != current.encr ||
			negotiated.EncryptionKeyLen != current.encrKeyBits ||
			negotiated.Integrity != current.integ ||
			negotiated.PRF != current.prf {
			continue
		}
		return acceptedIKESAProposal{negotiatedIKESA: negotiated, DHGroup: current.dhGroup, ProposalNumber: proposal.Number}, binary.BigEndian.Uint64(proposal.SPI), nil
	}
	return acceptedIKESAProposal{}, 0, errors.New("no acceptable ike sa rekey proposal")
}

func validateRequestProposalNumbers(proposals []ike.Proposal) error {
	for i, proposal := range proposals {
		want := byte(i + 1)
		if proposal.Number != want {
			return fmt.Errorf("create_child_sa request proposal number = %d, want %d", proposal.Number, want)
		}
	}
	return nil
}

func childSARequestDHGroup(ke *ike.KeyExchangePayload) (uint16, bool) {
	if ke == nil {
		return 0, true
	}
	if err := validateDHGroup(ke.DHGroup); err != nil {
		return 0, false
	}
	return ke.DHGroup, true
}

func preferredChildSADHGroup(cfg Config) uint16 {
	if len(cfg.DHGroups) != 0 {
		return cfg.DHGroups[0]
	}
	return transformDH2048MODP
}

func preferredChildSAProposalDHGroup(proposals []ike.Proposal, cfg Config, current Info, rejected uint16) (uint16, bool) {
	if rejected == 0 {
		return 0, false
	}
	for _, group := range preferredChildSADHGroups(cfg) {
		if group == rejected {
			continue
		}
		if _, _, err := acceptedChildSAProposal(proposals, current, group); err == nil {
			return group, true
		}
	}
	return 0, false
}

func preferredChildSADHGroups(cfg Config) []uint16 {
	if len(cfg.DHGroups) != 0 {
		return cfg.DHGroups
	}
	return []uint16{transformDH2048MODP}
}

func acceptedChildSAProposal(proposals []ike.Proposal, current Info, dhGroup uint16) (uint32, acceptedChildSA, error) {
	for _, proposal := range proposals {
		if proposal.ProtocolID != proposalProtocolESP || len(proposal.SPI) != 4 {
			continue
		}
		info, err := acceptedChildSARequestProposal(proposal, current, dhGroup)
		if err != nil {
			continue
		}
		if !acceptedChildSAMatchesCurrent(info, current) {
			continue
		}
		return binary.BigEndian.Uint32(proposal.SPI), info, nil
	}
	return 0, acceptedChildSA{}, errors.New("no acceptable child sa proposal")
}

func acceptedChildSAMatchesCurrent(accepted acceptedChildSA, current Info) bool {
	return accepted.Encryption == current.Encryption &&
		accepted.EncryptionKeyLen == current.EncryptionKeyLen &&
		accepted.Integrity == current.Integrity
}

func acceptedChildSARequestProposal(proposal ike.Proposal, current Info, dhGroup uint16) (acceptedChildSA, error) {
	if proposal.ProtocolID != proposalProtocolESP {
		return acceptedChildSA{}, fmt.Errorf("building create_child_sa child response: invalid proposal protocol id %d", proposal.ProtocolID)
	}
	if len(proposal.SPI) != 4 {
		return acceptedChildSA{}, fmt.Errorf("building create_child_sa child response: invalid peer esp spi length %d", len(proposal.SPI))
	}
	info := Info{ESPResponderSPI: binary.BigEndian.Uint32(proposal.SPI)}
	accepted := acceptedChildSA{Info: info, ProposalNumber: proposal.Number}
	seenESN := false
	seenDH := false
	for _, transform := range proposal.Transforms {
		switch transform.TransformType {
		case transformTypeENCR:
			if accepted.Encryption != 0 {
				continue
			}
			if transform.ID != transformENCRAESCBC {
				continue
			}
			keyLen, ok := transformKeyLength(transform)
			if !ok {
				continue
			}
			if transform.ID != current.Encryption || keyLen != current.EncryptionKeyLen {
				continue
			}
			accepted.Encryption = transform.ID
			accepted.EncryptionKeyLen = keyLen
		case transformTypeINTEG:
			if accepted.Integrity == 0 && transform.ID == current.Integrity {
				accepted.Integrity = transform.ID
			}
		case transformTypeESN:
			if transform.ID != transformESNNoESN {
				continue
			}
			seenESN = true
		case transformTypeDH:
			if dhGroup == 0 {
				return acceptedChildSA{}, fmt.Errorf("building create_child_sa child response: unexpected dh group %d", transform.ID)
			}
			if transform.ID == dhGroup {
				accepted.DHGroup = transform.ID
				seenDH = true
			}
		default:
			return acceptedChildSA{}, fmt.Errorf("building create_child_sa child response: unsupported proposal transform type %d", transform.TransformType)
		}
	}
	if accepted.Encryption == 0 || accepted.EncryptionKeyLen == 0 || accepted.Integrity == 0 || !seenESN {
		return acceptedChildSA{}, errors.New("building create_child_sa child response: proposal transform is incomplete")
	}
	if dhGroup != 0 && !seenDH {
		return acceptedChildSA{}, fmt.Errorf("building create_child_sa child response: dh group = 0, want %d", dhGroup)
	}
	return accepted, nil
}

func transformKeyLength(transform ike.Transform) (uint16, bool) {
	for _, attr := range transform.Attributes {
		if attr.Type != transformAttrKeyLength {
			continue
		}
		return attr.Uint16()
	}
	return 0, false
}

func childSAResponseProposal(info acceptedChildSA, localInboundSPI uint32) ike.Proposal {
	transforms := []ike.Transform{
		aesCBCTransform(info.EncryptionKeyLen),
		{TransformType: transformTypeINTEG, ID: info.Integrity},
	}
	if info.DHGroup != 0 {
		transforms = append(transforms, ike.Transform{TransformType: transformTypeDH, ID: info.DHGroup})
	}
	transforms = append(transforms, ike.Transform{TransformType: transformTypeESN, ID: transformESNNoESN})
	return ike.Proposal{
		Number:     info.ProposalNumber,
		ProtocolID: proposalProtocolESP,
		SPI:        uint32Bytes(localInboundSPI),
		Transforms: transforms,
	}
}

func ikeSARekeyResponseProposal(proposal acceptedIKESAProposal, responderSPI uint64) ike.Proposal {
	return ike.Proposal{
		Number:     proposal.ProposalNumber,
		ProtocolID: proposalProtocolIKE,
		SPI:        uint64Bytes(responderSPI),
		Transforms: []ike.Transform{
			aesCBCTransform(proposal.EncryptionKeyLen),
			{TransformType: transformTypeINTEG, ID: proposal.Integrity},
			{TransformType: transformTypePRF, ID: proposal.PRF},
			{TransformType: transformTypeDH, ID: proposal.DHGroup},
		},
	}
}

func validRekeySANotifySPI(notify *ike.NotifyPayload) (uint32, bool) {
	if notify.ProtocolID != protocolIDESP || len(notify.SPI) != 4 || len(notify.Data) != 0 {
		return 0, false
	}
	return binary.BigEndian.Uint32(notify.SPI), true
}

func createChildSAErrorNotify(notifyType uint16, spi []byte) []ike.Payload {
	protocolID := protocolIDUnset
	if len(spi) != 0 {
		protocolID = protocolIDESP
	}
	return []ike.Payload{&ike.NotifyPayload{ProtocolID: protocolID, NotifyType: notifyType, SPI: append([]byte(nil), spi...)}}
}

func createChildSAInvalidKEPayloadNotify(dhGroup uint16) []ike.Payload {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, dhGroup)
	return []ike.Payload{&ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeInvalidKEPayload, Data: data}}
}

func (s *Session) writeCreateChildSAResponse(state createChildSARequestState, messageID uint32, request []byte, payloads []ike.Payload, addr net.Addr) error {
	wire, err := state.ike.SealIKE(createChildSAResponseHeader(state, messageID), payloads, state.localInitiator)
	if err != nil {
		return fmt.Errorf("sealing create_child_sa response: %w", err)
	}
	wire = prependNonESPMarker(wire)
	s.cacheInformationalResponseForState(state.informationalState(), messageID, request, wire)
	return s.writeCreateChildSAResponseWire(state, messageID, len(payloads), wire, addr)
}

func (s *Session) writeCreateChildSAResponseWire(state createChildSARequestState, messageID uint32, payloadCount int, wire []byte, addr net.Addr) error {
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	peer := s.informationalResponsePeer(addr, nil)
	if err := s.writeProtectedWire(ctx, "writing create_child_sa response", state.ike, wire, peer, false); err != nil {
		return err
	}
	s.logger.Debug("replied to create_child_sa request", "message_id", messageID, "payload_count", payloadCount)
	return nil
}

func createChildSAResponseHeader(state createChildSARequestState, messageID uint32) ike.IKEHeader {
	flags := flagResponse
	if state.localInitiator {
		flags |= flagInitiator
	}
	return ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeCreateChildSA,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func proposalTransformIDValue(proposal ike.Proposal, transformType byte) uint16 {
	for _, transform := range proposal.Transforms {
		if transform.TransformType == transformType {
			return transform.ID
		}
	}
	return 0
}
