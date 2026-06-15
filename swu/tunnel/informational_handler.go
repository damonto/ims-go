package tunnel

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

func (s *Session) handleInformationalResponse(state informationalState, packet ike.IKEPacket, data []byte, addr net.Addr) (bool, error) {
	key := ikeMessageKeyForHeader(packet.Header)
	if !s.hasInformationalWaiter(key) {
		s.logger.Debug("ignoring informational response without matching request", "message_id", packet.Header.MessageID)
		return true, nil
	}
	payloads, _, complete, stored, err := s.openIKEPacketForState(state, packet, state.peerInitiator())
	if err != nil {
		return true, fmt.Errorf("opening informational response: %w", err)
	}
	if !stored {
		return true, nil
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state, data, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state, now)
	if !complete {
		return true, nil
	}
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(key, inboundIKE{data: append([]byte(nil), data...), payloads: payloads, addr: cloneUDPAddr(udpAddr)}) {
		s.logger.Debug("matched informational response", "message_id", packet.Header.MessageID)
	}
	if accept.expired {
		s.failSecurityAssociations(errIKESAExpired)
	}
	return true, nil
}

func (s *Session) handleCreateChildSAResponse(state informationalState, packet ike.IKEPacket, data []byte, addr net.Addr) (bool, error) {
	key := ikeMessageKeyForHeader(packet.Header)
	if !s.hasInformationalWaiter(key) {
		s.logger.Debug("ignoring create_child_sa response without matching request", "message_id", packet.Header.MessageID)
		return true, nil
	}
	payloads, _, complete, stored, err := s.openIKEPacketForState(state, packet, state.peerInitiator())
	if err != nil {
		return true, err
	}
	if !stored {
		return true, nil
	}
	if packet.Header.ExchangeType != exchangeTypeCreateChildSA {
		return true, fmt.Errorf("handling create_child_sa response: unexpected exchange type %d", packet.Header.ExchangeType)
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state, data, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state, now)
	if !complete {
		return true, nil
	}
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(key, inboundIKE{data: append([]byte(nil), data...), payloads: payloads, addr: cloneUDPAddr(udpAddr)}) {
		s.logger.Debug("matched create_child_sa response", "message_id", packet.Header.MessageID)
	}
	if accept.expired {
		s.failSecurityAssociations(errIKESAExpired)
	}
	return true, nil
}

func informationalResponseHeader(state informationalState, messageID uint32) ike.IKEHeader {
	flags := flagResponse
	if state.localInitiator {
		flags |= flagInitiator
	}
	return ike.IKEHeader{
		InitiatorSPI: state.initiatorSPI,
		ResponderSPI: state.responderSPI,
		Version:      ikeVersion20,
		ExchangeType: exchangeTypeInformational,
		Flags:        flags,
		MessageID:    messageID,
	}
}

func (s *Session) sealInformationalResponse(state informationalState, messageID uint32, payloads []ike.Payload) ([][]byte, error) {
	wires, err := sealIKEPackets(state.ike, informationalResponseHeader(state, messageID), payloads, state.localInitiator, state.ikeFragmentationSupported)
	if err != nil {
		return nil, fmt.Errorf("sealing informational response: %w", err)
	}
	return buildIKEWires(wires, state.useNATT), nil
}

func (s *Session) writeInformationalResponse(state informationalState, messageID uint32, request []byte, payloads []ike.Payload, addr net.Addr) error {
	wires, err := s.sealInformationalResponse(state, messageID, payloads)
	if err != nil {
		return err
	}
	s.cacheInformationalResponseForState(state, messageID, request, wires)
	return s.writeInformationalResponseWire(state, messageID, len(payloads), wires, addr)
}

func (s *Session) writeInformationalResponseWire(state informationalState, messageID uint32, payloadCount int, wires [][]byte, addr net.Addr) error {
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	peer := s.informationalResponsePeer(addr, state.peer)
	if err := s.writeProtectedWires(ctx, ikeActionWriteInformationalResponse, state.ike, wires, peer, false); err != nil {
		return err
	}
	s.logger.Debug("replied to informational request", "message_id", messageID, "payload_count", payloadCount)
	return nil
}

func (s *Session) handleInformationalRequest(state informationalState, packet ike.IKEPacket, addr net.Addr) (bool, error) {
	relation := s.peerRequestMessageIDRelationForState(state, packet.Header.MessageID)
	if relation != ikeMessageIDCurrent {
		return s.handleNonCurrentInformationalRequest(state, packet, addr, relation)
	}
	payloads, cacheRequest, complete, stored, err := s.openIKEPacketForState(state, packet, state.peerInitiator())
	if err != nil {
		if responsePayloads, ok := ikeErrorNotifyResponse(err); ok {
			return s.writeIKEErrorNotifyInformationalResponse(state, packet, cacheRequest, addr, responsePayloads)
		}
		return true, fmt.Errorf("opening informational request: %w", err)
	}
	if !stored {
		return true, nil
	}
	if state.promoteIKESA {
		s.promotePendingIKESecurityAssociation()
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state, packet.Raw, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state, now)
	expireAfterRequest := accept.expired
	if canRetransmitCachedResponse(packet) {
		if wires, ok := s.cachedInformationalResponseForState(state, packet.Header.MessageID, cacheRequest); ok {
			err := s.writeInformationalResponseWire(state, packet.Header.MessageID, 0, wires, addr)
			if expireAfterRequest {
				s.failSecurityAssociations(errIKESAExpired)
			}
			return true, err
		}
	}
	if !complete {
		return true, nil
	}
	defer func() {
		if expireAfterRequest {
			s.failSecurityAssociations(errIKESAExpired)
		}
	}()
	responsePayloads, action, err := buildInformationalResponsePayloads(state, payloads, state.identity)
	if err != nil {
		return true, err
	}
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, cacheRequest, responsePayloads, addr); err != nil {
		return true, err
	}
	advanceErr := s.advancePeerRequestMessageIDForState(state, packet.Header.MessageID)
	if action.deleteIKE {
		s.logger.Debug("received IKE delete request", "message_id", packet.Header.MessageID, "reactivation_requested", action.reactivationRequested)
		if state.retiredIKESA {
			expireAfterRequest = false
			s.removeRetiredIKESA(state)
			if advanceErr != nil {
				s.failSecurityAssociations(advanceErr)
				return true, advanceErr
			}
			return true, nil
		}
		if s.promotePendingIKESecurityAssociation() {
			expireAfterRequest = false
			if advanceErr != nil {
				s.failSecurityAssociations(advanceErr)
				return true, advanceErr
			}
			return true, nil
		}
		expireAfterRequest = false
		cause := errors.New("peer deleted IKE SA")
		if action.reactivationRequested {
			cause = reactivationRequestedError(cause)
		}
		if action.pdnDeactivated {
			cause = pdnDeactivatedError(cause)
		}
		s.failSecurityAssociations(cause)
	}
	if action.deleteChild {
		s.logger.Debug("received child sa delete request", "message_id", packet.Header.MessageID, "inbound_spi", state.inboundSPI, "outbound_spi", state.outboundSPI, "reactivation_requested", action.reactivationRequested)
		cause := errors.New("peer deleted child SA")
		if action.reactivationRequested {
			cause = reactivationRequestedError(cause)
		}
		if action.pdnDeactivated {
			cause = pdnDeactivatedError(cause)
		}
		s.discardChildSecurityAssociations(cause)
	}
	if action.promotePendingChild {
		s.logger.Debug("received old child sa delete request", "message_id", packet.Header.MessageID, "old_inbound_spi", state.oldInboundSPI, "old_outbound_spi", state.outboundSPI)
		s.promotePendingChildSecurityAssociation()
	}
	for _, spi := range action.deleteRetiredChildSPIs {
		s.removeRetiredChildSA(spi)
	}
	if action.pcscfReselection {
		s.applyPCSCFReselection(action.pcscfInfo)
	}
	if advanceErr != nil {
		s.failSecurityAssociations(advanceErr)
		return true, advanceErr
	}
	return true, nil
}

func (s *Session) handleNonCurrentInformationalRequest(state informationalState, packet ike.IKEPacket, addr net.Addr, relation ikeMessageIDRelation) (bool, error) {
	switch relation {
	case ikeMessageIDFuture:
		s.logger.Debug("ignoring informational request outside message id window", "message_id", packet.Header.MessageID)
		if err := s.sendInvalidMessageIDNotification(state, packet.Header.MessageID); err != nil {
			s.logger.Debug("sending invalid message id notification failed", "message_id", packet.Header.MessageID, "err", err)
		}
		return true, nil
	case ikeMessageIDOld:
		if canRetransmitCachedResponse(packet) {
			if wires, ok := s.cachedInformationalResponseForState(state, packet.Header.MessageID, packet.Raw); ok {
				return true, s.writeInformationalResponseWire(state, packet.Header.MessageID, 0, wires, addr)
			}
		}
		s.logger.Debug("ignoring old informational request without cached response", "message_id", packet.Header.MessageID)
		return true, nil
	default:
		return true, nil
	}
}

func (s *Session) applyPCSCFReselection(info Info) {
	if len(info.PCSCFIPs) == 0 {
		return
	}
	s.mu.Lock()
	if !s.connected {
		s.mu.Unlock()
		return
	}
	next := cloneInfo(s.tunnel)
	next.PCSCFIPs = cloneIPList(info.PCSCFIPs)
	local, remote := innerAddrsForInfo(next, nil, s.cfg.LocalSIPPort, s.cfg.SIPPort)
	if local == nil || remote == nil {
		s.mu.Unlock()
		return
	}
	s.tunnel = next
	s.innerLocal = local
	s.innerRemote = remote
	current := cloneInfo(s.tunnel)
	s.mu.Unlock()

	s.tryDeliverError(fmt.Errorf("reading packet: %w", pcscfReselectionRequestedError(current)))
}

func ikeErrorNotifyResponse(err error) ([]ike.Payload, bool) {
	var critical ike.UnsupportedCriticalPayloadError
	if errors.As(err, &critical) {
		return []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeUnsupportedCriticalPayload, Data: []byte{critical.PayloadType}}}, true
	}
	var invalidSyntax ike.InvalidSyntaxError
	if errors.As(err, &invalidSyntax) {
		return []ike.Payload{&ike.NotifyPayload{NotifyType: notifyTypeInvalidSyntax}}, true
	}
	return nil, false
}

func (s *Session) writeIKEErrorNotifyInformationalResponse(state informationalState, packet ike.IKEPacket, request []byte, addr net.Addr, payloads []ike.Payload) (bool, error) {
	if state.promoteIKESA {
		s.promotePendingIKESecurityAssociation()
	}
	now := time.Now()
	accept, err := s.acceptIKEProtectedBytesForState(state, packet.Raw, now)
	if err != nil {
		return true, err
	}
	if !accept.accepted {
		if accept.expired {
			s.failSecurityAssociations(errIKESAExpired)
		}
		return true, nil
	}
	s.markProtectedRxForState(state, now)
	expireAfterRequest := accept.expired
	defer func() {
		if expireAfterRequest {
			s.failSecurityAssociations(errIKESAExpired)
		}
	}()
	switch s.peerRequestMessageIDRelationForState(state, packet.Header.MessageID) {
	case ikeMessageIDCurrent:
	case ikeMessageIDFuture:
		if err := s.sendInvalidMessageIDNotification(state, packet.Header.MessageID); err != nil {
			s.logger.Debug("sending invalid message id notification failed", "message_id", packet.Header.MessageID, "err", err)
		}
		return true, nil
	default:
		return true, nil
	}
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, responseCacheRequest(packet, request), payloads, addr); err != nil {
		return true, err
	}
	if err := s.advancePeerRequestMessageIDForState(state, packet.Header.MessageID); err != nil {
		s.failSecurityAssociations(err)
		return true, err
	}
	return true, nil
}

func (s *Session) handleIKEPacket(data []byte, addr net.Addr) (bool, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return false, nil
	}
	state, ok := s.informationalStateForPacket(packet)
	if !ok {
		return false, nil
	}
	if packet.Header.Flags&flagResponse != 0 {
		if packet.Header.ExchangeType == exchangeTypeCreateChildSA {
			return s.handleCreateChildSAResponse(state, packet, data, addr)
		}
		if packet.Header.ExchangeType != exchangeTypeInformational {
			return false, nil
		}
		return s.handleInformationalResponse(state, packet, data, addr)
	}
	if packet.Header.ExchangeType != exchangeTypeInformational {
		if packet.Header.ExchangeType == exchangeTypeCreateChildSA {
			return s.handleCreateChildSARequest(state.createChildSARequestState(), packet, addr)
		}
		return false, nil
	}
	return s.handleInformationalRequest(state, packet, addr)
}

func decodeIKEHeader(data []byte) (ike.IKEHeader, bool) {
	var header ike.IKEHeader
	if err := header.UnmarshalBinary(data); err != nil {
		return ike.IKEHeader{}, false
	}
	return header, true
}
