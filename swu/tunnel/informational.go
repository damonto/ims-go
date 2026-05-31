package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/damonto/vowifi-go/swu/ike"
)

const informationalResponseCacheWindow = 8
const maxIKEMessageID = ^uint32(0)
const minCookie2NotifyDataLength = 8
const natKeepaliveWriteTimeout = 2 * time.Second

var errIKESASuperseded = errors.New("ike sa was superseded")
var errIKERequestIncomplete = errors.New("ike request completed without response")
var errIKEMessageIDExhausted = errors.New("ike message id exhausted")
var livenessCheckTimeout = 30 * time.Second
var invalidMessageIDNotifyTimeout = 750 * time.Millisecond

const invalidMessageIDNotifyMinInterval = 10 * time.Second

type ikeMessageIDRelation byte

const (
	ikeMessageIDCurrent ikeMessageIDRelation = iota
	ikeMessageIDOld
	ikeMessageIDFuture
)

type ikeMessageKey struct {
	initiatorSPI uint64
	responderSPI uint64
	messageID    uint32
}

func (s *Session) allocateMessageID() (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextMessageID == maxIKEMessageID {
		return 0, errIKEMessageIDExhausted
	}
	messageID := s.nextMessageID
	s.nextMessageID = messageID + 1
	return messageID, nil
}

func (s *Session) peerRequestMessageIDCurrent(messageID uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return messageID == s.nextPeerMessageID
}

func (s *Session) allowInvalidMessageIDNotification(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastInvalidMessageID.IsZero() && now.Sub(s.lastInvalidMessageID) < invalidMessageIDNotifyMinInterval {
		return false
	}
	s.lastInvalidMessageID = now
	return true
}

func (s *Session) acquireIKERequest(ctx context.Context, action string) (func(), error) {
	select {
	case s.ikeRequestGate <- struct{}{}:
		return func() { <-s.ikeRequestGate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", action, ctx.Err())
	case <-s.closeDone():
		return nil, fmt.Errorf("%s: session is closed", action)
	}
}

func (s *Session) advancePeerRequestMessageID(messageID uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if messageID == s.nextPeerMessageID {
		if messageID == maxIKEMessageID {
			return errIKEMessageIDExhausted
		}
		s.nextPeerMessageID = messageID + 1
	}
	return nil
}

func (s *Session) peerRequestMessageIDRelationForState(state informationalState, messageID uint32) ikeMessageIDRelation {
	expected := state.nextPeerMessageID
	if !state.retiredIKESA {
		s.mu.RLock()
		expected = s.nextPeerMessageID
		s.mu.RUnlock()
	}
	switch {
	case messageID == expected:
		return ikeMessageIDCurrent
	case messageID < expected:
		return ikeMessageIDOld
	default:
		return ikeMessageIDFuture
	}
}

func (s *Session) advancePeerRequestMessageIDForState(state informationalState, messageID uint32) error {
	if !state.retiredIKESA {
		return s.advancePeerRequestMessageID(messageID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if !retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			continue
		}
		if messageID == s.retiredIKESAs[i].nextPeerMessageID {
			if messageID == maxIKEMessageID {
				return errIKEMessageIDExhausted
			}
			s.retiredIKESAs[i].nextPeerMessageID = messageID + 1
		}
		return nil
	}
	return nil
}

func (s *Session) registerInformationalWaiter(key ikeMessageKey) chan inboundIKE {
	ch := make(chan inboundIKE, 1)
	s.mu.Lock()
	if s.informWaiters == nil {
		s.informWaiters = make(map[ikeMessageKey]chan inboundIKE)
	}
	s.informWaiters[key] = ch
	s.mu.Unlock()
	return ch
}

func (s *Session) unregisterInformationalWaiter(key ikeMessageKey, ch chan inboundIKE) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if current, ok := s.informWaiters[key]; ok && current == ch {
		delete(s.informWaiters, key)
	}
}

func (s *Session) hasInformationalWaiter(key ikeMessageKey) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.informWaiters[key]
	return ok
}

func (s *Session) deliverInformationalWaiter(key ikeMessageKey, packet inboundIKE) bool {
	s.mu.Lock()
	ch, ok := s.informWaiters[key]
	if ok {
		delete(s.informWaiters, key)
	}
	s.mu.Unlock()
	if !ok {
		return false
	}
	select {
	case ch <- packet:
	default:
	}
	return true
}

func (s *Session) abortInformationalWaiters(err error) {
	s.mu.Lock()
	waiters := s.informWaiters
	s.informWaiters = nil
	s.mu.Unlock()
	notifyInformationalWaiters(waiters, err)
}

func notifyInformationalWaiters(waiters map[ikeMessageKey]chan inboundIKE, err error) {
	if err == nil {
		return
	}
	for _, ch := range waiters {
		select {
		case ch <- inboundIKE{err: err}:
		default:
		}
	}
}

func (s *Session) cachedInformationalResponse(messageID uint32, request []byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.informResponses) == 0 {
		return nil, false
	}
	wire, ok := s.informResponses[messageID]
	if !ok {
		return nil, false
	}
	if cachedRequest, ok := s.informResponseReqs[messageID]; ok && !bytes.Equal(cachedRequest, request) {
		return nil, false
	}
	return append([]byte(nil), wire...), true
}

func (s *Session) cachedInformationalResponseForState(state informationalState, messageID uint32, request []byte) ([]byte, bool) {
	if !state.retiredIKESA {
		return s.cachedInformationalResponse(messageID, request)
	}
	wire, ok := state.responses[messageID]
	if !ok {
		return nil, false
	}
	if cachedRequest, ok := state.responseReqs[messageID]; ok && !bytes.Equal(cachedRequest, request) {
		return nil, false
	}
	return append([]byte(nil), wire...), true
}

func (s *Session) cacheInformationalResponse(messageID uint32, request, wire []byte) {
	if len(wire) == 0 {
		return
	}
	s.mu.Lock()
	if s.informResponses == nil {
		s.informResponses = make(map[uint32][]byte)
	}
	s.informResponses[messageID] = append([]byte(nil), wire...)
	if len(request) != 0 {
		if s.informResponseReqs == nil {
			s.informResponseReqs = make(map[uint32][]byte)
		}
		s.informResponseReqs[messageID] = append([]byte(nil), request...)
	}
	for cachedID := range s.informResponses {
		if messageID >= cachedID && messageID-cachedID >= informationalResponseCacheWindow {
			delete(s.informResponses, cachedID)
			delete(s.informResponseReqs, cachedID)
		}
	}
	s.mu.Unlock()
}

func (s *Session) cacheInformationalResponseForState(state informationalState, messageID uint32, request, wire []byte) {
	if !state.retiredIKESA {
		s.cacheInformationalResponse(messageID, request, wire)
		return
	}
	if len(wire) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if !retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			continue
		}
		if s.retiredIKESAs[i].responses == nil {
			s.retiredIKESAs[i].responses = make(map[uint32][]byte)
		}
		s.retiredIKESAs[i].responses[messageID] = append([]byte(nil), wire...)
		if len(request) != 0 {
			if s.retiredIKESAs[i].responseReqs == nil {
				s.retiredIKESAs[i].responseReqs = make(map[uint32][]byte)
			}
			s.retiredIKESAs[i].responseReqs[messageID] = append([]byte(nil), request...)
		}
		for cachedID := range s.retiredIKESAs[i].responses {
			if messageID >= cachedID && messageID-cachedID >= informationalResponseCacheWindow {
				delete(s.retiredIKESAs[i].responses, cachedID)
				delete(s.retiredIKESAs[i].responseReqs, cachedID)
			}
		}
		return
	}
}

type informationalState struct {
	connected         bool
	ike               *ikeCrypto
	localInitiator    bool
	ikeRekeying       bool
	pendingIKESA      bool
	retiredIKESA      bool
	childRekeying     bool
	cfg               Config
	initiatorSPI      uint64
	responderSPI      uint64
	identity          string
	peer              *net.UDPAddr
	info              Info
	inboundSPI        uint32
	outboundSPI       uint32
	pendingChild      bool
	oldInboundSPI     uint32
	retiredChildSAs   []retiredChildSAState
	promoteIKESA      bool
	nextPeerMessageID uint32
	responses         map[uint32][]byte
	responseReqs      map[uint32][]byte
}

type retiredChildSAState struct {
	inboundSPI  uint32
	outboundSPI uint32
}

type informationalAction struct {
	deleteIKE             bool
	deleteChild           bool
	reactivationRequested bool
	promotePendingChild   bool
	deleteRetiredChildSPI uint32
	pcscfReselection      bool
	pcscfInfo             Info
}

func (s *Session) currentInformationalState() informationalState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentInformationalStateLocked()
}

func (s *Session) currentInformationalStateLocked() informationalState {
	return informationalState{
		connected:         s.connected,
		ike:               s.ike,
		localInitiator:    s.ikeLocalInitiator,
		ikeRekeying:       s.ikeSARekeying,
		pendingIKESA:      s.pendingIKESAReady,
		childRekeying:     s.childSARekeying,
		cfg:               s.cfg,
		initiatorSPI:      s.initiatorSPI,
		responderSPI:      s.responderSPI,
		identity:          s.deviceIdentity,
		peer:              cloneUDPAddr(s.outerNAT),
		info:              cloneInfo(s.tunnel),
		inboundSPI:        s.tunnel.ESPInitiatorSPI,
		outboundSPI:       s.tunnel.ESPResponderSPI,
		pendingChild:      s.pendingChildSA.ready,
		oldInboundSPI:     s.pendingChildSA.oldInbound,
		retiredChildSAs:   retiredChildSAStates(s.retiredChildSAs),
		nextPeerMessageID: s.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(s.informResponses),
		responseReqs:      cloneIKEMessageResponses(s.informResponseReqs),
	}
}

func retiredChildSAStates(children []retiredChildSA) []retiredChildSAState {
	states := make([]retiredChildSAState, 0, len(children))
	for _, child := range children {
		states = append(states, retiredChildSAState{
			inboundSPI:  child.inbound.SPI,
			outboundSPI: child.outboundSPI,
		})
	}
	return states
}

func (s *Session) informationalStateForPacket(packet ike.IKEPacket) (informationalState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.pruneRetiredIKESAsLocked(now)
	state := s.currentInformationalStateLocked()
	if state.matches(packet) {
		return state, true
	}
	if s.pendingIKESAReady {
		pending := state
		pending.ike = s.pendingIKESA.crypto
		pending.localInitiator = s.pendingIKESA.localInitiator
		pending.initiatorSPI = s.pendingIKESA.initiatorSPI
		pending.responderSPI = s.pendingIKESA.responderSPI
		pending.ikeRekeying = false
		pending.pendingIKESA = false
		pending.promoteIKESA = true
		if pending.matches(packet) {
			return pending, true
		}
	}
	for _, retired := range s.retiredIKESAs {
		retiredState := state
		retiredState.ike = retired.ike
		retiredState.localInitiator = retired.localInitiator
		retiredState.initiatorSPI = retired.initiatorSPI
		retiredState.responderSPI = retired.responderSPI
		retiredState.peer = cloneUDPAddr(retired.peer)
		retiredState.ikeRekeying = false
		retiredState.pendingIKESA = false
		retiredState.retiredIKESA = true
		retiredState.promoteIKESA = false
		retiredState.nextPeerMessageID = retired.nextPeerMessageID
		retiredState.responses = cloneIKEMessageResponses(retired.responses)
		retiredState.responseReqs = cloneIKEMessageResponses(retired.responseReqs)
		if retiredState.matches(packet) {
			return retiredState, true
		}
	}
	return informationalState{}, false
}

func (state informationalState) matches(packet ike.IKEPacket) bool {
	if state.ike == nil {
		return false
	}
	return packet.Header.InitiatorSPI == state.initiatorSPI && packet.Header.ResponderSPI == state.responderSPI
}

func (state informationalState) canSendDelete() bool {
	return state.available()
}

func (state informationalState) sealDeleteRequest(messageID uint32) ([]byte, error) {
	return state.sealInitiatorRequest(messageID, []ike.Payload{&ike.DeletePayload{ProtocolID: protocolIDIKE}})
}

func (s *Session) sendDeleteRequest(ctx context.Context) error {
	state := s.currentInformationalState()
	if !state.canSendDelete() {
		return nil
	}
	release, err := s.acquireIKERequest(ctx, "closing swu session")
	if err != nil {
		return err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return fmt.Errorf("closing swu session: %w", err)
	}
	key := state.messageKey(messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wire, err := state.sealDeleteRequest(messageID)
	if err != nil {
		return fmt.Errorf("closing swu session: sealing delete request: %w", err)
	}
	payloads, err := s.exchangeInformationalRequest(ctx, state, messageID, wire, waiter, "closing swu session", false)
	if err != nil {
		return err
	}
	return validateIKEDeleteResponsePayloads("closing swu session", payloads)
}

func validateIKEDeleteResponsePayloads(action string, payloads []ike.Payload) error {
	if len(payloads) != 0 {
		return fmt.Errorf("%s: ike delete response payload count %d", action, len(payloads))
	}
	return nil
}

func (s *Session) closeDone() <-chan struct{} {
	return s.closeCtx.Done()
}

func (state informationalState) available() bool {
	return state.ike != nil && state.peer != nil
}

func (state informationalState) messageKey(messageID uint32) ikeMessageKey {
	return ikeMessageKey{
		initiatorSPI: state.initiatorSPI,
		responderSPI: state.responderSPI,
		messageID:    messageID,
	}
}

func ikeMessageKeyForHeader(header ike.IKEHeader) ikeMessageKey {
	return ikeMessageKeyForSPIs(header.InitiatorSPI, header.ResponderSPI, header.MessageID)
}

func ikeMessageKeyForSPIs(initiatorSPI, responderSPI uint64, messageID uint32) ikeMessageKey {
	return ikeMessageKey{
		initiatorSPI: initiatorSPI,
		responderSPI: responderSPI,
		messageID:    messageID,
	}
}

func (state informationalState) initiatorHeader(messageID uint32) ike.IKEHeader {
	flags := byte(0)
	if state.localInitiator {
		flags = flagInitiator
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

func (state informationalState) sealInitiatorRequest(messageID uint32, payloads []ike.Payload) ([]byte, error) {
	return state.ike.SealIKE(state.initiatorHeader(messageID), payloads, state.localInitiator)
}

func (s *Session) sendInvalidMessageIDNotification(state informationalState, invalidMessageID uint32) error {
	if !state.available() || !s.allowInvalidMessageIDNotification(time.Now()) {
		return nil
	}
	ctx, cancel := context.WithTimeout(s.closeCtx, invalidMessageIDNotifyTimeout)
	defer cancel()
	release, err := s.acquireIKERequest(ctx, "sending invalid message id notification")
	if err != nil {
		return err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return fmt.Errorf("sending invalid message id notification: %w", err)
	}
	key := state.messageKey(messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wire, err := state.sealInitiatorRequest(messageID, []ike.Payload{
		&ike.NotifyPayload{NotifyType: notifyTypeInvalidMessageID, Data: uint32Bytes(invalidMessageID)},
	})
	if err != nil {
		return fmt.Errorf("sending invalid message id notification: sealing request: %w", err)
	}
	if _, err := s.exchangeInformational(ctx, state, messageID, wire, waiter); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return nil
}

func (state informationalState) peerInitiator() bool {
	return !state.localInitiator
}

func (state informationalState) createChildSARequestState() createChildSARequestState {
	return createChildSARequestState{
		ike:               state.ike,
		localInitiator:    state.localInitiator,
		ikeRekeying:       state.ikeRekeying,
		pendingIKESA:      state.pendingIKESA,
		retiredIKESA:      state.retiredIKESA,
		childRekeying:     state.childRekeying,
		cfg:               state.cfg,
		info:              cloneInfo(state.info),
		initiatorSPI:      state.initiatorSPI,
		responderSPI:      state.responderSPI,
		peer:              cloneUDPAddr(state.peer),
		inboundSPI:        state.inboundSPI,
		outboundSPI:       state.outboundSPI,
		promoteIKESA:      state.promoteIKESA,
		nextPeerMessageID: state.nextPeerMessageID,
		responses:         cloneIKEMessageResponses(state.responses),
		responseReqs:      cloneIKEMessageResponses(state.responseReqs),
	}
}

func (s *Session) sendInformational(ctx context.Context, payloads []ike.Payload) ([]ike.Payload, error) {
	if s.isClosed() {
		return nil, errors.New("sending informational: session is closed")
	}
	if err := s.expireIKESAIfNeeded("sending informational"); err != nil {
		return nil, err
	}
	if s.ikeSARekeyActive() {
		return nil, errIKESARekeyInProgress
	}
	state := s.currentInformationalState()
	if !state.available() {
		return nil, errors.New("sending informational: ike state is unavailable")
	}
	release, err := s.acquireIKERequest(ctx, "sending informational")
	if err != nil {
		return nil, err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return nil, fmt.Errorf("sending informational: %w", err)
	}
	key := state.messageKey(messageID)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wire, err := state.sealInitiatorRequest(messageID, payloads)
	if err != nil {
		return nil, fmt.Errorf("sending informational: sealing request: %w", err)
	}
	return s.exchangeInformational(ctx, state, messageID, wire, waiter)
}

func (s *Session) exchangeInformational(ctx context.Context, state informationalState, messageID uint32, wire []byte, waiter <-chan inboundIKE) ([]ike.Payload, error) {
	return s.exchangeInformationalRequest(ctx, state, messageID, wire, waiter, "sending informational", false)
}

func (s *Session) exchangeInformationalRequest(ctx context.Context, state informationalState, messageID uint32, wire []byte, waiter <-chan inboundIKE, action string, skipIKESAByteAccounting bool) ([]ike.Payload, error) {
	for attempt, delay := range s.ikeRetransmitDelays() {
		if err := s.writeInformationalRequest(ctx, state, wire, action, skipIKESAByteAccounting); err != nil {
			return nil, err
		}
		payloads, received, err := s.awaitInformationalResponse(ctx, state, waiter, delay)
		if err != nil {
			return nil, err
		}
		if received {
			return payloads, nil
		}
		s.logger.Debug("retransmitting informational message", "action", action, "message_id", messageID, "attempt", attempt+1)
	}
	return nil, fmt.Errorf("%s: waiting message %d: %w", action, messageID, errIKERequestIncomplete)
}

func (s *Session) writeInformationalRequest(ctx context.Context, state informationalState, wire []byte, action string, skipIKESAByteAccounting bool) error {
	return s.writeProtectedWire(ctx, action, state.ike, prependNonESPMarker(wire), state.peer, skipIKESAByteAccounting)
}

func (s *Session) awaitInformationalResponse(ctx context.Context, state informationalState, waiter <-chan inboundIKE, delay time.Duration) ([]ike.Payload, bool, error) {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return nil, false, fmt.Errorf("%w: %w", errIKERequestIncomplete, ctx.Err())
	case <-s.closeDone():
		return nil, false, errors.New("sending informational: session is closed")
	case response := <-waiter:
		if response.err != nil {
			return nil, false, fmt.Errorf("sending informational: %w", response.err)
		}
		payloads, err := s.openInformationalResponse(state, response.data)
		if err != nil {
			return nil, false, err
		}
		return payloads, true, nil
	case <-timer.C:
		return nil, false, nil
	}
}

func (s *Session) openInformationalResponse(state informationalState, data []byte) ([]ike.Payload, error) {
	var packet ike.IKEPacket
	if err := packet.UnmarshalBinary(data); err != nil {
		return nil, fmt.Errorf("sending informational: parsing response: %w", err)
	}
	payloads, err := state.ike.OpenIKE(packet, state.peerInitiator())
	if err != nil {
		return nil, fmt.Errorf("sending informational: opening response: %w", err)
	}
	return payloads, nil
}

func (s *Session) acceptIKEProtectedBytesForState(state informationalState, wire []byte, now time.Time) (ikeAcceptResult, error) {
	if !state.retiredIKESA {
		return s.acceptIKEProtectedBytes(state.ike, wire, now)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.retiredIKESAs {
		if !retiredIKESAMatches(s.retiredIKESAs[i], state.initiatorSPI, state.responderSPI) {
			continue
		}
		if !s.retiredIKESAs[i].expiresAt.IsZero() && !now.Before(s.retiredIKESAs[i].expiresAt) {
			s.retiredIKESAs = append(s.retiredIKESAs[:i], s.retiredIKESAs[i+1:]...)
			return ikeAcceptResult{}, nil
		}
		return ikeAcceptResult{accepted: true}, nil
	}
	return ikeAcceptResult{}, nil
}

func (s *Session) markProtectedRxForState(state informationalState, now time.Time) {
	if state.retiredIKESA {
		return
	}
	s.markProtectedRx(now)
}

func (s *Session) livenessLoop() {
	defer s.wg.Done()
	for {
		if !s.waitForLivenessCheck(s.nextLivenessCheckDeadline()) {
			return
		}
		s.mu.RLock()
		timeout := s.livenessTimeout
		lastRx := s.lastProtectedRx
		s.mu.RUnlock()
		if timeout <= 0 || lastRx.IsZero() || time.Since(lastRx) < timeout {
			continue
		}
		ctx, cancel := context.WithTimeout(s.closeCtx, livenessCheckTimeout)
		_, err := s.sendInformational(ctx, nil)
		cancel()
		if err == nil {
			s.markProtectedRx(time.Now())
			continue
		}
		if errors.Is(err, errIKESARekeyInProgress) {
			if !s.waitForLivenessCheck(time.Now().Add(time.Second)) {
				return
			}
			continue
		}
		cause := fmt.Errorf("liveness check: %w", err)
		s.tryDeliverError(cause)
		s.failSecurityAssociations(cause)
		return
	}
}

func (s *Session) nextLivenessCheckDeadline() time.Time {
	s.mu.RLock()
	timeout := s.livenessTimeout
	lastRx := s.lastProtectedRx
	s.mu.RUnlock()
	if timeout <= 0 || lastRx.IsZero() {
		return time.Time{}
	}
	return lastRx.Add(timeout)
}

func (s *Session) waitForLivenessCheck(deadline time.Time) bool {
	if deadline.IsZero() {
		<-s.closeCtx.Done()
		return false
	}
	if !time.Now().Before(deadline) {
		return true
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-s.closeCtx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (s *Session) natKeepaliveLoop() {
	defer s.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.closeCtx.Done():
			return
		case <-ticker.C:
		}
		s.mu.RLock()
		interval := s.natKeepaliveInterval
		lastTx := s.lastProtectedTx
		peer := cloneUDPAddr(s.outerNAT)
		s.mu.RUnlock()
		if interval <= 0 || peer == nil || lastTx.IsZero() || time.Since(lastTx) < interval {
			continue
		}
		ctx, cancel := context.WithTimeout(s.closeCtx, natKeepaliveWriteTimeout)
		err := s.writeOuter(ctx, []byte{0xff}, peer)
		cancel()
		if err != nil {
			if s.closeCtx.Err() == nil {
				s.logger.Debug("sending NAT keepalive failed", "err", err)
			}
			continue
		}
		s.markProtectedTx(time.Now())
	}
}

func buildDeviceIdentityResponsePayload(payloads []ike.Payload, identity string) (*ike.NotifyPayload, bool, error) {
	notify := ike.FindNotifyPayload(payloads, notifyTypeDeviceIdentity)
	if notify == nil {
		return nil, false, nil
	}
	var request ike.DeviceIdentity
	if err := request.UnmarshalBinary(notify.Data); err != nil {
		return nil, false, err
	}
	if len(request.Value) != 0 {
		return nil, false, nil
	}
	response, err := ike.NewDeviceIdentity(identity, request.Type)
	if err != nil {
		return nil, false, err
	}
	data, err := response.MarshalBinary()
	if err != nil {
		return nil, false, err
	}
	return &ike.NotifyPayload{ProtocolID: protocolIDUnset, NotifyType: notifyTypeDeviceIdentity, Data: data}, true, nil
}

func appendCookie2ResponsePayloads(responsePayloads []ike.Payload, payloads []ike.Payload) ([]ike.Payload, error) {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if !ok || notify.NotifyType != notifyTypeCookie2 {
			continue
		}
		if len(notify.Data) < minCookie2NotifyDataLength || len(notify.Data) > maxCookieNotifyDataLength {
			return nil, fmt.Errorf("parsing informational cookie2: invalid COOKIE2 length %d", len(notify.Data))
		}
		responsePayloads = append(responsePayloads, &ike.NotifyPayload{
			ProtocolID: protocolIDUnset,
			NotifyType: notifyTypeCookie2,
			Data:       append([]byte(nil), notify.Data...),
		})
	}
	return responsePayloads, nil
}

func buildInformationalConfigReply(state informationalState, payloads []ike.Payload) (*ike.ConfigPayload, informationalAction) {
	request := ike.FindConfigPayload(payloads)
	if request == nil || request.ConfigType != configTypeRequest {
		return nil, informationalAction{}
	}
	attrs := make([]ike.Attribute, 0, len(request.Attributes))
	action := informationalAction{}
	if state.cfg.DisablePCSCFRestoration {
		state.cfg.PCSCFIPv4ConfigAttribute = 0
		state.cfg.PCSCFIPv6ConfigAttribute = 0
	}
	pcscfReplyTypes := pcscfReselectionReplyTypes(request.Attributes, state.cfg)
	for _, attrType := range pcscfReplyTypes {
		attrs = append(attrs, ike.NewTLVAttribute(attrType, nil))
	}
	if len(pcscfReplyTypes) != 0 {
		if info, ok := pcscfReselectionInfo(state.info, request.Attributes, state.cfg); ok {
			action.pcscfReselection = true
			action.pcscfInfo = info
		}
	}
	if len(attrs) == 0 {
		return nil, informationalAction{}
	}
	return &ike.ConfigPayload{ConfigType: configTypeReply, Attributes: attrs}, action
}

func pcscfReselectionReplyTypes(attrs []ike.Attribute, cfg Config) []uint16 {
	if cfg.DisablePCSCFRestoration {
		return nil
	}
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(handshakeConfig(cfg))
	replyTypes := make([]uint16, 0, 2)
	for _, attr := range attrs {
		if attr.Type != pcscfIPv4Attr && attr.Type != pcscfIPv6Attr && attr.Type != configAttrPCSCFIPv4Address && attr.Type != configAttrPCSCFIPv6Address {
			continue
		}
		if !containsUint16(replyTypes, attr.Type) {
			replyTypes = append(replyTypes, attr.Type)
		}
	}
	return replyTypes
}

func pcscfReselectionInfo(previous Info, attrs []ike.Attribute, cfg Config) (Info, bool) {
	pcscfIPv4Attr, pcscfIPv6Attr := pcscfConfigAttributes(handshakeConfig(cfg))
	addresses := tunnelAddresses(attrs, pcscfIPv4Attr, pcscfIPv6Attr)
	ips := make([]net.IP, 0, len(addresses.pcscfIPv6)+len(addresses.pcscfIPv4))
	ips = append(ips, addresses.pcscfIPv6...)
	ips = append(ips, addresses.pcscfIPv4...)
	if len(ips) == 0 {
		return Info{}, false
	}
	return pcscfInfoFromAddresses(previous, ips), true
}

func containsUint16(values []uint16, target uint16) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func buildInformationalResponsePayloads(state informationalState, payloads []ike.Payload, identity string) ([]ike.Payload, informationalAction, error) {
	if responsePayloads, action, ok, err := buildDeleteResponsePayloads(state, payloads); ok || err != nil {
		return responsePayloads, action, err
	}
	responsePayloads := make([]ike.Payload, 0, 2)
	var err error
	responsePayloads, err = appendCookie2ResponsePayloads(responsePayloads, payloads)
	if err != nil {
		return nil, informationalAction{}, err
	}
	deviceIdentityPayload, ok, err := buildDeviceIdentityResponsePayload(payloads, identity)
	if err != nil {
		return nil, informationalAction{}, fmt.Errorf("building informational device identity: %w", err)
	}
	if ok {
		responsePayloads = append(responsePayloads, deviceIdentityPayload)
	}
	if configReply, configAction := buildInformationalConfigReply(state, payloads); configReply != nil {
		responsePayloads = append(responsePayloads, configReply)
		if configAction.pcscfReselection {
			return responsePayloads, configAction, nil
		}
	}
	return responsePayloads, informationalAction{}, nil
}

func buildDeleteResponsePayloads(state informationalState, payloads []ike.Payload) ([]ike.Payload, informationalAction, bool, error) {
	deletePayloads := findDeletePayloads(payloads)
	if len(deletePayloads) == 0 {
		return nil, informationalAction{}, false, nil
	}
	reactivationRequested := hasNotifyPayload(payloads, notifyTypeReactivationRequestedCause)
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID == protocolIDIKE {
			return nil, informationalAction{
				deleteIKE:             true,
				reactivationRequested: reactivationRequested,
			}, true, nil
		}
	}
	if state.inboundSPI == 0 || state.outboundSPI == 0 {
		return nil, informationalAction{}, true, nil
	}
	for _, deletePayload := range deletePayloads {
		if deletePayload.ProtocolID != protocolIDESP {
			continue
		}
		for _, spi := range deletePayload.SPIs {
			if len(spi) != 4 {
				return nil, informationalAction{}, true, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
			}
			if binary.BigEndian.Uint32(spi) != state.outboundSPI {
				continue
			}
			responseSPI := state.inboundSPI
			action := informationalAction{
				deleteChild:           true,
				reactivationRequested: reactivationRequested,
			}
			if state.pendingChild {
				responseSPI = state.oldInboundSPI
				action = informationalAction{
					promotePendingChild:   true,
					deleteRetiredChildSPI: responseSPI,
				}
			}
			return []ike.Payload{
				&ike.DeletePayload{
					ProtocolID: protocolIDESP,
					SPIs:       [][]byte{uint32Bytes(responseSPI)},
				},
			}, action, true, nil
		}
	}
	for _, child := range state.retiredChildSAs {
		for _, deletePayload := range deletePayloads {
			if deletePayload.ProtocolID != protocolIDESP {
				continue
			}
			for _, spi := range deletePayload.SPIs {
				if len(spi) != 4 {
					return nil, informationalAction{}, true, fmt.Errorf("parsing informational delete: invalid esp spi length %d", len(spi))
				}
				if binary.BigEndian.Uint32(spi) != child.outboundSPI {
					continue
				}
				return []ike.Payload{
					&ike.DeletePayload{
						ProtocolID: protocolIDESP,
						SPIs:       [][]byte{uint32Bytes(child.inboundSPI)},
					},
				}, informationalAction{deleteRetiredChildSPI: child.inboundSPI}, true, nil
			}
		}
	}
	return nil, informationalAction{}, true, nil
}

func hasNotifyPayload(payloads []ike.Payload, notifyType uint16) bool {
	for _, payload := range payloads {
		notify, ok := payload.(*ike.NotifyPayload)
		if ok && notify.NotifyType == notifyType {
			return true
		}
	}
	return false
}

func findDeletePayloads(payloads []ike.Payload) []*ike.DeletePayload {
	deletes := make([]*ike.DeletePayload, 0)
	for _, payload := range payloads {
		deletePayload, ok := payload.(*ike.DeletePayload)
		if ok && deletePayload != nil {
			deletes = append(deletes, deletePayload)
		}
	}
	return deletes
}

func (s *Session) informationalResponsePeer(addr net.Addr, fallback *net.UDPAddr) *net.UDPAddr {
	udpAddr, _ := addr.(*net.UDPAddr)
	if udpAddr != nil {
		return cloneUDPAddr(udpAddr)
	}
	return cloneUDPAddr(fallback)
}

func (s *Session) timeoutContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.closeCtx, timeout)
}

func (s *Session) handleInformationalResponse(state informationalState, packet ike.IKEPacket, data []byte, addr net.Addr) (bool, error) {
	key := ikeMessageKeyForHeader(packet.Header)
	if !s.hasInformationalWaiter(key) {
		s.logger.Debug("ignoring informational response without matching request", "message_id", packet.Header.MessageID)
		return true, nil
	}
	if _, err := state.ike.OpenIKE(packet, state.peerInitiator()); err != nil {
		return true, fmt.Errorf("opening informational response: %w", err)
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
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(key, inboundIKE{data: append([]byte(nil), data...), addr: cloneUDPAddr(udpAddr)}) {
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
	if _, err := openProtectedResponse(state.ike, data, exchangeTypeCreateChildSA, "handling create_child_sa response", state.peerInitiator()); err != nil {
		return true, err
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
	udpAddr, _ := addr.(*net.UDPAddr)
	if s.deliverInformationalWaiter(key, inboundIKE{data: append([]byte(nil), data...), addr: cloneUDPAddr(udpAddr)}) {
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

func (s *Session) sealInformationalResponse(state informationalState, messageID uint32, payloads []ike.Payload) ([]byte, error) {
	wire, err := state.ike.SealIKE(informationalResponseHeader(state, messageID), payloads, state.localInitiator)
	if err != nil {
		return nil, fmt.Errorf("sealing informational response: %w", err)
	}
	return prependNonESPMarker(wire), nil
}

func (s *Session) writeInformationalResponse(state informationalState, messageID uint32, request []byte, payloads []ike.Payload, addr net.Addr) error {
	wire, err := s.sealInformationalResponse(state, messageID, payloads)
	if err != nil {
		return err
	}
	s.cacheInformationalResponseForState(state, messageID, request, wire)
	return s.writeInformationalResponseWire(state, messageID, len(payloads), wire, addr)
}

func (s *Session) writeInformationalResponseWire(state informationalState, messageID uint32, payloadCount int, wire []byte, addr net.Addr) error {
	ctx, cancel := s.timeoutContext(2 * time.Second)
	defer cancel()
	peer := s.informationalResponsePeer(addr, state.peer)
	if err := s.writeProtectedWire(ctx, "writing informational response", state.ike, wire, peer, false); err != nil {
		return err
	}
	s.logger.Debug("replied to informational request", "message_id", messageID, "payload_count", payloadCount)
	return nil
}

func (s *Session) handleInformationalRequest(state informationalState, packet ike.IKEPacket, addr net.Addr) (bool, error) {
	payloads, err := state.ike.OpenIKE(packet, state.peerInitiator())
	if err != nil {
		if responsePayloads, ok := ikeErrorNotifyResponse(err); ok {
			return s.writeIKEErrorNotifyInformationalResponse(state, packet, addr, responsePayloads)
		}
		return true, fmt.Errorf("opening informational request: %w", err)
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
	defer func() {
		if expireAfterRequest {
			s.failSecurityAssociations(errIKESAExpired)
		}
	}()
	if wire, ok := s.cachedInformationalResponseForState(state, packet.Header.MessageID, packet.Raw); ok {
		return true, s.writeInformationalResponseWire(state, packet.Header.MessageID, 0, wire, addr)
	}
	switch s.peerRequestMessageIDRelationForState(state, packet.Header.MessageID) {
	case ikeMessageIDCurrent:
	case ikeMessageIDFuture:
		s.logger.Debug("ignoring informational request outside message id window", "message_id", packet.Header.MessageID)
		if err := s.sendInvalidMessageIDNotification(state, packet.Header.MessageID); err != nil {
			s.logger.Debug("sending invalid message id notification failed", "message_id", packet.Header.MessageID, "err", err)
		}
		return true, nil
	default:
		s.logger.Debug("ignoring old informational request without cached response", "message_id", packet.Header.MessageID)
		return true, nil
	}
	responsePayloads, action, err := buildInformationalResponsePayloads(state, payloads, state.identity)
	if err != nil {
		return true, err
	}
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, packet.Raw, responsePayloads, addr); err != nil {
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
		s.failSecurityAssociations(cause)
	}
	if action.deleteChild {
		s.logger.Debug("received child sa delete request", "message_id", packet.Header.MessageID, "inbound_spi", state.inboundSPI, "outbound_spi", state.outboundSPI, "reactivation_requested", action.reactivationRequested)
		cause := errors.New("peer deleted child SA")
		if action.reactivationRequested {
			cause = reactivationRequestedError(cause)
		}
		s.discardChildSecurityAssociations(cause)
	}
	if action.promotePendingChild {
		s.logger.Debug("received old child sa delete request", "message_id", packet.Header.MessageID, "old_inbound_spi", state.oldInboundSPI, "old_outbound_spi", state.outboundSPI)
		s.promotePendingChildSecurityAssociation()
	}
	if action.deleteRetiredChildSPI != 0 {
		s.removeRetiredChildSA(action.deleteRetiredChildSPI)
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

func (s *Session) applyPCSCFReselection(info Info) {
	if len(info.PCSCFIPs) == 0 {
		return
	}
	s.mu.Lock()
	if !s.connected {
		s.mu.Unlock()
		return
	}
	s.tunnel.PCSCFIP = append(net.IP(nil), info.PCSCFIP...)
	s.tunnel.PCSCFIPs = cloneIPList(info.PCSCFIPs)
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

func (s *Session) writeIKEErrorNotifyInformationalResponse(state informationalState, packet ike.IKEPacket, addr net.Addr, payloads []ike.Payload) (bool, error) {
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
	if err := s.writeInformationalResponse(state, packet.Header.MessageID, packet.Raw, payloads, addr); err != nil {
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
