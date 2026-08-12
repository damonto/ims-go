package tunnel

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/damonto/ims-go/swu/ike"
)

var errIKERequestIncomplete = errors.New("ike request completed without response")

func (s *Session) acquireIKERequest(ctx context.Context, action ikeAction) (func(), error) {
	select {
	case s.ikeRequestGate <- struct{}{}:
		return func() { <-s.ikeRequestGate }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("%s: %w", action, ctx.Err())
	case <-s.closeDone():
		return nil, fmt.Errorf("%s: session is closed", action)
	}
}

func (s *Session) sendInformational(ctx context.Context, payloads []ike.Payload) ([]ike.Payload, error) {
	if s.isClosed() {
		return nil, errors.New("sending informational: session is closed")
	}
	if err := s.expireIKESAIfNeeded(); err != nil {
		return nil, fmt.Errorf("sending informational: %w", err)
	}
	if s.ikeSARekeyActive() {
		return nil, errIKESARekeyInProgress
	}
	state := s.currentInformationalState()
	if !state.available() {
		return nil, errors.New("sending informational: ike state is unavailable")
	}
	release, err := s.acquireIKERequest(ctx, ikeActionSendInformational)
	if err != nil {
		return nil, err
	}
	defer release()
	messageID, err := s.allocateMessageID()
	if err != nil {
		return nil, fmt.Errorf("sending informational: %w", err)
	}
	key := state.responseMessageKey(messageID, exchangeTypeInformational)
	waiter := s.registerInformationalWaiter(key)
	defer s.unregisterInformationalWaiter(key, waiter)
	wires, err := state.sealInitiatorRequest(messageID, payloads)
	if err != nil {
		return nil, fmt.Errorf("sending informational: sealing request: %w", err)
	}
	return s.exchangeInformational(ctx, state, messageID, wires, waiter)
}

func (s *Session) exchangeInformational(ctx context.Context, state informationalState, messageID uint32, wires [][]byte, waiter <-chan inboundIKE) ([]ike.Payload, error) {
	return s.exchangeInformationalRequest(ctx, state, messageID, wires, waiter, ikeActionSendInformational, false)
}

func (s *Session) exchangeInformationalRequest(ctx context.Context, state informationalState, messageID uint32, wires [][]byte, waiter <-chan inboundIKE, action ikeAction, skipIKESAByteAccounting bool) ([]ike.Payload, error) {
	for attempt, delay := range s.ikeRetransmitDelays() {
		if err := s.writeInformationalRequest(ctx, state, wires, action, skipIKESAByteAccounting); err != nil {
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

func (s *Session) writeInformationalRequest(ctx context.Context, state informationalState, wires [][]byte, action ikeAction, skipIKESAByteAccounting bool) error {
	return s.writeProtectedWires(ctx, action, state.ike, buildIKEWires(wires, state.useNATT), state.peer, skipIKESAByteAccounting)
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
		if response.payloads != nil {
			return response.payloads, true, nil
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
	var packet ike.Packet
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
