package ussd

import (
	"context"
	"fmt"

	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) emit(msg Message) {
	defer func() { _ = recover() }()
	select {
	case s.events <- msg:
	default:
		s.service.logger.Debug("dropping USSD event", "call_id", s.callID, "text", msg.Text)
	}
}

func (s *Session) markACK() *queuedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acked {
		return nil
	}
	s.acked = true
	switch s.state {
	case sessionStateWaitingACK:
		s.state = sessionStateActive
	case sessionStateWaitingACKInfoInFlight:
		s.state = sessionStateInfoInFlight
	}
	pending := s.pendingInitial
	s.pendingInitial = nil
	if s.ackCh != nil {
		close(s.ackCh)
	}
	return pending
}

func (s *Session) setDialogKind(payload Message) {
	kind := kindFromPayload(payload)
	if kind == dialogKindNone {
		return
	}
	s.mu.Lock()
	s.responseKind = kind
	s.mu.Unlock()
}

func (s *Session) finish(fromNetwork bool) {
	s.mu.Lock()
	if s.state == sessionStateClosed {
		s.mu.Unlock()
		return
	}
	s.state = sessionStateClosed
	s.deliveringInvite = false
	s.pendingInitial = nil
	stop := s.inviteOKStop
	s.inviteOKStop = nil
	if !s.acked && s.ackCh != nil {
		close(s.ackCh)
		s.acked = true
	}
	s.mu.Unlock()
	if stop != nil {
		close(stop)
	}
	if s.dialogAttachment != nil {
		_ = s.dialogAttachment.Close()
		s.dialogAttachment = nil
	}
	s.service.removeSession(s.sessionKey())
	s.closeEvents()
	s.service.logger.Debug("ended USSD session", "call_id", s.callID, "from_network", fromNetwork)
}

func (s *Session) closeEvents() {
	defer func() { _ = recover() }()
	close(s.events)
}

func (s *Session) setDeliveringInvite(active bool) {
	s.mu.Lock()
	s.deliveringInvite = active
	s.mu.Unlock()
}

func (s *Session) queueInitialRequest(ctx context.Context, msg sip.Message, action string, final bool) (bool, error) {
	timeout, err := queuedRequestTimeout(ctx)
	if err != nil {
		return false, fmt.Errorf("%s: %w", action, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.networkInitiated || s.acked || s.ackCh == nil {
		return false, nil
	}
	if s.pendingInitial != nil {
		return false, fmt.Errorf("%s: initial response already queued", action)
	}
	if !s.deliveringInvite {
		return false, nil
	}
	s.pendingInitial = &queuedRequest{
		msg:     msg,
		action:  action,
		final:   final,
		timeout: timeout,
	}
	return true, nil
}

func kindFromPayload(payload Message) dialogKind {
	if payload.Request {
		return dialogKindRequest
	}
	if payload.Notify {
		return dialogKindNotify
	}
	return dialogKindNone
}
