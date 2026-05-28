package ussd

import (
	"context"
	"fmt"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"strings"
	"sync/atomic"
)

func (s *Session) buildACK() sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest("ACK", s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", "70")
	sip.ApplyRouteSet(&msg, s.routeSet)
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", s.inviteSeq))
	return msg
}

func (s *Session) buildDialogRequest(method string, body []byte) sip.Message {
	state := s.service.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest(method, s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.service.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", atomic.AddInt64(&s.service.cseq, 1), method))
	msg.Headers.Add("Contact", contactValue(state))
	s.service.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	msg.Body = body
	return msg
}

func (s *Session) handleRequest(ctx context.Context, req session.Request) error {
	switch strings.ToUpper(req.Message.Method()) {
	case "ACK":
		s.handleACK()
		return nil
	case "INFO":
		return s.handleInfo(ctx, req)
	case "BYE":
		return s.handleBye(ctx, req)
	default:
		return nil
	}
}

func (s *Session) handleACK() {
	pending := s.markACK()
	if pending == nil {
		return
	}
	s.service.startBackgroundTask(func() {
		ctx, cancel := context.WithTimeout(s.service.cleanupCtx, pending.timeout)
		defer cancel()
		if err := s.exchange(ctx, pending.msg, pending.action); err != nil {
			s.service.logger.Warn("sending queued ussd response", "call_id", s.callID, "method", pending.msg.Method(), "err", err)
			return
		}
		if pending.final {
			s.finish(false)
		}
	})
}

func (s *Session) handleInfo(ctx context.Context, req session.Request) error {
	payload, err := validateInboundInfo(req.Message, s.networkInitiated)
	if err != nil {
		return s.service.sess.WriteStatus(ctx, req, 415, "Unsupported Media Type")
	}
	if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	s.releaseInfoExchange()
	if s.isDuplicateRemote(req.Message) {
		s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
		return nil
	}
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	s.emit(payload)
	return nil
}

func (s *Session) handleBye(ctx context.Context, req session.Request) error {
	s.releaseInfoExchange()
	var payload Message
	hasPayload := len(req.Message.Body) > 0 || strings.TrimSpace(req.Message.Header("Content-Type")) != ""
	if hasPayload {
		decoded, err := decodeSinglePayload("parsing USSD BYE", req.Message)
		if err != nil {
			return s.service.sess.WriteStatus(ctx, req, 415, "Unsupported Media Type")
		}
		payload = decoded
	}
	if s.isDuplicateRemote(req.Message) {
		if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
			return err
		}
		s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
		return nil
	}
	if err := s.service.sess.WriteStatus(ctx, req, 200, "OK"); err != nil {
		return err
	}
	payload.Final = true
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	if hasPayload {
		s.emit(payload)
	}
	s.finish(true)
	return nil
}

func (s *Session) emit(msg Message) {
	defer func() { _ = recover() }()
	select {
	case s.events <- msg:
	default:
		s.service.logger.Debug("dropping USSD event", "call_id", s.callID, "text", msg.Text)
	}
}

func (s *Session) isDuplicateRemote(msg sip.Message) bool {
	key := msg.Method() + "|" + msg.Header("CSeq")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.remoteCSeqs[key]; ok {
		return true
	}
	s.remoteCSeqs[key] = struct{}{}
	return false
}

func (s *Session) markACK() *queuedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.acked {
		return nil
	}
	s.acked = true
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
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.deliveringInvite = false
	s.pendingInitial = nil
	if !s.acked && s.ackCh != nil {
		close(s.ackCh)
		s.acked = true
	}
	s.mu.Unlock()
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

func (s *Session) localDialogURI() string {
	if uri := strings.TrimSpace(s.localURI); uri != "" {
		return uri
	}
	return preferredIdentity(s.service.reg.State())
}

func (s *Session) sessionKey() string {
	return dialogSessionKey(sip.DialogID{
		CallID:    s.callID,
		LocalTag:  s.localTag,
		RemoteTag: s.remoteTag,
	})
}

func (s *Session) inviteRequestKey() string {
	if !s.networkInitiated {
		return ""
	}
	return strings.TrimSpace(s.incomingInviteID)
}

func dialogSessionKey(id sip.DialogID) string {
	return id.CallID + "|" + id.LocalTag + "|" + id.RemoteTag
}

func incomingInviteKey(msg sip.Message) string {
	method := strings.ToUpper(strings.TrimSpace(msg.Method()))
	if method == "" {
		return ""
	}
	if method == "ACK" {
		method = "INVITE"
	}

	via := strings.TrimSpace(msg.Header("Via"))
	branch := strings.TrimSpace(sip.TopViaBranch(via))
	if strings.HasPrefix(branch, "z9hG4bK") {
		sentBy := strings.TrimSpace(sip.TopViaSentBy(via))
		if sentBy == "" {
			return ""
		}
		return branch + "|" + sentBy + "|" + method
	}

	requestURI := strings.TrimSpace(sip.RequestURI(msg))
	callID := strings.TrimSpace(msg.Header("Call-ID"))
	cseq := strings.TrimSpace(msg.Header("CSeq"))
	fromTag := strings.TrimSpace(sip.HeaderTag(msg.Header("From")))
	toTag := strings.TrimSpace(sip.HeaderTag(msg.Header("To")))
	if requestURI == "" || via == "" || callID == "" || cseq == "" || fromTag == "" {
		return ""
	}
	return requestURI + "|" + toTag + "|" + fromTag + "|" + callID + "|" + cseq + "|" + via
}

func looksLikeDialogMessage(msg sip.Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return sip.TokenListContains(msg.Header("Info-Package"), infoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	return false
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
