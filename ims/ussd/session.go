package ussd

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	imssession "github.com/damonto/ims-go/ims/session"
	"github.com/damonto/ims-go/ims/sip"
)

func (s *Session) Events() <-chan Message {
	return s.events
}

func (s *Session) CloseLocal() {
	s.finish(false)
}

func (s *Session) Reply(ctx context.Context, text string) error {
	if err := s.ensureActive(); err != nil {
		return fmt.Errorf("replying USSD: %w", err)
	}
	payload, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage()})
	if err != nil {
		return fmt.Errorf("replying USSD: encoding XML payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", infoPackageDisposition)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, sessionActionReplyUSSD, false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, sessionActionReplyUSSD)
}

func (s *Session) ReplyError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive(); err != nil {
		return fmt.Errorf("replying USSD: %w", err)
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode)}}).MarshalText()
	if err != nil {
		return fmt.Errorf("replying USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("INFO", payload)
	msg.Headers.Add("Info-Package", infoPackage)
	msg.Headers.Add("Content-Disposition", infoPackageDisposition)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, sessionActionReplyUSSD, false); queued || err != nil {
		return err
	}
	return s.exchange(ctx, msg, sessionActionReplyUSSD)
}

func (s *Session) End(ctx context.Context, text string) error {
	if err := s.ensureActive(); err != nil {
		return fmt.Errorf("ending USSD: %w", err)
	}
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	if queued, err := s.queueInitialRequest(ctx, msg, sessionActionEndUSSD, true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, sessionActionEndUSSD); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) EndError(ctx context.Context, errorCode int) error {
	if err := s.ensureActive(); err != nil {
		return fmt.Errorf("ending USSD: %w", err)
	}
	payload, err := (xmlBody{Message: Message{Language: s.currentLanguage(), ErrorCode: normalizeErrorCode(errorCode), Final: true}}).MarshalText()
	if err != nil {
		return fmt.Errorf("ending USSD: encoding error payload: %w", err)
	}
	msg := s.buildDialogRequest("BYE", payload)
	msg.Headers.Add("Content-Type", xmlContentType)
	if queued, err := s.queueInitialRequest(ctx, msg, sessionActionEndUSSD, true); queued || err != nil {
		return err
	}
	if err := s.exchange(ctx, msg, sessionActionEndUSSD); err != nil {
		return err
	}
	s.finish(false)
	return nil
}

func (s *Session) endDirect(ctx context.Context, text string) error {
	var payload []byte
	if strings.TrimSpace(text) != "" {
		encoded, err := s.marshalDialogPayload(Message{Text: text, Language: s.currentLanguage(), Final: true})
		if err != nil {
			return fmt.Errorf("ending USSD: encoding XML payload: %w", err)
		}
		payload = encoded
	}
	msg := s.buildDialogRequest("BYE", payload)
	if len(payload) > 0 {
		msg.Headers.Add("Content-Type", xmlContentType)
	}
	if err := s.exchange(ctx, msg, sessionActionEndUSSD); err != nil {
		return err
	}
	return nil
}

func (s *Session) marshalDialogPayload(msg Message) ([]byte, error) {
	if s.networkInitiated {
		switch s.dialogKind() {
		case dialogKindRequest:
			msg.Request = true
		case dialogKindNotify:
			msg.Notify = true
		}
	}
	return (xmlBody{Message: msg}).MarshalText()
}

func (s *Session) dialogKind() dialogKind {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.responseKind
}

func (s *Session) currentLanguage() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.language
}

func (s *Session) setLanguage(language string) {
	if strings.TrimSpace(language) == "" {
		return
	}
	s.mu.Lock()
	s.language = language
	s.mu.Unlock()
}

func (s *Session) ensureActive() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == sessionStateClosed {
		return errors.New("session is closed")
	}
	return nil
}

func (s *Session) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state == sessionStateClosed
}

func (s *Session) markInviteFinalResponseSent() {
	s.mu.Lock()
	s.inviteFinalSent = true
	s.mu.Unlock()
}

func (s *Session) inviteHasFinalResponse() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inviteFinalSent
}

func (s *Session) waitForACK(ctx context.Context) error {
	s.mu.Lock()
	if !s.networkInitiated || s.acked || s.ackCh == nil {
		s.mu.Unlock()
		return nil
	}
	ackCh := s.ackCh
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-ackCh:
		return nil
	}
}

func (s *Session) exchange(ctx context.Context, msg sip.Message, action sessionAction) error {
	releaseInfo := false
	if strings.EqualFold(msg.Method(), "INFO") {
		if err := s.beginInfoExchange(action); err != nil {
			return err
		}
		releaseInfo = true
		defer func() {
			if releaseInfo {
				s.releaseInfoExchange()
			}
		}()
	}
	if err := s.waitForACK(ctx); err != nil {
		return fmt.Errorf("%s: %w", action, err)
	}
	// RFC 3261 section 15.1.1 terminates the session when BYE is handed
	// to the client transaction, independently of the eventual response.
	if strings.EqualFold(msg.Method(), "BYE") {
		s.finish(false)
	}
	resp, err := s.endpoint.sess.Exchange(ctx, msg)
	if err != nil {
		if imssession.TransactionTimerExpired(err, "B") || imssession.TransactionTimerExpired(err, "F") {
			s.finish(false)
		}
		return fmt.Errorf("%s: %w", action, err)
	}
	if resp.StatusCode() < 200 || resp.StatusCode() >= 300 {
		if ussdDialogTerminatedByResponse(resp.StatusCode()) {
			s.finish(false)
		}
		return fmt.Errorf("%s: unexpected response: %w", action, sip.NewResponseError(resp))
	}
	releaseInfo = false
	return nil
}

func ussdDialogTerminatedByResponse(status int) bool {
	return status == sipStatusCallTransactionDoesNotExist || status == sipStatusRequestTimeout
}

func (s *Session) beginInfoExchange(action sessionAction) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case sessionStateClosed:
		return fmt.Errorf("%s: session is closed", action)
	case sessionStateInfoInFlight, sessionStateWaitingACKInfoInFlight:
		return fmt.Errorf("%s: awaiting remote INFO", action)
	case sessionStateWaitingACK:
		s.state = sessionStateWaitingACKInfoInFlight
	default:
		s.state = sessionStateInfoInFlight
	}
	return nil
}

func (s *Session) releaseInfoExchange() {
	s.mu.Lock()
	switch s.state {
	case sessionStateInfoInFlight:
		s.state = sessionStateActive
	case sessionStateWaitingACKInfoInFlight:
		s.state = sessionStateWaitingACK
	}
	s.mu.Unlock()
}

func (s *Session) buildACK() sip.Message {
	state := s.endpoint.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest("ACK", s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.endpoint.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("Max-Forwards", strconv.Itoa(sip.DefaultMaxForwards))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d ACK", s.inviteSeq))
	s.endpoint.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	msg.Headers.Del("Require")
	msg.Headers.Del("Proxy-Require")
	return msg
}

func (s *Session) buildDialogRequest(method string, body []byte) sip.Message {
	state := s.endpoint.reg.State()
	senderIdentity := s.localDialogURI()
	msg := sip.NewRequest(method, s.targetURI)
	msg.Headers.Add("Via", sip.BuildVia(sip.TransportToken(s.endpoint.sess.LocalAddr()), state.ContactHost, state.MessagePort, sip.RandomAlphaNum(15)))
	msg.Headers.Add("From", fmt.Sprintf("<%s>;tag=%s", senderIdentity, s.localTag))
	msg.Headers.Add("To", s.remoteTo)
	msg.Headers.Add("Call-ID", s.callID)
	msg.Headers.Add("Session-ID", s.sessionID)
	msg.Headers.Add("CSeq", fmt.Sprintf("%d %s", s.nextCSeq(), method))
	msg.Headers.Add("Contact", requestContactValue(state, s.endpoint.cfg.NetworkInitiatedSupported))
	s.endpoint.reg.DialogRequestPolicy(s.routeSet).Apply(&msg)
	msg.Body = body
	return msg
}

func (s *Session) nextCSeq() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localCSeq++
	return s.localCSeq
}

func (s *Session) emit(msg Message) {
	s.mu.Lock()
	if s.state == sessionStateClosed {
		s.mu.Unlock()
		return
	}
	dropped := false
	select {
	case s.events <- msg:
	default:
		dropped = true
	}
	s.mu.Unlock()
	if dropped {
		s.endpoint.logger.Debug("dropping USSD event", "call_id", s.callID, "text", msg.Text)
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
	if err := s.finishError(fromNetwork); err != nil {
		s.endpoint.logger.Warn("closing USSD session resources failed", "call_id", s.callID, "err", err)
	}
}

func (s *Session) finishError(fromNetwork bool) error {
	s.mu.Lock()
	if s.state == sessionStateClosed {
		s.mu.Unlock()
		return nil
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
	var closeErr error
	if s.dialogAttachment != nil {
		closeErr = s.dialogAttachment.Close()
		s.dialogAttachment = nil
	}
	s.endpoint.removeSession(s.sessionKey())
	s.closeEvents()
	s.endpoint.logger.Debug("ended USSD session", "call_id", s.callID, "from_network", fromNetwork)
	return closeErr
}

func (s *Session) closeEvents() {
	close(s.events)
}

func (s *Session) setDeliveringInvite(active bool) {
	s.mu.Lock()
	s.deliveringInvite = active
	s.mu.Unlock()
}

func (s *Session) queueInitialRequest(ctx context.Context, msg sip.Message, action sessionAction, final bool) (bool, error) {
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

func (s *Session) localDialogURI() string {
	if uri := strings.TrimSpace(s.localURI); uri != "" {
		return uri
	}
	return preferredIdentity(s.endpoint.reg.State())
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
	if method == "ACK" || method == "CANCEL" {
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
	if number := sip.CSeqNumber(cseq); number > 0 && (strings.EqualFold(sip.CSeqMethod(cseq), "ACK") || strings.EqualFold(sip.CSeqMethod(cseq), "CANCEL")) {
		cseq = fmt.Sprintf("%d INVITE", number)
	}
	fromTag := strings.TrimSpace(sip.HeaderTag(msg.Header("From")))
	toTag := strings.TrimSpace(sip.HeaderTag(msg.Header("To")))
	if requestURI == "" || via == "" || callID == "" || cseq == "" || fromTag == "" {
		return ""
	}
	return requestURI + "|" + toTag + "|" + fromTag + "|" + callID + "|" + cseq + "|" + via
}

func looksLikeDialogMessage(msg sip.Message) bool {
	if strings.EqualFold(msg.Method(), "INFO") {
		return msg.HeaderHasToken("Info-Package", infoPackage) || strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	if strings.EqualFold(msg.Method(), "BYE") {
		return strings.Contains(strings.ToLower(msg.Header("Content-Type")), xmlContentType)
	}
	return false
}

func (s *Session) handleRequest(ctx context.Context, req imssession.Request) error {
	method := strings.ToUpper(req.Message.Method())
	if method != "ACK" && method != "CANCEL" {
		duplicate, status, reason := s.recordRemoteCSeq(req.Message)
		if status != 0 {
			return s.endpoint.sess.WriteStatus(ctx, req, status, reason)
		}
		if duplicate {
			if err := s.endpoint.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
				return err
			}
			s.endpoint.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
			return nil
		}
	}
	switch method {
	case "ACK":
		if !s.ackMatchesInvite(req.Message) {
			s.endpoint.logger.Debug("ignoring ACK with mismatched CSeq", "call_id", s.callID, "cseq", req.Message.Header("CSeq"), "invite_cseq", s.inviteSeq)
			return nil
		}
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

func (s *Session) ackMatchesInvite(msg sip.Message) bool {
	return strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "ACK") && sip.CSeqNumber(msg.Header("CSeq")) == s.inviteSeq
}

func (s *Session) recordRemoteCSeq(msg sip.Message) (bool, int, string) {
	method := strings.ToUpper(msg.Method())
	if !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), method) {
		return false, sipStatusBadRequest, "Bad Request"
	}
	cseq := sip.CSeqNumber(msg.Header("CSeq"))
	if cseq <= 0 {
		return false, sipStatusBadRequest, "Bad Request"
	}
	key := method + "|" + msg.Header("CSeq")
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.remoteCSeqs[key]; ok {
		return true, 0, ""
	}
	if s.remoteCSeq != 0 && cseq <= s.remoteCSeq {
		return false, sipStatusServerInternalError, "Server Internal Error"
	}
	s.remoteCSeq = cseq
	s.remoteCSeqs[key] = struct{}{}
	return false, 0, ""
}

func (s *Session) handleACK() {
	s.stopInviteOKRetransmit()
	pending := s.markACK()
	if pending == nil {
		return
	}
	s.endpoint.startBackgroundTask(func(done <-chan struct{}) {
		ctx, cancel := contextWithDoneTimeout(done, pending.timeout)
		defer cancel()
		if err := s.exchange(ctx, pending.msg, pending.action); err != nil {
			s.endpoint.logger.Warn("sending queued ussd response", "call_id", s.callID, "method", pending.msg.Method(), "err", err)
			return
		}
		if pending.final {
			s.finish(false)
		}
	})
}

func (s *Session) stopInviteOKRetransmit() {
	s.mu.Lock()
	stop := s.inviteOKStop
	s.inviteOKStop = nil
	s.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (s *Session) handleInfo(ctx context.Context, req imssession.Request) error {
	payload, err := validateInboundInfo(req.Message, s.networkInitiated)
	if err != nil {
		if errors.Is(err, errBadInfoPackage) {
			return s.endpoint.sess.WriteStatus(ctx, req, sipStatusBadInfoPackage, "Bad Info Package")
		}
		return s.endpoint.writeUnsupportedMediaType(ctx, req)
	}
	if err := s.endpoint.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return err
	}
	s.releaseInfoExchange()
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	s.emit(payload)
	return nil
}

func (s *Session) handleBye(ctx context.Context, req imssession.Request) error {
	defer s.finish(true)
	s.releaseInfoExchange()
	var payload Message
	hasPayload := len(req.Message.Body) > 0 || strings.TrimSpace(req.Message.Header("Content-Type")) != ""
	if hasPayload {
		decoded, presence, err := decodeSinglePayloadWithPresence(payloadContextUSSDBye, req.Message)
		if err != nil {
			// A malformed optional body cannot reject an in-dialog BYE. RFC 3261
			// section 15.1.2 requires a 2xx response and session termination.
			s.endpoint.logger.Warn("ignoring invalid USSD BYE payload", "call_id", s.callID, "err", err)
			hasPayload = false
		} else if !presence.error && (!presence.text || !presence.language) {
			s.endpoint.logger.Warn("ignoring incomplete USSD BYE payload", "call_id", s.callID)
			hasPayload = false
		} else {
			payload = decoded
		}
	}
	if err := s.endpoint.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return err
	}
	payload.Final = true
	s.setLanguage(payload.Language)
	s.setDialogKind(payload)
	if hasPayload {
		s.emit(payload)
	}
	return nil
}
