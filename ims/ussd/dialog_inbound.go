package ussd

import (
	"context"
	"errors"
	"strings"

	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func (s *Session) handleRequest(ctx context.Context, req session.Request) error {
	method := strings.ToUpper(req.Message.Method())
	if method != "ACK" && method != "CANCEL" {
		if duplicate, status, reason := s.recordRemoteCSeq(req.Message); status != 0 {
			return s.service.sess.WriteStatus(ctx, req, status, reason)
		} else if duplicate {
			if err := s.service.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
				return err
			}
			s.service.logger.Debug("suppressing duplicate USSD request", "call_id", s.callID, "cseq", req.Message.Header("CSeq"))
			return nil
		}
	}
	switch method {
	case "ACK":
		if !s.ackMatchesInvite(req.Message) {
			s.service.logger.Debug("ignoring ACK with mismatched CSeq", "call_id", s.callID, "cseq", req.Message.Header("CSeq"), "invite_cseq", s.inviteSeq)
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
	s.service.startBackgroundTask(func(done <-chan struct{}) {
		ctx, cancel := contextWithDoneTimeout(done, pending.timeout)
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

func (s *Session) stopInviteOKRetransmit() {
	s.mu.Lock()
	stop := s.inviteOKStop
	s.inviteOKStop = nil
	s.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

func (s *Session) handleInfo(ctx context.Context, req session.Request) error {
	payload, err := validateInboundInfo(req.Message, s.networkInitiated)
	if err != nil {
		if errors.Is(err, errBadInfoPackage) {
			return s.service.sess.WriteStatus(ctx, req, sipStatusBadInfoPackage, "Bad Info Package")
		}
		return s.service.writeUnsupportedMediaType(ctx, req)
	}
	if err := s.service.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
		return err
	}
	s.releaseInfoExchange()
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
		decoded, err := decodeSinglePayload(payloadContextUSSDBye, req.Message)
		if err != nil {
			return s.service.writeUnsupportedMediaType(ctx, req)
		}
		payload = decoded
	}
	if err := s.service.sess.WriteStatus(ctx, req, sipStatusOK, "OK"); err != nil {
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
