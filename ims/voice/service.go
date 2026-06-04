package voice

import (
	"context"
	"fmt"
	"strings"

	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
)

func New(cfg Config, sess *session.Session, reg *registration.Service) (*Service, error) {
	normalized, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}
	svc := &Service{
		cfg:       normalized,
		sess:      sess,
		reg:       reg,
		logger:    normalized.Logger.With("component", "ims-voice"),
		timers:    sess.TransactionTimers(),
		nextPort:  normalized.LocalRTPPortMin,
		calls:     make(map[string]*Call),
		incomings: make(map[string]*Call),
		bgDone:    make(chan struct{}),
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating voice service: %w", err)
	}
	svc.attachment = attachment
	sess.SetResponseDecorator(svc.addAccessNetworkInfo)
	return svc, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	attachment := s.attachment
	s.attachment = nil
	calls := make([]*Call, 0, len(s.calls))
	for _, call := range s.calls {
		calls = append(calls, call)
	}
	s.calls = make(map[string]*Call)
	s.incomings = make(map[string]*Call)
	close(s.bgDone)
	s.mu.Unlock()

	var err error
	if attachment != nil {
		err = attachment.Close()
	}
	for _, call := range calls {
		call.finish(CallStateEnded, "")
	}
	s.bgWG.Wait()
	return err
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		if sip.HeaderTag(req.Message.Header("To")) != "" {
			call := s.lookupCallForMessage(req.Message)
			if call == nil {
				return true, s.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
			}
			return true, call.handleRequest(ctx, req)
		}
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK", "BYE", "CANCEL", "INFO", "PRACK", "UPDATE":
		call := s.lookupCallForMessage(req.Message)
		if call == nil && strings.EqualFold(req.Message.Method(), "CANCEL") {
			call = s.lookupIncoming(req.Message)
		}
		if call == nil {
			s.logger.Debug("call request did not match dialog",
				"method", req.Message.Method(),
				"call_id", req.Message.Header("Call-ID"),
				"from", req.Message.Header("From"),
				"to", req.Message.Header("To"),
				"cseq", req.Message.Header("CSeq"),
			)
			if strings.EqualFold(req.Message.Method(), "PRACK") {
				return true, s.writeStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
			}
			return false, nil
		}
		return true, call.handleRequest(ctx, req)
	default:
		return false, nil
	}
}

func (s *Service) HandleResponse(ctx context.Context, msg sip.Message) (bool, error) {
	if !strings.EqualFold(sip.CSeqMethod(msg.Header("CSeq")), "INVITE") {
		return false, nil
	}
	call := s.lookupCall(strings.TrimSpace(msg.Header("Call-ID")))
	if call == nil {
		return false, nil
	}
	if msg.StatusCode() >= sipStatusTrying && msg.StatusCode() < sipStatusOK {
		call.markInviteResponse()
		if msg.StatusCode() == sipStatusTrying {
			return true, nil
		}
		return true, call.handleProvisionalResponse(ctx, msg)
	}
	if msg.StatusCode() < sipStatusOK || msg.StatusCode() >= sipStatusMultipleChoices {
		return false, nil
	}
	return true, call.handleResponse(ctx, msg)
}

func (s *Service) HandleError(err error) {
	if err != nil {
		s.emitError(err)
	}
}
