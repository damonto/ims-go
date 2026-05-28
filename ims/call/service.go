package call

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"github.com/damonto/ims-client/ims/sip"
	"log/slog"
	"strings"
)

func New(cfg Config, sess *session.Session, reg *registration.Service) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating call service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating call service: registration service is nil")
	}
	normalized, err := cfg.Normalized()
	if err != nil {
		return nil, err
	}
	svc := &Service{
		cfg:       normalized,
		sess:      sess,
		reg:       reg,
		logger:    slog.Default().With("component", "ims-call"),
		timers:    sess.TransactionTimers(),
		nextPort:  normalized.LocalRTPPortMin,
		calls:     make(map[string]*Call),
		incomings: make(map[string]*Call),
	}
	attachment, err := sess.Attach(svc)
	if err != nil {
		return nil, fmt.Errorf("creating call service: %w", err)
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
	calls := make([]*Call, 0, len(s.calls))
	for _, call := range s.calls {
		calls = append(calls, call)
	}
	s.calls = make(map[string]*Call)
	s.incomings = make(map[string]*Call)
	s.mu.Unlock()

	if s.attachment != nil {
		_ = s.attachment.Close()
	}
	for _, call := range calls {
		call.finish(StateEnded, "")
	}
	return nil
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK", "BYE", "CANCEL", "PRACK":
		call := s.lookupCallForMessage(req.Message)
		if call == nil {
			s.logger.Debug("call request did not match dialog",
				"method", req.Message.Method(),
				"call_id", req.Message.Header("Call-ID"),
				"from", req.Message.Header("From"),
				"to", req.Message.Header("To"),
				"cseq", req.Message.Header("CSeq"),
			)
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
	if msg.StatusCode() >= 100 && msg.StatusCode() < 200 {
		call.markInviteResponse(ctx)
		if msg.StatusCode() == 100 {
			return true, nil
		}
		return true, call.handleProvisionalResponse(ctx, msg)
	}
	if msg.StatusCode() < 200 || msg.StatusCode() >= 300 {
		return false, nil
	}
	return true, call.handleResponse(ctx, msg)
}

func (s *Service) HandleError(err error) {
	if err != nil {
		s.emitError(err)
	}
}
