package ussd

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"github.com/damonto/vowifi-go/ims/sip"
	"strings"
)

func New(cfg Config, sess *session.Session, reg *registration.Service) (*Service, error) {
	cfg.Language = strings.TrimSpace(cfg.Language)
	s := &Service{
		cfg:           cfg,
		sess:          sess,
		reg:           reg,
		logger:        cfg.Logger.With("component", "ims-ussd"),
		sessions:      make(map[string]*Session),
		incomingIndex: make(map[string]string),
		done:          make(chan struct{}),
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating ussd service: %w", err)
	}
	s.attachment = attachment
	return s, nil
}

func (s *Service) Start(ctx context.Context, code string) (*Session, error) {
	if err := s.ensureNoActiveSession("starting USSD"); err != nil {
		return nil, err
	}
	start, invite, err := s.newStart(code)
	if err != nil {
		return nil, err
	}
	resp, err := s.sess.Exchange(ctx, invite)
	if err != nil {
		if ctx.Err() != nil {
			s.cancelInvite(invite)
		}
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	if status := resp.StatusCode(); status == sipStatusNotFound {
		return nil, errors.New("starting USSD: missing network support")
	} else if status != sipStatusOK {
		return nil, fmt.Errorf("starting USSD: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.startSession(ctx, start, invite, resp)
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
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = make(map[string]*Session)
	s.incomingIndex = make(map[string]string)
	close(s.done)
	s.mu.Unlock()

	var err error
	if attachment != nil {
		err = attachment.Close()
	}

	for _, session := range sessions {
		session.finish(false)
	}
	s.bgWG.Wait()
	return err
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	switch strings.ToUpper(req.Message.Method()) {
	case "INVITE":
		if !looksLikeInvite(req.Message) {
			return false, nil
		}
		return true, s.handleIncomingInvite(ctx, req)
	case "ACK":
		session := s.lookupSessionForMessage(req.Message)
		if session == nil {
			return false, nil
		}
		return true, session.handleRequest(ctx, req)
	case "CANCEL":
		session := s.lookupIncomingInviteSession(req.Message)
		if session == nil {
			return false, nil
		}
		session.finish(false)
		return true, nil
	case "INFO", "BYE":
		session := s.lookupSessionForMessage(req.Message)
		if session != nil {
			return true, session.handleRequest(ctx, req)
		}
		if looksLikeDialogMessage(req.Message) {
			return true, s.sess.WriteStatus(ctx, req, sipStatusCallTransactionDoesNotExist, "Call/Transaction Does Not Exist")
		}
		return false, nil
	default:
		return false, nil
	}
}

func (s *Service) HandleError(err error) {
	if err == nil {
		return
	}
	s.logger.Debug("session error", "err", err)
}

func (s *Service) writeUnsupportedMediaType(ctx context.Context, req session.Request) error {
	resp := sip.NewResponse(sipStatusUnsupportedMediaType, "Unsupported Media Type")
	resp.Headers = sip.ResponseHeaders(req.Message, sipStatusUnsupportedMediaType)
	resp.Headers.Add("Accept", acceptHeader)
	return s.sess.WriteResponse(ctx, req, resp)
}
