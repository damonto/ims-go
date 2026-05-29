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
	if sess == nil {
		return nil, errors.New("creating ussd service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating ussd service: registration service is nil")
	}
	cfg.Language = strings.TrimSpace(cfg.Language)
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:           cfg,
		sess:          sess,
		reg:           reg,
		logger:        cfg.Logger.With("component", "ims-ussd"),
		sessions:      make(map[string]*Session),
		incomingIndex: make(map[string]string),
		cleanupCtx:    cleanupCtx,
		cleanupCancel: cleanupCancel,
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating ussd service: %w", err)
	}
	s.attachment = attachment
	return s, nil
}

func (s *Service) Start(ctx context.Context, code string) (*Session, error) {
	start, invite, err := s.newStart(code)
	if err != nil {
		return nil, err
	}
	resp, err := s.sess.Exchange(ctx, invite)
	if err != nil {
		if ctx.Err() != nil {
			s.cancelInvite(ctx, invite)
		}
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	if status := resp.StatusCode(); status == 404 {
		return nil, errors.New("starting USSD: missing network support")
	} else if status != 200 {
		return nil, fmt.Errorf("starting USSD: unexpected response: %w", sip.NewResponseError(resp))
	}
	return s.startSession(ctx, start, invite, resp)
}

func (s *Service) CloseContext(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	sessions := make([]*Session, 0, len(s.sessions))
	for _, sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.sessions = make(map[string]*Session)
	s.incomingIndex = make(map[string]string)
	s.mu.Unlock()

	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.attachment != nil {
		_ = s.attachment.Close()
	}

	var err error
	for _, ussdSession := range sessions {
		if !ussdSession.isClosed() {
			err = errors.Join(err, ussdSession.endDirect(ctx, ""))
		}
		ussdSession.finish(false)
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
		ussdSession := s.lookupSessionForMessage(req.Message)
		if ussdSession == nil {
			return false, nil
		}
		return true, ussdSession.handleRequest(ctx, req)
	case "INFO", "BYE":
		ussdSession := s.lookupSessionForMessage(req.Message)
		if ussdSession != nil {
			return true, ussdSession.handleRequest(ctx, req)
		}
		if looksLikeDialogMessage(req.Message) {
			return true, s.sess.WriteStatus(ctx, req, 481, "Call/Transaction Does Not Exist")
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
