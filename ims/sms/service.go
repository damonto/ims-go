package sms

import (
	"context"
	"errors"
	"fmt"
	"github.com/damonto/ims-client/ims/registration"
	"github.com/damonto/ims-client/ims/session"
	"log/slog"
	"mime"
	"strings"
	"time"
)

func New(cfg Config, sess *session.Session, reg *registration.Service, card Card) (*Service, error) {
	if sess == nil {
		return nil, errors.New("creating sms service: session is nil")
	}
	if reg == nil {
		return nil, errors.New("creating sms service: registration service is nil")
	}
	if card == nil {
		return nil, errors.New("creating sms service: card is nil")
	}
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	cleanupCtx, cleanupCancel := context.WithCancel(context.Background())
	s := &Service{
		cfg:           normalized,
		sess:          sess,
		reg:           reg,
		card:          card,
		logger:        slog.Default().With("component", "ims-sms"),
		cleanupCtx:    cleanupCtx,
		cleanupCancel: cleanupCancel,
		rpRefs:        make(map[byte]struct{}),
		pending:       make(map[string]pendingEntry),
		submitted:     make(map[string]submittedEntry),
		recent:        make(map[string]time.Time),
		concat:        make(map[string]concatState),
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating sms service: %w", err)
	}
	s.attachment = attachment
	s.cleanupWG.Go(func() {
		s.runSubmitCleanup()
	})
	return s, nil
}

func (s *Service) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()
	if s.cleanupCancel != nil {
		s.cleanupCancel()
	}
	if s.attachment != nil {
		_ = s.attachment.Close()
	}
	s.cleanupWG.Wait()
	return nil
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "MESSAGE") {
		return false, nil
	}
	if mediaType, _, err := mime.ParseMediaType(req.Message.Header("Content-Type")); err != nil || !strings.EqualFold(mediaType, "application/vnd.3gpp.sms") {
		return false, nil
	}
	return true, s.handleMessageRequest(ctx, req)
}

func (s *Service) HandleError(err error) {
	s.emitAsyncError(err)
}

func (s *Service) emitAsyncError(err error) {
	if err == nil || s.cfg.OnError == nil {
		return
	}
	s.cfg.OnError(err)
}
