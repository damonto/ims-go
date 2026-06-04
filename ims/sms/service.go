package sms

import (
	"context"
	"fmt"
	"github.com/damonto/vowifi-go/ims/registration"
	"github.com/damonto/vowifi-go/ims/session"
	"mime"
	"strings"
	"time"
)

func New(cfg Config, sess *session.Session, reg *registration.Service, card Card) (*Service, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	s := &Service{
		cfg:       normalized,
		sess:      sess,
		reg:       reg,
		card:      card,
		logger:    normalized.Logger.With("component", "ims-sms"),
		done:      make(chan struct{}),
		rpRefs:    make(map[byte]struct{}),
		pending:   make(map[string]pendingEntry),
		submitted: make(map[string]submittedEntry),
		recent:    make(map[string]time.Time),
		concat:    make(map[string]concatState),
	}
	attachment, err := sess.Attach(s)
	if err != nil {
		return nil, fmt.Errorf("creating sms service: %w", err)
	}
	s.attachment = attachment
	s.bgWG.Go(func() {
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
	attachment := s.attachment
	s.attachment = nil
	close(s.done)
	s.mu.Unlock()

	var err error
	if attachment != nil {
		err = attachment.Close()
	}
	s.bgWG.Wait()
	return err
}

func (s *Service) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
	if !strings.EqualFold(req.Message.Method(), "MESSAGE") {
		return false, nil
	}
	mediaType, _, err := mime.ParseMediaType(req.Message.Header("Content-Type"))
	if err != nil {
		return true, s.writeMessageStatus(ctx, req, sipStatusUnsupportedMediaType, "Unsupported Media Type")
	}
	if !strings.EqualFold(mediaType, messageContentType) && !strings.EqualFold(mediaType, mixedMultipartType) {
		return true, s.writeMessageStatus(ctx, req, sipStatusUnsupportedMediaType, "Unsupported Media Type")
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

func (s *Service) cleanupStopped() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}
