package sms

import (
	"context"
	"fmt"
	"log/slog"
	"mime"
	"strings"
	"sync"
	"time"

	"github.com/damonto/ims-go/ims/registration"
	"github.com/damonto/ims-go/ims/session"
)

func New(cfg Config, sess *session.Stack, reg *registration.Registrar, card Card) (*Endpoint, error) {
	endpointCfg, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	logger := endpointCfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	endpoint := &Endpoint{
		cfg:                         endpointCfg,
		sess:                        sess,
		reg:                         reg,
		card:                        card,
		logger:                      logger.With("component", "ims-sms"),
		done:                        make(chan struct{}),
		rpRefs:                      make(map[byte]struct{}),
		pending:                     make(map[string]pendingEntry),
		submitted:                   make(map[string]submittedEntry),
		recent:                      make(map[string]time.Time),
		concat:                      make(map[string]concatState),
		memoryAvailableRetryTimeout: defaultTRATimeout,
	}
	endpoint.submitTimeout.Store(int64(endpointCfg.SubmitReportTimeout))
	attachment, err := sess.Attach(endpoint)
	if err != nil {
		return nil, fmt.Errorf("creating SMS endpoint: %w", err)
	}
	endpoint.attachment = attachment
	endpoint.bgWG.Go(func() {
		endpoint.runSubmitCleanup()
	})
	return endpoint, nil
}

func (s *Endpoint) Close() error {
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
	s.closePendingSubmissions()
	return err
}

func (s *Endpoint) HandleRequest(ctx context.Context, req session.Request) (bool, error) {
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

func (s *Endpoint) HandleError(err error) {
	s.emitAsyncError(err)
}

func (s *Endpoint) emitAsyncError(err error) {
	if err == nil || s.cfg.OnError == nil {
		return
	}
	s.cfg.OnError(err)
}

func (s *Endpoint) cleanupStopped() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Endpoint) startBackgroundTask(task func(done <-chan struct{})) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	done := s.done
	s.bgWG.Go(func() {
		task(done)
	})
	s.mu.Unlock()
	return true
}

func contextWithDoneTimeout(done <-chan struct{}, timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	stop := make(chan struct{})
	var once sync.Once
	go func() {
		select {
		case <-done:
			cancel()
		case <-stop:
		}
	}()
	return ctx, func() {
		once.Do(func() {
			close(stop)
			cancel()
		})
	}
}
