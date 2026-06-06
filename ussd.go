package vowifi

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	imsussd "github.com/damonto/vowifi-go/ims/ussd"
)

const ussdResultBufferSize = 16

type USSDMessage = imsussd.Message

type USSDResult struct {
	Message    USSDMessage
	HasMessage bool
	Closed     bool
	ReceivedAt time.Time
}

type IncomingUSSD struct {
	Session    *USSDSession
	Message    USSDMessage
	ReceivedAt time.Time
}

type USSDService struct {
	client *Client
}

type USSDSession struct {
	client *Client

	mu      sync.Mutex
	low     *imsussd.Session
	results chan USSDResult
	started bool
	closed  bool
	busy    bool

	watchOnce sync.Once
}

func (s *USSDService) Start() (*USSDSession, error) {
	if _, err := s.client.currentUSSDService(); err != nil {
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	return newSession(s.client), nil
}

func (s *USSDSession) Send(ctx context.Context, code string) (USSDResult, error) {
	if err := s.beginSend(); err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}
	defer s.finishOperation()

	service, err := s.client.currentUSSDService()
	if err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}

	s.client.logger.Info("sending USSD", "code", code)
	low, err := service.Start(ctx, code)
	if err != nil {
		s.client.logger.Error("sending USSD", "code", code, "err", err)
		return USSDResult{}, err
	}
	if err := s.attachLowSession(low, false); err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}

	result, err := s.awaitResult(ctx)
	if err != nil {
		s.client.logger.Error("waiting for USSD result", "code", code, "err", err)
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}
	s.client.logger.Info("USSD result", "closed", result.Closed, "request", result.Message.Request, "notify", result.Message.Notify, "final", result.Message.Final, "error_code", result.Message.ErrorCode)
	return result, nil
}

func (s *USSDSession) Reply(ctx context.Context, text string) (USSDResult, error) {
	low, err := s.beginActive()
	if err != nil {
		return USSDResult{}, fmt.Errorf("replying USSD: %w", err)
	}
	defer s.finishOperation()

	if err := low.Reply(ctx, text); err != nil {
		s.client.logger.Error("replying USSD", "err", err)
		return USSDResult{}, err
	}

	result, err := s.awaitResult(ctx)
	if err != nil {
		s.client.logger.Error("waiting for USSD reply result", "err", err)
		return USSDResult{}, fmt.Errorf("replying USSD: %w", err)
	}
	s.client.logger.Info("USSD reply result", "closed", result.Closed, "request", result.Message.Request, "notify", result.Message.Notify, "final", result.Message.Final, "error_code", result.Message.ErrorCode)
	return result, nil
}

func (s *USSDSession) Close(ctx context.Context) (USSDResult, error) {
	low, started, err := s.beginClose()
	if err != nil {
		return USSDResult{}, fmt.Errorf("closing USSD: %w", err)
	}
	defer s.finishOperation()

	receivedAt := time.Now()
	if !started {
		s.markClosed(nil)
		s.client.logger.Info("USSD closed")
		return USSDResult{Closed: true, ReceivedAt: receivedAt}, nil
	}

	if err := low.End(ctx, ""); err != nil {
		s.client.logger.Error("closing USSD", "err", err)
		return USSDResult{}, err
	}

	s.markClosed(low)
	s.client.logger.Info("USSD closed")
	return USSDResult{Closed: true, ReceivedAt: receivedAt}, nil
}

func (c *Client) currentUSSDService() (*imsussd.Service, error) {
	return currentIMSService(c, func(ims imsRuntime) *imsussd.Service { return ims.ussd })
}

func (c *Client) handleUSSD(low *imsussd.Session, msg imsussd.Message) {
	wrapper, err := c.bindUSSDSession(low, true)
	if err != nil {
		c.logger.Warn("binding ussd session", "err", err)
		return
	}

	c.emitIncomingUSSD(IncomingUSSD{
		Session:    wrapper,
		Message:    msg,
		ReceivedAt: time.Now(),
	})
}

func newSession(client *Client) *USSDSession {
	return &USSDSession{
		client:  client,
		results: make(chan USSDResult, ussdResultBufferSize),
	}
}

func (c *Client) bindUSSDSession(low *imsussd.Session, skipFirst bool) (*USSDSession, error) {
	var session *USSDSession
	c.withStateLock(func(*clientState) {
		session = c.ussdSessions[low]
		if session == nil {
			session = newSession(c)
			c.ussdSessions[low] = session
		}
	})

	if err := session.attachLowSession(low, skipFirst); err != nil {
		return nil, err
	}
	return session, nil
}

func (c *Client) forgetUSSDSession(low *imsussd.Session) {
	if low == nil {
		return
	}
	c.withStateLock(func(*clientState) {
		delete(c.ussdSessions, low)
	})
}

func (c *Client) clearUSSDSessionBindings() {
	c.withStateLock(func(*clientState) {
		c.ussdSessions = make(map[*imsussd.Session]*USSDSession)
	})
}

func (s *USSDSession) attachLowSession(low *imsussd.Session, skipFirst bool) error {
	s.mu.Lock()
	switch {
	case s.closed:
		s.mu.Unlock()
		return ErrUSSDClosed
	case s.low != nil && s.low != low:
		s.mu.Unlock()
		return ErrUSSDAlreadyStarted
	case s.low == low:
		s.started = true
		s.mu.Unlock()
		return nil
	default:
		s.low = low
		s.started = true
		s.mu.Unlock()
	}

	s.watchOnce.Do(func() {
		go s.watchLowEvents(low, skipFirst)
	})
	return nil
}

func (s *USSDSession) watchLowEvents(low *imsussd.Session, skipFirst bool) {
	events := low.Events()
	if events == nil {
		return
	}
	if skipFirst {
		_, ok := <-events
		if !ok {
			s.enqueueCloseOnly()
			return
		}
	}

	for msg := range events {
		result := ussdResultFromMessage(msg)
		if result.Closed {
			s.markClosed(low)
		}
		s.enqueueResult(result)
	}

	s.enqueueCloseOnly()
}

func (s *USSDSession) enqueueResult(result USSDResult) {
	select {
	case s.results <- result:
	default:
		s.client.logger.Debug("dropping ussd result", "text", result.Message.Text, "closed", result.Closed)
	}
}

func (s *USSDSession) enqueueCloseOnly() {
	if !s.markClosed(s.currentLow()) {
		return
	}
	s.enqueueResult(USSDResult{Closed: true, ReceivedAt: time.Now()})
}

func (s *USSDSession) awaitResult(ctx context.Context) (USSDResult, error) {
	select {
	case result := <-s.results:
		return result, nil
	case <-ctx.Done():
		return USSDResult{}, ctx.Err()
	}
}

func (s *USSDSession) beginSend() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.busy {
		return ErrUSSDInProgress
	}
	if s.closed {
		return ErrUSSDClosed
	}
	if s.started || s.low != nil {
		return ErrUSSDAlreadyStarted
	}

	s.busy = true
	return nil
}

func (s *USSDSession) beginActive() (*imsussd.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.busy {
		return nil, ErrUSSDInProgress
	}
	if s.closed {
		return nil, ErrUSSDClosed
	}
	if s.low == nil {
		return nil, ErrUSSDNotStarted
	}

	s.busy = true
	return s.low, nil
}

func (s *USSDSession) beginClose() (*imsussd.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.busy {
		return nil, false, ErrUSSDInProgress
	}
	if s.closed {
		return nil, false, ErrUSSDClosed
	}

	s.busy = true
	return s.low, s.low != nil, nil
}

func (s *USSDSession) finishOperation() {
	s.mu.Lock()
	s.busy = false
	s.mu.Unlock()
}

func (s *USSDSession) markClosed(low *imsussd.Session) bool {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return false
	}
	s.closed = true
	current := s.low
	s.mu.Unlock()

	if low == nil {
		low = current
	}
	s.client.forgetUSSDSession(low)
	return true
}

func (s *USSDSession) currentLow() *imsussd.Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.low
}

func ussdResultFromMessage(msg USSDMessage) USSDResult {
	return USSDResult{
		Message:    msg,
		HasMessage: hasUSSDMessage(msg),
		Closed:     msg.Final,
		ReceivedAt: time.Now(),
	}
}

func hasUSSDMessage(msg USSDMessage) bool {
	return strings.TrimSpace(msg.Text) != "" ||
		strings.TrimSpace(msg.Language) != "" ||
		msg.ErrorCode != 0 ||
		msg.Request ||
		msg.Notify ||
		msg.Final
}
