package imsclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	imsussd "github.com/damonto/ims-client/ims/ussd"
)

const ussdResultBufferSize = 16

func (s *USSDService) Start() (*Session, error) {
	if _, err := s.client.currentUSSDService(); err != nil {
		return nil, fmt.Errorf("starting USSD: %w", err)
	}
	return newSession(s.client), nil
}

func (s *Session) Send(ctx context.Context, code string) (USSDResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := s.beginSend(); err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}
	defer s.finishOperation()

	service, err := s.client.currentUSSDService()
	if err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}

	low, err := service.Start(ctx, code)
	if err != nil {
		return USSDResult{}, err
	}
	if err := s.attachLowSession(low, false); err != nil {
		return USSDResult{}, fmt.Errorf("sending USSD: %w", err)
	}

	result, err := s.awaitResult(ctx, "sending USSD")
	if err != nil {
		return USSDResult{}, err
	}
	return result, nil
}

func (s *Session) Reply(ctx context.Context, text string) (USSDResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	low, err := s.beginActive("replying USSD")
	if err != nil {
		return USSDResult{}, err
	}
	defer s.finishOperation()

	if err := low.Reply(ctx, text); err != nil {
		return USSDResult{}, err
	}

	result, err := s.awaitResult(ctx, "replying USSD")
	if err != nil {
		return USSDResult{}, err
	}
	return result, nil
}

func (s *Session) Close(ctx context.Context) (USSDResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	low, started, err := s.beginClose()
	if err != nil {
		return USSDResult{}, fmt.Errorf("closing USSD: %w", err)
	}
	defer s.finishOperation()

	receivedAt := time.Now()
	if !started {
		s.markClosed(nil)
		return USSDResult{Closed: true, ReceivedAt: receivedAt}, nil
	}

	if err := low.End(ctx, ""); err != nil {
		return USSDResult{}, err
	}

	s.markClosed(low)
	return USSDResult{Closed: true, ReceivedAt: receivedAt}, nil
}

func (c *Client) currentUSSDService() (*imsussd.Service, error) {
	c.mu.Lock()
	active := c.active
	c.mu.Unlock()
	if active == nil || active.ussd == nil {
		return nil, ErrClientNotConnected
	}
	return active.ussd, nil
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

func newSession(client *Client) *Session {
	return &Session{
		client:  client,
		results: make(chan USSDResult, ussdResultBufferSize),
	}
}

func (c *Client) bindUSSDSession(low *imsussd.Session, skipFirst bool) (*Session, error) {
	if low == nil {
		return nil, fmt.Errorf("binding ussd session: session is nil")
	}

	c.mu.Lock()
	session := c.ussdSessions[low]
	if session == nil {
		session = newSession(c)
		c.ussdSessions[low] = session
	}
	c.mu.Unlock()

	if err := session.attachLowSession(low, skipFirst); err != nil {
		return nil, err
	}
	return session, nil
}

func (c *Client) forgetUSSDSession(low *imsussd.Session) {
	if low == nil {
		return
	}
	c.mu.Lock()
	delete(c.ussdSessions, low)
	c.mu.Unlock()
}

func (c *Client) clearUSSDSessionBindings() {
	c.mu.Lock()
	c.ussdSessions = make(map[*imsussd.Session]*Session)
	c.mu.Unlock()
}

func (s *Session) attachLowSession(low *imsussd.Session, skipFirst bool) error {
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

func (s *Session) watchLowEvents(low *imsussd.Session, skipFirst bool) {
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

func (s *Session) enqueueResult(result USSDResult) {
	select {
	case s.results <- result:
	default:
		s.client.logger.Debug("dropping ussd result", "text", result.Message.Text, "closed", result.Closed)
	}
}

func (s *Session) enqueueCloseOnly() {
	if !s.markClosed(s.currentLow()) {
		return
	}
	s.enqueueResult(USSDResult{Closed: true, ReceivedAt: time.Now()})
}

func (s *Session) awaitResult(ctx context.Context, action string) (USSDResult, error) {
	select {
	case result := <-s.results:
		return result, nil
	case <-ctx.Done():
		return USSDResult{}, fmt.Errorf("%s: %w", action, ctx.Err())
	}
}

func (s *Session) beginSend() error {
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

func (s *Session) beginActive(action string) (*imsussd.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.busy {
		return nil, fmt.Errorf("%s: %w", action, ErrUSSDInProgress)
	}
	if s.closed {
		return nil, fmt.Errorf("%s: %w", action, ErrUSSDClosed)
	}
	if s.low == nil {
		return nil, fmt.Errorf("%s: %w", action, ErrUSSDNotStarted)
	}

	s.busy = true
	return s.low, nil
}

func (s *Session) beginClose() (*imsussd.Session, bool, error) {
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

func (s *Session) finishOperation() {
	s.mu.Lock()
	s.busy = false
	s.mu.Unlock()
}

func (s *Session) markClosed(low *imsussd.Session) bool {
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

func (s *Session) currentLow() *imsussd.Session {
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
